"""Evidence vault: registration, SHA-256 integrity hashing, optional AES-256-GCM encryption at
rest, recomputed-hash verification, deletion and backup.

An integrity hash shows that bytes have not changed since registration *as recorded by this
workstation*. It is NOT a digital signature, is not independently timestamped, and is not proof
of chain of custody or legal admissibility.
"""
from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import sqlite3
import uuid
import zipfile
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..config import get_settings
from ..db import db, next_ref, row_to_dict, rows_to_dicts, utcnow
from ..errors import GhostError, NotFound, Unavailable
from . import audit
from .findings import link, upsert_entity

MAGIC = b"GHOSTENC1"


def _key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def _encrypt(plain: bytes, passphrase: str) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, plain, MAGIC)


def _decrypt(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise GhostError("Vault file is not in the expected encrypted format", 500, "corrupt")
    salt, nonce, body = blob[9:25], blob[25:37], blob[37:]
    try:
        return AESGCM(_key(passphrase, salt)).decrypt(nonce, body, MAGIC)
    except InvalidTag:
        raise GhostError("Decryption failed: wrong passphrase or the vault file was modified", 422, "decrypt_failed")


def _read_plain(row: sqlite3.Row | dict) -> bytes:
    path = get_settings().vault_dir / row["stored_name"]
    if not path.is_file():
        raise GhostError("Evidence file is missing from the vault", 410, "missing")
    blob = path.read_bytes()
    if row["encrypted"]:
        pw = get_settings().vault_passphrase
        if not pw:
            raise Unavailable("This evidence is encrypted but GHOST_VAULT_PASSPHRASE is not set.", "vault_locked")
        return _decrypt(blob, pw)
    return blob


def register(stream: BinaryIO, filename: str, *, case_id: int | None = None, description: str = "",
             source: str = "", created_by: str | None = None) -> dict[str, Any]:
    s = get_settings()
    s.ensure_dirs()
    limit = s.max_upload_mb * 1024 * 1024
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise GhostError(f"File exceeds the {s.max_upload_mb} MB limit", 413, "too_large")
    if not data:
        raise GhostError("Evidence file is empty", 422, "validation")
    name = Path(filename or "evidence.bin").name[:200]
    sha = hashlib.sha256(data).hexdigest()
    encrypted = bool(s.vault_passphrase)
    stored = f"{uuid.uuid4().hex}.bin"
    with db() as c:
        if case_id is not None and not c.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
            raise NotFound("Case")
        (s.vault_dir / stored).write_bytes(_encrypt(data, s.vault_passphrase) if encrypted else data)
        ref = next_ref(c, "EVD")
        cur = c.execute(
            """INSERT INTO evidence(ref, case_id, name, description, source, sha256, size, mime, stored_name, encrypted,
                                    created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (ref, case_id, name, description.strip()[:2000], source.strip()[:500], sha, len(data),
             mimetypes.guess_type(name)[0] or "application/octet-stream", stored, int(encrypted),
             created_by or audit.current_actor(), utcnow()))
        ent = upsert_entity(c, "evidence", ref, name, {"sha256": sha, "size": len(data)})
        if case_id is not None:
            case = c.execute("SELECT ref, name FROM cases WHERE id=?", (case_id,)).fetchone()
            link(c, upsert_entity(c, "case", case["ref"], case["name"]), ent, "has_evidence", "analyst registration", ref)
        audit.record(c, "evidence.register", entity_type="evidence", entity_id=ref, case_id=case_id,
                     detail={"name": name, "sha256": sha, "size": len(data), "encrypted": encrypted})
        return get(cur.lastrowid, conn=c)


def get(evidence_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    def _g(c):
        row = row_to_dict(c.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone())
        if not row:
            raise NotFound("Evidence")
        row["encrypted"] = bool(row["encrypted"])
        row.pop("stored_name", None)
        row["custody_log"] = rows_to_dicts(c.execute(
            "SELECT ts, actor, action, detail FROM audit WHERE entity_type='evidence' AND entity_id=? ORDER BY ts, id", (row["ref"],)), ("detail",))
        return row
    if conn is not None:
        return _g(conn)
    with db() as c:
        return _g(c)


def list_evidence(case_id: int | None = None, q: str | None = None, limit: int = 300) -> list[dict[str, Any]]:
    sql, args = "SELECT e.*, c.ref AS case_ref FROM evidence e LEFT JOIN cases c ON c.id=e.case_id WHERE 1=1", []
    if case_id is not None:
        sql += " AND e.case_id=?"
        args.append(case_id)
    if q:
        sql += " AND (e.name LIKE ? OR e.sha256 LIKE ? OR e.ref LIKE ? OR e.description LIKE ?)"
        args += [f"%{q}%"] * 4
    sql += " ORDER BY e.created_at DESC LIMIT ?"
    args.append(min(limit, 1000))
    with db() as c:
        rows = rows_to_dicts(c.execute(sql, args))
    for r in rows:
        r["encrypted"] = bool(r["encrypted"])
        r.pop("stored_name", None)
    return rows


def verify(evidence_id: int) -> dict[str, Any]:
    """Recompute SHA-256 from the stored bytes (never trusts the stored value) and compare."""
    with db() as c:
        row = c.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row:
            raise NotFound("Evidence")
    try:
        data = _read_plain(row)
        recomputed = hashlib.sha256(data).hexdigest()
        result = "match" if recomputed == row["sha256"] else "MISMATCH"
        detail = {"recorded": row["sha256"], "recomputed": recomputed}
    except GhostError as exc:
        result, recomputed = f"unverifiable: {exc.code}", None
        detail = {"recorded": row["sha256"], "error": exc.message}
    with db() as c:
        c.execute("UPDATE evidence SET last_verified_at=?, last_verify_result=? WHERE id=?", (utcnow(), result, evidence_id))
        audit.record(c, "evidence.verify", entity_type="evidence", entity_id=row["ref"], case_id=row["case_id"],
                     detail={**detail, "result": result})
    return {"ref": row["ref"], "result": result, "intact": result == "match", "recorded_sha256": row["sha256"],
            "recomputed_sha256": recomputed, "verified_at": utcnow(), **({"error": detail.get("error")} if "error" in detail else {}),
            "disclaimer": "Integrity hash only — not a digital signature, trusted timestamp, or proof of chain of custody."}


def read_bytes(evidence_id: int) -> tuple[bytes, str, str]:
    with db() as c:
        row = c.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row:
            raise NotFound("Evidence")
        audit.record(c, "evidence.export", entity_type="evidence", entity_id=row["ref"], case_id=row["case_id"])
    return _read_plain(row), row["name"], row["mime"]


def delete(evidence_id: int) -> dict[str, Any]:
    with db() as c:
        row = c.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not row:
            raise NotFound("Evidence")
        (get_settings().vault_dir / row["stored_name"]).unlink(missing_ok=True)
        ent = c.execute("SELECT id FROM entities WHERE type='evidence' AND key=?", (row["ref"],)).fetchone()
        if ent:
            c.execute("DELETE FROM relations WHERE src_id=? OR dst_id=?", (ent["id"], ent["id"]))
            c.execute("DELETE FROM entities WHERE id=?", (ent["id"],))
        c.execute("DELETE FROM evidence WHERE id=?", (evidence_id,))
        audit.record(c, "evidence.delete", entity_type="evidence", entity_id=row["ref"], case_id=row["case_id"],
                     detail={"name": row["name"], "sha256": row["sha256"]})
    return {"deleted": row["ref"]}


def create_backup(dest_dir: Path | None = None) -> Path:
    """Consistent snapshot: SQLite online-backup + vault files + manifest of SHA-256 hashes.
    Encrypted evidence stays encrypted in the archive. The database itself is NOT encrypted."""
    s = get_settings()
    s.ensure_dirs()
    dest_dir = dest_dir or (s.data_dir / "backups")
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = utcnow()[:19].replace(":", "").replace("-", "")
    out = dest_dir / f"ghost-backup-{stamp}.zip"
    snap = dest_dir / f".snapshot-{uuid.uuid4().hex}.db"
    src = sqlite3.connect(s.db_path)
    dst = sqlite3.connect(snap)
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    manifest: dict[str, Any] = {"created_at": utcnow(), "files": {}}
    try:
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
            z.write(snap, "ghost.db")
            manifest["files"]["ghost.db"] = hashlib.sha256(snap.read_bytes()).hexdigest()
            for f in sorted(s.vault_dir.glob("*")):
                if f.is_file():
                    z.write(f, f"vault/{f.name}")
                    manifest["files"][f"vault/{f.name}"] = hashlib.sha256(f.read_bytes()).hexdigest()
            z.writestr("manifest.json", json.dumps(manifest, indent=2))
    finally:
        snap.unlink(missing_ok=True)
    with db() as c:
        audit.record(c, "backup.create", detail={"file": out.name, "files": len(manifest["files"])})
    return out
