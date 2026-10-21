import { FormEvent, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Download, FileCheck2, Lock, Trash2, Upload } from "lucide-react";
import { Case, Evidence as Ev, VerifyResult, del, get, post, qs, upload } from "../api";
import { useApp } from "../state";
import { errMsg, fmtBytes, useLoad, utc } from "../lib";
import { Badge, Button, Empty, ErrorNote, Field, Input, Kv, Loading, Modal, PageHeader, Panel, Select, Textarea, Unavailable, cx } from "../ui";

export default function Evidence() {
  const [sp, setSp] = useSearchParams();
  const { status, notify, fail, config } = useApp();
  const sel = sp.get("sel") ? Number(sp.get("sel")) : null;
  const fileIn = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [caseId, setCaseId] = useState<number | "">(sp.get("case") ? Number(sp.get("case")) : "");
  const [description, setDescription] = useState("");
  const [source, setSource] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [confirmDel, setConfirmDel] = useState(false);

  const cases = useLoad(() => get<Case[]>("/cases"), []);
  const list = useLoad(() => get<Ev[]>(`/evidence${qs({ q })}`), [q]);
  const detail = useLoad(() => (sel ? get<Ev>(`/evidence/${sel}`) : Promise.resolve(null)), [sel]);
  const d = detail.data;
  const vault = status.data?.vault;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setBusy(true); setError(null);
    const fd = new FormData();
    fd.append("file", file);
    if (caseId !== "") fd.append("case_id", String(caseId));
    fd.append("description", description);
    fd.append("source", source);
    try {
      const ev = await upload<Ev>("/evidence", fd);
      notify("ok", `Registered ${ev.ref} · SHA-256 ${ev.sha256.slice(0, 12)}…`);
      setFile(null); setDescription(""); setSource(""); if (fileIn.current) fileIn.current.value = "";
      setSp({ sel: String(ev.id) }); list.reload();
    } catch (ex) { setError(errMsg(ex)); } finally { setBusy(false); }
  };

  const runVerify = async () => {
    if (!d) return;
    setVerifying(true);
    try { const r = await post<VerifyResult>(`/evidence/${d.id}/verify`); setVerify(r); detail.reload(); list.reload(); } catch (e) { fail(e); } finally { setVerifying(false); }
  };

  return (
    <div className="mx-auto max-w-[1600px]">
      <PageHeader code="EVIDENCE VAULT" title="Evidence register & integrity" sub="Files are hashed (SHA-256) on registration. Verification recomputes the hash from the stored bytes — it never trusts the recorded value." />
      <div className="mb-3">
        <Unavailable title="What an integrity hash is — and is not">
          A SHA-256 shows the stored bytes are unchanged since this workstation registered them. It is <b>not</b> a digital signature, is not independently timestamped, and does not by itself establish chain of custody or legal admissibility.
        </Unavailable>
      </div>
      <div className="grid gap-3 xl:grid-cols-[340px_minmax(0,1.1fr)_minmax(0,0.95fr)]">
        <Panel title="Register evidence" icon={<Upload size={13} />}>
          <form onSubmit={submit} className="space-y-3">
            {error && <ErrorNote message={error} />}
            <div className="flex items-center justify-between border border-line bg-bg2 px-2.5 py-2">
              <span className="label flex items-center gap-1.5"><Lock size={11} /> At-rest encryption</span>
              <Badge tone={vault?.encryption === "enabled" ? "lime" : "amber"}>{vault?.encryption ?? "…"}</Badge>
            </div>
            {vault?.encryption !== "enabled" && <p className="text-[11.5px] text-mute">{vault?.note}</p>}
            <Field label="File" hint={`Max ${config?.max_upload_mb ?? 200} MB.`}>{(id) => <input id={id} ref={fileIn} type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} required className="mono block w-full border border-line2 bg-bg2 text-[12px] file:mr-3 file:border-0 file:border-r file:border-line2 file:bg-elev file:px-3 file:py-1.5 file:text-ink" />}</Field>
            <Field label="Case">{(id) => <Select id={id} value={caseId} onChange={(e) => setCaseId(e.target.value ? Number(e.target.value) : "")}><option value="">Unassigned</option>{(cases.data ?? []).map((c) => <option key={c.id} value={c.id}>{c.ref} — {c.name}</option>)}</Select>}</Field>
            <Field label="Source / provenance" hint="Where did this come from? (device, URL, person, date)">{(id) => <Input id={id} value={source} onChange={(e) => setSource(e.target.value)} maxLength={500} />}</Field>
            <Field label="Description">{(id) => <Textarea id={id} value={description} onChange={(e) => setDescription(e.target.value)} maxLength={2000} className="!min-h-16" />}</Field>
            <Button type="submit" variant="primary" busy={busy} disabled={!file} className="w-full !h-9" icon={<FileCheck2 size={14} />}>Hash &amp; register</Button>
          </form>
        </Panel>

        <Panel title="Register" flush right={<span className="mono text-[10px] text-dim">{list.data?.length ?? 0} ITEMS</span>}>
          <div className="border-b border-line p-2.5"><Input aria-label="Search evidence" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name, ref, hash…" className="mono" /></div>
          {list.error && <div className="p-3"><ErrorNote message={list.error} onRetry={list.reload} /></div>}
          {list.loading && !list.data ? <Loading /> : !list.data?.length ? <div className="p-3"><Empty icon={<Lock size={22} />} title={q ? "No matches" : "Vault is empty"}>{q ? "Try a different search." : "Registered files appear here with their SHA-256, size and verification state."}</Empty></div> : (
            <div className="max-h-[640px] overflow-auto"><table className="dt"><thead><tr><th>Ref</th><th>Name</th><th>Size</th><th>Integrity</th></tr></thead>
              <tbody>{list.data.map((e) => (
                <tr key={e.id} className={cx("cursor-pointer", sel === e.id && "sel")} onClick={() => { setSp({ sel: String(e.id) }); setVerify(null); }} tabIndex={0} onKeyDown={(ev) => ev.key === "Enter" && setSp({ sel: String(e.id) })}>
                  <td className="mono whitespace-nowrap text-[11px] text-mute">{e.ref}</td>
                  <td><div className="max-w-52 truncate text-[12.5px]">{e.name}</div><div className="mono text-[10px] text-dim">{e.sha256.slice(0, 20)}…</div></td>
                  <td className="mono whitespace-nowrap text-[11px]">{fmtBytes(e.size)}</td>
                  <td>{e.last_verify_result ? <Badge tone={e.last_verify_result === "match" ? "lime" : "crit"}>{e.last_verify_result === "match" ? "verified" : "FAILED"}</Badge> : <Badge>unverified</Badge>}</td>
                </tr>))}</tbody></table></div>
          )}
        </Panel>

        <Panel title="Evidence detail" right={d && <div className="flex gap-1.5">
          <Button small variant="primary" busy={verifying} icon={<FileCheck2 size={11} />} onClick={runVerify}>Verify</Button>
          <a href={`/api/evidence/${d.id}/download`} className="mono inline-flex h-7 items-center gap-1.5 border border-line2 bg-elev px-2 text-[10px] uppercase tracking-[0.1em] hover:border-lime/60 hover:text-lime"><Download size={11} /> Export</a>
          <Button small variant="danger" icon={<Trash2 size={11} />} onClick={() => setConfirmDel(true)} aria-label="Delete evidence" />
        </div>}>
          {!sel ? <Empty title="Select an item">See metadata, run an integrity check and read its custody log.</Empty> : detail.loading && !d ? <Loading /> : detail.error ? <ErrorNote message={detail.error} /> : d && (
            <div className="space-y-3">
              {verify && verify.ref === d.ref && (
                <div role="status" className={cx("border px-3 py-2", verify.intact ? "border-lime/40 bg-lime/[0.05]" : "border-crit/50 bg-crit/[0.07]")}>
                  <div className={cx("label", verify.intact ? "!text-lime" : "!text-crit")}>{verify.intact ? "✓ HASH MATCHES — bytes unchanged since registration" : `✗ ${verify.result.toUpperCase()}`}</div>
                  <div className="mono mt-1 break-all text-[10.5px] text-mute">RECORDED&nbsp;&nbsp;&nbsp;{verify.recorded_sha256}<br />RECOMPUTED&nbsp;{verify.recomputed_sha256 ?? "—"}</div>
                  {verify.error && <div className="mt-1 text-[11.5px] text-crit">{verify.error}</div>}
                  <div className="mt-1 text-[10.5px] text-dim">{verify.disclaimer}</div>
                </div>
              )}
              <dl>
                <Kv k="Ref">{d.ref}</Kv><Kv k="Name"><span className="break-all">{d.name}</span></Kv>
                <Kv k="SHA-256"><span className="break-all">{d.sha256}</span></Kv>
                <Kv k="Size">{fmtBytes(d.size)} ({d.size.toLocaleString()} B)</Kv><Kv k="Type">{d.mime}</Kv>
                <Kv k="Storage">{d.encrypted ? "AES-256-GCM encrypted at rest" : "UNENCRYPTED"}</Kv>
                <Kv k="Case">{d.case_id ? `#${d.case_id}` : "Unassigned"}</Kv>
                <Kv k="Source" mono={false}>{d.source || <span className="text-dim">not recorded</span>}</Kv>
                <Kv k="Description" mono={false}>{d.description || <span className="text-dim">—</span>}</Kv>
                <Kv k="Registered">{utc(d.created_at)} by {d.created_by}</Kv>
                <Kv k="Last verified">{d.last_verified_at ? `${utc(d.last_verified_at)} · ${d.last_verify_result}` : "never"}</Kv>
              </dl>
              <div>
                <div className="label mb-1.5">Activity log</div>
                <ol className="mono border border-line text-[11px]">{d.custody_log?.map((l, i) => <li key={i} className="grid grid-cols-[130px_1fr] gap-2 border-b border-line px-2.5 py-1 last:border-0"><span className="text-dim">{utc(l.ts)}</span><span>{l.action} <span className="text-dim">· {l.actor}</span></span></li>)}</ol>
                <p className="mt-1 text-[10.5px] text-dim">This is an application activity log, not a certified chain-of-custody record.</p>
              </div>
            </div>
          )}
        </Panel>
      </div>
      <Modal open={confirmDel} title="Delete evidence" onClose={() => setConfirmDel(false)}>
        <p className="text-[13px]">Permanently delete <b className="mono">{d?.ref}</b> and its stored file from the vault? A deletion record (name and hash) stays in the audit trail. This cannot be undone.</p>
        <div className="mt-4 flex justify-end gap-2"><Button onClick={() => setConfirmDel(false)}>Cancel</Button>
          <Button variant="danger" onClick={async () => { if (!d) return; try { await del(`/evidence/${d.id}`); notify("ok", `${d.ref} deleted`); setConfirmDel(false); setSp({}); list.reload(); } catch (e) { fail(e); } }}>Delete permanently</Button></div>
      </Modal>
    </div>
  );
}
