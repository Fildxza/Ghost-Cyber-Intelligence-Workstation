import { useState } from "react";
import { Database, Download, Lock, WifiOff } from "lucide-react";
import { put, post } from "../api";
import { useApp } from "../state";
import { fmtBytes, useOnline, utc } from "../lib";
import { Badge, Button, Check, Kv, Loading, PageHeader, Panel, Unavailable } from "../ui";

export default function Settings() {
  const { status, notify, fail, workspaces, workspace } = useApp();
  const online = useOnline();
  const s = status.data;
  const [busy, setBusy] = useState(false);
  const [backup, setBackup] = useState<{ file: string; size: number; download: string } | null>(null);

  if (!s) return <Loading />;
  const toggleField = async (enabled: boolean) => {
    try { await put("/settings/field-mode", { enabled }); status.reload(); notify("ok", enabled ? "Field Mode on — outbound lookups refused" : "Field Mode off"); } catch (e) { fail(e); }
  };
  const makeBackup = async () => {
    setBusy(true);
    try { const r = await post<{ file: string; size: number; download: string }>("/system/backup"); setBackup(r); notify("ok", `Backup created (${fmtBytes(r.size)})`); } catch (e) { fail(e); } finally { setBusy(false); }
  };

  return (
    <div className="mx-auto max-w-[1300px]">
      <PageHeader code="SYSTEM SETTINGS" title="Settings, Field Mode & data protection" sub="Local-first: everything is stored on this machine. There is no cloud sync and no sync queue — none is implemented." />
      <div className="grid gap-3 lg:grid-cols-2">
        <Panel title="Field Mode" icon={<WifiOff size={13} />} right={<Badge tone={s.field_mode ? "amber" : "mute"}>{s.field_mode ? "active" : "off"}</Badge>}>
          <div className="space-y-3">
            <Check checked={s.field_mode} onChange={toggleField}><b>Work offline / minimise network exposure.</b> While on, the backend refuses every operation that would make an outbound request (OSINT lookups, enrichment). Cases, notes, evidence, PCAP analysis, graph and reports keep working from local storage.</Check>
            <dl className="border border-line px-3">
              <Kv k="Browser link">{online ? "online" : "offline"} (navigator.onLine)</Kv>
              <Kv k="Backend">{status.error ? "unreachable" : "reachable"}</Kv>
            </dl>
            <p className="text-[11.5px] text-dim">Field Mode reduces what this application sends; it does not hide your machine, IP address or activity from your network or provider.</p>
          </div>
        </Panel>
        <Panel title="Data protection" icon={<Lock size={13} />}>
          <dl>
            <Kv k="Evidence encryption"><Badge tone={s.vault.encryption === "enabled" ? "lime" : "amber"}>{s.vault.encryption}</Badge> {s.vault.algorithm}</Kv>
            <Kv k="Database"><span className="break-all">{s.database.path}</span></Kv>
            <Kv k="DB encryption">NOT encrypted (SQLite file). Use full-disk encryption (BitLocker / LUKS).</Kv>
          </dl>
          {s.vault.encryption !== "enabled" && <div className="mt-3"><Unavailable title="Evidence stored unencrypted">{s.vault.note} The passphrase is read from the environment only and is never stored or shown. Losing it makes encrypted evidence unrecoverable.</Unavailable></div>}
          <p className="mt-3 text-[11.5px] text-dim">No session lock screen is implemented; rely on your OS lock screen.</p>
        </Panel>
        <Panel title="Backup & export" icon={<Database size={13} />}>
          <p className="mb-3 text-[12.5px] text-mute">Creates a consistent snapshot (SQLite online-backup + vault files + SHA-256 manifest) as a ZIP in the data directory. Encrypted evidence stays encrypted inside the archive; the database does not. Store backups on encrypted media.</p>
          <Button variant="primary" busy={busy} onClick={makeBackup} icon={<Database size={13} />}>Create backup</Button>
          {backup && <div className="mono mt-3 flex items-center justify-between border border-lime/30 bg-lime/[0.05] px-3 py-2 text-[11.5px]"><span>{backup.file} · {fmtBytes(backup.size)}</span><a href={backup.download} className="flex items-center gap-1.5 text-lime hover:underline"><Download size={12} /> DOWNLOAD</a></div>}
        </Panel>
        <Panel title="Retention & deletion">
          <p className="text-[12.5px] text-mute">There is no automatic retention policy. Deletion is manual and explicit:</p>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-[12.5px] text-mute">
            <li>Evidence can be deleted from the Evidence Vault (file removed; a deletion record with its hash stays in the audit trail).</li>
            <li>Cases are archived rather than deleted so the investigation record stays intact.</li>
            <li>The audit trail is append-only and has no delete control.</li>
          </ul>
        </Panel>
        <Panel title="Runtime" className="lg:col-span-2" flush>
          <dl className="px-3">
            <Kv k="Version">{s.version}</Kv><Kv k="Session">{s.session_id} · started {utc(s.started_at)}</Kv><Kv k="Analyst">{s.analyst}</Kv>
            <Kv k="Workspace">{workspace?.name} ({workspaces.data?.length ?? 0} total)</Kv>
            <Kv k="Database">{s.database.engine} · schema v{s.database.schema_version} · {s.database.latency_ms} ms</Kv>
            <Kv k="Worker">{s.worker.kind} · {s.worker.workers} threads · {s.worker.completed} completed · {s.worker.failed} failed</Kv>
          </dl>
        </Panel>
      </div>
    </div>
  );
}
