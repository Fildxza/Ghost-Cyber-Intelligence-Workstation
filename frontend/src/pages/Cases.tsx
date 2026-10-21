import { FormEvent, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Archive, FilePlus2, FileText, FolderOpen, Pencil, ShieldCheck, ShieldAlert as ShieldWarn, Search as SearchIcon } from "lucide-react";
import { AuditEvent, Case, CaseStatus, Evidence, Finding, Indicator, Note, Operation, Report, get, patch, post, qs } from "../api";
import { useApp } from "../state";
import { ago, fmtBytes, useLoad, utc } from "../lib";
import { Badge, Button, Empty, ErrorNote, Input, Kv, Loading, PageHeader, Panel, Select, StatusBadge, Tabs, Textarea, priorityTone, severityTone } from "../ui";
import CaseFormModal from "../components/CaseForm";
import ReportModal, { openReport } from "../components/ReportModal";
import { FindingList } from "../components/Findings";

export function CaseList() {
  const { workspace } = useApp();
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [priority, setPriority] = useState("");
  const [archived, setArchived] = useState(false);
  const [creating, setCreating] = useState(false);
  const list = useLoad(() => get<Case[]>(`/cases${qs({ q, status, priority, include_archived: archived, workspace_id: workspace?.id })}`), [q, status, priority, archived, workspace?.id]);
  const rows = list.data ?? [];
  return (
    <div className="mx-auto max-w-[1500px]">
      <PageHeader code="CASE FILES" title="Investigation case files" sub={`Workspace ${workspace?.name ?? "—"}. Each case holds scope, authorisation, notes, findings and evidence. Reference IDs are issued by the backend.`}
        actions={<Button variant="primary" icon={<FilePlus2 size={14} />} onClick={() => setCreating(true)}>New case</Button>} />
      <Panel flush title="Cases" right={<span className="mono text-[10px] text-dim">{rows.length} SHOWN</span>}>
        <div className="flex flex-wrap items-center gap-2 border-b border-line p-3">
          <div className="relative min-w-52 flex-1"><SearchIcon size={13} className="absolute left-2.5 top-2.5 text-dim" /><Input aria-label="Search cases" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name, ref, objective, tag…" className="!pl-8" /></div>
          <Select aria-label="Filter by status" value={status} onChange={(e) => setStatus(e.target.value)} className="!w-36"><option value="">ALL STATUS</option>{["open", "active", "closed", "archived"].map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}</Select>
          <Select aria-label="Filter by priority" value={priority} onChange={(e) => setPriority(e.target.value)} className="!w-36"><option value="">ALL PRIORITY</option>{["low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}</Select>
          <label className="mono flex items-center gap-2 text-[11px] text-mute"><input type="checkbox" checked={archived} onChange={(e) => setArchived(e.target.checked)} className="accent-[#B7F36B]" /> INCLUDE ARCHIVED</label>
        </div>
        {list.error && <div className="p-3"><ErrorNote message={list.error} onRetry={list.reload} /></div>}
        {list.loading && !list.data ? <Loading /> : rows.length === 0 ? (
          <div className="p-4"><Empty icon={<FolderOpen size={24} />} title={q || status || priority ? "No cases match these filters" : "No cases yet"} action={!q && !status && !priority ? <Button variant="primary" onClick={() => setCreating(true)}>Create the first case</Button> : undefined}>
            {q || status || priority ? "Adjust or clear the filters." : "Cases are stored in the local SQLite database and survive restarts."}</Empty></div>
        ) : (
          <div className="overflow-x-auto"><table className="dt">
            <thead><tr><th>Ref</th><th>Name</th><th>Priority</th><th>Status</th><th>Scope</th><th>Tags</th><th>Author</th><th>Updated</th></tr></thead>
            <tbody>{rows.map((c) => (
              <tr key={c.id} className="cursor-pointer" onClick={() => nav(`/cases/${c.id}`)}>
                <td className="mono whitespace-nowrap text-[11px] text-mute">{c.ref}</td>
                <td><Link to={`/cases/${c.id}`} className="hover:text-lime" onClick={(e) => e.stopPropagation()}>{c.name}</Link></td>
                <td><Badge tone={priorityTone(c.priority)}>{c.priority}</Badge></td>
                <td><Badge tone={c.status === "archived" ? "mute" : "ink"}>{c.status}</Badge></td>
                <td>{c.authorisation_ack && c.scope ? <Badge tone="lime"><ShieldCheck size={10} /> declared</Badge> : <Badge tone="amber"><ShieldWarn size={10} /> no authorisation</Badge>}</td>
                <td className="max-w-48"><div className="flex flex-wrap gap-1">{c.tags.map((t) => <Badge key={t}>{t}</Badge>)}</div></td>
                <td className="mono text-[11px] text-mute">{c.author}</td>
                <td className="mono whitespace-nowrap text-[11px] text-mute" title={utc(c.updated_at)}>{ago(c.updated_at)}</td>
              </tr>))}</tbody>
          </table></div>
        )}
      </Panel>
      <CaseFormModal open={creating} onClose={() => setCreating(false)} onSaved={(c) => nav(`/cases/${c.id}`)} />
    </div>
  );
}

type Tab = "overview" | "notes" | "timeline" | "findings" | "indicators" | "evidence" | "operations" | "reports";

export function CaseDetail() {
  const { id } = useParams();
  const caseId = Number(id);
  const { notify, fail } = useApp();
  const nav = useNavigate();
  const [tab, setTab] = useState<Tab>("overview");
  const [editing, setEditing] = useState(false);
  const [reporting, setReporting] = useState(false);
  const c = useLoad(() => get<Case>(`/cases/${caseId}`), [caseId]);
  const notes = useLoad(() => get<Note[]>(`/cases/${caseId}/notes`), [caseId]);
  const timeline = useLoad(() => get<AuditEvent[]>(`/cases/${caseId}/timeline`), [caseId], tab === "timeline" ? 6000 : undefined);
  const findings = useLoad(() => get<Finding[]>(`/findings${qs({ case_id: caseId })}`), [caseId]);
  const inds = useLoad(() => get<Indicator[]>(`/intel/indicators${qs({ case_id: caseId })}`), [caseId]);
  const evid = useLoad(() => get<Evidence[]>(`/evidence${qs({ case_id: caseId })}`), [caseId]);
  const ops = useLoad(() => get<Operation[]>(`/operations${qs({ case_id: caseId })}`), [caseId]);
  const reps = useLoad(() => get<Report[]>(`/reports${qs({ case_id: caseId })}`), [caseId]);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  if (c.loading && !c.data) return <Loading />;
  if (c.error || !c.data) return <div className="mx-auto max-w-3xl"><ErrorNote message={c.error ?? "Case not found"} onRetry={c.reload} /><div className="mt-3"><Link to="/cases" className="label !text-lime">← BACK TO CASE FILES</Link></div></div>;
  const cs = c.data;
  const archived = cs.status === "archived";

  const setStatus = async (status: CaseStatus) => {
    try { await patch(`/cases/${cs.id}`, { status }); c.reload(); notify("ok", `Status set to ${status}`); } catch (e) { fail(e); }
  };
  const addNote = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try { await post(`/cases/${cs.id}/notes`, { body: note }); setNote(""); notes.reload(); c.reload(); timeline.reload(); } catch (ex) { fail(ex); } finally { setBusy(false); }
  };

  return (
    <div className="mx-auto max-w-[1500px]">
      <PageHeader code={`CASE FILE · ${cs.ref}`} title={cs.name}
        sub={<span className="flex flex-wrap items-center gap-2"><Badge tone={priorityTone(cs.priority)}>{cs.priority}</Badge><Badge>{cs.status}</Badge>{cs.authorisation_ack && cs.scope ? <Badge tone="lime"><ShieldCheck size={10} /> scope & authorisation declared</Badge> : <Badge tone="amber"><ShieldWarn size={10} /> active checks locked — declare scope</Badge>}<span className="mono text-[11px] text-dim">opened {utc(cs.created_at)} by {cs.author}</span></span>}
        actions={<>
          <Select aria-label="Case status" value={cs.status} onChange={(e) => setStatus(e.target.value as CaseStatus)} className="!w-32">{["open", "active", "closed", "archived"].map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}</Select>
          <Button icon={<Pencil size={13} />} onClick={() => setEditing(true)} disabled={archived}>Edit</Button>
          <Button icon={<FileText size={13} />} onClick={() => setReporting(true)}>Report</Button>
          {!archived && <Button variant="danger" icon={<Archive size={13} />} onClick={async () => { try { await post(`/cases/${cs.id}/archive`); notify("ok", "Case archived"); nav("/cases"); } catch (e) { fail(e); } }}>Archive</Button>}
        </>} />
      {archived && <div className="mb-3"><ErrorNote message="This case is archived and read-only. Change its status to reopen it." /></div>}

      <Tabs value={tab} onChange={setTab} tabs={[
        { id: "overview", label: "Overview" }, { id: "notes", label: "Notes", count: cs.counts?.notes }, { id: "timeline", label: "Timeline" },
        { id: "findings", label: "Findings", count: cs.counts?.findings }, { id: "indicators", label: "Indicators", count: cs.counts?.indicators },
        { id: "evidence", label: "Evidence", count: cs.counts?.evidence }, { id: "operations", label: "Operations", count: cs.counts?.operations }, { id: "reports", label: "Reports", count: reps.data?.length },
      ]} />

      <div className="mt-3">
        {tab === "overview" && (
          <div className="grid gap-3 lg:grid-cols-2">
            <Panel title="Brief"><dl>
              <Kv k="Objective" mono={false}>{cs.objective || <span className="text-dim">Not stated</span>}</Kv>
              <Kv k="Declared scope" mono={false}>{cs.scope || <span className="text-dim">Not declared</span>}</Kv>
              <Kv k="Authorisation">{cs.authorisation_ack ? "ACKNOWLEDGED by analyst" : "NOT acknowledged"}</Kv>
              <Kv k="Tags">{cs.tags.length ? <span className="flex flex-wrap gap-1">{cs.tags.map((t) => <Badge key={t}>{t}</Badge>)}</span> : "—"}</Kv>
              <Kv k="Updated">{utc(cs.updated_at)}</Kv>
            </dl></Panel>
            <Panel title="Case inventory"><dl>
              {(["operations", "findings", "indicators", "evidence", "notes"] as const).map((k) => <Kv key={k} k={k}>{cs.counts?.[k] ?? 0}</Kv>)}
            </dl>
              <div className="mt-3 flex flex-wrap gap-2">
                <Button onClick={() => nav(`/osint?case=${cs.id}`)} disabled={archived}>Investigate domain</Button>
                <Button onClick={() => nav(`/intel?case=${cs.id}`)} disabled={archived}>Add indicator</Button>
                <Button onClick={() => nav(`/network?case=${cs.id}`)} disabled={archived}>Analyse PCAP</Button>
                <Button onClick={() => nav(`/evidence?case=${cs.id}`)} disabled={archived}>Register evidence</Button>
                <Button onClick={() => nav(`/graph?case=${cs.id}`)}>Entity graph</Button>
              </div></Panel>
          </div>
        )}
        {tab === "notes" && (
          <div className="grid gap-3 lg:grid-cols-[1fr_380px]">
            <Panel title="Analyst notes" flush>{notes.loading && !notes.data ? <Loading /> : !notes.data?.length ? <div className="p-3"><Empty title="No notes">Record observations, decisions and context here.</Empty></div> : (
              <ul>{notes.data.map((n) => <li key={n.id} className="border-b border-line px-3 py-2.5"><div className="mono text-[10.5px] text-dim">{utc(n.created_at)} · {n.author}</div><p className="mt-1 whitespace-pre-wrap text-[13px]">{n.body}</p></li>)}</ul>)}</Panel>
            <Panel title="Add note"><form onSubmit={addNote} className="space-y-2"><Textarea aria-label="Note" value={note} onChange={(e) => setNote(e.target.value)} maxLength={20000} required disabled={archived} placeholder="Observation, decision, context…" className="!min-h-36" /><Button type="submit" variant="primary" busy={busy} disabled={archived || !note.trim()}>Add note</Button></form></Panel>
          </div>
        )}
        {tab === "timeline" && (
          <Panel title="Investigation timeline" flush right={<span className="mono text-[10px] text-dim">AUDIT TRAIL · NEWEST FIRST</span>}>
            {timeline.loading && !timeline.data ? <Loading /> : !timeline.data?.length ? <div className="p-3"><Empty title="No activity">Every action on this case is recorded here.</Empty></div> : (
              <ol className="mono text-[11.5px]">{timeline.data.map((e) => <li key={e.id} className="grid grid-cols-[150px_1fr] gap-3 border-b border-line px-3 py-1.5"><span className="text-dim">{utc(e.ts)}</span><span><b className="font-medium text-ink">{e.action}</b> <span className="text-mute">{e.entity_id}</span> <span className="text-dim">· {e.actor}</span>{Object.keys(e.detail).length > 0 && <span className="block truncate text-[10.5px] text-dim">{JSON.stringify(e.detail)}</span>}</span></li>)}</ol>)}
          </Panel>
        )}
        {tab === "findings" && <Panel title="Findings" flush>{findings.loading && !findings.data ? <Loading /> : <FindingList findings={findings.data ?? []} onChange={() => { findings.reload(); c.reload(); }} emptyHint="Run a domain investigation or enrichment attached to this case." />}</Panel>}
        {tab === "indicators" && (
          <Panel title="Indicators" flush>{!inds.data?.length ? <div className="p-3"><Empty title="No indicators linked">Add or link indicators from Threat Intelligence.</Empty></div> : (
            <table className="dt"><thead><tr><th>Ref</th><th>Type</th><th>Value</th><th>Severity</th><th>Confidence</th></tr></thead><tbody>{inds.data.map((i) => <tr key={i.id}><td className="mono text-[11px] text-mute">{i.ref}</td><td><Badge>{i.type}</Badge></td><td className="mono break-all text-[12px]"><Link to={`/intel?sel=${i.id}`} className="hover:text-lime">{i.value}</Link></td><td><Badge tone={severityTone(i.severity)}>{i.severity}</Badge></td><td className="mono text-[11px]">{i.confidence}</td></tr>)}</tbody></table>)}</Panel>
        )}
        {tab === "evidence" && (
          <Panel title="Evidence" flush>{!evid.data?.length ? <div className="p-3"><Empty title="No evidence registered">Register files in the Evidence Vault to hash and track them.</Empty></div> : (
            <table className="dt"><thead><tr><th>Ref</th><th>Name</th><th>SHA-256</th><th>Size</th><th>Verified</th></tr></thead><tbody>{evid.data.map((e) => <tr key={e.id}><td className="mono text-[11px] text-mute">{e.ref}</td><td><Link to={`/evidence?sel=${e.id}`} className="hover:text-lime">{e.name}</Link></td><td className="mono text-[10.5px] text-mute">{e.sha256.slice(0, 24)}…</td><td className="mono text-[11px]">{fmtBytes(e.size)}</td><td>{e.last_verify_result ? <Badge tone={e.last_verify_result === "match" ? "lime" : "crit"}>{e.last_verify_result}</Badge> : <span className="text-dim">never</span>}</td></tr>)}</tbody></table>)}</Panel>
        )}
        {tab === "operations" && (
          <Panel title="Operations" flush>{!ops.data?.length ? <div className="p-3"><Empty title="No operations">Investigations and analyses run against this case appear here.</Empty></div> : (
            <table className="dt"><thead><tr><th>Ref</th><th>Kind</th><th>Target</th><th>Status</th><th>Finished</th></tr></thead><tbody>{ops.data.map((o) => <tr key={o.id}><td className="mono text-[11px] text-mute">{o.ref}</td><td className="text-[12px]">{o.kind.replace(/_/g, " ")}</td><td className="mono break-all text-[12px]">{o.target}</td><td><StatusBadge status={o.status} /></td><td className="mono text-[11px] text-mute">{ago(o.finished_at)}</td></tr>)}</tbody></table>)}</Panel>
        )}
        {tab === "reports" && (
          <Panel title="Reports" flush right={<Button small icon={<FileText size={12} />} onClick={() => setReporting(true)}>Generate</Button>}>{!reps.data?.length ? <div className="p-3"><Empty title="No reports generated" /></div> : (
            <table className="dt"><thead><tr><th>Ref</th><th>Generated</th><th>SHA-256</th><th>Size</th><th /></tr></thead><tbody>{reps.data.map((r) => <tr key={r.id}><td className="mono text-[11px]">{r.ref}</td><td className="mono text-[11px] text-mute">{utc(r.created_at)}</td><td className="mono text-[10.5px] text-mute">{r.sha256.slice(0, 20)}…</td><td className="mono text-[11px]">{fmtBytes(r.size)}</td><td><Button small onClick={() => openReport(r.id)}>Open</Button></td></tr>)}</tbody></table>)}</Panel>
        )}
      </div>

      <CaseFormModal open={editing} existing={cs} onClose={() => setEditing(false)} onSaved={() => { c.reload(); timeline.reload(); }} />
      <ReportModal open={reporting} defaultCase={cs.id} onClose={() => setReporting(false)} onDone={() => reps.reload()} />
    </div>
  );
}
