import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FilePlus2, FileText, Globe, Share2, Network, ShieldAlert, Activity, FolderOpen, Cpu, Database, Wrench, Briefcase, ScrollText, Layers } from "lucide-react";
import { Overview, get, post, qs } from "../api";
import { useApp } from "../state";
import { ago, fmtNum, useLoad, utc, utcTime } from "../lib";
import { Badge, Button, Dot, Empty, ErrorNote, Loading, Metric, Panel, StatusBadge, cx, priorityTone } from "../ui";
import MapPanel from "../components/MapPanel";
import TopologyPanel from "../components/TopologyPanel";
import Timeline from "../components/Timeline";
import CaseFormModal from "../components/CaseForm";
import ReportModal from "../components/ReportModal";

const ACTION_TONE = (a: string) => (a.endsWith(".failed") || a.endsWith(".delete") ? "crit" : a.endsWith(".completed") || a.endsWith(".create") || a.endsWith(".register") ? "lime" : a.includes("verify") ? "amber" : "mute") as "crit" | "lime" | "amber" | "mute";

function Health() {
  const { status, apiUp } = useApp();
  const s = status.data;
  const row = (icon: React.ReactNode, label: string, tone: "lime" | "amber" | "crit" | "mute", value: string, sub?: string) => (
    <li className="flex items-start gap-3 border-b border-line py-2 last:border-0">
      <span className="mt-0.5 text-dim">{icon}</span>
      <div className="min-w-0 flex-1"><div className="label">{label}</div>{sub && <div className="mono mt-0.5 truncate text-[10.5px] text-dim">{sub}</div>}</div>
      <span className="mono flex items-center gap-1.5 text-[11px]"><Dot tone={tone} />{value}</span>
    </li>
  );
  if (!s && status.error) return <ErrorNote message={`Status unavailable: ${status.error}`} onRetry={status.reload} />;
  if (!s) return <Loading label="PROBING" />;
  return (
    <ul>
      {row(<Cpu size={14} />, "API", apiUp ? "lime" : "crit", apiUp ? "REACHABLE" : "DOWN", `v${s.version} · started ${ago(s.started_at)}`)}
      {row(<Database size={14} />, "DATABASE", s.database.ok ? "lime" : "crit", s.database.ok ? "OK" : "FAULT", s.database.ok ? `sqlite · schema v${s.database.schema_version} · ${s.database.latency_ms} ms` : s.database.error)}
      {row(<Layers size={14} />, "WORKER", s.worker.running > 0 ? "amber" : "lime", `${s.worker.running} RUN · ${s.worker.queued} QUEUE`, `${s.worker.kind} · ${s.worker.workers} threads · ${s.worker.completed} done · ${s.worker.failed} failed`)}
      {s.tools.map((t) => row(<Wrench size={14} />, t.name.toUpperCase(), t.installed ? "lime" : "amber", t.installed ? "AVAILABLE" : "NOT INSTALLED", t.installed ? (t.version ?? t.path ?? undefined) : "see Toolkit for install steps"))}
    </ul>
  );
}

export default function Command() {
  const { status, workspace, notify, fail } = useApp();
  const nav = useNavigate();
  const [newCase, setNewCase] = useState(false);
  const [report, setReport] = useState(false);
  const [sampling, setSampling] = useState(false);
  const [view, setView] = useState<"map" | "topology">("map");
  const ov = useLoad(() => get<Overview>(`/command/overview${qs({ workspace_id: workspace?.id })}`), [workspace?.id], 8000);
  const d = ov.data;
  const m = d?.metrics;
  const sid = status.data?.session_id ?? "OPS-—";

  const loadSample = async () => {
    setSampling(true);
    try {
      const r = await post<{ case: { id: number; ref: string } }>("/sample");
      notify("ok", `Sample case ${r.case.ref} created — real lookups are running`);
      nav(`/cases/${r.case.id}`);
    } catch (e) { fail(e); } finally { setSampling(false); }
  };

  const actions = [
    { label: "Create Case", icon: <FilePlus2 size={14} />, run: () => setNewCase(true) },
    { label: "Investigate Domain", icon: <Globe size={14} />, run: () => nav("/osint") },
    { label: "Analyse PCAP", icon: <Network size={14} />, run: () => nav("/network") },
    { label: "Enrich Indicator", icon: <ShieldAlert size={14} />, run: () => nav("/intel") },
    { label: "Generate Report", icon: <FileText size={14} />, run: () => setReport(true) },
  ];

  return (
    <div className="mx-auto max-w-[1700px] space-y-3">
      {/* header */}
      <div className="relative flex flex-wrap items-end justify-between gap-4 border border-line bg-panel px-4 py-3">
        <div className="absolute inset-y-0 left-0 w-[3px] bg-lime" />
        <div>
          <div className="label !text-lime">TACTICAL OVERVIEW · {workspace?.name ?? "—"}</div>
          <h1 className="mt-1 text-[22px] font-semibold tracking-[0.12em]">COMMAND OVERVIEW</h1>
        </div>
        <dl className="mono grid grid-cols-2 gap-x-8 gap-y-1 text-[11px] sm:grid-cols-3">
          <div><dt className="text-[9px] tracking-[0.18em] text-dim">OPERATION ID</dt><dd className="text-lime">{sid}</dd></div>
          <div><dt className="text-[9px] tracking-[0.18em] text-dim">SESSION OPENED</dt><dd>{utc(status.data?.started_at)}</dd></div>
          <div><dt className="text-[9px] tracking-[0.18em] text-dim">ANALYST</dt><dd>{status.data?.analyst ?? "—"}</dd></div>
        </dl>
      </div>

      {ov.error && <ErrorNote message={ov.error} onRetry={ov.reload} />}

      {/* metrics */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric label="Open cases" value={m ? fmtNum(m.open_cases) : "—"} icon={<FolderOpen size={14} />} tone={m && m.open_cases > 0 ? "lime" : "ink"} hint={d ? `${d.totals.cases} total in workspace` : undefined} />
        <Metric label="Findings awaiting review" value={m ? fmtNum(m.findings_pending_review) : "—"} icon={<ScrollText size={14} />} tone={m && m.findings_pending_review > 0 ? "amber" : "ink"} hint="Unreviewed by an analyst" />
        <Metric label="High-priority indicators" value={m ? fmtNum(m.high_priority_indicators) : "—"} icon={<ShieldAlert size={14} />} tone={m && m.high_priority_indicators > 0 ? "crit" : "ink"} hint={d ? `${d.totals.indicators} indicators tracked` : undefined} />
        <Metric label="Completed analyses · 7d" value={m ? fmtNum(m.recent_completed_analyses) : "—"} icon={<Activity size={14} />} hint={d ? `${d.totals.operations} operations all-time` : undefined} />
      </div>

      {/* map + side column */}
      <div className="grid gap-3 xl:grid-cols-12">
        <Panel title={view === "map" ? "Geospatial picture" : "Network topology"} icon={view === "map" ? <Globe size={13} /> : <Share2 size={13} />} className="xl:col-span-8" flush bodyClassName="min-h-[420px]"
          right={<>
            <div role="tablist" aria-label="Picture view" className="flex">
              {(["map", "topology"] as const).map((v) => (
                <button key={v} role="tab" aria-selected={view === v} onClick={() => setView(v)}
                  className={cx("mono border px-2.5 py-1 text-[10px] uppercase tracking-[0.12em]", view === v ? "border-lime/50 bg-lime/[0.08] text-lime" : "border-line text-mute hover:text-ink")}>{v === "map" ? "Geo map" : "Topology"}</button>))}
            </div>
            <Badge tone="mute">NO SIMULATED DATA</Badge></>}>
          {view === "map" ? <MapPanel points={d?.geo ?? []} /> : <TopologyPanel />}
        </Panel>
        <div className="flex flex-col gap-3 xl:col-span-4">
          <Panel title="Quick actions" icon={<Briefcase size={13} />}>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
              {actions.map((a, i) => (
                <Button key={a.label} variant={i === 0 ? "primary" : "ghost"} icon={a.icon} onClick={a.run} className={cx("!h-9 justify-start", i === actions.length - 1 && "sm:col-span-2 xl:col-span-1 2xl:col-span-2")}>{a.label}</Button>
              ))}
            </div>
          </Panel>
          <Panel title="System health" icon={<Cpu size={13} />} className="flex-1" right={<span className="mono text-[10px] text-dim">POLL 8s</span>}><Health /></Panel>
        </div>
      </div>

      {/* timeline + stream */}
      <div className="grid gap-3 xl:grid-cols-12">
        <Panel title="Threat activity timeline · 14d" className="xl:col-span-7" right={<span className="mono text-[10px] text-dim">SOURCE: AUDIT TRAIL</span>}>
          {d ? <Timeline data={d.timeline} /> : <Loading />}
        </Panel>
        <Panel title="Event stream" className="xl:col-span-5" flush right={<span className="mono flex items-center gap-1.5 text-[10px] text-dim"><Dot tone="mute" />POLLED · NOT PUSH</span>}>
          <div className="max-h-[262px] overflow-y-auto">
            {!d ? <Loading /> : d.events.length === 0 ? (
              <div className="p-3"><Empty title="No events recorded">Actions you take — creating cases, running investigations, registering evidence — are written to the audit trail and appear here with real timestamps.</Empty></div>
            ) : (
              <ol className="mono text-[11px]">
                {d.events.map((e) => (
                  <li key={e.id} className="grid grid-cols-[62px_1fr] gap-x-3 border-b border-line px-3 py-1.5 hover:bg-elev/50" title={utc(e.ts)}>
                    <span className="tabular-nums text-dim">{utcTime(e.ts)}Z</span>
                    <span className="min-w-0 truncate"><Badge tone={ACTION_TONE(e.action)}>{e.action}</Badge> <span className="text-mute">{e.entity_id ?? ""}</span> <span className="text-dim">· {e.actor}</span></span>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </Panel>
      </div>

      {/* investigations + operations */}
      <div className="grid gap-3 xl:grid-cols-12">
        <Panel title="Recent investigations" className="xl:col-span-7" flush right={<Link to="/cases" className="label !text-lime hover:underline">ALL CASES →</Link>}>
          {!d ? <Loading /> : d.recent_cases.length === 0 ? (
            <div className="p-3"><Empty icon={<FolderOpen size={22} />} title="No investigations yet" action={<div className="flex flex-wrap justify-center gap-2"><Button variant="primary" icon={<FilePlus2 size={13} />} onClick={() => setNewCase(true)}>Create first case</Button><Button busy={sampling} icon={<Globe size={13} />} onClick={loadSample}>Load sample investigation</Button></div>}>Cases hold your scope, notes, findings and evidence. Everything is stored locally in SQLite. The sample runs real passive lookups against example.com (needs internet).</Empty></div>
          ) : (
            <div className="overflow-x-auto">
              <table className="dt">
                <thead><tr><th>Case</th><th>Priority</th><th>Status</th><th>Last operation</th><th>Finds</th><th>Updated</th></tr></thead>
                <tbody>
                  {d.recent_cases.map((c) => (
                    <tr key={c.id}>
                      <td className="min-w-44"><Link to={`/cases/${c.id}`} className="block truncate hover:text-lime" title={c.name}>{c.name}</Link><span className="mono text-[10px] text-dim">{c.ref}</span></td>
                      <td><Badge tone={priorityTone(c.priority)}>{c.priority}</Badge></td>
                      <td><Badge>{c.status}</Badge></td>
                      <td>{c.last_operation_status ? <span className="flex items-center gap-1.5"><StatusBadge status={c.last_operation_status} /><span className="mono hidden text-[10px] text-dim 2xl:inline">{c.last_operation_kind?.replace(/_/g, " ")}</span></span> : <span className="text-dim">—</span>}</td>
                      <td className="mono text-center">{c.findings}</td>
                      <td className="mono whitespace-nowrap text-[11px] text-mute">{ago(c.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        <Panel title="Recent operations" className="xl:col-span-5" flush right={<Link to="/operations" className="label !text-lime hover:underline">ALL →</Link>}>
          {!d ? <Loading /> : d.recent_operations.length === 0 ? (
            <div className="p-3"><Empty title="No operations run">Domain investigations, indicator enrichments and PCAP analyses are tracked here with their true status.</Empty></div>
          ) : (
            <ul>
              {d.recent_operations.map((o) => (
                <li key={o.id} className="flex items-center gap-3 border-b border-line px-3 py-2">
                  <StatusBadge status={o.status} />
                  <div className="min-w-0 flex-1"><div className="truncate text-[12.5px]">{o.target}</div><div className="mono truncate text-[10px] text-dim">{o.ref} · {o.kind.replace(/_/g, " ")}{o.error ? ` · ${o.error}` : ""}</div></div>
                  <span className="mono text-[10px] text-dim">{ago(o.finished_at ?? o.created_at)}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>

      <CaseFormModal open={newCase} onClose={() => setNewCase(false)} onSaved={(c) => nav(`/cases/${c.id}`)} />
      <ReportModal open={report} onClose={() => setReport(false)} />
    </div>
  );
}
