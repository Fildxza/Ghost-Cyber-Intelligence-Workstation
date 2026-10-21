import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Activity } from "lucide-react";
import { Operation, get, qs } from "../api";
import { ago, useLoad } from "../lib";
import { Button, Empty, ErrorNote, Loading, PageHeader, Panel, StatusBadge, cx } from "../ui";
import OperationView, { ACTIVE } from "../components/OperationView";

const FILTERS = ["all", "draft", "queued", "running", "completed", "failed", "cancelled"] as const;

export default function Operations() {
  const [sp, setSp] = useSearchParams();
  const nav = useNavigate();
  const sel = sp.get("sel") ? Number(sp.get("sel")) : null;
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("all");
  const [poll, setPoll] = useState<number | undefined>(4000);
  const ops = useLoad(async () => {
    const r = await get<Operation[]>(`/operations${qs({ status: filter === "all" ? undefined : filter })}`);
    setPoll(r.some((o) => ACTIVE.includes(o.status)) ? 1500 : 6000);
    return r;
  }, [filter], poll);
  const rows = ops.data ?? [];

  return (
    <div className="mx-auto max-w-[1600px]">
      <PageHeader code="OPERATIONS" title="Operations register" sub="Every investigation, enrichment and analysis is a tracked operation with an honest lifecycle: draft → queued → running → completed / failed / cancelled." />
      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
        <Panel title="Register" flush right={<span className="mono text-[10px] text-dim">{rows.length} SHOWN</span>}>
          <div role="group" aria-label="Filter by status" className="flex flex-wrap gap-1 border-b border-line p-2">
            {FILTERS.map((f) => <button key={f} onClick={() => setFilter(f)} aria-pressed={filter === f} className={cx("mono border px-2 py-1 text-[10px] uppercase tracking-[0.1em]", filter === f ? "border-lime/50 bg-lime/[0.07] text-lime" : "border-line text-mute hover:text-ink")}>{f}</button>)}
          </div>
          {ops.error && <div className="p-3"><ErrorNote message={ops.error} onRetry={ops.reload} /></div>}
          {ops.loading && !ops.data ? <Loading /> : rows.length === 0 ? (
            <div className="p-4"><Empty icon={<Activity size={22} />} title={filter === "all" ? "No operations yet" : `No ${filter} operations`}
              action={filter === "all" ? <div className="flex flex-wrap justify-center gap-2"><Button onClick={() => nav("/osint")}>Investigate domain</Button><Button onClick={() => nav("/intel")}>Enrich indicator</Button><Button onClick={() => nav("/network")}>Analyse PCAP</Button></div> : undefined}>
              {filter === "all" ? "Start one from OSINT, Threat Intelligence or Network Analysis." : "Nothing in this state."}</Empty></div>
          ) : (
            <div className="overflow-x-auto"><table className="dt"><thead><tr><th>Ref</th><th>Kind</th><th>Target</th><th>Status</th><th>When</th></tr></thead>
              <tbody>{rows.map((o) => (
                <tr key={o.id} className={cx("cursor-pointer", sel === o.id && "sel")} onClick={() => setSp({ sel: String(o.id) })} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && setSp({ sel: String(o.id) })}>
                  <td className="mono whitespace-nowrap text-[11px] text-mute">{o.ref}</td>
                  <td className="text-[12px]">{o.kind.replace(/_/g, " ")}</td>
                  <td className="mono max-w-56 truncate text-[12px]">{o.target}</td>
                  <td><StatusBadge status={o.status} /></td>
                  <td className="mono whitespace-nowrap text-[11px] text-mute">{ago(o.finished_at ?? o.started_at ?? o.created_at)}</td>
                </tr>))}</tbody></table></div>
          )}
        </Panel>
        <Panel title="Operation detail">
          {sel ? <OperationView key={sel} id={sel} onChange={ops.reload} /> : <Empty title="Select an operation">Choose a row to see its steps, errors and the findings it produced.</Empty>}
        </Panel>
      </div>
    </div>
  );
}
