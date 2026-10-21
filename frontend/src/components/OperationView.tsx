import { ReactNode, useEffect, useState } from "react";
import { Ban, Download } from "lucide-react";
import { Operation, get, post } from "../api";
import { useApp } from "../state";
import { useLoad, utc } from "../lib";
import { Badge, Button, ErrorNote, Kv, Loading, StatusBadge, cx } from "../ui";
import { FindingList } from "./Findings";

export const ACTIVE = ["draft", "queued", "running"];

/** Loads one operation and polls every 1.5 s until it reaches a terminal state. */
export function useOperation(id: number) {
  const [poll, setPoll] = useState<number | undefined>(1500);
  const op = useLoad(() => get<Operation>(`/operations/${id}`), [id], poll);
  const active = !op.data || ACTIVE.includes(op.data.status);
  useEffect(() => { setPoll(active ? 1500 : undefined); }, [active]);
  return op;
}

interface Step { step: string; status: string; error?: string; finding?: string; at?: string; warnings?: string[] }

export function StepList({ steps }: { steps: Step[] }) {
  const tone = (s: string) => (s === "ok" ? "lime" : s === "failed" ? "crit" : "mute") as "lime" | "crit" | "mute";
  return (
    <ul className="border border-line">
      {steps.map((s) => (
        <li key={s.step} className="flex items-start gap-3 border-b border-line px-3 py-2 last:border-0">
          <Badge tone={tone(s.status)}>{s.status}</Badge>
          <div className="min-w-0 flex-1">
            <div className="mono text-[11.5px] uppercase tracking-[0.08em]">{s.step.replace(/_/g, " ")}</div>
            {s.error && <div className={cx("text-[12px]", s.status === "failed" ? "text-crit" : "text-mute")}>{s.error}</div>}
            {s.warnings?.map((w) => <div key={w} className="text-[11.5px] text-amber">{w}</div>)}
          </div>
          {s.finding && <span className="mono text-[10.5px] text-dim">{s.finding}</span>}
        </li>
      ))}
    </ul>
  );
}

/** Live view of one operation: status, steps, error and the findings it produced. */
export default function OperationView({ id, extra, onChange }: { id: number; extra?: (op: Operation) => ReactNode; onChange?: () => void }) {
  const { fail, notify } = useApp();
  const op = useOperation(id);
  const o = op.data;
  if (op.loading && !o) return <Loading label="LOADING OPERATION" />;
  if (op.error || !o) return <ErrorNote message={op.error ?? "Operation not found"} onRetry={op.reload} />;
  const active = ACTIVE.includes(o.status);
  const steps = (o.result?.steps ?? []) as Step[];
  return (
    <div className="space-y-3">
      <div className={cx("flex flex-wrap items-center gap-3 border px-3 py-2.5", o.status === "failed" ? "border-crit/40" : "border-line")}>
        <StatusBadge status={o.status} />
        <div className="min-w-0 flex-1">
          <div className="mono text-[12px]">{o.ref} · {o.kind.replace(/_/g, " ")}</div>
          <div className="mono break-all text-[11px] text-mute">{o.target}</div>
        </div>
        <div className="mono text-[10.5px] text-dim">
          {o.started_at ? <>START {utc(o.started_at)}</> : <>CREATED {utc(o.created_at)}</>}{o.finished_at && <><br />END {utc(o.finished_at)}</>}
        </div>
        <div className="flex gap-2">
          {active && <Button small variant="danger" icon={<Ban size={11} />} onClick={async () => { try { await post(`/operations/${o.id}/cancel`); notify("info", o.status === "running" ? "Cancellation requested — stops at the next step boundary" : "Cancelled"); op.reload(); onChange?.(); } catch (e) { fail(e); } }}>Cancel</Button>}
          {!active && <a href={`/api/operations/${o.id}/download`} className="mono inline-flex h-7 items-center gap-1.5 border border-line2 bg-elev px-2 text-[10px] uppercase tracking-[0.1em] hover:border-lime/60 hover:text-lime"><Download size={11} /> JSON</a>}
        </div>
      </div>
      {o.authorised && <Kv k="Active checks">AUTHORISED — {o.auth_note}</Kv>}
      {o.status === "failed" && o.error && <ErrorNote message={o.error} />}
      {o.status === "cancelled" && <div className="mono text-[11px] text-mute">Operation was cancelled before completion; partial findings (if any) are kept.</div>}
      {steps.length > 0 && <StepList steps={steps} />}
      {extra?.(o)}
      {(o.findings?.length ?? 0) > 0 && (
        <div className="border border-line"><div className="label border-b border-line px-3 py-2">Findings produced · {o.findings!.length}</div><FindingList findings={o.findings!} onChange={op.reload} /></div>
      )}
      {!active && o.status === "completed" && (o.findings?.length ?? 0) === 0 && <div className="mono text-[11px] text-mute">Completed with no findings.</div>}
      <span className="sr-only" aria-live="polite">{`Operation ${o.ref} ${o.status}`}</span>
    </div>
  );
}
