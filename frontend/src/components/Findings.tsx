import { useState } from "react";
import { Check, ChevronDown, ChevronRight, ExternalLink, RotateCcw, X } from "lucide-react";
import { Finding, patch } from "../api";
import { useApp } from "../state";
import { utc } from "../lib";
import { Badge, Button, Empty, Freshness, cx } from "../ui";

const confTone = (c: string) => (c === "high" ? "lime" : c === "medium" ? "amber" : "mute") as "lime" | "amber" | "mute";

/** A finding with full provenance: source, URL, retrieval time, confidence, freshness, review state. */
export function FindingRow({ f, onChange }: { f: Finding; onChange?: () => void }) {
  const { fail, notify } = useApp();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const review = async (status: Finding["review_status"]) => {
    setBusy(true);
    try { await patch(`/findings/${f.id}/review`, { review_status: status }); notify("ok", `${f.ref} marked ${status}`); onChange?.(); }
    catch (e) { fail(e); } finally { setBusy(false); }
  };
  const isUrl = f.source_url && /^https?:\/\//.test(f.source_url);
  return (
    <li className={cx("border-b border-line", f.review_status === "dismissed" && "opacity-55")}>
      <div className="flex items-start gap-2 px-3 py-2">
        <button onClick={() => setOpen(!open)} aria-expanded={open} aria-label={open ? "Collapse finding" : "Expand finding"} className="mt-0.5 text-mute hover:text-ink">{open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</button>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-[10px] text-dim">{f.ref}</span>
            <Badge>{f.kind.replace(/_/g, " ")}</Badge>
            <Badge tone={confTone(f.confidence)} title="Confidence in the source/method, not a threat verdict">conf {f.confidence}</Badge>
            <Freshness value={f.freshness} />
            {f.review_status === "confirmed" && <Badge tone="lime">confirmed</Badge>}
            {f.review_status === "pending" && <Badge tone="amber">unreviewed</Badge>}
            {f.review_status === "dismissed" && <Badge>dismissed</Badge>}
          </div>
          <div className="mt-1 text-[13px]">{f.title}</div>
          {f.summary && <div className="text-[12px] text-mute">{f.summary}</div>}
          <div className="mono mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10.5px] text-dim">
            <span>SRC {f.source}</span>
            <span>RETRIEVED {utc(f.retrieved_at)}</span>
            {isUrl && <a href={f.source_url!} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-mute hover:text-lime">{f.source_url!.slice(0, 64)}<ExternalLink size={10} /></a>}
            {!isUrl && f.source_url && <span>{f.source_url}</span>}
          </div>
        </div>
        <div className="flex shrink-0 gap-1">
          {f.review_status !== "confirmed" && <Button small variant="ghost" busy={busy} onClick={() => review("confirmed")} icon={<Check size={11} />} aria-label={`Confirm ${f.ref}`}>Confirm</Button>}
          {f.review_status !== "dismissed" && <Button small variant="quiet" busy={busy} onClick={() => review("dismissed")} icon={<X size={11} />} aria-label={`Dismiss ${f.ref}`}>Dismiss</Button>}
          {f.review_status !== "pending" && <Button small variant="quiet" busy={busy} onClick={() => review("pending")} icon={<RotateCcw size={11} />} aria-label={`Reset review of ${f.ref}`} />}
        </div>
      </div>
      {open && <pre className="mono mx-3 mb-3 max-h-72 overflow-auto border border-line bg-bg2 p-2.5 text-[11px] text-mute">{JSON.stringify(f.data, null, 2)}</pre>}
    </li>
  );
}

export function FindingList({ findings, onChange, emptyHint }: { findings: Finding[]; onChange?: () => void; emptyHint?: string }) {
  if (!findings.length) return <div className="p-3"><Empty title="No findings">{emptyHint ?? "Findings are created only by operations that actually returned data."}</Empty></div>;
  return <ul>{findings.map((f) => <FindingRow key={f.id} f={f} onChange={onChange} />)}</ul>;
}
