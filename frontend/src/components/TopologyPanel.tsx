import { useMemo, useState } from "react";
import { Share2 } from "lucide-react";
import { GraphEdge, GraphNode, get } from "../api";
import { TYPE_COLOR } from "../graphColors";
import { useLoad, utc } from "../lib";
import { Badge, Empty, ErrorNote, Kv, Loading } from "../ui";
import ForceGraph from "./ForceGraph";

const RECENT_MS = 15 * 60 * 1000;

/** Animated network topology of REAL recorded entities and relationships.
 *  Markers travel along each edge in its recorded direction; amber rings ping entities recorded in the last 15 minutes.
 *  Motion encodes structure and recency — it is not live traffic and nothing here is simulated. */
export default function TopologyPanel() {
  const g = useLoad(() => get<{ nodes: GraphNode[]; edges: GraphEdge[] }>("/graph?limit=140"), [], 15000);
  const [selected, setSelected] = useState<number | null>(null);
  const nodes = useMemo(() => (g.data?.nodes ?? []).map((n) => ({ id: n.id, label: n.label, type: n.type, color: TYPE_COLOR[n.type] ?? "#849487" })), [g.data]);
  const edges = useMemo(() => (g.data?.edges ?? []).map((e) => ({ id: e.id, source: e.src_id, target: e.dst_id, label: e.rel_type.replace(/_/g, " ") })), [g.data]);
  const recent = useMemo(() => {
    const now = Date.now();
    return new Set((g.data?.nodes ?? []).filter((n) => now - new Date(n.created_at.endsWith("Z") ? n.created_at : n.created_at + "Z").getTime() < RECENT_MS).map((n) => n.id));
  }, [g.data]);
  const sel = g.data?.nodes.find((n) => n.id === selected) ?? null;
  const rels = sel ? (g.data?.edges ?? []).filter((e) => e.src_id === sel.id || e.dst_id === sel.id) : [];
  const counts = useMemo(() => { const c: Record<string, number> = {}; (g.data?.nodes ?? []).forEach((n) => { c[n.type] = (c[n.type] ?? 0) + 1; }); return c; }, [g.data]);

  return (
    <div className="relative h-full min-h-[360px] bg-grid">
      {/* static range rings: decorative reference geometry, not data */}
      <svg className="pointer-events-none absolute inset-0 h-full w-full opacity-40" aria-hidden>
        {[0.18, 0.34, 0.5, 0.66].map((r) => <circle key={r} cx="50%" cy="50%" r={`${r * 100}%`} fill="none" stroke="#243026" strokeWidth="1" strokeDasharray="2 6" />)}
        <line x1="0" y1="50%" x2="100%" y2="50%" stroke="#243026" strokeWidth="1" /><line x1="50%" y1="0" x2="50%" y2="100%" stroke="#243026" strokeWidth="1" />
      </svg>
      {g.loading && !g.data ? <Loading label="BUILDING TOPOLOGY" /> : g.error ? <div className="p-3"><ErrorNote message={g.error} onRetry={g.reload} /></div> : nodes.length === 0 ? (
        <div className="absolute inset-0 flex items-center justify-center p-6"><Empty icon={<Share2 size={24} />} title="No topology recorded yet">Entities and relationships appear here as operations run — domain investigations (DNS, nameservers, certificates), PCAP analyses, evidence and indicator links. Nothing is simulated.</Empty></div>
      ) : (
        <ForceGraph nodes={nodes} edges={edges} selected={selected} onSelect={setSelected} query="" animate recent={recent} />
      )}
      <div className="mono pointer-events-none absolute left-3 top-3 z-10 flex flex-col gap-1">
        <span className="bg-bg/90"><Badge tone="mute">TOPOLOGY · {nodes.length} NODES · {edges.length} LINKS</Badge></span>
        {recent.size > 0 && <span className="bg-bg/90"><Badge tone="amber">{recent.size} RECORDED IN LAST 15 MIN</Badge></span>}
      </div>
      <ul className="mono pointer-events-none absolute right-3 top-3 z-10 flex flex-col gap-0.5 border border-line bg-bg/85 px-2 py-1.5 text-[10px] tracking-[0.08em]" aria-label="Legend">
        {Object.entries(counts).map(([t, n]) => <li key={t} className="flex items-center gap-1.5"><span className="inline-block h-2 w-2" style={{ background: TYPE_COLOR[t] }} />{t.toUpperCase()} <span className="text-dim">{n}</span></li>)}
      </ul>
      <div className="mono pointer-events-none absolute bottom-2 left-3 right-3 z-10 text-[10px] tracking-[0.1em] text-dim">MOTION = RELATIONSHIP DIRECTION (SOURCE → TARGET) · AMBER PING = RECENTLY RECORDED · NOT LIVE TRAFFIC</div>
      {sel && (
        <div className="absolute bottom-7 left-3 z-10 max-w-sm border border-line2 bg-panel/95 px-3 py-2 shadow-xl">
          <dl><Kv k="Entity"><span className="break-all">{sel.type} · {sel.key}</span></Kv><Kv k="Recorded">{utc(sel.created_at)}</Kv><Kv k="Links">{rels.length}</Kv></dl>
        </div>
      )}
    </div>
  );
}
