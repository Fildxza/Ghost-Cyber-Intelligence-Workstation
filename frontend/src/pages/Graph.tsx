import { useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Activity, Maximize2, Minus, Plus, RotateCcw, Share2 } from "lucide-react";
import { Case, GraphEdge, GraphNode, get, qs } from "../api";
import { useLoad, utc } from "../lib";
import { Badge, Button, Empty, ErrorNote, Input, Kv, Loading, PageHeader, Panel, Select, cx } from "../ui";
import ForceGraph, { ForceGraphHandle } from "../components/ForceGraph";
import { ENTITY_TYPES, TYPE_COLOR } from "../graphColors";

const STYLE: Record<string, { color: string }> = Object.fromEntries(Object.entries(TYPE_COLOR).map(([k, color]) => [k, { color }]));
const TYPES = ENTITY_TYPES;

export default function Graph() {
  const [sp, setSp] = useSearchParams();
  const caseId = sp.get("case") ? Number(sp.get("case")) : null;
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const fg = useRef<ForceGraphHandle>(null);
  const [animate, setAnimate] = useState(true);
  const cases = useLoad(() => get<Case[]>("/cases"), []);
  const g = useLoad(() => get<{ nodes: GraphNode[]; edges: GraphEdge[] }>(`/graph${qs({ case_id: caseId })}`), [caseId]);

  const nodes = useMemo(() => (g.data?.nodes ?? []).filter((n) => !hidden.has(n.type)), [g.data, hidden]);
  const nodeIds = useMemo(() => new Set(nodes.map((n) => n.id)), [nodes]);
  const edges = useMemo(() => (g.data?.edges ?? []).filter((e) => nodeIds.has(e.src_id) && nodeIds.has(e.dst_id)), [g.data, nodeIds]);
  const counts = useMemo(() => { const c: Record<string, number> = {}; (g.data?.nodes ?? []).forEach((n) => { c[n.type] = (c[n.type] ?? 0) + 1; }); return c; }, [g.data]);

  const gnodes = useMemo(() => nodes.map((n) => ({ id: n.id, label: n.label, type: n.type, color: STYLE[n.type]?.color ?? "#849487" })), [nodes]);
  const gedges = useMemo(() => edges.map((e) => ({ id: e.id, source: e.src_id, target: e.dst_id, label: e.rel_type.replace(/_/g, " ") })), [edges]);

  const sel = g.data?.nodes.find((n) => n.id === selected) ?? null;
  const rels = useMemo(() => (sel ? (g.data?.edges ?? []).filter((e) => e.src_id === sel.id || e.dst_id === sel.id) : []), [sel, g.data]);
  const byId = useMemo(() => new Map((g.data?.nodes ?? []).map((n) => [n.id, n])), [g.data]);
  const total = g.data?.nodes.length ?? 0;

  return (
    <div className="mx-auto max-w-[1700px]">
      <PageHeader code="ENTITY GRAPH" title="Relationship graph" sub="Nodes are entities recorded by operations and analyst actions. Every edge carries a relationship type and the source that supports it; nothing is inferred." />
      <div className="grid gap-3 xl:grid-cols-[minmax(0,1fr)_340px]">
        <Panel title="Graph" icon={<Share2 size={13} />} flush right={<span className="mono text-[10px] text-dim">{nodes.length} NODES · {edges.length} EDGES</span>}>
          <div className="flex flex-wrap items-center gap-2 border-b border-line p-2.5">
            <Select aria-label="Scope graph to case" value={caseId ?? ""} onChange={(e) => setSp(e.target.value ? { case: e.target.value } : {})} className="!w-56"><option value="">ALL ENTITIES</option>{(cases.data ?? []).map((c) => <option key={c.id} value={c.id}>{c.ref} — {c.name}</option>)}</Select>
            <Input aria-label="Find entity" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Find entity…" className="mono !w-44" />
            <div className="ml-auto flex gap-1.5">
              <Button small aria-pressed={animate} aria-label="Toggle relationship motion" variant={animate ? "primary" : "ghost"} icon={<Activity size={12} />} onClick={() => setAnimate(!animate)}>Motion</Button>
              <Button small aria-label="Zoom in" icon={<Plus size={12} />} onClick={() => fg.current?.zoomBy(1.3)} />
              <Button small aria-label="Zoom out" icon={<Minus size={12} />} onClick={() => fg.current?.zoomBy(1 / 1.3)} />
              <Button small aria-label="Fit graph" icon={<Maximize2 size={12} />} onClick={() => fg.current?.fit()}>Fit</Button>
              <Button small aria-label="Reset layout" icon={<RotateCcw size={12} />} onClick={() => { setQuery(""); setSelected(null); fg.current?.relayout(); }}>Reset</Button>
            </div>
          </div>
          <div role="group" aria-label="Filter entity types" className="flex flex-wrap gap-1.5 border-b border-line px-2.5 py-2">
            {TYPES.map((t) => (
              <button key={t} aria-pressed={!hidden.has(t)} disabled={!counts[t]} onClick={() => setHidden((h) => { const n = new Set(h); n.has(t) ? n.delete(t) : n.add(t); return n; })}
                className={cx("mono flex items-center gap-1.5 border px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] disabled:opacity-35", hidden.has(t) ? "border-line text-dim line-through" : "border-line2 text-ink")}>
                <span className="inline-block h-2 w-2" style={{ background: STYLE[t].color }} />{t} <span className="text-dim">{counts[t] ?? 0}</span>
              </button>))}
          </div>
          <div className="relative h-[560px]">
            <div className="bg-grid absolute inset-0">
              <ForceGraph handle={fg} nodes={gnodes} edges={gedges} selected={selected} onSelect={setSelected} query={query} animate={animate} />
            </div>
            {g.loading && !g.data && <div className="absolute inset-0"><Loading /></div>}
            {g.error && <div className="absolute inset-x-3 top-3"><ErrorNote message={g.error} onRetry={g.reload} /></div>}
            {!g.loading && !g.error && total === 0 && <div className="absolute inset-0 flex items-center justify-center p-6"><Empty icon={<Share2 size={24} />} title={caseId ? "No relationships recorded for this case" : "No entities recorded yet"}>Entities and relationships are created by real operations — domain investigations (DNS, certificates, CT), PCAP analyses, evidence registration and indicator–case links.</Empty></div>}
          </div>
        </Panel>
        <Panel title="Entity detail">
          {!sel ? <Empty title="Select a node">Click an entity to see its properties and every recorded relationship with its source.</Empty> : (
            <div className="space-y-3">
              <dl>
                <Kv k="Type"><Badge>{sel.type}</Badge></Kv>
                <Kv k="Key"><span className="break-all">{sel.key}</span></Kv>
                <Kv k="Recorded">{utc(sel.created_at)}</Kv>
                {Object.entries(sel.props).map(([k, v]) => <Kv key={k} k={k}><span className="break-all">{String(v)}</span></Kv>)}
              </dl>
              <div>
                <div className="label mb-1.5">Relationships · {rels.length}</div>
                <ul className="max-h-96 space-y-1.5 overflow-auto">{rels.map((e) => {
                  const other = byId.get(e.src_id === sel.id ? e.dst_id : e.src_id);
                  return (
                    <li key={e.id} className="border border-line px-2.5 py-1.5">
                      <div className="mono text-[11px]"><span className="text-lime">{e.src_id === sel.id ? "→" : "←"} {e.rel_type.replace(/_/g, " ")}</span></div>
                      <button className="mono break-all text-left text-[11.5px] hover:text-lime" onClick={() => setSelected(other?.id ?? null)}>{other?.label ?? "?"}</button>
                      <div className="mono text-[10px] text-dim">SOURCE {e.source}{e.evidence_ref ? ` · ${e.evidence_ref}` : ""}</div>
                    </li>);
                })}</ul>
              </div>
            </div>
          )}
        </Panel>
      </div>
    </div>
  );
}
