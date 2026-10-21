import { Ref, useEffect, useImperativeHandle, useMemo, useRef } from "react";
import cytoscape from "cytoscape";

export interface GNode { id: number; label: string; type: string; color: string }
export interface GEdge { id: number; source: number; target: number; label: string }
export interface ForceGraphHandle { zoomBy: (f: number) => void; fit: () => void; relayout: () => void }

const SHAPES: Record<string, string> = {
  domain: "ellipse", ip: "round-rectangle", url: "round-tag", hash: "hexagon", certificate: "diamond",
  case: "barrel", evidence: "rectangle", indicator: "triangle",
};

const STYLE: cytoscape.StylesheetJson = [
  { selector: "node", style: {
    "background-color": "#131B16", "border-width": 1.6, "border-color": "data(color)", shape: "data(shape)" as never, label: "data(label)",
    color: "#E5ECE5", "font-size": 10, "font-family": "IBM Plex Mono, Cascadia Mono, Consolas, monospace", "text-valign": "bottom", "text-margin-y": 6,
    "text-wrap": "ellipsis", "text-max-width": "120px", width: 26, height: 26, "text-outline-color": "#0B0F0D", "text-outline-width": 2 } },
  { selector: "node[type = 'case']", style: { width: 36, height: 36 } },
  { selector: "node:selected", style: { "border-width": 3.5, "background-color": "#19241D", "overlay-opacity": 0 } },
  { selector: "node.match", style: { "border-width": 3, "background-color": "#2a3a20" } },
  { selector: ".dim", style: { opacity: 0.12 } },
  { selector: "edge", style: {
    width: 1, "line-color": "#34443a", "target-arrow-color": "#4a5e50", "target-arrow-shape": "triangle", "arrow-scale": 0.7, "curve-style": "bezier",
    label: "", "font-size": 7.5, color: "#849487", "font-family": "IBM Plex Mono, Cascadia Mono, Consolas, monospace", "text-rotation": "autorotate",
    "text-background-color": "#0B0F0D", "text-background-opacity": 0.9, "text-background-padding": "2px" } },
  { selector: "edge.hi", style: { "line-color": "#B7F36B", "target-arrow-color": "#B7F36B", width: 2, label: "data(rel)", color: "#B7F36B" } },
  { selector: "edge:selected, edge.hover", style: { label: "data(rel)" } },
];

const LAYOUT = { name: "cose", animate: false, padding: 50, nodeRepulsion: () => 90000, idealEdgeLength: () => 140, nodeOverlap: 40, gravity: 0.3, numIter: 1500, componentSpacing: 140, edgeElasticity: () => 80, randomize: true, fit: true } as cytoscape.LayoutOptions;

/** Interactive entity graph on Cytoscape.js: wheel-zoom, drag-pan, drag nodes, select, highlight by query. */
export default function ForceGraph({ nodes, edges, selected, onSelect, query, handle }: {
  nodes: GNode[]; edges: GEdge[]; selected: number | null; onSelect: (id: number | null) => void; query: string; handle?: Ref<ForceGraphHandle>;
}) {
  const el = useRef<HTMLDivElement>(null);
  const cy = useRef<cytoscape.Core | null>(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  useEffect(() => {
    if (!el.current) return;
    const inst = cytoscape({ container: el.current, style: STYLE, minZoom: 0.12, maxZoom: 3.5, wheelSensitivity: 0.3 });
    inst.on("tap", "node", (e) => onSelectRef.current(Number(e.target.id())));
    inst.on("tap", (e) => { if (e.target === inst) onSelectRef.current(null); });
    inst.on("mouseover", "edge", (e) => e.target.addClass("hover"));
    inst.on("mouseout", "edge", (e) => e.target.removeClass("hover"));
    cy.current = inst;
    // Cytoscape reads its container size at layout time. Re-measure whenever the box changes and
    // (re)fit once it first has real dimensions, so the graph never renders into a 0x0 canvas.
    let sized = false;
    const ro = new ResizeObserver(() => {
      inst.resize();
      if (!sized && inst.width() > 50 && inst.height() > 50) { sized = true; if (inst.nodes().nonempty()) { inst.layout(LAYOUT).run(); } }
    });
    ro.observe(el.current);
    return () => { ro.disconnect(); inst.destroy(); cy.current = null; };
  }, []);

  const key = useMemo(() => nodes.map((n) => n.id).join(",") + "|" + edges.map((e) => e.id).join(","), [nodes, edges]);
  useEffect(() => {
    const inst = cy.current;
    if (!inst) return;
    inst.batch(() => {
      inst.elements().remove();
      inst.add([
        ...nodes.map((n) => ({ group: "nodes" as const, data: { id: String(n.id), label: n.label, type: n.type, color: n.color, shape: SHAPES[n.type] ?? "ellipse" } })),
        ...edges.map((e) => ({ group: "edges" as const, data: { id: `e${e.id}`, source: String(e.source), target: String(e.target), rel: e.label } })),
      ]);
    });
    inst.resize();
    if (nodes.length) inst.layout(LAYOUT).run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  // selection + search highlighting
  useEffect(() => {
    const inst = cy.current;
    if (!inst) return;
    inst.batch(() => {
      inst.elements().removeClass("dim match hi");
      inst.nodes().unselect();
      const q = query.trim().toLowerCase();
      if (q) {
        const m = inst.nodes().filter((n) => String(n.data("label")).toLowerCase().includes(q));
        inst.elements().addClass("dim");
        m.removeClass("dim").addClass("match");
        m.connectedEdges().removeClass("dim");
        if (m.length) inst.animate({ fit: { eles: m, padding: 90 }, duration: 250 });
      } else if (selected !== null) {
        const n = inst.getElementById(String(selected));
        if (n.nonempty()) {
          n.select();
          const hood = n.closedNeighborhood();
          inst.elements().not(hood).addClass("dim");
          n.connectedEdges().addClass("hi");
        }
      }
    });
  }, [selected, query, key]);

  useImperativeHandle(handle, () => ({
    zoomBy: (f) => { const c = cy.current; if (c) c.zoom({ level: c.zoom() * f, renderedPosition: { x: c.width() / 2, y: c.height() / 2 } }); },
    fit: () => cy.current?.fit(undefined, 40),
    relayout: () => { cy.current?.layout(LAYOUT).run(); },
  }), []);

  return (
    <div className="absolute inset-0">
      <div ref={el} className="h-full w-full" role="img" aria-label="Entity relationship graph. Use the detail panel to navigate relationships." />
      <div className="mono pointer-events-none absolute bottom-2 left-3 text-[10px] tracking-[0.1em] text-dim">CYTOSCAPE · DRAG TO PAN · SCROLL TO ZOOM · DRAG NODES · CLICK TO SELECT</div>
    </div>
  );
}
