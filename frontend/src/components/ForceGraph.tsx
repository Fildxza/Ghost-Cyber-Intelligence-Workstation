import { Ref, useEffect, useImperativeHandle, useMemo, useRef } from "react";
import cytoscape from "cytoscape";

export interface GNode { id: number; label: string; type: string; color: string }
export interface GEdge { id: number; source: number; target: number; label: string }
export interface ForceGraphHandle { zoomBy: (f: number) => void; fit: () => void; relayout: () => void }

const SHAPES: Record<string, string> = {
  domain: "ellipse", ip: "round-rectangle", url: "round-tag", hash: "hexagon", certificate: "diamond",
  case: "barrel", evidence: "rectangle", indicator: "triangle",
};
const MONO = "IBM Plex Mono, Cascadia Mono, Consolas, monospace";

const STYLE: cytoscape.StylesheetJson = [
  { selector: "node", style: {
    "background-color": "#131B16", "border-width": 1.6, "border-color": "data(color)", shape: "data(shape)" as never, label: "data(label)",
    color: "#E5ECE5", "font-size": 10, "font-family": MONO, "text-valign": "bottom", "text-margin-y": 6,
    "text-wrap": "ellipsis", "text-max-width": "120px", width: 26, height: 26, "text-outline-color": "#0B0F0D", "text-outline-width": 2 } },
  { selector: "node[type = 'case']", style: { width: 36, height: 36 } },
  { selector: "node:selected", style: { "border-width": 3.5, "background-color": "#19241D", "overlay-opacity": 0 } },
  { selector: "node.match", style: { "border-width": 3, "background-color": "#2a3a20" } },
  { selector: ".dim", style: { opacity: 0.12 } },
  { selector: "edge", style: {
    width: 1, "line-color": "#34443a", "target-arrow-color": "#4a5e50", "target-arrow-shape": "triangle", "arrow-scale": 0.7, "curve-style": "bezier",
    label: "", "font-size": 7.5, color: "#849487", "font-family": MONO, "text-rotation": "autorotate",
    "text-background-color": "#0B0F0D", "text-background-opacity": 0.9, "text-background-padding": "2px" } },
  { selector: "edge.hi", style: { "line-color": "#B7F36B", "target-arrow-color": "#B7F36B", width: 2, label: "data(rel)", color: "#B7F36B" } },
  { selector: "edge:selected, edge.hover", style: { label: "data(rel)" } },
];

const LAYOUT = { name: "cose", animate: false, padding: 50, nodeRepulsion: () => 90000, idealEdgeLength: () => 140, nodeOverlap: 40, gravity: 0.3, numIter: 1500, componentSpacing: 140, edgeElasticity: () => 80, randomize: true, fit: true } as cytoscape.LayoutOptions;

const prefersReducedMotion = () => typeof window !== "undefined" && !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

/** Interactive entity graph on Cytoscape.js. With `animate`, a canvas overlay moves a marker along every
 *  relationship in its recorded direction (source → target) and pings recently-recorded entities.
 *  The motion encodes structure only — it is not live traffic. */
export default function ForceGraph({ nodes, edges, selected, onSelect, query, handle, animate = false, recent, interactive = true, labels = true }: {
  nodes: GNode[]; edges: GEdge[]; selected: number | null; onSelect: (id: number | null) => void; query: string; handle?: Ref<ForceGraphHandle>;
  animate?: boolean; recent?: Set<number>; interactive?: boolean; labels?: boolean;
}) {
  const el = useRef<HTMLDivElement>(null);
  const overlay = useRef<HTMLCanvasElement>(null);
  const cy = useRef<cytoscape.Core | null>(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;
  const recentRef = useRef(recent);
  recentRef.current = recent;

  useEffect(() => {
    if (!el.current) return;
    const inst = cytoscape({ container: el.current, style: STYLE, minZoom: 0.12, maxZoom: 3.5, wheelSensitivity: 0.3,
      userZoomingEnabled: interactive, userPanningEnabled: interactive, boxSelectionEnabled: false });
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
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const key = useMemo(() => nodes.map((n) => n.id).join(",") + "|" + edges.map((e) => e.id).join(","), [nodes, edges]);
  useEffect(() => {
    const inst = cy.current;
    if (!inst) return;
    inst.batch(() => {
      inst.elements().remove();
      inst.add([
        ...nodes.map((n) => ({ group: "nodes" as const, data: { id: String(n.id), label: labels ? n.label : "", type: n.type, color: n.color, shape: SHAPES[n.type] ?? "ellipse" } })),
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

  // motion overlay: markers travelling source → target along each relationship, ping rings on recent entities
  useEffect(() => {
    const c = overlay.current, inst = cy.current, host = el.current;
    if (!c) return;
    const ctx = c.getContext("2d");
    if (!ctx) return;
    if (!animate || !inst || !host || prefersReducedMotion()) { ctx.clearRect(0, 0, c.width, c.height); return; }
    let raf = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const resize = () => { const r = host.getBoundingClientRect(); c.width = r.width * dpr; c.height = r.height * dpr; c.style.width = `${r.width}px`; c.style.height = `${r.height}px`; };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(host);
    const frame = (t: number) => {
      raf = requestAnimationFrame(frame);
      if (document.hidden) return;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, c.width, c.height);
      const hot = inst.edges(".hi");
      inst.edges().forEach((e, i) => {
        if (e.hasClass("dim")) return;
        const a = e.source().renderedPosition(), b = e.target().renderedPosition();
        const speed = 0.00018 + (i % 5) * 0.00003;
        const p = (t * speed + i * 0.37) % 1;
        const x = a.x + (b.x - a.x) * p, y = a.y + (b.y - a.y) * p;
        const emph = hot.nonempty() && e.hasClass("hi");
        const rad = emph ? 9 : 6;
        const g = ctx.createRadialGradient(x, y, 0, x, y, rad);
        g.addColorStop(0, "rgba(183,243,107,0.95)");
        g.addColorStop(1, "rgba(183,243,107,0)");
        ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(x, y, rad, 0, Math.PI * 2); ctx.fill();
        for (let k = 1; k <= 4; k++) { // short fading tail behind the marker
          const pp = (p - k * 0.012 + 1) % 1;
          ctx.fillStyle = `rgba(183,243,107,${0.35 - k * 0.07})`;
          ctx.beginPath(); ctx.arc(a.x + (b.x - a.x) * pp, a.y + (b.y - a.y) * pp, 1.6, 0, Math.PI * 2); ctx.fill();
        }
      });
      const rec = recentRef.current;
      if (rec?.size) {
        inst.nodes().forEach((n) => {
          if (!rec.has(Number(n.id()))) return;
          const pos = n.renderedPosition();
          const ph = (t / 1800 + Number(n.id()) * 0.13) % 1;
          ctx.strokeStyle = `rgba(214,166,79,${0.7 * (1 - ph)})`;
          ctx.lineWidth = 1.2;
          ctx.beginPath(); ctx.arc(pos.x, pos.y, 14 + ph * 22, 0, Math.PI * 2); ctx.stroke();
        });
      }
    };
    raf = requestAnimationFrame(frame);
    return () => { cancelAnimationFrame(raf); ro.disconnect(); ctx.clearRect(0, 0, c.width, c.height); };
  }, [animate, key]);

  useImperativeHandle(handle, () => ({
    zoomBy: (f) => { const c = cy.current; if (c) c.zoom({ level: c.zoom() * f, renderedPosition: { x: c.width() / 2, y: c.height() / 2 } }); },
    fit: () => cy.current?.fit(undefined, 40),
    relayout: () => { cy.current?.layout(LAYOUT).run(); },
  }), []);

  return (
    <div className="absolute inset-0">
      <div ref={el} className="h-full w-full" role="img" aria-label="Entity relationship graph. Use the detail panel to navigate relationships." />
      <canvas ref={overlay} className="pointer-events-none absolute inset-0" aria-hidden />
    </div>
  );
}
