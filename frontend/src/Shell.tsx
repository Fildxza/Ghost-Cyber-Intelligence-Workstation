import { ReactNode, useEffect, useMemo, useRef, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  Activity, Check, ChevronsLeft, ChevronsRight, FileText, FolderOpen, Globe, Lock, Menu, Network, Radar, Search, Settings as Cog,
  Share2, ShieldAlert, User, Wifi, WifiOff, Wrench, X, Plus, ChevronDown,
} from "lucide-react";
import { Case, Evidence, Indicator, get, qs, post } from "./api";
import { useApp } from "./state";
import { ago, errMsg, useNow, useOnline, utc } from "./lib";
import { Badge, Button, Dot, Input, Modal, Field, Wordmark, cx } from "./ui";

export const NAV = [
  { to: "/", label: "COMMAND", icon: Radar, end: true },
  { to: "/operations", label: "OPERATIONS", icon: Activity },
  { to: "/cases", label: "CASE FILES", icon: FolderOpen },
  { to: "/osint", label: "OSINT", icon: Globe },
  { to: "/intel", label: "THREAT INTELLIGENCE", icon: ShieldAlert },
  { to: "/network", label: "NETWORK ANALYSIS", icon: Network },
  { to: "/graph", label: "ENTITY GRAPH", icon: Share2 },
  { to: "/evidence", label: "EVIDENCE VAULT", icon: Lock },
  { to: "/reports", label: "REPORTS", icon: FileText },
  { to: "/toolkit", label: "TOOLKIT", icon: Wrench },
  { to: "/settings", label: "SYSTEM SETTINGS", icon: Cog },
] as const;

const pad = (n: number) => String(n).padStart(2, "0");

function Clocks() {
  const now = useNow(1000);
  const local = `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
  const z = `${pad(now.getUTCHours())}:${pad(now.getUTCMinutes())}:${pad(now.getUTCSeconds())}`;
  const tz = -now.getTimezoneOffset() / 60;
  return (
    <div className="mono hidden items-center gap-3 border-x border-line px-3 text-[11px] leading-tight lg:flex" aria-label="Clocks">
      <div><div className="text-[9px] tracking-[0.18em] text-dim">LOCAL UTC{tz >= 0 ? "+" : ""}{tz}</div><div className="tabular-nums text-ink">{local}</div></div>
      <div><div className="text-[9px] tracking-[0.18em] text-dim">UTC / ZULU</div><div className="tabular-nums text-lime">{z}Z</div></div>
    </div>
  );
}

function Chip({ tone, label, value, to, title }: { tone: "lime" | "amber" | "crit" | "mute"; label: string; value: string; to?: string; title?: string }) {
  const nav = useNavigate();
  const col = { lime: "text-lime", amber: "text-amber", crit: "text-crit", mute: "text-mute" }[tone];
  return (
    <button onClick={() => to && nav(to)} title={title} className="mono flex items-center gap-1.5 border border-line px-2 py-1 text-[10px] tracking-[0.1em] hover:border-line2" aria-label={`${label}: ${value}`}>
      <Dot tone={tone} pulse={tone === "crit"} />
      <span className="text-dim">{label}</span>
      <span className={col}>{value}</span>
    </button>
  );
}

function StatusChips() {
  const { status, apiUp } = useApp();
  const online = useOnline();
  const s = status.data;
  const toolsOk = s ? s.tools.filter((t) => t.installed).length : 0;
  const toolsAll = s ? s.tools.length : 0;
  return (
    <div className="hidden items-center gap-1.5 xl:flex">
      {apiUp ? <Chip tone="lime" label="API" value="ONLINE" title="Last /api/status poll succeeded" /> : status.loading && !status.data ? <Chip tone="mute" label="API" value="CHECKING" /> : <Chip tone="crit" label="API" value="UNREACHABLE" title={status.error ?? ""} />}
      {s && <Chip tone={toolsOk === toolsAll ? "lime" : "amber"} label="TOOLS" value={`${toolsOk}/${toolsAll}`} to="/toolkit" title="Installed analysis tools (detected on this machine)" />}
      {s && <Chip tone={s.vault.encryption === "enabled" ? "lime" : "amber"} label="VAULT" value={s.vault.encryption === "enabled" ? "ENCRYPTED" : "UNENCRYPTED"} to="/settings" title={s.vault.note} />}
      {s?.field_mode ? <Chip tone="amber" label="MODE" value="FIELD · OFFLINE OPS" to="/settings" /> : !online ? <Chip tone="amber" label="LINK" value="NO NETWORK" /> : null}
    </div>
  );
}

function WorkspaceSelect() {
  const { workspaces, workspace, setWorkspace, notify, fail } = useApp();
  const [open, setOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);
  const create = async () => {
    try {
      const w = await post<{ id: number }>("/workspaces", { name });
      await setWorkspace(w.id);
      workspaces.reload();
      setCreating(false);
      setName("");
      notify("ok", "Workspace created");
    } catch (e) { fail(e); }
  };
  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen(!open)} aria-haspopup="listbox" aria-expanded={open} className="mono flex h-8 items-center gap-2 border border-line2 bg-bg2 px-2.5 text-[11px] tracking-[0.08em] hover:border-lime/50">
        <span className="hidden text-dim sm:inline">WS</span>
        <span className="max-w-28 truncate text-ink">{workspace?.name ?? "—"}</span>
        <ChevronDown size={12} className="text-mute" />
      </button>
      {open && (
        <div role="listbox" className="absolute left-0 top-9 z-[1500] w-56 border border-line2 bg-panel py-1 shadow-xl">
          {(workspaces.data ?? []).map((w) => (
            <button key={w.id} role="option" aria-selected={w.id === workspace?.id} onClick={() => { void setWorkspace(w.id).then(() => setOpen(false)).catch(fail); }}
              className="mono flex w-full items-center justify-between px-3 py-1.5 text-left text-[11px] hover:bg-elev">
              {w.name}{w.id === workspace?.id && <Check size={12} className="text-lime" />}
            </button>
          ))}
          <button onClick={() => { setCreating(true); setOpen(false); }} className="mono flex w-full items-center gap-2 border-t border-line px-3 py-1.5 text-[11px] text-lime hover:bg-elev"><Plus size={12} /> NEW WORKSPACE</button>
        </div>
      )}
      <Modal open={creating} title="New workspace" onClose={() => setCreating(false)}>
        <form onSubmit={(e) => { e.preventDefault(); void create(); }} className="space-y-3">
          <Field label="Workspace name" hint="Cases created while a workspace is active belong to it.">{(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} maxLength={40} required minLength={2} />}</Field>
          <div className="flex justify-end gap-2"><Button type="button" onClick={() => setCreating(false)}>Cancel</Button><Button variant="primary" type="submit">Create</Button></div>
        </form>
      </Modal>
    </div>
  );
}

interface Hit { kind: string; label: string; sub: string; to: string }

function GlobalSearch() {
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const [hits, setHits] = useState<Hit[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const wrap = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test((document.activeElement?.tagName ?? ""))) { e.preventDefault(); input.current?.focus(); }
    };
    const click = (e: MouseEvent) => { if (!wrap.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("keydown", k);
    document.addEventListener("mousedown", click);
    return () => { document.removeEventListener("keydown", k); document.removeEventListener("mousedown", click); };
  }, []);

  useEffect(() => {
    if (q.trim().length < 2) { setHits([]); setErr(null); return; }
    let cancelled = false;
    const t = window.setTimeout(async () => {
      setBusy(true);
      try {
        const [c, i, e] = await Promise.all([
          get<Case[]>(`/cases${qs({ q, include_archived: true })}`),
          get<Indicator[]>(`/intel/indicators${qs({ q })}`),
          get<Evidence[]>(`/evidence${qs({ q })}`),
        ]);
        if (cancelled) return;
        setHits([
          ...c.slice(0, 5).map((x) => ({ kind: "CASE", label: x.name, sub: x.ref, to: `/cases/${x.id}` })),
          ...i.slice(0, 5).map((x) => ({ kind: x.type.toUpperCase(), label: x.value, sub: x.ref, to: `/intel?sel=${x.id}` })),
          ...e.slice(0, 5).map((x) => ({ kind: "EVIDENCE", label: x.name, sub: x.ref, to: `/evidence?sel=${x.id}` })),
        ]);
        setErr(null);
        setActive(0);
      } catch (ex) { if (!cancelled) setErr(errMsg(ex)); }
      finally { if (!cancelled) setBusy(false); }
    }, 250);
    return () => { cancelled = true; window.clearTimeout(t); };
  }, [q]);

  const go = (h: Hit) => { nav(h.to); setOpen(false); setQ(""); input.current?.blur(); };

  return (
    <div className="relative min-w-0 flex-1 md:min-w-56 md:max-w-xl" ref={wrap}>
      <Search size={13} className="pointer-events-none absolute left-2.5 top-2.5 text-dim" />
      <input ref={input} value={q} onChange={(e) => { setQ(e.target.value); setOpen(true); }} onFocus={() => setOpen(true)}
        onKeyDown={(e) => {
          if (e.key === "Escape") { setOpen(false); input.current?.blur(); }
          if (e.key === "ArrowDown") { e.preventDefault(); setActive((a) => Math.min(a + 1, hits.length - 1)); }
          if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)); }
          if (e.key === "Enter" && hits[active]) go(hits[active]);
        }}
        placeholder="Search cases, indicators, evidence…" aria-label="Global search" role="combobox" aria-expanded={open && q.length >= 2} aria-controls="gsearch-list"
        className="mono h-8 w-full border border-line2 bg-bg2 pl-8 pr-8 text-[12px] text-ink placeholder:text-dim focus:border-lime/70 focus:outline-none" />
      <kbd className="mono pointer-events-none absolute right-2 top-1.5 hidden border border-line2 px-1.5 text-[10px] leading-4 text-dim sm:block">/</kbd>
      {open && q.trim().length >= 2 && (
        <div id="gsearch-list" role="listbox" className="absolute left-0 top-9 z-[1500] max-h-96 w-[min(560px,92vw)] overflow-y-auto border border-line2 bg-panel shadow-xl">
          {busy && <div className="mono px-3 py-2 text-[11px] text-mute">SEARCHING…</div>}
          {err && <div className="px-3 py-2 text-[12px] text-crit">{err}</div>}
          {!busy && !err && hits.length === 0 && <div className="mono px-3 py-2 text-[11px] text-mute">NO MATCHES FOR “{q}”</div>}
          {hits.map((h, i) => (
            <button key={h.to + h.sub} role="option" aria-selected={i === active} onMouseEnter={() => setActive(i)} onClick={() => go(h)}
              className={cx("flex w-full items-center gap-3 px-3 py-1.5 text-left", i === active && "bg-elev")}>
              <Badge>{h.kind}</Badge><span className="min-w-0 flex-1 truncate text-[12.5px]">{h.label}</span><span className="mono text-[10px] text-dim">{h.sub}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function AnalystMenu() {
  const { status, setNavCompact, navCompact } = useApp();
  const [open, setOpen] = useState(false);
  const nav = useNavigate();
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);
  const name = status.data?.analyst ?? "analyst";
  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen(!open)} aria-haspopup="menu" aria-expanded={open} aria-label="Analyst menu" className="flex h-8 items-center gap-2 border border-line2 bg-bg2 px-2 hover:border-lime/50">
        <User size={14} className="text-lime" /><span className="mono hidden max-w-24 truncate text-[11px] sm:inline">{name}</span>
      </button>
      {open && (
        <div role="menu" className="absolute right-0 top-9 z-[1500] w-60 border border-line2 bg-panel py-1 shadow-xl">
          <div className="border-b border-line px-3 py-2"><div className="label">ANALYST PROFILE</div><div className="mono mt-0.5 text-[12px]">{name}</div><div className="mono text-[10px] text-dim">Local OS account · no remote login</div></div>
          <button role="menuitem" onClick={() => { nav("/settings"); setOpen(false); }} className="mono block w-full px-3 py-1.5 text-left text-[11px] hover:bg-elev">SYSTEM SETTINGS</button>
          <button role="menuitem" onClick={() => { setNavCompact(!navCompact); setOpen(false); }} className="mono block w-full px-3 py-1.5 text-left text-[11px] hover:bg-elev">{navCompact ? "EXPAND" : "COMPACT"} NAVIGATION</button>
          <button role="menuitem" onClick={() => { nav("/toolkit"); setOpen(false); }} className="mono block w-full px-3 py-1.5 text-left text-[11px] hover:bg-elev">CLI REFERENCE</button>
        </div>
      )}
    </div>
  );
}

function NavRail({ mobileOpen, close }: { mobileOpen: boolean; close: () => void }) {
  const { navCompact, setNavCompact } = useApp();
  const compact = navCompact;
  return (
    <>
      {mobileOpen && <div className="fixed inset-0 z-[1800] bg-black/60 md:hidden" onClick={close} />}
      <nav aria-label="Primary" className={cx(
        "z-[1900] flex shrink-0 flex-col border-r border-line bg-bg2 transition-[width,transform] duration-150",
        "fixed inset-y-0 left-0 w-60 pt-12 md:static md:pt-0", mobileOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0",
        compact ? "md:w-14" : "md:w-56")}>
        <div className="flex-1 overflow-y-auto py-2">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={"end" in n ? n.end : false} onClick={close} title={compact ? n.label : undefined}
              className={({ isActive }) => cx("mono group relative flex h-9 items-center gap-3 px-4 text-[11px] tracking-[0.12em] transition-colors",
                compact && "md:justify-center md:px-0", isActive ? "bg-lime/[0.07] text-lime" : "text-mute hover:bg-elev hover:text-ink")}>
              {({ isActive }) => (<>
                {isActive && <span className="absolute inset-y-1 left-0 w-0.5 bg-lime" />}
                <n.icon size={16} strokeWidth={1.6} className="shrink-0" />
                <span className={cx(compact && "md:hidden")}>{n.label}</span>
              </>)}
            </NavLink>
          ))}
        </div>
        <button onClick={() => setNavCompact(!compact)} className="mono hidden h-9 items-center gap-2 border-t border-line px-4 text-[10px] tracking-[0.14em] text-dim hover:text-ink md:flex" aria-label={compact ? "Expand navigation" : "Compact navigation"}>
          {compact ? <ChevronsRight size={14} className="mx-auto" /> : <><ChevronsLeft size={14} /> COMPACT</>}
        </button>
      </nav>
    </>
  );
}

function StatusStrip() {
  const { status, apiUp, workspace } = useApp();
  const s = status.data;
  const now = useNow(15000);
  const sep = <span className="text-line2">│</span>;
  return (
    <footer className="mono flex h-7 shrink-0 items-center gap-3 overflow-x-auto whitespace-nowrap border-t border-line bg-bg2 px-3 text-[10px] tracking-[0.08em] text-mute" aria-label="Status strip">
      <span className="text-ink">FIDX-GHOST {s ? `v${s.version}` : ""}</span>{sep}
      <span className="flex items-center gap-1.5"><Dot tone={apiUp ? "lime" : "crit"} /> API {apiUp ? "REACHABLE" : "UNREACHABLE"}</span>{sep}
      <span className="flex items-center gap-1.5"><Dot tone={s ? (s.database.ok ? "lime" : "crit") : "mute"} /> DB {s ? (s.database.ok ? `SQLITE v${s.database.schema_version} · ${s.database.latency_ms}ms` : "ERROR") : "—"}</span>{sep}
      <span className="flex items-center gap-1.5"><Dot tone={s ? (s.worker.running + s.worker.queued > 0 ? "amber" : "mute") : "mute"} pulse={!!s && s.worker.running > 0} /> QUEUE {s ? `${s.worker.queued} QUEUED · ${s.worker.running} RUNNING` : "—"}</span>{sep}
      <span>WS {workspace?.name ?? "—"}</span>{sep}
      <span title={s?.last_operation?.finished_at ? utc(s.last_operation.finished_at) : ""}>LAST OP {s?.last_operation ? `${s.last_operation.ref} · ${ago(s.last_operation.finished_at, now.getTime())}` : "NONE YET"}</span>
      <span className="ml-auto hidden text-dim md:inline">SESSION {s?.session_id ?? "—"}</span>
    </footer>
  );
}

function Toasts() {
  const { toasts, dismissToast } = useApp();
  return (
    <div className="pointer-events-none fixed bottom-10 right-3 z-[3000] flex w-80 max-w-[calc(100vw-1.5rem)] flex-col gap-2" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} role={t.kind === "err" ? "alert" : "status"} className={cx("pointer-events-auto flex items-start gap-2 border bg-panel px-3 py-2 text-[12.5px] shadow-xl",
          t.kind === "err" ? "border-crit/50" : t.kind === "ok" ? "border-lime/40" : "border-line2")}>
          <span className="flex-1">{t.text}</span>
          <button onClick={() => dismissToast(t.id)} aria-label="Dismiss" className="text-mute hover:text-ink"><X size={13} /></button>
        </div>
      ))}
    </div>
  );
}

function BackendBanner() {
  const { status, apiUp } = useApp();
  if (apiUp || status.loading) return null;
  return (
    <div role="alert" className="mono flex items-center gap-2 border-b border-crit/40 bg-crit/[0.07] px-4 py-2 text-[11px] tracking-[0.06em] text-crit">
      <WifiOff size={14} /> BACKEND UNREACHABLE — data below may be stale or missing. Start it with <code className="border border-crit/30 px-1">ghost serve</code> ({status.error})
    </div>
  );
}

export default function Shell(): ReactNode {
  const [mobile, setMobile] = useState(false);
  const loc = useLocation();
  const { status } = useApp();
  const online = useOnline();
  const main = useRef<HTMLElement>(null);
  useEffect(() => { setMobile(false); main.current?.scrollTo?.(0, 0); }, [loc.pathname]);
  const title = useMemo(() => NAV.find((n) => (n.to === "/" ? loc.pathname === "/" : loc.pathname.startsWith(n.to)))?.label ?? "FIDX-GHOST", [loc.pathname]);
  useEffect(() => { document.title = `${title} · FIDX-GHOST`; }, [title]);

  return (
    <div className="flex h-full flex-col bg-bg">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-[4000] focus:bg-lime focus:px-3 focus:py-1 focus:text-bg">Skip to content</a>
      <header className="z-[2000] flex h-12 shrink-0 items-center gap-3 border-b border-line bg-bg2 px-3">
        <button onClick={() => setMobile(!mobile)} className="text-mute hover:text-ink md:hidden" aria-label="Toggle navigation">{mobile ? <X size={18} /> : <Menu size={18} />}</button>
        <div className="hidden sm:block"><Wordmark /></div>
        <div className="sm:hidden"><Wordmark compact /></div>
        <div className="mx-1 hidden h-6 w-px bg-line md:block" />
        <WorkspaceSelect />
        <GlobalSearch />
        <Clocks />
        <StatusChips />
        <span className="hidden items-center 2xl:flex" title={status.data?.field_mode ? "Field Mode on" : online ? "Network link up" : "No network link"}>
          {online && !status.data?.field_mode ? <Wifi size={14} className="text-mute" /> : <WifiOff size={14} className="text-amber" />}
        </span>
        <AnalystMenu />
      </header>
      <div className="flex min-h-0 flex-1">
        <NavRail mobileOpen={mobile} close={() => setMobile(false)} />
        <div className="flex min-w-0 flex-1 flex-col">
          <BackendBanner />
          <main id="main" ref={main} tabIndex={-1} className="bg-grid min-h-0 flex-1 overflow-y-auto p-3 sm:p-4 lg:p-5"><Outlet /></main>
        </div>
      </div>
      <StatusStrip />
      <Toasts />
    </div>
  );
}
