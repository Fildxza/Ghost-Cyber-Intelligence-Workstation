import { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes, useEffect, useId, useRef } from "react";
import { Loader2, X } from "lucide-react";

export const cx = (...a: (string | false | null | undefined)[]) => a.filter(Boolean).join(" ");

// ---- brand -------------------------------------------------------------------------

/** Fidx-Ghost mark: a ghost silhouette whose eye is a radar sweep (geometric, original). */
export function GhostMark({ size = 28, className }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" className={className} role="img" aria-label="Fidx-Ghost">
      <rect x="0.5" y="0.5" width="31" height="31" fill="none" stroke="var(--color-line2)" />
      <path d="M7 26V15.5a9 9 0 0 1 18 0V26l-3-2.6-3 2.6-3-2.6-3 2.6-3-2.6z" fill="none" stroke="var(--color-lime)" strokeWidth="1.5" strokeLinejoin="round" />
      <circle cx="16" cy="15.5" r="4.2" fill="none" stroke="var(--color-lime)" strokeWidth="0.9" opacity="0.55" />
      <path d="M16 15.5 19.4 12.6" stroke="var(--color-lime)" strokeWidth="1.2" strokeLinecap="round" />
      <circle cx="16" cy="15.5" r="1.1" fill="var(--color-lime)" />
      <path d="M2 5V2h3M27 2h3v3M30 27v3h-3M5 30H2v-3" stroke="var(--color-mute)" strokeWidth="0.8" fill="none" />
    </svg>
  );
}

export function Wordmark({ compact = false }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-2.5 select-none">
      <GhostMark size={compact ? 24 : 30} />
      {!compact && (
        <div className="leading-none">
          <div className="mono text-[15px] font-semibold tracking-[0.22em] text-ink">
            FIDX<span className="text-lime">·</span>GHOST
          </div>
          <div className="mono mt-1 text-[8.5px] tracking-[0.28em] text-mute">CYBER INTELLIGENCE WORKSTATION</div>
        </div>
      )}
    </div>
  );
}

// ---- structure ----------------------------------------------------------------------

export function Panel({
  title, icon, right, children, className, bodyClassName, flush, id,
}: { title?: ReactNode; icon?: ReactNode; right?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string; flush?: boolean; id?: string }) {
  return (
    <section id={id} className={cx("flex min-w-0 flex-col border border-line bg-panel", className)}>
      {title && (
        <header className="flex min-h-9 items-center justify-between gap-3 border-b border-line px-3">
          <h2 className="label flex items-center gap-2 !text-ink">
            {icon && <span className="text-mute">{icon}</span>}
            {title}
          </h2>
          {right && <div className="flex items-center gap-2">{right}</div>}
        </header>
      )}
      <div className={cx("min-h-0 flex-1", !flush && "p-3", bodyClassName)}>{children}</div>
    </section>
  );
}

export function PageHeader({ code, title, sub, actions }: { code: string; title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3 border-b border-line pb-3">
      <div>
        <div className="label !text-lime">{code}</div>
        <h1 className="mt-1 text-[19px] font-semibold tracking-[0.04em] text-ink">{title}</h1>
        {sub && <p className="mt-1 max-w-3xl text-[12.5px] text-mute">{sub}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Metric({ label, value, hint, tone = "ink", icon }: { label: string; value: ReactNode; hint?: ReactNode; tone?: "ink" | "lime" | "amber" | "crit"; icon?: ReactNode }) {
  const color = { ink: "text-ink", lime: "text-lime", amber: "text-amber", crit: "text-crit" }[tone];
  return (
    <div className="relative border border-line bg-panel px-3 py-2.5">
      <div className="flex items-center justify-between">
        <span className="label">{label}</span>
        {icon && <span className="text-dim">{icon}</span>}
      </div>
      <div className={cx("mono mt-1.5 text-[28px] font-medium leading-none tabular-nums", color)}>{value}</div>
      {hint && <div className="mono mt-1.5 text-[10.5px] text-dim">{hint}</div>}
    </div>
  );
}

// ---- status ----------------------------------------------------------------------------

type Tone = "lime" | "amber" | "crit" | "mute" | "ink";
const toneClass: Record<Tone, string> = {
  lime: "border-lime/40 text-lime bg-lime/[0.06]",
  amber: "border-amber/40 text-amber bg-amber/[0.06]",
  crit: "border-crit/45 text-crit bg-crit/[0.07]",
  mute: "border-line2 text-mute bg-transparent",
  ink: "border-line2 text-ink bg-transparent",
};

export function Badge({ tone = "mute", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span title={title} className={cx("mono inline-flex items-center gap-1 border px-1.5 py-px text-[10px] uppercase leading-4 tracking-[0.1em] whitespace-nowrap", toneClass[tone])}>
      {children}
    </span>
  );
}

export function Dot({ tone, pulse }: { tone: Tone; pulse?: boolean }) {
  const c = { lime: "bg-lime", amber: "bg-amber", crit: "bg-crit", mute: "bg-dim", ink: "bg-ink" }[tone];
  return <span className={cx("inline-block h-1.5 w-1.5 shrink-0", c, pulse && "pulse")} aria-hidden />;
}

export const severityTone = (s: string): Tone => (s === "critical" || s === "high" ? "crit" : s === "medium" ? "amber" : s === "low" ? "ink" : "mute");
export const priorityTone = (s: string): Tone => (s === "critical" ? "crit" : s === "high" ? "amber" : s === "medium" ? "ink" : "mute");
export const opTone = (s: string): Tone => (s === "completed" ? "lime" : s === "failed" ? "crit" : s === "running" || s === "queued" ? "amber" : "mute");

export function StatusBadge({ status }: { status: string }) {
  const running = status === "running" || status === "queued";
  return (
    <Badge tone={opTone(status)}>
      {running ? <Loader2 size={10} className="animate-spin" /> : <Dot tone={opTone(status)} />}
      {status}
    </Badge>
  );
}

export function Freshness({ value }: { value: string }) {
  const tone: Tone = value === "live" ? "lime" : value === "simulated" ? "amber" : "mute";
  return <Badge tone={tone}>{value}</Badge>;
}

// ---- controls --------------------------------------------------------------------------

type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "ghost" | "danger" | "quiet"; busy?: boolean; icon?: ReactNode; small?: boolean };
export function Button({ variant = "ghost", busy, icon, small, children, className, disabled, ...rest }: BtnProps) {
  const v = {
    primary: "border-lime bg-lime text-bg hover:bg-[#c8ff7d] font-semibold",
    ghost: "border-line2 bg-elev text-ink hover:border-lime/60 hover:text-lime",
    danger: "border-crit/50 bg-transparent text-crit hover:bg-crit/10",
    quiet: "border-transparent bg-transparent text-mute hover:text-ink",
  }[variant];
  return (
    <button
      {...rest}
      disabled={disabled || busy}
      className={cx("mono inline-flex shrink-0 items-center justify-center gap-1.5 border uppercase tracking-[0.1em] transition-colors disabled:cursor-not-allowed disabled:opacity-45",
        small ? "h-7 px-2 text-[10px]" : "h-8 px-3 text-[11px]", v, className)}
    >
      {busy ? <Loader2 size={13} className="animate-spin" /> : icon}
      {children}
    </button>
  );
}

const fieldBase = "w-full border border-line2 bg-bg2 px-2.5 text-[13px] text-ink placeholder:text-dim hover:border-dim focus:border-lime/70 focus:outline-none disabled:opacity-50";

export function Field({ label, hint, error, children, className }: { label: string; hint?: ReactNode; error?: string | null; children: (id: string) => ReactNode; className?: string }) {
  const id = useId();
  return (
    <div className={className}>
      <label htmlFor={id} className="label mb-1 block">{label}</label>
      {children(id)}
      {error ? <p className="mt-1 text-[11.5px] text-crit" role="alert">{error}</p> : hint ? <p className="mt-1 text-[11.5px] text-dim">{hint}</p> : null}
    </div>
  );
}

export const Input = ({ className, ...p }: InputHTMLAttributes<HTMLInputElement>) => <input {...p} className={cx(fieldBase, "h-8", className)} />;
export const Select = ({ className, children, ...p }: SelectHTMLAttributes<HTMLSelectElement>) => <select {...p} className={cx(fieldBase, "h-8 pr-6", className)}>{children}</select>;
export const Textarea = ({ className, ...p }: TextareaHTMLAttributes<HTMLTextAreaElement>) => <textarea {...p} className={cx(fieldBase, "min-h-20 py-2", className)} />;

export function Check({ checked, onChange, children, disabled }: { checked: boolean; onChange: (v: boolean) => void; children: ReactNode; disabled?: boolean }) {
  return (
    <label className={cx("flex cursor-pointer items-start gap-2.5 text-[12.5px] text-ink", disabled && "cursor-not-allowed opacity-50")}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} className="peer sr-only" />
      <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center border border-line2 bg-bg2 text-[11px] leading-none text-bg peer-checked:border-lime peer-checked:bg-lime peer-focus-visible:outline peer-focus-visible:outline-1 peer-focus-visible:outline-lime" aria-hidden>
        {checked ? "✓" : ""}
      </span>
      <span>{children}</span>
    </label>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; count?: number }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div role="tablist" className="flex gap-px overflow-x-auto border-b border-line">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} onClick={() => onChange(t.id)}
          className={cx("mono -mb-px whitespace-nowrap border-b-2 px-3 py-2 text-[11px] uppercase tracking-[0.1em]", value === t.id ? "border-lime text-lime" : "border-transparent text-mute hover:text-ink")}>
          {t.label}{t.count !== undefined && <span className="ml-1.5 text-dim">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

// ---- states ----------------------------------------------------------------------------

export function Empty({ icon, title, children, action }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="bg-grid flex flex-col items-center justify-center gap-2 border border-dashed border-line2 px-6 py-8 text-center">
      {icon && <div className="text-dim">{icon}</div>}
      <div className="label !text-ink">{title}</div>
      {children && <p className="max-w-md text-[12.5px] text-mute">{children}</p>}
      {action && <div className="mt-1">{action}</div>}
    </div>
  );
}

export function Unavailable({ title, children, action }: { title: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className="border border-amber/40 bg-amber/[0.05] px-3 py-2.5">
      <div className="label !text-amber">⚠ {title}</div>
      <div className="mt-1 text-[12.5px] text-mute">{children}</div>
      {action && <div className="mt-2">{action}</div>}
    </div>
  );
}

export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-center justify-between gap-3 border border-crit/40 bg-crit/[0.06] px-3 py-2 text-[12.5px] text-crit">
      <span>{message}</span>
      {onRetry && <Button small variant="danger" onClick={onRetry}>Retry</Button>}
    </div>
  );
}

export function Loading({ label = "LOADING" }: { label?: string }) {
  return (
    <div className="mono flex items-center gap-2 px-3 py-6 text-[11px] tracking-[0.14em] text-mute" role="status">
      <Loader2 size={14} className="animate-spin text-lime" /> {label}…
    </div>
  );
}

export function Kv({ k, children, mono = true }: { k: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-[110px_1fr] gap-2 border-b border-line py-1.5 last:border-0 sm:grid-cols-[140px_1fr]">
      <dt className="label pt-0.5">{k}</dt>
      <dd className={cx("min-w-0 break-words text-[12.5px]", mono && "mono text-[12px]")}>{children}</dd>
    </div>
  );
}

// ---- modal -----------------------------------------------------------------------------

export function Modal({ open, title, onClose, children, wide }: { open: boolean; title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const prev = document.activeElement as HTMLElement | null;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (e.key === "Tab" && ref.current) {
        const f = ref.current.querySelectorAll<HTMLElement>("button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])");
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    };
    document.addEventListener("keydown", onKey);
    window.setTimeout(() => ref.current?.querySelector<HTMLElement>("input, textarea, select, button")?.focus(), 30);
    return () => { document.removeEventListener("keydown", onKey); prev?.focus?.(); };
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[2000] flex items-start justify-center overflow-y-auto bg-black/70 p-4 pt-[8vh]" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} role="dialog" aria-modal="true" aria-label={title} className={cx("w-full border border-line2 bg-panel shadow-2xl", wide ? "max-w-3xl" : "max-w-xl")}>
        <header className="flex items-center justify-between border-b border-line px-4 py-2.5">
          <h2 className="label !text-lime">{title}</h2>
          <button onClick={onClose} aria-label="Close dialog" className="text-mute hover:text-ink"><X size={16} /></button>
        </header>
        <div className="p-4">{children}</div>
      </div>
    </div>
  );
}

/** Horizontal proportional bar used for distributions. */
export function Bar({ value, max, tone = "lime" }: { value: number; max: number; tone?: "lime" | "amber" | "mute" }) {
  const w = max > 0 ? Math.max(1.5, (value / max) * 100) : 0;
  const c = { lime: "bg-lime/70", amber: "bg-amber/70", mute: "bg-dim" }[tone];
  return <div className="h-1.5 w-full bg-bg2"><div className={cx("h-full", c)} style={{ width: `${w}%` }} /></div>;
}
