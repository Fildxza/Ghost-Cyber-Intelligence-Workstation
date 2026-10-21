import { useState } from "react";
import { Link } from "react-router-dom";
import { Bot, Check, Copy, Terminal, Wrench } from "lucide-react";
import { AiResult, Case, get, post } from "../api";
import { useApp } from "../state";
import { errMsg, useLoad, utc } from "../lib";
import { Badge, Button, Empty, ErrorNote, Field, Kv, Loading, PageHeader, Panel, Select, Textarea, Unavailable } from "../ui";

const CLI: { cmd: string; what: string }[] = [
  { cmd: "ghost --help", what: "List all commands" },
  { cmd: "ghost status [--json] [--api]", what: "Database, worker, tools, providers, vault — real checks" },
  { cmd: "ghost serve [--port 8787]", what: "Run the HTTP API (and the built UI)" },
  { cmd: "ghost case list [--q text] [--json]", what: "List cases" },
  { cmd: 'ghost case create "Name" --scope example.com --authorised', what: "Create a case with scope + authorisation declaration" },
  { cmd: "ghost osint domain example.com [--case 1] [--active --authorisation \"ticket #\"]", what: "DNS, RDAP, CT (+ TLS/HTTP with --active)" },
  { cmd: "ghost intel add <value> [--case 1]", what: "Validate, normalise and de-duplicate an indicator" },
  { cmd: "ghost intel enrich <value> [--case 1] [--json]", what: "Enrich through configured providers" },
  { cmd: "ghost intel export --format csv --output iocs.csv", what: "Export indicators" },
  { cmd: "ghost network analyze capture.pcap [--case 1] [--output out.json]", what: "Analyse a pcap / pcapng" },
  { cmd: "ghost evidence add file.bin --case 1", what: "Register evidence and record SHA-256" },
  { cmd: "ghost evidence verify 1", what: "Recompute the hash and compare (exit 4 on mismatch)" },
  { cmd: "ghost report generate 1 --output report.html", what: "Generate an HTML case report" },
];

const TASKS: { id: string; label: string }[] = [
  { id: "summarise", label: "Summarise findings" }, { id: "explain", label: "Explain in plain language" },
  { id: "next_steps", label: "Suggest defensive next steps" }, { id: "draft_section", label: "Draft report section" }, { id: "gaps", label: "Identify uncertainty & gaps" },
];

function Cli() {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = async (c: string) => { try { await navigator.clipboard.writeText(c); setCopied(c); window.setTimeout(() => setCopied(null), 1500); } catch { /* clipboard unavailable */ } };
  return (
    <ul>{CLI.map((c) => (
      <li key={c.cmd} className="flex items-start gap-2 border-b border-line px-3 py-2 last:border-0">
        <div className="min-w-0 flex-1"><code className="mono block break-all text-[11.5px] text-lime">$ {c.cmd}</code><div className="text-[11.5px] text-mute">{c.what}</div></div>
        <button onClick={() => copy(c.cmd)} aria-label={`Copy ${c.cmd}`} className="mt-0.5 text-dim hover:text-ink">{copied === c.cmd ? <Check size={13} className="text-lime" /> : <Copy size={13} />}</button>
      </li>))}</ul>
  );
}

function Ai() {
  const { status } = useApp();
  const ai = status.data?.ai;
  const cases = useLoad(() => get<Case[]>("/cases"), []);
  const [caseId, setCaseId] = useState<number | "">("");
  const [task, setTask] = useState("summarise");
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<AiResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (!ai) return <Loading />;
  if (!ai.configured) return (
    <div className="space-y-3">
      <Unavailable title="AI analyst not configured" action={<Link to="/settings#integrations" className="mono inline-flex h-8 items-center border border-lime bg-lime px-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-bg hover:bg-[#c8ff7d]">Set it up in Settings</Link>}>
        It needs a model you control (for example a free local Ollama model). Setup is a paste-and-click form — no file editing.
      </Unavailable>
      <p className="text-[12px] text-dim">Everything else in Fidx-Ghost works without it. When configured, the model only sees a bounded snapshot of the selected case and its output is always labelled as unverified.</p>
    </div>
  );
  const run = async () => {
    if (caseId === "") return;
    setBusy(true); setError(null); setRes(null);
    try { setRes(await post<AiResult>("/ai/analyse", { case_id: caseId, task, question })); } catch (e) { setError(errMsg(e)); } finally { setBusy(false); }
  };
  return (
    <div className="space-y-3">
      <div className="mono flex items-center gap-2 text-[11px] text-mute"><Badge tone="lime">configured</Badge> model <b className="text-ink">{ai.model}</b> · {ai.base_url}</div>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Case">{(id) => <Select id={id} value={caseId} onChange={(e) => setCaseId(e.target.value ? Number(e.target.value) : "")}><option value="">Select…</option>{(cases.data ?? []).map((c) => <option key={c.id} value={c.id}>{c.ref} — {c.name}</option>)}</Select>}</Field>
        <Field label="Task">{(id) => <Select id={id} value={task} onChange={(e) => setTask(e.target.value)}>{TASKS.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}</Select>}</Field>
      </div>
      <Field label="Question (optional)">{(id) => <Textarea id={id} value={question} onChange={(e) => setQuestion(e.target.value)} maxLength={500} className="!min-h-14" />}</Field>
      <Button variant="primary" busy={busy} disabled={caseId === ""} onClick={run} icon={<Bot size={14} />}>Run analysis</Button>
      {error && <ErrorNote message={error} />}
      {res && (
        <div className="border border-amber/40 bg-amber/[0.04]">
          <div className="flex flex-wrap items-center gap-2 border-b border-amber/30 px-3 py-2"><Badge tone="amber">{res.label}</Badge><span className="mono text-[10.5px] text-dim">{res.model} · {utc(res.generated_at)} · grounded on {res.grounding_refs.length} records</span></div>
          <div className="whitespace-pre-wrap px-3 py-3 text-[13px] leading-relaxed">{res.text}</div>
          <div className="border-t border-amber/30 px-3 py-2 text-[11.5px] text-amber">{res.notice}</div>
        </div>
      )}
    </div>
  );
}

export default function Toolkit() {
  const { status } = useApp();
  const s = status.data;
  return (
    <div className="mx-auto max-w-[1500px]">
      <PageHeader code="TOOLKIT" title="Tools, providers & CLI" sub="What is actually installed and configured on this machine, how to drive it from the terminal, and the optional AI analyst." />
      <div className="grid gap-3 xl:grid-cols-2">
        <div className="space-y-3">
          <Panel title="Installed tools" icon={<Wrench size={13} />} flush>
            {!s ? <Loading /> : <ul>{s.tools.map((t) => (
              <li key={t.id} className="border-b border-line px-3 py-2.5 last:border-0">
                <div className="flex items-center justify-between"><span className="text-[13px]">{t.name}</span><Badge tone={t.installed ? "lime" : "amber"}>{t.installed ? "available" : "not installed"}</Badge></div>
                <div className="text-[11.5px] text-mute">{t.role}</div>
                {t.installed ? <div className="mono mt-0.5 truncate text-[10.5px] text-dim">{t.version ?? t.path}</div> : <div className="mt-1 text-[11.5px] text-amber">{t.install_hint}</div>}
                {t.error && <div className="text-[11.5px] text-crit">{t.error}</div>}
              </li>))}</ul>}
          </Panel>
          <Panel title="Threat-intel providers" flush>
            {!s ? <Loading /> : <ul>{s.providers.map((p) => (
              <li key={p.id} className="border-b border-line px-3 py-2.5 last:border-0">
                <div className="flex items-center justify-between"><span className="text-[13px]">{p.name}</span><Badge tone={p.configured ? "lime" : "amber"}>{p.configured ? (p.needs_key ? "key configured" : "ready · no key") : "key needed"}</Badge></div>
                <div className="mono text-[10.5px] text-dim">{p.types.join(" · ")} · {p.env || "no key required"} · sends to {p.sends_to}</div>{!p.configured && <div className="mt-1 text-[11.5px] text-mute">{p.setup}</div>}
              </li>))}</ul>}
            <div className="border-t border-line px-3 py-2 text-[11px] text-dim">Configured means a key is present — it is verified only when a request is made. Keys never leave the backend.</div>
          </Panel>
        </div>
        <div className="space-y-3">
          <Panel title="ghost CLI" icon={<Terminal size={13} />} flush right={<Badge tone="mute">exit codes 0 ok · 1 err · 3 unavailable · 4 op failed</Badge>}><Cli /></Panel>
          <Panel title="AI analyst" icon={<Bot size={13} />} right={<Badge tone="mute">optional</Badge>}><Ai /></Panel>
        </div>
      </div>
      {!s && <Empty title="Status unavailable" />}
      {s && <dl className="sr-only"><Kv k="v">{s.version}</Kv></dl>}
    </div>
  );
}
