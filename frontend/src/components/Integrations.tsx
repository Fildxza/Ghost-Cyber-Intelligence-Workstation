import { FormEvent, useState } from "react";
import { Bot, CheckCircle2, KeyRound, Loader2, Trash2, XCircle } from "lucide-react";
import { get, post, put } from "../api";
import { useApp } from "../state";
import { errMsg, useLoad } from "../lib";
import { Badge, Button, ErrorNote, Loading, Panel } from "../ui";

export interface IntegrationField { env: string; label: string; kind: "secret" | "url" | "text" | "path"; help: string; configured: boolean; hint?: string }
interface TestResult { ok: boolean; status: string; message: string }

/** Paste-a-key settings. Secrets are write-only: after saving, only "configured ••••1234" is ever shown again. */
export default function Integrations() {
  const { notify, fail, status } = useApp();
  const f = useLoad(() => get<IntegrationField[]>("/settings/integrations"), []);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, TestResult>>({});
  const fields = f.data ?? [];
  const by = (env: string) => fields.find((x) => x.env === env);
  const field = (env: string) => by(env);

  const save = async (envs: string[], group: string) => {
    const values: Record<string, string> = {};
    envs.forEach((e) => { if ((draft[e] ?? "").trim()) values[e] = draft[e].trim(); });
    if (!Object.keys(values).length) { notify("info", "Nothing to save — type or paste a value first."); return; }
    setBusy(`save:${group}`);
    try {
      await put("/settings/integrations", { values });
      setDraft((d) => { const n = { ...d }; envs.forEach((e) => delete n[e]); return n; });
      notify("ok", "Saved to the .env file on this computer — active immediately");
      f.reload(); status.reload();
    } catch (e) { fail(e); } finally { setBusy(null); }
  };
  const remove = async (envs: string[], group: string) => {
    setBusy(`rm:${group}`);
    try {
      await put("/settings/integrations", { values: Object.fromEntries(envs.map((e) => [e, null])) });
      setResults((r) => { const n = { ...r }; delete n[group]; return n; });
      notify("ok", "Removed"); f.reload(); status.reload();
    } catch (e) { fail(e); } finally { setBusy(null); }
  };
  const test = async (target: string) => {
    setBusy(`test:${target}`);
    try { setResults((r) => ({ ...r, [target]: undefined as unknown as TestResult })); const r = await post<TestResult>("/settings/integrations/test", { target }); setResults((x) => ({ ...x, [target]: r })); }
    catch (e) { setResults((x) => ({ ...x, [target]: { ok: false, status: "error", message: errMsg(e) } })); }
    finally { setBusy(null); }
  };

  const result = (id: string) => {
    const r = results[id];
    if (busy === `test:${id}`) return <span className="mono flex items-center gap-1.5 text-[11px] text-mute"><Loader2 size={12} className="animate-spin" /> TESTING…</span>;
    if (!r) return null;
    return <span role="status" className={`flex items-start gap-1.5 text-[12px] ${r.ok ? "text-lime" : "text-crit"}`}>{r.ok ? <CheckCircle2 size={14} className="mt-px shrink-0" /> : <XCircle size={14} className="mt-px shrink-0" />}{r.message}</span>;
  };

  const secretRow = (env: string, group: string, tested = true) => {
    const x = field(env);
    if (!x) return null;
    const submit = (e: FormEvent) => { e.preventDefault(); void save([env], group); };
    return (
      <form onSubmit={submit} className="border border-line px-3 py-2.5">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <label htmlFor={`int-${env}`} className="text-[13px]">{x.label}</label>
          <Badge tone={x.configured ? "lime" : "mute"}>{x.configured ? `saved ${x.hint}` : "not set"}</Badge>
        </div>
        <p className="mt-0.5 text-[11.5px] text-dim">{x.help}</p>
        <div className="mt-2 flex flex-wrap gap-2">
          <input id={`int-${env}`} type="password" autoComplete="off" spellCheck={false} value={draft[env] ?? ""} onChange={(e) => setDraft({ ...draft, [env]: e.target.value })}
            placeholder={x.configured ? "paste a new key to replace it" : "paste your key here"} className="mono h-8 min-w-56 flex-1 border border-line2 bg-bg2 px-2.5 text-[12px] focus:border-lime/70 focus:outline-none" />
          <Button type="submit" variant="primary" small busy={busy === `save:${group}`} icon={<KeyRound size={11} />}>Save</Button>
          {tested && <Button type="button" small disabled={!x.configured} onClick={() => test(group)}>Test</Button>}
          {x.configured && <Button type="button" small variant="danger" busy={busy === `rm:${group}`} onClick={() => remove([env], group)} icon={<Trash2 size={11} />} aria-label={`Remove ${x.label}`} />}
        </div>
        <div className="mt-2">{result(group)}</div>
      </form>
    );
  };

  const aiUrl = field("GHOST_AI_BASE_URL"), aiModel = field("GHOST_AI_MODEL");
  const aiEnvs = ["GHOST_AI_BASE_URL", "GHOST_AI_MODEL", "GHOST_AI_API_KEY"];

  return (
    <Panel title="Integrations" icon={<KeyRound size={13} />} className="lg:col-span-2" id="integrations"
      right={<span className="mono text-[10px] text-dim">SAVED TO .env ON THIS COMPUTER · WRITE-ONLY</span>}>
      {f.loading && !f.data ? <Loading /> : f.error ? <ErrorNote message={f.error} onRetry={f.reload} /> : (
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-3">
            <div><div className="label mb-1.5">Threat-intel reputation (optional)</div>
              <p className="mb-2 text-[12px] text-mute">Everything works without these. Add a key only if you want a malicious / benign <b>verdict</b> on indicators.</p>
              <div className="space-y-2"><div key="virustotal">{secretRow("VIRUSTOTAL_API_KEY", "virustotal")}</div><div key="abuseipdb">{secretRow("ABUSEIPDB_API_KEY", "abuseipdb")}</div><div key="ipinfo">{secretRow("IPINFO_TOKEN", "ipinfo")}</div></div>
            </div>
          </div>
          <div className="space-y-3">
            <div className="label flex items-center gap-1.5"><Bot size={12} /> AI analyst (optional)</div>
            <p className="text-[12px] text-mute">Runs on a model <b>you</b> control. No model yet? Install <b>Ollama</b> (ollama.com), run <code className="mono border border-line px-1">ollama pull llama3.1</code>, then press “Use local Ollama”.</p>
            <div className="space-y-2 border border-line px-3 py-2.5">
              {[aiUrl, aiModel].map((x) => x && (
                <div key={x.env}>
                  <div className="flex items-center justify-between"><label htmlFor={`int-${x.env}`} className="text-[12.5px]">{x.label}</label><Badge tone={x.configured ? "lime" : "mute"}>{x.configured ? "set" : "not set"}</Badge></div>
                  <input id={`int-${x.env}`} value={draft[x.env] ?? ""} onChange={(e) => setDraft({ ...draft, [x.env]: e.target.value })} placeholder={x.configured ? x.hint : x.help} spellCheck={false}
                    className="mono mt-1 h-8 w-full border border-line2 bg-bg2 px-2.5 text-[12px] focus:border-lime/70 focus:outline-none" />
                </div>))}
              <div>
                <div className="flex items-center justify-between"><label htmlFor="int-GHOST_AI_API_KEY" className="text-[12.5px]">API key <span className="text-dim">(hosted providers only)</span></label>
                  <Badge tone={field("GHOST_AI_API_KEY")?.configured ? "lime" : "mute"}>{field("GHOST_AI_API_KEY")?.configured ? `saved ${field("GHOST_AI_API_KEY")?.hint}` : "not needed for local"}</Badge></div>
                <input id="int-GHOST_AI_API_KEY" type="password" autoComplete="off" value={draft["GHOST_AI_API_KEY"] ?? ""} onChange={(e) => setDraft({ ...draft, GHOST_AI_API_KEY: e.target.value })}
                  className="mono mt-1 h-8 w-full border border-line2 bg-bg2 px-2.5 text-[12px] focus:border-lime/70 focus:outline-none" />
              </div>
              <div className="flex flex-wrap gap-2 pt-1">
                <Button small onClick={() => setDraft({ ...draft, GHOST_AI_BASE_URL: "http://localhost:11434/v1", GHOST_AI_MODEL: draft["GHOST_AI_MODEL"] || "llama3.1" })}>Use local Ollama</Button>
                <Button small variant="primary" busy={busy === "save:ai"} onClick={() => save(aiEnvs, "ai")}>Save</Button>
                <Button small disabled={!aiUrl?.configured || !aiModel?.configured} onClick={() => test("ai")}>Test</Button>
                {(aiUrl?.configured || aiModel?.configured) && <Button small variant="danger" busy={busy === "rm:ai"} onClick={() => remove(aiEnvs, "ai")} icon={<Trash2 size={11} />} aria-label="Remove AI settings" />}
              </div>
              {result("ai")}
            </div>
            <p className="text-[11px] text-dim">Each Test sends one tiny request to confirm the setting works. Keys are never shown again after saving.</p>
          </div>
        </div>
      )}
    </Panel>
  );
}
