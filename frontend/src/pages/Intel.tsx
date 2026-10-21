import { FormEvent, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Download, Link2, Plus, ShieldAlert, Zap } from "lucide-react";
import { Case, Indicator, Provider, get, post, qs } from "../api";
import { useApp } from "../state";
import { errMsg, useLoad, utc } from "../lib";
import { Badge, Button, Empty, ErrorNote, Field, Input, Kv, Loading, PageHeader, Panel, Select, Unavailable, cx, severityTone } from "../ui";
import OperationView from "../components/OperationView";

const TYPES = ["", "domain", "ip", "url", "hash"] as const;

export default function Intel() {
  const [sp, setSp] = useSearchParams();
  const { notify, status } = useApp();
  const sel = sp.get("sel") ? Number(sp.get("sel")) : null;
  const [value, setValue] = useState("");
  const [type, setType] = useState<(typeof TYPES)[number]>("");
  const [caseId, setCaseId] = useState<number | "">(sp.get("case") ? Number(sp.get("case")) : "");
  const [preview, setPreview] = useState<{ type: string; value: string; providers: string[] } | null>(null);
  const [previewErr, setPreviewErr] = useState<string | null>(null);
  const [busy, setBusy] = useState<"add" | "enrich" | null>(null);
  const [opId, setOpId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [ftype, setFtype] = useState("");
  const [minSev, setMinSev] = useState("");

  const cases = useLoad(() => get<Case[]>("/cases"), []);
  const providers = useLoad(() => get<Provider[]>("/intel/providers"), []);
  const list = useLoad(() => get<Indicator[]>(`/intel/indicators${qs({ q, type: ftype, min_severity: minSev, case_id: undefined })}`), [q, ftype, minSev]);
  const detail = useLoad(() => (sel ? get<Indicator>(`/intel/indicators/${sel}`) : Promise.resolve(null)), [sel]);

  // live validation / normalisation preview straight from the backend
  useEffect(() => {
    if (!value.trim()) { setPreview(null); setPreviewErr(null); return; }
    let stop = false;
    const t = window.setTimeout(async () => {
      try { const r = await post<{ type: string; value: string; providers: string[] }>("/intel/validate", { value, type: type || undefined }); if (!stop) { setPreview(r); setPreviewErr(null); } }
      catch (e) { if (!stop) { setPreview(null); setPreviewErr(errMsg(e)); } }
    }, 300);
    return () => { stop = true; window.clearTimeout(t); };
  }, [value, type]);

  const anyProvider = (providers.data ?? []).some((p) => p.configured);
  const reputation = (providers.data ?? []).some((p) => p.configured && p.reputation);

  const submit = async (e: FormEvent, enrich: boolean) => {
    e.preventDefault();
    setBusy(enrich ? "enrich" : "add");
    setError(null);
    try {
      const ind = await post<Indicator>("/intel/indicators", { value, type: type || undefined, case_id: caseId === "" ? null : caseId });
      notify(ind.duplicate ? "info" : "ok", ind.duplicate ? `Duplicate — ${ind.ref} already tracked${caseId ? "; linked to case" : ""}` : `Indicator ${ind.ref} added`);
      setSp({ sel: String(ind.id), ...(caseId ? { case: String(caseId) } : {}) });
      if (enrich) {
        const op = await post<{ id: number }>(`/intel/indicators/${ind.id}/enrich${qs({ case_id: caseId || undefined })}`);
        setOpId(op.id);
      }
      setValue("");
      list.reload();
      detail.reload();
    } catch (ex) { setError(errMsg(ex)); list.reload(); }
    finally { setBusy(null); }
  };

  const enrichSelected = async () => {
    if (!sel) return;
    setError(null);
    try { const op = await post<{ id: number }>(`/intel/indicators/${sel}/enrich`); setOpId(op.id); } catch (e) { setError(errMsg(e)); }
  };

  const d = detail.data;
  const rows = list.data ?? [];

  return (
    <div className="mx-auto max-w-[1700px]">
      <PageHeader code="THREAT INTELLIGENCE" title="Indicator workspace"
        sub="Validate and normalise indicators, de-duplicate them, enrich through configured providers, and keep the reasoning behind every severity rating. No provider is assumed — unconfigured sources are shown as unavailable."
        actions={<>
          <a href={`/api/intel/export?format=csv`} className="mono inline-flex h-8 items-center gap-1.5 border border-line2 bg-elev px-3 text-[11px] uppercase tracking-[0.1em] hover:border-lime/60 hover:text-lime"><Download size={13} /> CSV</a>
          <a href={`/api/intel/export?format=json`} className="mono inline-flex h-8 items-center gap-1.5 border border-line2 bg-elev px-3 text-[11px] uppercase tracking-[0.1em] hover:border-lime/60 hover:text-lime"><Download size={13} /> JSON</a>
        </>} />

      <div className="grid gap-3 xl:grid-cols-[340px_minmax(0,1.25fr)_minmax(0,0.9fr)]">
        <div className="space-y-3">
          <Panel title="Add indicator" icon={<Plus size={13} />}>
            <form onSubmit={(e) => submit(e, false)} className="space-y-3">
              {error && <ErrorNote message={error} />}
              <Field label="Indicator" hint="Domain, IP, URL or MD5/SHA-1/SHA-256. Defanged input (hxxp, [.]) is accepted.">
                {(id) => <Input id={id} value={value} onChange={(e) => setValue(e.target.value)} required className="mono" placeholder="evil[.]example / 203.0.113.9 / hash…" spellCheck={false} autoComplete="off" />}
              </Field>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Type">{(id) => <Select id={id} value={type} onChange={(e) => setType(e.target.value as typeof type)}>{TYPES.map((t) => <option key={t} value={t}>{t ? t.toUpperCase() : "AUTO-DETECT"}</option>)}</Select>}</Field>
                <Field label="Case">{(id) => <Select id={id} value={caseId} onChange={(e) => setCaseId(e.target.value ? Number(e.target.value) : "")}><option value="">None</option>{(cases.data ?? []).map((c) => <option key={c.id} value={c.id}>{c.ref}</option>)}</Select>}</Field>
              </div>
              {previewErr && value && <p className="text-[11.5px] text-crit" role="alert">{previewErr}</p>}
              {preview && (
                <div className="mono border border-line bg-bg2 px-2.5 py-2 text-[11px]">
                  <div className="text-dim">NORMALISED · {preview.type.toUpperCase()}</div>
                  <div className="break-all text-lime">{preview.value}</div>
                  <div className="mt-1 text-dim">{preview.providers.length ? `PROVIDERS: ${preview.providers.join(", ")}` : "NO PROVIDER CONFIGURED FOR THIS TYPE"}</div>
                </div>
              )}
              <div className="flex gap-2">
                <Button type="submit" busy={busy === "add"} disabled={!preview} className="flex-1" icon={<Plus size={13} />}>Add</Button>
                <Button type="button" variant="primary" busy={busy === "enrich"} disabled={!preview || !preview.providers.length || status.data?.field_mode} className="flex-1" icon={<Zap size={13} />} onClick={(e) => submit(e as unknown as FormEvent, true)}>Add &amp; enrich</Button>
              </div>
            </form>
          </Panel>
          <Panel title="Enrichment providers" icon={<ShieldAlert size={13} />}>
            {!providers.data ? <Loading /> : (
              <ul className="space-y-2">{providers.data.map((p) => (
                <li key={p.id} className="border border-line px-2.5 py-2">
                  <div className="flex items-center justify-between gap-2"><span className="text-[12.5px]">{p.name}</span>
                    <Badge tone={p.configured ? "lime" : "amber"}>{p.configured ? (p.needs_key ? "key configured" : "ready · no key") : "key needed"}</Badge></div>
                  <div className="mono mt-0.5 text-[10px] text-dim">{p.types.join(" · ")}{p.reputation ? " · reputation verdict" : " · context only"}</div>
                  <div className="mono text-[10px] text-dim">SENDS TO {p.sends_to}</div>
                  {!p.configured && <p className="mt-1 text-[11.5px] text-mute">{p.setup}{p.needs_key && <> · <Link to="/settings#integrations" className="text-lime hover:underline">add it in Settings</Link></>}</p>}
                </li>))}</ul>
            )}
            {providers.data && !reputation && <div className="mt-3"><Unavailable title="Reputation verdicts unavailable">Free sources give context (location, owner, exposure, known files, DNS posture) but no malicious/benign verdict. For severity ratings add a VirusTotal or AbuseIPDB key — keys stay on the backend and are never sent to the browser.</Unavailable></div>}
          </Panel>
        </div>

        <Panel title="Indicators" flush right={<span className="mono text-[10px] text-dim">{rows.length} SHOWN</span>}>
          <div className="flex flex-wrap gap-2 border-b border-line p-2.5">
            <Input aria-label="Search indicators" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search value or ref…" className="mono min-w-40 flex-1" />
            <Select aria-label="Filter type" value={ftype} onChange={(e) => setFtype(e.target.value)} className="!w-32"><option value="">ALL TYPES</option>{TYPES.slice(1).map((t) => <option key={t} value={t}>{t.toUpperCase()}</option>)}</Select>
            <Select aria-label="Minimum severity" value={minSev} onChange={(e) => setMinSev(e.target.value)} className="!w-40"><option value="">ANY SEVERITY</option>{["low", "medium", "high"].map((t) => <option key={t} value={t}>≥ {t.toUpperCase()}</option>)}</Select>
          </div>
          {list.error && <div className="p-3"><ErrorNote message={list.error} onRetry={list.reload} /></div>}
          {list.loading && !list.data ? <Loading /> : rows.length === 0 ? (
            <div className="p-3"><Empty icon={<ShieldAlert size={22} />} title={q || ftype || minSev ? "No indicators match" : "No indicators tracked"}>{q || ftype || minSev ? "Clear the filters to see all." : "Add one on the left. Duplicates are detected automatically."}</Empty></div>
          ) : (
            <div className="max-h-[640px] overflow-auto"><table className="dt"><thead><tr><th>Type</th><th>Value</th><th>Severity</th><th>Conf.</th><th>Cases</th></tr></thead>
              <tbody>{rows.map((i) => (
                <tr key={i.id} onClick={() => setSp({ sel: String(i.id) })} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && setSp({ sel: String(i.id) })} className={cx("cursor-pointer", sel === i.id && "sel")}>
                  <td><Badge>{i.type}</Badge></td><td className="mono max-w-60 break-all text-[12px]">{i.value}</td>
                  <td><Badge tone={severityTone(i.severity)}>{i.severity}</Badge></td><td className="mono text-[11px] text-mute">{i.confidence}</td><td className="mono text-[11px]">{i.case_count}</td>
                </tr>))}</tbody></table></div>
          )}
        </Panel>

        <Panel title="Indicator detail" right={d && <Button small variant="primary" icon={<Zap size={11} />} onClick={enrichSelected} disabled={!anyProvider || status.data?.field_mode}>Enrich</Button>}>
          {!sel ? <Empty title="Select an indicator">See provider responses, severity reasoning and case links.</Empty> : detail.loading && !d ? <Loading /> : detail.error ? <ErrorNote message={detail.error} /> : d && (
            <div className="space-y-3">
              <dl>
                <Kv k="Ref">{d.ref}</Kv><Kv k="Type">{d.type.toUpperCase()}</Kv><Kv k="Value"><span className="break-all">{d.value}</span></Kv>
                <Kv k="Severity"><Badge tone={severityTone(d.severity)}>{d.severity}</Badge></Kv><Kv k="Confidence">{d.confidence}</Kv>
                <Kv k="First seen">{utc(d.first_seen)}</Kv><Kv k="Last seen">{utc(d.last_seen)}</Kv>
                {d.geo_label && <Kv k="Geolocation">{d.geo_label} ({d.geo_lat?.toFixed(2)}, {d.geo_lon?.toFixed(2)}) · ipinfo</Kv>}
              </dl>
              <div>
                <div className="label mb-1.5">Reasoning</div>
                {d.reasoning.length ? <ul className="space-y-1 border-l-2 border-lime/40 pl-3 text-[12.5px]">{d.reasoning.map((r) => <li key={r}>{r}</li>)}</ul> : <p className="text-[12px] text-dim">Not enriched yet — severity is <b>unknown</b>, not “safe”.</p>}
              </div>
              <div>
                <div className="label mb-1.5 flex items-center gap-1.5"><Link2 size={11} /> Linked cases</div>
                {d.cases?.length ? <div className="flex flex-wrap gap-1">{d.cases.map((c) => <Badge key={c.id} tone="ink">{c.ref}</Badge>)}</div> : <p className="text-[12px] text-dim">Not linked to a case.</p>}
                <div className="mt-2 flex gap-2"><Select aria-label="Link to case" value="" onChange={async (e) => { if (!e.target.value) return; try { await post(`/intel/indicators/${d.id}/link`, { case_id: Number(e.target.value) }); notify("ok", "Linked to case"); detail.reload(); list.reload(); } catch (ex) { notify("err", errMsg(ex)); } }}><option value="">Link to case…</option>{(cases.data ?? []).map((c) => <option key={c.id} value={c.id}>{c.ref} — {c.name}</option>)}</Select></div>
              </div>
              {d.enrichments && d.enrichments.length > 0 && (
                <div>
                  <div className="label mb-1.5">Provider responses</div>
                  <ul className="space-y-2">{d.enrichments.slice(0, 8).map((en) => (
                    <li key={en.id} className="border border-line px-2.5 py-2">
                      <div className="flex items-center justify-between"><span className="text-[12.5px]">{en.provider}</span><Badge tone={en.status === "ok" ? "lime" : en.status === "not_found" ? "mute" : "amber"}>{en.status}{en.http_status ? ` · ${en.http_status}` : ""}</Badge></div>
                      <div className="mono text-[10px] text-dim">RETRIEVED {utc(en.retrieved_at)}</div>
                      {en.error && <div className="text-[11.5px] text-amber">{en.error}</div>}
                      {en.status === "ok" && <pre className="mono mt-1 max-h-32 overflow-auto text-[10.5px] text-mute">{JSON.stringify(en.data, null, 1)}</pre>}
                    </li>))}</ul>
                </div>
              )}
            </div>
          )}
          {opId && <div className="mt-4 border-t border-line pt-3"><div className="label mb-2">Latest enrichment run</div><OperationView key={opId} id={opId} onChange={() => { detail.reload(); list.reload(); }} /></div>}
        </Panel>
      </div>
    </div>
  );
}
