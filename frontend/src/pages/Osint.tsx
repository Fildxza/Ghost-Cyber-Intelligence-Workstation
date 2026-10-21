import { FormEvent, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Globe, Search as SearchIcon } from "lucide-react";
import { Case, Operation, get, post, qs } from "../api";
import { useApp } from "../state";
import { ago, errMsg, useLoad } from "../lib";
import { Badge, Button, Check, Empty, ErrorNote, Field, Input, PageHeader, Panel, Select, StatusBadge, Unavailable, cx } from "../ui";
import OperationView from "../components/OperationView";

export default function Osint() {
  const [sp, setSp] = useSearchParams();
  const { status, notify } = useApp();
  const [domain, setDomain] = useState("");
  const [caseId, setCaseId] = useState<number | "">(sp.get("case") ? Number(sp.get("case")) : "");
  const [active, setActive] = useState(false);
  const [authNote, setAuthNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sel = sp.get("sel") ? Number(sp.get("sel")) : null;

  const cases = useLoad(() => get<Case[]>("/cases"), []);
  const recent = useLoad(() => get<Operation[]>(`/operations${qs({ kind: "domain_investigation", limit: 15 })}`), [], 5000);
  const chosen = (cases.data ?? []).find((c) => c.id === caseId);
  const authorised = !!chosen && chosen.authorisation_ack && !!chosen.scope.trim();
  const field = status.data?.field_mode;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const op = await post<Operation>("/osint/domain", { domain, case_id: caseId === "" ? null : caseId, active, authorisation_note: authNote });
      setSp({ sel: String(op.id), ...(caseId ? { case: String(caseId) } : {}) });
      notify("info", `${op.ref} queued`);
      recent.reload();
    } catch (ex) { setError(errMsg(ex)); }
    finally { setBusy(false); }
  };

  return (
    <div className="mx-auto max-w-[1600px]">
      <PageHeader code="OSINT" title="Domain investigation workspace"
        sub="Passive by default: DNS, registration (RDAP) and certificate-transparency data. Direct TLS and HTTP checks are active and need a case with declared scope and authorisation. Every result carries its source and retrieval time." />
      <div className="grid gap-3 xl:grid-cols-[400px_minmax(0,1fr)]">
        <div className="space-y-3">
          <Panel title="New investigation" icon={<SearchIcon size={13} />}>
            <form onSubmit={submit} className="space-y-3.5">
              {field && <Unavailable title="Field Mode active">Outbound lookups are disabled. Turn Field Mode off in System Settings to investigate.</Unavailable>}
              {error && <ErrorNote message={error} />}
              <Field label="Domain" hint="Bare domain only — no scheme, path or port.">{(id) => <Input id={id} value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" required autoComplete="off" spellCheck={false} className="mono" />}</Field>
              <Field label="Attach to case" hint="Findings, graph relationships and the audit trail are linked to the case.">
                {(id) => <Select id={id} value={caseId} onChange={(e) => { setCaseId(e.target.value ? Number(e.target.value) : ""); setActive(false); }}>
                  <option value="">No case (passive only)</option>
                  {(cases.data ?? []).map((c) => <option key={c.id} value={c.id}>{c.ref} — {c.name}</option>)}
                </Select>}
              </Field>
              <div className={cx("space-y-2 border p-3", active ? "border-amber/50 bg-amber/[0.04]" : "border-line bg-bg2")}>
                <Check checked={active} onChange={setActive} disabled={!authorised}>
                  <b>Include active checks</b> — direct TLS handshake and HTTPS request to the target.
                </Check>
                {!chosen && <p className="text-[11.5px] text-dim">Select a case to enable active checks.</p>}
                {chosen && !authorised && <p className="text-[11.5px] text-amber">Case {chosen.ref} has no declared scope and authorisation acknowledgement. Edit the case first.</p>}
                {chosen && authorised && !active && <p className="text-[11.5px] text-dim">Case scope: <span className="mono">{chosen.scope.slice(0, 80)}</span></p>}
                {active && (
                  <Field label="Authorisation statement" hint="Who authorised testing of this target? Stored in the audit trail.">
                    {(id) => <Input id={id} value={authNote} onChange={(e) => setAuthNote(e.target.value)} required maxLength={500} placeholder="e.g. Asset owner approval, ticket #1234" />}
                  </Field>
                )}
              </div>
              <Button type="submit" variant="primary" busy={busy} disabled={field || !domain.trim()} className="w-full !h-9" icon={<Globe size={14} />}>Run investigation</Button>
              <p className="text-[11px] leading-snug text-dim">Requests are made by the backend only. Destinations are resolved once, checked to be public addresses, pinned, and re-validated on every redirect. Private, loopback and link-local targets are refused.</p>
            </form>
          </Panel>
          <Panel title="Recent investigations" flush>
            {!recent.data?.length ? <div className="p-3"><Empty title="None yet" /></div> : (
              <ul>{recent.data.map((o) => (
                <li key={o.id}><button onClick={() => setSp({ sel: String(o.id) })} className={cx("flex w-full items-center gap-3 border-b border-line px-3 py-2 text-left hover:bg-elev/50", sel === o.id && "bg-lime/[0.06]")}>
                  <StatusBadge status={o.status} /><span className="mono min-w-0 flex-1 truncate text-[12px]">{o.target}</span>{o.authorised && <Badge tone="amber">active</Badge>}<span className="mono text-[10px] text-dim">{ago(o.finished_at ?? o.created_at)}</span>
                </button></li>))}</ul>)}
          </Panel>
        </div>
        <Panel title="Investigation results">
          {sel ? <OperationView key={sel} id={sel} onChange={recent.reload} /> : (
            <Empty icon={<Globe size={24} />} title="No investigation selected">Run an investigation or pick a recent one. Steps that fail or are unavailable are reported as such — nothing is filled in.</Empty>
          )}
        </Panel>
      </div>
    </div>
  );
}
