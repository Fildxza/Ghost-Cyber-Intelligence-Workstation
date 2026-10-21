import { DragEvent, FormEvent, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { FileUp, Network as NetIcon, Wrench } from "lucide-react";
import { Case, Operation, Tool, get, post, qs, upload } from "../api";
import { useApp } from "../state";
import { ago, errMsg, fmtBytes, fmtNum, useLoad, utc } from "../lib";
import { Badge, Bar, Button, Empty, ErrorNote, Field, Kv, PageHeader, Panel, Select, StatusBadge, Tabs, Unavailable, cx } from "../ui";
import OperationView from "../components/OperationView";

type Res = {
  file: { filename: string; size: number; sha256: string; format: string }; engine: string; warnings: string[]; tool_errors: string[]; note: string; tshark_available: boolean;
  analysis: {
    packets: number; ip_bytes: number; start: string | null; end: string | null; duration_seconds: number | null; undecoded_packets: number;
    protocols: { name: string; packets: number }[]; transport: { name: string; packets: number }[];
    conversations: { a: string; a_port: number; b: string; b_port: number; proto: string; service: string; packets: number; bytes: number; first: string | null; last: string | null }[]; conversation_count: number;
    tcp_endpoints: { ip: string; port: number; service: string; packets: number; bytes: number; syn_in: number }[];
    dns_queries: { name: string; type: string; count: number; answers: string[] }[]; dns_query_count: number;
    indicators: { domains: string[]; public_ips: string[] };
  };
};

function Results({ op }: { op: Operation }) {
  const { notify } = useApp();
  const [tab, setTab] = useState<"proto" | "conv" | "dns" | "tcp" | "ioc">("proto");
  const r = op.result as Res | null;
  if (!r) return null;
  const a = r.analysis;
  const maxProto = Math.max(1, ...a.protocols.map((p) => p.packets));
  const addIoc = async (value: string) => {
    try { const i = await post<{ ref: string; duplicate: boolean }>("/intel/indicators", { value, case_id: op.case_id }); notify(i.duplicate ? "info" : "ok", i.duplicate ? `${value} already tracked` : `Added ${i.ref}`); }
    catch (e) { notify("err", errMsg(e)); }
  };
  return (
    <div className="space-y-3">
      <dl className="border border-line px-3">
        <Kv k="File">{r.file.filename} · {fmtBytes(r.file.size)} · {r.file.format}</Kv>
        <Kv k="SHA-256"><span className="break-all">{r.file.sha256}</span></Kv>
        <Kv k="Engine">{r.engine}{r.engine === "builtin" && " (pure-Python parser)"}</Kv>
        <Kv k="Capture window">{a.start ? `${utc(a.start)} → ${utc(a.end)}${a.duration_seconds != null ? ` (${a.duration_seconds}s)` : ""}` : "no timestamps"}</Kv>
        <Kv k="Volume">{fmtNum(a.packets)} packets · {fmtBytes(a.ip_bytes)} IP bytes · {fmtNum(a.conversation_count)} conversations · {fmtNum(a.dns_query_count)} DNS queries</Kv>
      </dl>
      {r.warnings.map((w) => <Unavailable key={w} title="Analysis warning">{w}</Unavailable>)}
      {r.tool_errors.map((w) => <ErrorNote key={w} message={w} />)}
      <p className="text-[11.5px] text-dim">{r.note}</p>
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "proto", label: "Protocols" }, { id: "conv", label: "Conversations", count: a.conversations.length }, { id: "dns", label: "DNS", count: a.dns_queries.length }, { id: "tcp", label: "TCP endpoints", count: a.tcp_endpoints.length }, { id: "ioc", label: "Extracted indicators", count: a.indicators.domains.length + a.indicators.public_ips.length }]} />
      {tab === "proto" && (
        <div className="space-y-1.5">
          {a.protocols.map((p) => <div key={p.name} className="grid grid-cols-[110px_1fr_70px] items-center gap-3"><span className="mono text-[11px]">{p.name}</span><Bar value={p.packets} max={maxProto} /><span className="mono text-right text-[11px] text-mute">{fmtNum(p.packets)}</span></div>)}
          <div className="mono pt-2 text-[10.5px] text-dim">TRANSPORT: {a.transport.map((t) => `${t.name} ${fmtNum(t.packets)}`).join(" · ")}</div>
        </div>
      )}
      {tab === "conv" && (a.conversations.length ? <div className="max-h-96 overflow-auto"><table className="dt"><thead><tr><th>Endpoint A</th><th>Endpoint B</th><th>Proto</th><th>Svc</th><th>Pkts</th><th>Bytes</th></tr></thead><tbody>{a.conversations.slice(0, 100).map((c, i) => <tr key={i}><td className="mono text-[11px]">{c.a}{c.a_port ? `:${c.a_port}` : ""}</td><td className="mono text-[11px]">{c.b}{c.b_port ? `:${c.b_port}` : ""}</td><td className="mono text-[11px]">{c.proto}</td><td className="text-[11px] text-mute">{c.service}</td><td className="mono text-[11px]">{fmtNum(c.packets)}</td><td className="mono text-[11px]">{fmtBytes(c.bytes)}</td></tr>)}</tbody></table></div> : <Empty title="No conversations" />)}
      {tab === "dns" && (a.dns_queries.length ? <div className="max-h-96 overflow-auto"><table className="dt"><thead><tr><th>Query</th><th>Type</th><th>Count</th><th>Answers seen</th></tr></thead><tbody>{a.dns_queries.map((d, i) => <tr key={i}><td className="mono break-all text-[11.5px]">{d.name}</td><td className="mono text-[11px]">{d.type}</td><td className="mono text-[11px]">{d.count}</td><td className="mono text-[10.5px] text-mute">{d.answers.join(", ") || "—"}</td></tr>)}</tbody></table></div> : <Empty title="No DNS queries observed" />)}
      {tab === "tcp" && (a.tcp_endpoints.length ? <div className="max-h-96 overflow-auto"><table className="dt"><thead><tr><th>Endpoint</th><th>Service</th><th>Pkts in</th><th>Bytes in</th><th>SYNs</th></tr></thead><tbody>{a.tcp_endpoints.map((t, i) => <tr key={i}><td className="mono text-[11px]">{t.ip}:{t.port}</td><td className="text-[11px] text-mute">{t.service}</td><td className="mono text-[11px]">{fmtNum(t.packets)}</td><td className="mono text-[11px]">{fmtBytes(t.bytes)}</td><td className="mono text-[11px]">{t.syn_in}</td></tr>)}</tbody></table></div> : <Empty title="No TCP traffic" />)}
      {tab === "ioc" && (
        <div className="grid gap-3 md:grid-cols-2">
          {([["Domains from DNS queries", a.indicators.domains], ["Public IPs contacted", a.indicators.public_ips]] as const).map(([title, items]) => (
            <div key={title}><div className="label mb-1.5">{title} · {items.length}</div>
              {items.length ? <ul className="max-h-72 overflow-auto border border-line">{items.slice(0, 200).map((v) => <li key={v} className="flex items-center justify-between gap-2 border-b border-line px-2.5 py-1 last:border-0"><span className="mono break-all text-[11.5px]">{v}</span><Button small variant="quiet" onClick={() => addIoc(v)} aria-label={`Track ${v} as indicator`}>Track</Button></li>)}</ul> : <p className="text-[12px] text-dim">None.</p>}</div>))}
        </div>
      )}
      <p className="mono text-[10.5px] text-dim">Extraction lists what appeared in the capture. Presence is not evidence of malice.</p>
    </div>
  );
}

export default function Network() {
  const [sp, setSp] = useSearchParams();
  const { notify } = useApp();
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [drag, setDrag] = useState(false);
  const [caseId, setCaseId] = useState<number | "">(sp.get("case") ? Number(sp.get("case")) : "");
  const [engine, setEngine] = useState("auto");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const sel = sp.get("sel") ? Number(sp.get("sel")) : null;
  const cases = useLoad(() => get<Case[]>("/cases"), []);
  const tools = useLoad(() => get<Tool[]>("/network/tools"), []);
  const recent = useLoad(() => get<Operation[]>(`/operations${qs({ kind: "pcap_analysis", limit: 12 })}`), [], 6000);
  const cfgMax = useApp().config?.max_upload_mb ?? 200;
  const tshark = tools.data?.find((t) => t.id === "tshark");

  const onDrop = (e: DragEvent) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files?.[0]; if (f) setFile(f); };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setBusy(true); setError(null);
    const fd = new FormData();
    fd.append("file", file);
    if (caseId !== "") fd.append("case_id", String(caseId));
    fd.append("engine", engine);
    try { const op = await upload<Operation>("/network/analyze", fd); setSp({ sel: String(op.id) }); notify("info", `${op.ref} queued`); setFile(null); recent.reload(); }
    catch (ex) { setError(errMsg(ex)); }
    finally { setBusy(false); }
  };

  return (
    <div className="mx-auto max-w-[1600px]">
      <PageHeader code="NETWORK ANALYSIS" title="Packet capture analysis" sub="Analyse uploaded pcap / pcapng files. Missing tools are reported plainly — analysis never pretends to have succeeded." />
      <div className="grid gap-3 xl:grid-cols-[400px_minmax(0,1fr)]">
        <div className="space-y-3">
          <Panel title="Capture intake" icon={<FileUp size={13} />}>
            <form onSubmit={submit} className="space-y-3.5">
              {error && <ErrorNote message={error} />}
              <div onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={() => setDrag(false)} onDrop={onDrop}
                className={cx("bg-grid flex cursor-pointer flex-col items-center gap-2 border border-dashed px-4 py-7 text-center", drag ? "border-lime bg-lime/[0.05]" : "border-line2 hover:border-dim")}
                onClick={() => input.current?.click()} role="button" tabIndex={0} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()} aria-label="Choose capture file">
                <FileUp size={22} className="text-dim" />
                {file ? <><div className="mono text-[12px] text-lime">{file.name}</div><div className="mono text-[10.5px] text-dim">{fmtBytes(file.size)}</div></> : <><div className="label !text-ink">DROP .pcap / .pcapng</div><div className="text-[11.5px] text-dim">or click to browse · max {cfgMax} MB · never executed</div></>}
                <input ref={input} type="file" accept=".pcap,.pcapng,.cap" className="sr-only" onChange={(e) => setFile(e.target.files?.[0] ?? null)} tabIndex={-1} />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <Field label="Case">{(id) => <Select id={id} value={caseId} onChange={(e) => setCaseId(e.target.value ? Number(e.target.value) : "")}><option value="">None</option>{(cases.data ?? []).map((c) => <option key={c.id} value={c.id}>{c.ref}</option>)}</Select>}</Field>
                <Field label="Engine">{(id) => <Select id={id} value={engine} onChange={(e) => setEngine(e.target.value)}><option value="auto">AUTO</option><option value="builtin">BUILT-IN</option><option value="tshark" disabled={!tshark?.installed}>TSHARK{tshark?.installed ? "" : " (not installed)"}</option></Select>}</Field>
              </div>
              <Button type="submit" variant="primary" busy={busy} disabled={!file} className="w-full !h-9" icon={<NetIcon size={14} />}>Analyse capture</Button>
              <p className="text-[11px] leading-snug text-dim">The file is validated by magic bytes, size-capped, stored under a random name and hashed. Parsing is read-only; TShark (if used) runs without a shell and with a timeout.</p>
            </form>
          </Panel>
          <Panel title="Analysis tools" icon={<Wrench size={13} />}>
            {!tools.data ? null : <ul className="space-y-2">{tools.data.map((t) => (
              <li key={t.id} className="border border-line px-2.5 py-2"><div className="flex items-center justify-between"><span className="text-[12.5px]">{t.name}</span><Badge tone={t.installed ? "lime" : "amber"}>{t.installed ? "available" : "not installed"}</Badge></div>
                <div className="mono mt-0.5 truncate text-[10px] text-dim">{t.installed ? (t.version ?? t.path) : t.role}</div>{!t.installed && t.install_hint && <p className="mt-1 text-[11.5px] text-mute">{t.install_hint}</p>}</li>))}</ul>}
            {tshark && !tshark.installed && <div className="mt-3"><Unavailable title="TShark not detected">Analysis falls back to the built-in parser: packet counts, conversations, DNS and TCP summaries work; deep protocol dissection does not.</Unavailable></div>}
          </Panel>
          <Panel title="Recent analyses" flush>
            {!recent.data?.length ? <div className="p-3"><Empty title="None yet" /></div> : <ul>{recent.data.map((o) => <li key={o.id}><button onClick={() => setSp({ sel: String(o.id) })} className={cx("flex w-full items-center gap-3 border-b border-line px-3 py-2 text-left hover:bg-elev/50", sel === o.id && "bg-lime/[0.06]")}><StatusBadge status={o.status} /><span className="mono min-w-0 flex-1 truncate text-[12px]">{o.target}</span><span className="mono text-[10px] text-dim">{ago(o.finished_at ?? o.created_at)}</span></button></li>)}</ul>}
          </Panel>
        </div>
        <Panel title="Analysis results" right={sel && <a href={`/api/operations/${sel}/download`} className="label !text-lime hover:underline">DOWNLOAD JSON</a>}>
          {sel ? <OperationView key={sel} id={sel} extra={(o) => <Results op={o} />} onChange={recent.reload} /> : <Empty icon={<NetIcon size={24} />} title="No capture analysed">Upload a capture to get metadata, SHA-256, protocol distribution, conversations, DNS and TCP summaries and extractable indicators.</Empty>}
        </Panel>
      </div>
    </div>
  );
}
