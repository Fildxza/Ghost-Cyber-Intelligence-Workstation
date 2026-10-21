import { useState } from "react";
import { Link } from "react-router-dom";
import { FileText } from "lucide-react";
import { Report, get } from "../api";
import { fmtBytes, useLoad, utc } from "../lib";
import { Button, Empty, ErrorNote, Loading, PageHeader, Panel, Unavailable } from "../ui";
import ReportModal, { openReport } from "../components/ReportModal";

export default function Reports() {
  const [open, setOpen] = useState(false);
  const reps = useLoad(() => get<Report[]>("/reports"), []);
  return (
    <div className="mx-auto max-w-[1400px]">
      <PageHeader code="REPORTS" title="Case reports"
        sub="Self-contained HTML reports: scope, methodology, findings, indicators, evidence, limitations and rule-derived recommendations. Open a report and use your browser's Print → Save as PDF for a PDF copy."
        actions={<Button variant="primary" icon={<FileText size={14} />} onClick={() => setOpen(true)}>Generate report</Button>} />
      <div className="mb-3"><Unavailable title="Reports are not legal opinions">Reports summarise stored data and its provenance. Integrity hashes shown are not signatures, and nothing here asserts legal admissibility. Unreviewed findings are labelled UNREVIEWED; dismissed findings are omitted.</Unavailable></div>
      <Panel title="Generated reports" flush right={<span className="mono text-[10px] text-dim">{reps.data?.length ?? 0}</span>}>
        {reps.error && <div className="p-3"><ErrorNote message={reps.error} onRetry={reps.reload} /></div>}
        {reps.loading && !reps.data ? <Loading /> : !reps.data?.length ? (
          <div className="p-4"><Empty icon={<FileText size={22} />} title="No reports generated" action={<Button variant="primary" onClick={() => setOpen(true)}>Generate the first report</Button>}>Reports are built on the backend from a case's stored records.</Empty></div>
        ) : (
          <div className="overflow-x-auto"><table className="dt"><thead><tr><th>Ref</th><th>Case</th><th>Title</th><th>Generated (UTC)</th><th>SHA-256</th><th>Size</th><th /></tr></thead>
            <tbody>{reps.data.map((r) => (
              <tr key={r.id}><td className="mono text-[11px]">{r.ref}</td><td><Link to={`/cases/${r.case_id}`} className="mono text-[11px] text-mute hover:text-lime">{r.case_ref}</Link></td><td>{r.title}</td>
                <td className="mono whitespace-nowrap text-[11px] text-mute">{utc(r.created_at)}</td><td className="mono text-[10.5px] text-mute">{r.sha256.slice(0, 20)}…</td><td className="mono text-[11px]">{fmtBytes(r.size)}</td>
                <td className="whitespace-nowrap"><Button small onClick={() => openReport(r.id)}>Open</Button> <a href={`/api/reports/${r.id}/view?download=true`} className="mono ml-1 inline-flex h-7 items-center border border-line2 px-2 text-[10px] uppercase tracking-[0.1em] hover:text-lime">HTML</a></td></tr>))}</tbody></table></div>
        )}
      </Panel>
      <ReportModal open={open} onClose={() => setOpen(false)} onDone={() => reps.reload()} />
    </div>
  );
}
