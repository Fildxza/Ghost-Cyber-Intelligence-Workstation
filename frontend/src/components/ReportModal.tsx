import { useState } from "react";
import { Case, Report, get, post } from "../api";
import { errMsg, useLoad } from "../lib";
import { useApp } from "../state";
import { Button, Empty, ErrorNote, Field, Modal, Select } from "../ui";

export const openReport = (id: number) => window.open(`/api/reports/${id}/view`, "_blank", "noopener");

/** Pick a case, generate the HTML report on the backend, open it. */
export default function ReportModal({ open, onClose, defaultCase, onDone }: { open: boolean; onClose: () => void; defaultCase?: number; onDone?: (r: Report) => void }) {
  return open ? <Inner onClose={onClose} defaultCase={defaultCase} onDone={onDone} /> : null;
}

function Inner({ onClose, defaultCase, onDone }: { onClose: () => void; defaultCase?: number; onDone?: (r: Report) => void }) {
  const { notify } = useApp();
  const cases = useLoad(() => get<Case[]>("/cases"), []);
  const [caseId, setCaseId] = useState<number | "">(defaultCase ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const go = async () => {
    if (caseId === "") return;
    setBusy(true);
    setError(null);
    try {
      const r = await post<Report>(`/cases/${caseId}/report`);
      notify("ok", `Report ${r.ref} generated`);
      onDone?.(r);
      openReport(r.id);
      onClose();
    } catch (e) { setError(errMsg(e)); }
    finally { setBusy(false); }
  };

  const list = cases.data ?? [];
  return (
    <Modal open title="Generate case report" onClose={onClose}>
      <div className="space-y-3.5">
        {error && <ErrorNote message={error} />}
        {cases.error && <ErrorNote message={cases.error} onRetry={cases.reload} />}
        {!cases.loading && list.length === 0 ? (
          <Empty title="No cases to report on">Create a case first — reports are built from a case's stored findings, indicators and evidence.</Empty>
        ) : (
          <Field label="Case" hint="Report includes scope, methodology, findings, evidence, limitations and rule-derived recommendations.">
            {(id) => (
              <Select id={id} value={caseId} onChange={(e) => setCaseId(e.target.value ? Number(e.target.value) : "")}>
                <option value="">Select a case…</option>
                {list.map((c) => <option key={c.id} value={c.id}>{c.ref} — {c.name}</option>)}
              </Select>
            )}
          </Field>
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" busy={busy} disabled={caseId === ""} onClick={go}>Generate</Button>
        </div>
      </div>
    </Modal>
  );
}
