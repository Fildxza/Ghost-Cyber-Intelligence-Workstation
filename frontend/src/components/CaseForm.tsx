import { FormEvent, useState } from "react";
import { Case, Priority, patch, post } from "../api";
import { useApp } from "../state";
import { errMsg } from "../lib";
import { Button, Check, ErrorNote, Field, Input, Modal, Select, Textarea } from "../ui";

/** Create (no `existing`) or edit a case. Scope + authorisation declaration live here. */
interface Props { open: boolean; onClose: () => void; existing?: Case; onSaved?: (c: Case) => void }

/** Remounts the form on every open so stale values never leak between uses. */
export default function CaseFormModal(props: Props) {
  return props.open ? <CaseFormInner {...props} /> : null;
}

function CaseFormInner({ open, onClose, existing, onSaved }: Props) {
  const { notify, workspace } = useApp();
  const [name, setName] = useState(existing?.name ?? "");
  const [objective, setObjective] = useState(existing?.objective ?? "");
  const [scope, setScope] = useState(existing?.scope ?? "");
  const [ack, setAck] = useState(existing?.authorisation_ack ?? false);
  const [priority, setPriority] = useState<Priority>(existing?.priority ?? "medium");
  const [tags, setTags] = useState((existing?.tags ?? []).join(", "));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const scopeMissing = ack && !scope.trim();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (scopeMissing) { setError("Declare the target scope before acknowledging authorisation."); return; }
    setBusy(true);
    setError(null);
    const body = { name, objective, scope, authorisation_ack: ack, priority, tags: tags.split(",").map((t) => t.trim()).filter(Boolean) };
    try {
      const saved = existing
        ? await patch<Case>(`/cases/${existing.id}`, body)
        : await post<Case>("/cases", { ...body, workspace_id: workspace?.id });
      notify("ok", existing ? `Case ${saved.ref} updated` : `Case ${saved.ref} created`);
      onSaved?.(saved);
      onClose();
    } catch (ex) { setError(errMsg(ex)); }
    finally { setBusy(false); }
  };

  return (
    <Modal open={open} title={existing ? `Edit case · ${existing.ref}` : "Create case"} onClose={onClose} wide>
      <form onSubmit={submit} className="space-y-3.5">
        {error && <ErrorNote message={error} />}
        <div className="grid gap-3.5 sm:grid-cols-[1fr_160px]">
          <Field label="Case name">{(id) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} required minLength={3} maxLength={120} placeholder="e.g. Phishing infrastructure review" />}</Field>
          <Field label="Priority">{(id) => <Select id={id} value={priority} onChange={(e) => setPriority(e.target.value as Priority)}>{["low", "medium", "high", "critical"].map((p) => <option key={p} value={p}>{p.toUpperCase()}</option>)}</Select>}</Field>
        </div>
        <Field label="Objective">{(id) => <Textarea id={id} value={objective} onChange={(e) => setObjective(e.target.value)} maxLength={4000} placeholder="What question is this investigation answering?" />}</Field>
        <Field label="Target scope" hint="Domains / assets you are investigating. Required before active checks (direct TLS / HTTP) are permitted.">
          {(id) => <Textarea id={id} value={scope} onChange={(e) => setScope(e.target.value)} maxLength={4000} placeholder="example.com, *.example.com" />}
        </Field>
        <div className="border border-line bg-bg2 p-3">
          <Check checked={ack} onChange={setAck}>
            <b>Authorisation declaration.</b> I confirm I am authorised to investigate the declared scope, and that any active network checks are lawful and within that authorisation.
          </Check>
          {scopeMissing && <p className="mt-1.5 text-[11.5px] text-crit" role="alert">Scope is required to acknowledge authorisation.</p>}
        </div>
        <Field label="Tags" hint="Comma-separated.">{(id) => <Input id={id} value={tags} onChange={(e) => setTags(e.target.value)} placeholder="phishing, brand-abuse" />}</Field>
        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" busy={busy}>{existing ? "Save changes" : "Create case"}</Button>
        </div>
      </form>
    </Modal>
  );
}
