// Typed client for the Fidx-Ghost backend. All data shown in the UI comes through here.

export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public code: string,
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown, form?: FormData): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method,
      headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
      body: form ?? (body !== undefined ? JSON.stringify(body) : undefined),
    });
  } catch {
    throw new ApiError("Backend unreachable — is `ghost serve` running?", 0, "unreachable");
  }
  if (!res.ok) {
    let message = `HTTP ${res.status}`;
    let code = "error";
    try {
      const j = await res.json();
      if (j?.error) {
        message = j.error.message;
        code = j.error.code;
      } else if (j?.detail) {
        message = Array.isArray(j.detail) ? j.detail.map((d: { msg: string }) => d.msg).join("; ") : String(j.detail);
        code = "validation";
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(message, res.status, code);
  }
  return (await res.json()) as T;
}

export const get = <T,>(p: string) => request<T>("GET", p);
export const post = <T,>(p: string, b?: unknown) => request<T>("POST", p, b ?? {});
export const patch = <T,>(p: string, b: unknown) => request<T>("PATCH", p, b);
export const put = <T,>(p: string, b: unknown) => request<T>("PUT", p, b);
export const del = <T,>(p: string) => request<T>("DELETE", p);
export const upload = <T,>(p: string, form: FormData) => request<T>("POST", p, undefined, form);

export const qs = (o: Record<string, string | number | boolean | null | undefined>) => {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== "") u.set(k, String(v));
  const s = u.toString();
  return s ? `?${s}` : "";
};

// ---- types -----------------------------------------------------------------------

export interface Tool { id: string; name: string; installed: boolean; path: string | null; version: string | null; role: string; install_hint: string | null; error?: string }
export interface Provider { id: string; name: string; configured: boolean; env: string; types: string[]; setup: string }
export interface SystemStatus {
  version: string; session_id: string; server_time: string; started_at: string; analyst: string;
  api: { ok: boolean };
  database: { ok: boolean; engine: string; schema_version?: number; latency_ms?: number; error?: string; path?: string };
  worker: { ok: boolean; kind: string; workers: number; queued: number; running: number; completed: number; failed: number };
  tools: Tool[]; providers: Provider[];
  ai: { configured: boolean; base_url: string | null; model: string | null; setup: string };
  vault: { encryption: "enabled" | "disabled"; algorithm: string | null; note: string };
  field_mode: boolean;
  last_operation: { ref: string; kind: string; target: string; finished_at: string } | null;
  active_workspace_id: number | null;
}
export interface Workspace { id: number; name: string; created_at: string }
export type Priority = "low" | "medium" | "high" | "critical";
export type CaseStatus = "open" | "active" | "closed" | "archived";
export interface Case {
  id: number; ref: string; workspace_id: number; name: string; objective: string; scope: string; authorisation_ack: boolean;
  author: string; status: CaseStatus; priority: Priority; tags: string[]; created_at: string; updated_at: string;
  counts?: { operations: number; findings: number; evidence: number; indicators: number; notes: number };
}
export interface Note { id: number; body: string; author: string; created_at: string }
export interface AuditEvent { id: number; ts: string; actor: string; action: string; entity_type: string | null; entity_id: string | null; case_id: number | null; detail: Record<string, unknown> }
export type OpStatus = "draft" | "queued" | "running" | "completed" | "failed" | "cancelled";
export interface Operation {
  id: number; ref: string; case_id: number | null; kind: string; target: string; status: OpStatus; params: Record<string, unknown>;
  result: Record<string, any> | null; error: string | null; authorised: boolean; auth_note: string; created_at: string;
  started_at: string | null; finished_at: string | null; findings?: Finding[];
}
export interface Finding {
  id: number; ref: string; case_id: number | null; operation_id: number | null; kind: string; title: string; summary: string;
  data: Record<string, any>; source: string; source_url: string | null; retrieved_at: string; confidence: "low" | "medium" | "high";
  freshness: "live" | "stale" | "cached" | "simulated"; review_status: "pending" | "confirmed" | "dismissed"; created_at: string;
}
export interface Enrichment { id: number; provider: string; status: string; http_status: number | null; data: Record<string, any>; error: string | null; source_url: string | null; retrieved_at: string }
export interface Indicator {
  id: number; ref: string; type: "domain" | "ip" | "url" | "hash"; value: string; severity: string; confidence: string; reasoning: string[];
  geo_lat: number | null; geo_lon: number | null; geo_label: string | null; first_seen: string; last_seen: string;
  cases?: { id: number; ref: string; name: string }[]; enrichments?: Enrichment[]; case_count?: number; duplicate?: boolean;
}
export interface Evidence {
  id: number; ref: string; case_id: number | null; case_ref?: string | null; name: string; description: string; source: string; sha256: string; size: number;
  mime: string; encrypted: boolean; created_by: string; created_at: string; last_verified_at: string | null; last_verify_result: string | null;
  custody_log?: { ts: string; actor: string; action: string; detail: Record<string, unknown> }[];
}
export interface VerifyResult { ref: string; result: string; intact: boolean; recorded_sha256: string; recomputed_sha256: string | null; verified_at: string; disclaimer: string; error?: string }
export interface Report { id: number; ref: string; case_id: number; case_ref: string; title: string; format: string; filename: string; sha256: string; size: number; created_at: string; ai_sections: number }
export interface GraphNode { id: number; type: string; key: string; label: string; props: Record<string, unknown>; created_at: string }
export interface GraphEdge { id: number; src_id: number; dst_id: number; rel_type: string; source: string; evidence_ref: string | null; created_at: string }
export interface Overview {
  metrics: { open_cases: number; findings_pending_review: number; high_priority_indicators: number; recent_completed_analyses: number };
  totals: { cases: number; indicators: number; evidence: number; entities: number; operations: number };
  timeline: { date: string; findings: number; operations: number; indicators: number; evidence: number; cases: number }[];
  recent_cases: (Pick<Case, "id" | "ref" | "name" | "status" | "priority" | "updated_at"> & { last_operation_status: OpStatus | null; last_operation_kind: string | null; findings: number })[];
  events: AuditEvent[];
  geo: { id: number; ref: string; type: string; value: string; severity: string; confidence: string; lat: number; lon: number; label: string | null }[];
  recent_operations: Pick<Operation, "id" | "ref" | "kind" | "target" | "status" | "created_at" | "finished_at" | "error">[];
}
export interface AppConfig { map: { tile_url: string; attribution: string; dark: boolean }; version: string; max_upload_mb: number }
export interface AiResult { label: string; task: string; model: string; text: string; grounding_refs: string[]; generated_at: string; notice: string }
