import { render, screen, waitFor, within, fireEvent, cleanup } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppProvider } from "./state";
import App from "./App";
import CaseFormModal from "./components/CaseForm";
import { Modal } from "./ui";

vi.mock("./components/ForceGraph", () => ({ default: ({ nodes }: { nodes: unknown[] }) => <div data-testid="graph">graph:{nodes.length}</div> }));
vi.mock("./components/MapPanel", () => ({ default: ({ points }: { points: unknown[] }) => <div data-testid="map">map:{points.length}</div> }));

const status = {
  version: "0.1.0", session_id: "OPS-20261021-TEST", server_time: "2026-10-21T10:00:00.000000Z", started_at: "2026-10-21T09:00:00Z", analyst: "tester",
  api: { ok: true }, database: { ok: true, engine: "sqlite", schema_version: 1, latency_ms: 3.2, path: "x.db" },
  worker: { ok: true, kind: "in-process thread pool", workers: 2, queued: 0, running: 0, completed: 0, failed: 0 },
  tools: [{ id: "builtin-pcap", name: "Built-in PCAP parser", installed: true, path: "p", version: "v", role: "r", install_hint: null },
    { id: "tshark", name: "TShark", installed: false, path: null, version: null, role: "r", install_hint: "sudo apt install tshark" }],
  providers: [], ai: { configured: false, base_url: null, model: null, setup: "set env" },
  vault: { encryption: "disabled", algorithm: null, note: "Evidence is stored unencrypted." }, field_mode: false, last_operation: null, active_workspace_id: 1,
};
const emptyOverview = {
  metrics: { open_cases: 0, findings_pending_review: 0, high_priority_indicators: 0, recent_completed_analyses: 0 },
  totals: { cases: 0, indicators: 0, evidence: 0, entities: 0, operations: 0 },
  timeline: Array.from({ length: 14 }, (_, i) => ({ date: `2026-10-${String(i + 1).padStart(2, "0")}`, findings: 0, operations: 0, indicators: 0, evidence: 0, cases: 0 })),
  recent_cases: [], events: [], geo: [], recent_operations: [],
};

const json = (body: unknown, init: ResponseInit = {}) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" }, ...init });

function mockApi(routes: Record<string, (init?: RequestInit) => Response>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    const key = Object.keys(routes).find((k) => url.startsWith(k));
    return key ? routes[key](init) : json({ error: { code: "not_found", message: "no route " + url } }, { status: 404 });
  }));
  return calls;
}

const base = {
  "/api/status": () => json(status), "/api/workspaces": () => json([{ id: 1, name: "DEFAULT", created_at: "x" }]),
  "/api/config": () => json({ map: { tile_url: "x", attribution: "", dark: false }, version: "0.1.0", max_upload_mb: 200 }),
  "/api/command/overview": () => json(emptyOverview),
};

const renderApp = (path = "/") => render(<MemoryRouter initialEntries={[path]}><AppProvider><App /></AppProvider></MemoryRouter>);

beforeEach(() => { try { localStorage.clear(); } catch { /* jsdom */ } });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("Command Centre", () => {
  it("shows honest empty states and zero metrics when nothing is stored", async () => {
    mockApi(base);
    renderApp();
    expect(await screen.findByText("No investigations yet")).toBeInTheDocument();
    expect(screen.getByText("No events recorded")).toBeInTheDocument();
    expect(screen.getByText("No operations run")).toBeInTheDocument();
    expect(screen.getByText("NO EVENTS RECORDED IN THE LAST 14 DAYS")).toBeInTheDocument();
    expect(screen.getByTestId("map")).toHaveTextContent("map:0");
    expect(screen.getByText("NO SIMULATED DATA")).toBeInTheDocument();
  });

  it("derives status chips from the backend: API ONLINE, TOOLS 1/2, VAULT UNENCRYPTED", async () => {
    mockApi(base);
    renderApp();
    expect(await screen.findByRole("button", { name: "API: ONLINE" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "TOOLS: 1/2" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "VAULT: UNENCRYPTED" })).toBeInTheDocument();
    expect(screen.getAllByText(/OPS-20261021-TEST/).length).toBeGreaterThan(0);
  });

  it("NEVER shows a connected state when the backend is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network"); }));
    renderApp();
    expect(await screen.findByRole("button", { name: "API: UNREACHABLE" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "API: ONLINE" })).toBeNull();
    expect(screen.getAllByRole("alert").some((a) => /BACKEND UNREACHABLE/.test(a.textContent ?? ""))).toBe(true);
    expect(screen.getByText(/API UNREACHABLE/)).toBeInTheDocument();
  });

  it("every quick action is wired: Create Case opens the real form", async () => {
    mockApi(base);
    renderApp();
    const qa = (await screen.findByText("Quick actions")).closest("section")!;
    for (const label of ["Create Case", "Investigate Domain", "Analyse PCAP", "Enrich Indicator", "Generate Report"]) {
      expect(within(qa).getByRole("button", { name: new RegExp(label, "i") })).toBeEnabled();
    }
    fireEvent.click(within(qa).getByRole("button", { name: /create case/i }));
    expect(await screen.findByRole("dialog", { name: /create case/i })).toBeInTheDocument();
  });

  it("shows real operations and case rows when data exists", async () => {
    mockApi({
      ...base, "/api/command/overview": () => json({
        ...emptyOverview, metrics: { ...emptyOverview.metrics, open_cases: 2 },
        recent_cases: [{ id: 7, ref: "GHO-CASE-2026-0007", name: "Beacon review", status: "open", priority: "critical", updated_at: "2026-10-21T09:30:00Z", last_operation_status: "failed", last_operation_kind: "pcap_analysis", findings: 3 }],
        events: [{ id: 1, ts: "2026-10-21T09:30:00Z", actor: "tester", action: "case.create", entity_type: "case", entity_id: "GHO-CASE-2026-0007", case_id: 7, detail: {} }],
      }),
    });
    renderApp();
    expect(await screen.findByText("Beacon review")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.getByText("failed")).toBeInTheDocument();
    expect(screen.getByText("case.create")).toBeInTheDocument();
  });
});

describe("Topology view", () => {
  it("switches to the topology tab and shows an honest empty state when nothing is recorded", async () => {
    mockApi({ ...base, "/api/graph": () => json({ nodes: [], edges: [] }) });
    renderApp();
    fireEvent.click(await screen.findByRole("tab", { name: /topology/i }));
    expect(await screen.findByText("No topology recorded yet")).toBeInTheDocument();
    expect(screen.queryByTestId("map")).toBeNull();
    fireEvent.click(screen.getByRole("tab", { name: /geo map/i }));
    expect(await screen.findByTestId("map")).toBeInTheDocument();
  });

  it("renders real recorded entities with the not-live-traffic disclaimer", async () => {
    const nodes = [{ id: 1, type: "domain", key: "example.com", label: "example.com", props: {}, created_at: new Date().toISOString() },
      { id: 2, type: "ip", key: "93.184.216.34", label: "93.184.216.34", props: {}, created_at: "2026-01-01T00:00:00Z" }];
    mockApi({ ...base, "/api/graph": () => json({ nodes, edges: [{ id: 1, src_id: 1, dst_id: 2, rel_type: "resolves_to", source: "DNS", evidence_ref: null, created_at: "x" }] }) });
    renderApp();
    fireEvent.click(await screen.findByRole("tab", { name: /topology/i }));
    expect(await screen.findByTestId("graph")).toHaveTextContent("graph:2");
    expect(screen.getByText(/2 NODES · 1 LINKS/)).toBeInTheDocument();
    expect(screen.getByText(/1 RECORDED IN LAST 15 MIN/)).toBeInTheDocument();
    expect(screen.getByText(/NOT LIVE TRAFFIC/)).toBeInTheDocument();
  });
});

describe("Sample investigation", () => {
  it("offers a sample on the empty Command Centre and posts to /api/sample", async () => {
    let posted = false;
    mockApi({ ...base, "/api/sample": (init) => { posted = init?.method === "POST"; return json({ case: { id: 5, ref: "GHO-CASE-2026-0005" } }, { status: 201 }); }, "/api/cases/5": () => json({ error: { code: "not_found", message: "x" } }, { status: 404 }) });
    renderApp();
    fireEvent.click(await screen.findByRole("button", { name: /load sample investigation/i }));
    await waitFor(() => expect(posted).toBe(true));
  });
});

describe("Integrations (Settings)", () => {
  const rows = (vt: boolean) => [
    { env: "VIRUSTOTAL_API_KEY", label: "VirusTotal API key", kind: "secret", help: "Free key", configured: vt, ...(vt ? { hint: "••••7890" } : {}) },
    { env: "ABUSEIPDB_API_KEY", label: "AbuseIPDB API key", kind: "secret", help: "Free key", configured: false },
    { env: "IPINFO_TOKEN", label: "ipinfo.io token", kind: "secret", help: "Optional", configured: false },
    { env: "GHOST_AI_BASE_URL", label: "AI endpoint URL", kind: "url", help: "OpenAI-compatible", configured: false },
    { env: "GHOST_AI_MODEL", label: "AI model name", kind: "text", help: "e.g. llama3.1", configured: false },
    { env: "GHOST_AI_API_KEY", label: "AI API key", kind: "secret", help: "hosted only", configured: false },
  ];

  it("saves only what was typed, clears the field, and never shows the secret back", async () => {
    let sent: Record<string, unknown> | null = null;
    let saved = false;
    mockApi({
      ...base,
      "/api/settings/integrations": (init) => {
        if (init?.method === "PUT") { sent = JSON.parse(String(init.body)); saved = true; return json(rows(true)); }
        return json(rows(saved));
      },
    });
    renderApp("/settings");
    const input = (await screen.findByLabelText("VirusTotal API key")) as HTMLInputElement;
    expect(input.type).toBe("password");
    expect(screen.getAllByText("not set").length).toBeGreaterThan(0);
    fireEvent.change(input, { target: { value: "vt_ABCDEFGH1234567890" } });
    fireEvent.click(within(input.closest("form")!).getByRole("button", { name: /save/i }));
    await waitFor(() => expect(saved).toBe(true));
    expect(sent).toEqual({ values: { VIRUSTOTAL_API_KEY: "vt_ABCDEFGH1234567890" } });
    expect(await screen.findByText("saved ••••7890")).toBeInTheDocument();
    expect((screen.getByLabelText("VirusTotal API key") as HTMLInputElement).value).toBe("");
    expect(document.body.textContent).not.toContain("vt_ABCDEFGH1234567890");
  });

  it("shows the real test outcome: accepted vs rejected", async () => {
    let verdict = { ok: true, status: "ok", message: "Key accepted — the provider answered normally." };
    mockApi({ ...base, "/api/settings/integrations/test": () => json(verdict), "/api/settings/integrations": () => json(rows(true)) });
    renderApp("/settings");
    const form = (await screen.findByLabelText("VirusTotal API key")).closest("form")!;
    fireEvent.click(within(form).getByRole("button", { name: /^test$/i }));
    expect(await within(form).findByText(/Key accepted/)).toBeInTheDocument();
    verdict = { ok: false, status: "auth_error", message: "The provider REJECTED this key (HTTP 401/403). Check you copied the whole key." };
    fireEvent.click(within(form).getByRole("button", { name: /^test$/i }));
    expect(await within(form).findByText(/REJECTED this key/)).toBeInTheDocument();
  });

  it("surfaces a validation error from the backend instead of pretending it saved", async () => {
    mockApi({
      ...base,
      "/api/settings/integrations": (init) => init?.method === "PUT" ? json({ error: { code: "validation", message: "VirusTotal API key: expected 8-300 characters" } }, { status: 422 }) : json(rows(false)),
    });
    renderApp("/settings");
    const input = await screen.findByLabelText("VirusTotal API key");
    fireEvent.change(input, { target: { value: "short" } });
    fireEvent.click(within(input.closest("form")!).getByRole("button", { name: /save/i }));
    expect(await screen.findByText(/expected 8-300 characters/)).toBeInTheDocument();
  });

  it("'Use local Ollama' pre-fills the endpoint and model", async () => {
    mockApi({ ...base, "/api/settings/integrations": () => json(rows(false)) });
    renderApp("/settings");
    fireEvent.click(await screen.findByRole("button", { name: /use local ollama/i }));
    expect((screen.getByLabelText("AI endpoint URL") as HTMLInputElement).value).toBe("http://localhost:11434/v1");
    expect((screen.getByLabelText("AI model name") as HTMLInputElement).value).toBe("llama3.1");
  });
});

describe("Navigation shell", () => {
  it("contains all eleven required sections", async () => {
    mockApi(base);
    renderApp();
    const nav = await screen.findByRole("navigation", { name: "Primary" });
    for (const l of ["COMMAND", "OPERATIONS", "CASE FILES", "OSINT", "THREAT INTELLIGENCE", "NETWORK ANALYSIS", "ENTITY GRAPH", "EVIDENCE VAULT", "REPORTS", "TOOLKIT", "SYSTEM SETTINGS"]) {
      expect(within(nav).getByText(l)).toBeInTheDocument();
    }
  });
});

describe("Case form", () => {
  it("refuses to acknowledge authorisation without a declared scope and sends nothing", async () => {
    const calls = mockApi(base);
    render(<AppProvider><CaseFormModal open onClose={() => {}} /></AppProvider>);
    fireEvent.change(await screen.findByLabelText("Case name"), { target: { value: "Valid case name" } });
    fireEvent.click(screen.getByRole("checkbox"));
    expect(screen.getByRole("alert")).toHaveTextContent(/Scope is required/);
    fireEvent.click(screen.getByRole("button", { name: /create case/i }));
    await waitFor(() => expect(screen.getAllByRole("alert").length).toBeGreaterThan(0));
    expect(calls.some((c) => c.init?.method === "POST" && c.url === "/api/cases")).toBe(false);
  });

  it("posts the declared scope + authorisation to the backend", async () => {
    let body: Record<string, unknown> = {};
    mockApi({ ...base, "/api/cases": (init) => { body = JSON.parse(String(init?.body)); return json({ id: 1, ref: "GHO-CASE-2026-0001", name: "x" }, { status: 201 }); } });
    const saved = vi.fn();
    render(<AppProvider><CaseFormModal open onClose={() => {}} onSaved={saved} /></AppProvider>);
    fireEvent.change(await screen.findByLabelText("Case name"), { target: { value: "Valid case name" } });
    fireEvent.change(screen.getByLabelText("Target scope"), { target: { value: "example.com" } });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.change(screen.getByLabelText("Tags"), { target: { value: "a, b" } });
    fireEvent.click(screen.getByRole("button", { name: /create case/i }));
    await waitFor(() => expect(saved).toHaveBeenCalled());
    expect(body).toMatchObject({ name: "Valid case name", scope: "example.com", authorisation_ack: true, tags: ["a", "b"], priority: "medium" });
  });

  it("surfaces backend validation errors instead of swallowing them", async () => {
    mockApi({ ...base, "/api/cases": () => json({ error: { code: "validation", message: "Case name must be 3-120 characters" } }, { status: 422 }) });
    render(<AppProvider><CaseFormModal open onClose={() => {}} /></AppProvider>);
    fireEvent.change(await screen.findByLabelText("Case name"), { target: { value: "abc" } });
    fireEvent.click(screen.getByRole("button", { name: /create case/i }));
    expect(await screen.findByText("Case name must be 3-120 characters")).toBeInTheDocument();
  });
});

describe("Modal accessibility", () => {
  it("is a labelled dialog and closes on Escape", () => {
    const close = vi.fn();
    render(<Modal open title="Delete evidence" onClose={close}><button>ok</button></Modal>);
    expect(screen.getByRole("dialog", { name: "Delete evidence" })).toHaveAttribute("aria-modal", "true");
    fireEvent.keyDown(document, { key: "Escape" });
    expect(close).toHaveBeenCalled();
  });
});

describe("Threat intelligence page", () => {
  it("shows an honest unavailable state when no provider is configured", async () => {
    mockApi({
      ...base, "/api/cases": () => json([]), "/api/intel/providers": () => json([
        { id: "virustotal", name: "VirusTotal", configured: false, env: "VIRUSTOTAL_API_KEY", types: ["domain"], setup: "Create a free key and set VIRUSTOTAL_API_KEY", needs_key: true, reputation: true, sends_to: "virustotal.com" },
        { id: "ipwho", name: "ipwho.is", configured: true, env: "", types: ["ip"], setup: "No key needed.", needs_key: false, reputation: false, sends_to: "ipwho.is" }]),
      "/api/intel/indicators": () => json([]),
    });
    renderApp("/intel");
    expect(await screen.findByText(/Reputation verdicts unavailable/)).toBeInTheDocument();
    expect(screen.getByText("key needed")).toBeInTheDocument();
    expect(screen.getByText("ready · no key")).toBeInTheDocument();
    expect(screen.getByText("SENDS TO ipwho.is")).toBeInTheDocument();
    expect(screen.getByText(/Create a free key and set VIRUSTOTAL_API_KEY/)).toBeInTheDocument();
    expect(screen.getByText("No indicators tracked")).toBeInTheDocument();
  });
});
