import { render, screen, waitFor, within, fireEvent, cleanup } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppProvider } from "./state";
import App from "./App";
import CaseFormModal from "./components/CaseForm";
import { Modal } from "./ui";

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
      ...base, "/api/cases": () => json([]), "/api/intel/providers": () => json([{ id: "virustotal", name: "VirusTotal", configured: false, env: "VIRUSTOTAL_API_KEY", types: ["domain"], setup: "Create a free key and set VIRUSTOTAL_API_KEY" }]),
      "/api/intel/indicators": () => json([]),
    });
    renderApp("/intel");
    expect(await screen.findByText(/Enrichment unavailable/)).toBeInTheDocument();
    expect(screen.getAllByText("not configured").length).toBeGreaterThan(0);
    expect(screen.getByText(/Create a free key and set VIRUSTOTAL_API_KEY/)).toBeInTheDocument();
    expect(screen.getByText("No indicators tracked")).toBeInTheDocument();
  });
});
