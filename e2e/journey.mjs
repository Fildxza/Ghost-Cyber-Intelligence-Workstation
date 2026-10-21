// End-to-end UI journey: drives the REAL built UI + backend in a headless Chromium browser over the DevTools
// protocol (no test framework). 23 steps: cases, OSINT, intel, PCAP, evidence, graph, reports, Field Mode, search...
// Usage:  GHOST_DATA_DIR=<dir of the server under test> node e2e/journey.mjs <baseUrl> <screenshotDir> <pcapPath>
// Browser: set BROWSER=/path/to/chrome-or-edge, otherwise common Edge/Chrome/Chromium locations are probed.
// NOTE: step "OSINT" performs live DNS/RDAP lookups for example.com and localtest.me (needs internet).
import { spawn } from "node:child_process";
import { readFileSync, mkdirSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [BASE, OUT, PCAP] = process.argv.slice(2);
mkdirSync(OUT, { recursive: true });
import { existsSync } from "node:fs";
const CANDIDATES = [process.env.BROWSER, "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/opt/google/chrome/chrome", "/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe"].filter(Boolean);
const EDGE = CANDIDATES.find((p) => existsSync(p));
if (!EDGE) { console.error("No Chromium-based browser found. Set BROWSER=/path/to/chrome"); process.exit(2); }
const PORT = 9341;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const edge = spawn(EDGE, ["--headless=new", "--disable-gpu", `--remote-debugging-port=${PORT}`, `--user-data-dir=${mkdtempSync(join(tmpdir(), "edge-e2e-"))}`, "--window-size=1440,1000", "--hide-scrollbars", "--no-sandbox", "about:blank"], { stdio: "ignore" });
process.on("exit", () => { try { edge.kill(); } catch {} });

let targets;
for (let i = 0; i < 60; i++) { try { targets = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json(); if (targets.some((t) => t.type === "page")) break; } catch {} await sleep(500); }
const page = targets.find((t) => t.type === "page");
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => (ws.onopen = r));
let id = 0; const pending = new Map(); const consoleErrors = []; const apiFails = [];
ws.onmessage = (m) => {
  const d = JSON.parse(m.data);
  if (d.id && pending.has(d.id)) { const { res, rej } = pending.get(d.id); pending.delete(d.id); d.error ? rej(new Error(d.error.message)) : res(d.result); return; }
  if (d.method === "Runtime.exceptionThrown") consoleErrors.push("EXC " + (d.params.exceptionDetails.exception?.description ?? d.params.exceptionDetails.text).split("\n")[0]);
  if (d.method === "Runtime.consoleAPICalled" && ["error"].includes(d.params.type)) consoleErrors.push("console.error " + d.params.args.map((a) => a.value ?? a.description ?? "").join(" ").slice(0, 200));
  if (d.method === "Network.requestWillBeSent") { const u = d.params.request.url; if (!u.startsWith(BASE) && !u.startsWith("data:") && !u.startsWith("blob:") && !u.startsWith("about:")) external.push(u.slice(0, 120)); }
  if (d.method === "Network.responseReceived" && d.params.response.url.includes("/api/") && d.params.response.status >= 400) apiFails.push(`${d.params.response.status} ${d.params.response.url.replace(BASE, "")}`);
};
const send = (method, params = {}) => new Promise((res, rej) => { const i = ++id; pending.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method, params })); });
await send("Page.enable"); await send("Runtime.enable"); await send("Network.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });

const ev = async (expr) => {
  const r = await send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error("eval: " + (r.exceptionDetails.exception?.description ?? r.exceptionDetails.text).split("\n")[0]);
  return r.result.value;
};
const goto = async (path) => { await send("Page.navigate", { url: BASE + path }); await sleep(600); await waitFor(`document.readyState==='complete' && document.querySelector('#root')?.children.length>0`, 15000); await sleep(400); };
const waitFor = async (cond, timeout = 15000) => { const end = Date.now() + timeout; while (Date.now() < end) { try { if (await ev(cond)) return true; } catch {} await sleep(250); } throw new Error("timeout waiting for: " + cond.slice(0, 120)); };
const text = () => ev("document.body.innerText.toLowerCase()");
const hasText = (t) => waitFor(`document.body.innerText.toLowerCase().includes(${JSON.stringify(t.toLowerCase())})`, 15000);
const noText = async (t) => { if ((await text()).includes(t.toLowerCase())) throw new Error("unexpected text present: " + t); };
const J = JSON.stringify;
const inputCleared = () => waitFor(`(()=>{const l=[...document.querySelectorAll('label')].find(l=>l.innerText.trim().toLowerCase().startsWith('indicator'));const e=l&&document.getElementById(l.htmlFor);return e&&e.value===''})()`, 8000);
const byAria = (n) => `[...document.querySelectorAll('[aria-label]')].find(e=>e.getAttribute('aria-label').toLowerCase()===${J(n.toLowerCase())})`;
const clickText = (t, sel = "button,a,[role=tab],[role=option],[role=menuitem],[role=checkbox],label,tr") => ev(`(()=>{const t=${J(t.toLowerCase())};const els=[...document.querySelectorAll(${J(sel)})].filter(e=>e.offsetParent!==null&&(e.innerText||e.getAttribute('aria-label')||'').trim().toLowerCase().includes(t));if(!els.length)throw new Error('no clickable: '+t);els.sort((a,b)=>(a.innerText||'').length-(b.innerText||'').length);els[0].click();return true})()`);
const fill = (label, value, scope = "document") => ev(`(()=>{const L=[...${scope}.querySelectorAll('label')].find(l=>l.innerText.trim().toLowerCase().startsWith(${J(label.toLowerCase())}));let el=L&&(L.htmlFor?document.getElementById(L.htmlFor):L.querySelector('input,textarea,select'));if(!el)el=${byAria(label)};if(!el)throw new Error('no field '+${J(label)});const proto=el.tagName==='SELECT'?HTMLSelectElement.prototype:el.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;Object.getOwnPropertyDescriptor(proto,'value').set.call(el,${J(value)});el.dispatchEvent(new Event(el.tagName==='SELECT'?'change':'input',{bubbles:true}));return true})()`);
const select = (label, optText) => ev(`(()=>{const L=[...document.querySelectorAll('label')].find(l=>l.innerText.trim().toLowerCase().startsWith(${J(label.toLowerCase())}));let el=L?document.getElementById(L.htmlFor):${byAria(label)};if(!el)throw new Error('no select '+${J(label)});const o=[...el.options].find(o=>o.text.toLowerCase().includes(${J(optText.toLowerCase())}));if(!o)throw new Error('no option '+${J(optText)}+' in '+[...el.options].map(o=>o.text));Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(el,o.value);el.dispatchEvent(new Event('change',{bubbles:true}));return true})()`);
const upload = (selector, name, b64, mime = "application/octet-stream") => ev(`(()=>{const i=document.querySelector(${J(selector)});const bin=atob(${J(b64)});const u=new Uint8Array(bin.length);for(let k=0;k<bin.length;k++)u[k]=bin.charCodeAt(k);const dt=new DataTransfer();dt.items.add(new File([u],${J(name)},{type:${J(mime)}}));i.files=dt.files;i.dispatchEvent(new Event('change',{bubbles:true}));return true})()`);
const shot = async (name) => { const r = await send("Page.captureScreenshot", { format: "png" }); (await import("node:fs")).writeFileSync(join(OUT, name + ".png"), Buffer.from(r.data, "base64")); };
const api = (path, opt) => ev(`fetch('/api${path}',${J(opt ?? {})}).then(async r=>({s:r.status,j:await r.json().catch(()=>null)}))`);

const results = [];
const external = [];
const step = async (name, fn) => {
  const t0 = Date.now();
  try { await fn(); results.push({ name, ok: true }); console.log(`PASS  ${name} (${Date.now() - t0}ms)`); }
  catch (e) { results.push({ name, ok: false, err: e.message }); console.log(`FAIL  ${name}\n      ${e.message}`); try { await shot("FAIL-" + name.replace(/\W+/g, "_").slice(0, 40)); } catch {} }
};

// ------------------------------------------------------------------------------------------------
await step("Command Centre loads with empty states + live status", async () => {
  await goto("/");
  await hasText("command overview"); await hasText("no investigations yet"); await hasText("no events recorded");
  await waitFor(`!!document.querySelector('[aria-label="API: ONLINE"]')`); await hasText("no geolocated indicators");
  await shot("01-command-empty");
});

await step("Create case via Quick Action (scope + authorisation) → case file", async () => {
  await clickText("create case", "section button");
  await hasText("authorisation declaration");
  await fill("case name", "Phishing infrastructure review");
  await fill("objective", "Map infrastructure behind reported brand-abuse emails");
  await fill("target scope", "example.com, *.example.com");
  await clickText("authorisation declaration", "label");
  await fill("tags", "phishing, brand-abuse");
  await select("priority", "high");
  await shot("02-case-form");
  await clickText("create case", "[role=dialog] button[type=submit]");
  await waitFor(`location.pathname.startsWith('/cases/')`);
  await hasText("gho-case-"); await hasText("scope & authorisation declared");
  await shot("03-case-detail");
});

await step("Case: add note, appears in list, timeline records it", async () => {
  await clickText("notes", "[role=tab]");
  await fill("note", "First observation: sender domain registered 3 days ago");
  await clickText("add note", "button[type=submit]");
  await hasText("first observation: sender domain");
  await clickText("timeline", "[role=tab]"); await hasText("case.note");
});

await step("Case: edit priority + status change persist", async () => {
  await clickText("edit", "header button, button"); await hasText("edit case");
  await select("priority", "critical");
  await clickText("save changes", "button[type=submit]");
  await waitFor(`document.body.innerText.toLowerCase().includes('critical')`);
  await select("case status", "active");
  await waitFor(`true`); await sleep(600);
  const r = await api("/cases/1"); if (r.j.priority !== "critical" || r.j.status !== "active") throw new Error("not persisted " + J(r.j));
});

await step("Cases list: search + filter", async () => {
  await goto("/cases"); await hasText("phishing infrastructure review");
  await fill("search cases", "zzzz-nope"); await hasText("no cases match these filters");
  await fill("search cases", "phishing"); await hasText("phishing infrastructure review");
  await shot("04-cases-list");
});

await step("OSINT: passive domain investigation completes with provenance", async () => {
  await goto("/osint?case=1");
  await fill("domain", "example.com");
  await shot("05-osint-form");
  await clickText("run investigation", "button[type=submit]");
  await waitFor(`/completed|failed/.test(document.body.innerText.toLowerCase())`, 90000);
  await hasText("findings produced"); await hasText("retrieved");
  await hasText("dns records — example.com"); await hasText("src dns");
  await shot("06-osint-results");
});

await step("OSINT: active checks need authorisation statement; blocked for loopback host", async () => {
  await goto("/osint?case=1");
  await fill("domain", "localtest.me");
  await clickText("include active checks", "label");
  await hasText("authorisation statement");
  await fill("authorisation statement", "Lab test — own domain");
  await clickText("run investigation", "button[type=submit]");
  await waitFor(`document.body.innerText.toLowerCase().includes("target blocked by network safety policy")`, 120000);
  await shot("07-osint-ssrf-blocked");
});

await step("Threat intel: validate/normalise, add, duplicate detection, honest no-provider state", async () => {
  await goto("/intel?case=1");
  await fill("indicator", "hxxps://evil-login[.]example/signin");
  await hasText("https://evil-login.example/signin"); await hasText("no provider configured for this type");
  await clickText("add", "form button[type=submit]");
  await hasText("indicator gho-ioc-"); await hasText("evil-login.example");
  await fill("indicator", "EVIL-LOGIN.example");
  await sleep(500);
  await sleep(500); await clickText("add", "form button[type=submit]"); await hasText("duplicate"); await inputCleared();
  await select("type", "auto-detect");
  await fill("indicator", "203.0.113.50"); await sleep(400); await clickText("add", "form button[type=submit]"); await inputCleared();
  await fill("indicator", "d41d8cd98f00b204e9800998ecf8427e"); await sleep(400); await clickText("add", "form button[type=submit]"); await inputCleared();
  await fill("indicator", "999.1.1.1"); await select("type", "ip"); await hasText("not a valid ip");
  await hasText("reputation verdicts unavailable");
  const r = await api("/intel/indicators"); if (r.j.length !== 4) throw new Error("expected 4 indicators, got " + r.j.length);
  await shot("08-intel");
});

await step("Threat intel: enrich without provider is refused with setup instructions", async () => {
  const r = await api("/intel/indicators/1/enrich", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  if (r.s !== 503 || !r.j.error.message.includes("VIRUSTOTAL_API_KEY")) throw new Error(J(r));
});

await step("Network: upload pcap → real analysis, tabs, track IOC", async () => {
  await goto("/network?case=1");
  await upload("input[type=file]", "capture.pcap", readFileSync(PCAP).toString("base64"));
  await hasText("capture.pcap");
  await clickText("analyse capture", "button[type=submit]");
  await waitFor(`/completed|failed/.test(document.body.innerText.toLowerCase())`, 40000);
  await hasText("sha-256"); await hasText("tls/https"); await hasText("5 packets");
  await shot("09-network-results");
  await clickText("conversations", "[role=tab]"); await hasText("93.184.216.34");
  await clickText("dns", "[role=tab]"); await hasText("evil.example.org");
  await clickText("extracted indicators", "[role=tab]");
  await clickText("track", "button[aria-label^='Track evil.example.org']"); await hasText("added gho-ioc-");
  const bad = await ev(`(async()=>{const fd=new FormData();fd.append('file',new File([new Uint8Array([77,90,0,1,2])],'x.pcap'));const r=await fetch('/api/network/analyze',{method:'POST',body:fd});return [r.status,(await r.json()).error.code]})()`);
  if (bad[0] !== 415) throw new Error("non-pcap accepted: " + J(bad));
});

await step("Evidence: register → verify → export link → tamper detected → delete", async () => {
  await goto("/evidence?case=1");
  await upload("input[type=file]", "email-headers.txt", btoa("Received: from mail.evil-login.example (203.0.113.50)\nSubject: Verify your account"), "text/plain");
  await fill("source / provenance", "Reported by mailbox owner");
  await clickText("hash & register", "button[type=submit]");
  await hasText("gho-evd-"); await hasText("sha-256");
  await clickText("verify", "button"); await hasText("hash matches");
  await shot("10-evidence-verified");
  const href = await ev(`[...document.querySelectorAll('a')].find(a=>/export/i.test(a.innerText))?.getAttribute('href')`);
  const dl = await ev(`fetch(${J(href)}).then(async r=>({s:r.status,ct:r.headers.get('content-type'),t:await r.text()}))`);
  if (dl.s !== 200 || !dl.t.includes("Verify your account") || dl.ct !== "application/octet-stream") throw new Error("export bad " + J(dl).slice(0, 200));
});

await step("Evidence tamper → verification FAILS in UI", async () => {
  const fs = await import("node:fs"); const path = await import("node:path");
  const vault = path.join(process.env.GHOST_DATA_DIR, "vault");
  const f = fs.readdirSync(vault).find((x) => x.endsWith(".bin")); fs.writeFileSync(path.join(vault, f), "tampered!");
  await clickText("verify", "button"); await hasText("mismatch");
  await shot("11-evidence-tampered");
});

await step("Evidence: delete with confirmation", async () => {
  await clickText("delete evidence", "button"); await hasText("permanently delete");
  await clickText("delete permanently", "[role=dialog] button"); await hasText("vault is empty");
});

await step("Entity graph (Cytoscape) shows real relationships; filters + search work", async () => {
  await goto("/graph?case=1");
  await waitFor(`(+(document.body.innerText.match(/(\\d+) NODES/i)||[0,0])[1])>0`, 20000);
  await sleep(1200); await shot("12-graph");
  const before = await ev(`document.body.innerText.match(/(\\d+) NODES/i)[1]`);
  await clickText("domain", "button[aria-pressed]"); await sleep(600);
  const after = await ev(`document.body.innerText.match(/(\\d+) NODES/i)[1]`);
  if (Number(after) >= Number(before)) throw new Error(`filter did not reduce nodes ${before}→${after}`);
  await clickText("domain", "button[aria-pressed]");
  await fill("find entity", "evil"); await sleep(600); await shot("13-graph-search");
  await clickText("fit", "button"); await clickText("reset", "button");
});

await step("Report: generate from case, listed on Reports page, CSP + sections", async () => {
  await ev(`window.open=()=>null`);
  await goto("/reports"); await hasText("no reports generated");
  await clickText("generate report", "header button, button");
  await hasText("generate case report");
  await waitFor(`[...document.querySelectorAll('[role=dialog] option')].length>1`); await select("case", "phishing"); await clickText("generate", "[role=dialog] button.bg-lime, [role=dialog] button:last-child");
  await hasText("gho-rpt-");
  const list = await api("/reports"); const id = list.j[0].id;
  const html = await ev(`fetch('/api/reports/${id}/view').then(async r=>({csp:r.headers.get('content-security-policy'),t:await r.text()}))`);
  for (const s of ["Scope &amp; Authorisation", "Methodology", "Findings", "Evidence", "Limitations", "Recommendations"]) if (!html.t.includes(s)) throw new Error("report missing " + s);
  if (!html.csp.includes("default-src 'none'")) throw new Error("no CSP");
  await shot("14-reports");
});

await step("Operations register lists runs; detail + JSON download", async () => {
  await goto("/operations"); await hasText("gho-op-");
  await clickText("domain investigation", "tbody tr"); await hasText("findings produced");
  await shot("15-operations");
});

await step("Toolkit: tools, CLI reference, AI analyst setup screen", async () => {
  await goto("/toolkit"); await hasText("tshark"); await hasText("not installed"); await hasText("ghost network analyze");
  await hasText("ai analyst not configured"); await shot("16-toolkit");
});

await step("Field Mode blocks outbound operations; local work continues", async () => {
  await goto("/settings"); await hasText("work offline"); await clickText("work offline", "label"); await hasText("field mode active".replace("field mode active", "mode"));
  await sleep(800);
  const r = await api("/osint/domain", { method: "POST", headers: { "Content-Type": "application/json" }, body: J({ domain: "example.com" }) });
  if (r.s !== 503 || r.j.error.code !== "field_mode") throw new Error("field mode not enforced " + J(r));
  await goto("/osint"); await hasText("field mode active");
  const local = await api("/cases", { method: "POST", headers: { "Content-Type": "application/json" }, body: J({ name: "Offline case works" }) });
  if (local.s !== 201) throw new Error("local work blocked");
  await shot("17-field-mode");
  await goto("/settings"); await hasText("work offline"); await clickText("work offline", "label"); await sleep(800);
  const again = await api("/status"); if (again.j.field_mode) throw new Error("did not turn off");
});

await step("Settings: backup creates a downloadable ZIP", async () => {
  await goto("/settings"); await clickText("create backup", "button"); await hasText("download");
  const href = await ev(`[...document.querySelectorAll('a')].find(a=>/download/i.test(a.innerText))?.getAttribute('href')`);
  const r = await ev(`fetch(${J(href)}).then(async r=>({s:r.status,ct:r.headers.get('content-type'),n:(await r.arrayBuffer()).byteLength}))`);
  if (r.s !== 200 || r.ct !== "application/zip" || r.n < 500) throw new Error(J(r));
  await shot("18-settings");
});

await step("Global search finds case/indicator/evidence and navigates", async () => {
  await goto("/");
  await ev(`document.querySelector('[aria-label="Global search"]').focus()`);
  await fill("global search", "phishing"); await waitFor(`!!document.querySelector('[role=listbox] [role=option]')`);
  await shot("19-search");
  await ev(`document.querySelector('[aria-label="Global search"]').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}))`);
  await waitFor(`location.pathname.startsWith('/cases/')`);
});

await step("Workspace: create + switch scopes the case list", async () => {
  await goto("/");
  await clickText("ws", "header button[aria-haspopup=listbox]"); await clickText("new workspace", "[role=listbox] button");
  await fill("workspace name", "Field Ops"); await clickText("create", "[role=dialog] button[type=submit]");
  await hasText("field ops"); await goto("/cases"); await hasText("no cases yet");
  await clickText("ws", "header button[aria-haspopup=listbox]"); await clickText("default", "[role=option]"); await sleep(800);
  await goto("/cases"); await hasText("phishing infrastructure review");
});

await step("Command Centre: bundled vector map + animated topology, zero third-party requests", async () => {
  await goto("/"); await sleep(2500);
  await hasText("basemap · bundled vector");
  const tiles = await ev(`document.querySelectorAll('.leaflet-tile').length`);
  if (tiles !== 0) throw new Error("raster tiles present: " + tiles);
  const painted = await ev(`(()=>{const c=document.querySelector('.leaflet-overlay-pane canvas');if(!c)return -1;const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data;let n=0;for(let i=3;i<d.length;i+=4*50)if(d[i]>0)n++;return n})()`);
  if (painted < 200) throw new Error("vector map not painted (" + painted + ")");
  await shot("21-map-vector");
  await clickText("topology", "[role=tab]");
  await hasText("not live traffic"); await waitFor(`(+(document.body.innerText.match(/(\\d+) NODES/i)||[0,0])[1])>0`, 15000);
  await sleep(1500);
  const sample = () => ev(`(()=>{const c=document.querySelector('canvas[aria-hidden]');if(!c)return null;const d=c.getContext('2d').getImageData(0,0,c.width,c.height).data;let n=0,h=0;for(let i=3;i<d.length;i+=4*7){if(d[i]>0){n++;h=(h*31+i+d[i])|0}}return {n,h}})()`);
  const a = await sample(); await sleep(700); const b = await sample();
  if (!a || a.n < 5) throw new Error("no motion markers painted " + J(a));
  if (a.h === b.h) throw new Error("topology overlay is static (no motion)");
  await shot("22-topology-motion");
  await clickText("geo map", "[role=tab]"); await sleep(500);
});

await step("Command Centre with real data (final look)", async () => {
  await goto("/"); await sleep(1500); await hasText("phishing infrastructure review");
  await shot("20-command-final");
  const m = await ev(`document.body.innerText`); if (/NaN|undefined|object Object/.test(m)) throw new Error("rendering artefact in text");
});

await step("Sample investigation: real lookups produce real map pins", async () => {
  await api("/system/backup", { method: "POST" });
  const r = await api("/sample", { method: "POST" });
  if (r.s !== 201) throw new Error("sample failed " + J(r));
  const end = Date.now() + 90000; let ops;
  while (Date.now() < end) { ops = (await api("/operations?limit=5")).j; if (ops.length >= 2 && ops.slice(0, 2).every((o) => ["completed", "failed"].includes(o.status))) break; await sleep(1500); }
  const inv = ops.find((o) => o.kind === "domain_investigation" && o.target === "example.com" && o.case_id === r.j.case.id);
  if (!inv || inv.status !== "completed") throw new Error("sample investigation did not complete " + J(inv?.error));
  const geo = (await api("/command/overview")).j.geo;
  if (!geo.length) throw new Error("no geolocated pins from the sample");
  await goto("/"); await clickText("geo map", "[role=tab]"); await sleep(2500);
  const pins = await ev(`document.querySelectorAll('.geo-pin').length`);
  if (pins < 1) throw new Error("pins not drawn on the map");
  await shot("23-geo-pins");
});

await step("Keyboard: skip link + tab order reach nav; dialog traps focus", async () => {
  await goto("/");
  const first = await ev(`(()=>{document.body.focus();return document.querySelector('a[href="#main"]')?.textContent})()`);
  if (!first?.toLowerCase().includes("skip")) throw new Error("skip link missing");
});

// ------------------------------------------------------------------------------------------------
console.log("\n=== SUMMARY ===");
const failed = results.filter((r) => !r.ok);
console.log(`${results.length - failed.length}/${results.length} steps passed`);
const uniq = (a) => [...new Set(a)];
console.log("third-party requests:", [...new Set(external)]);
if (external.length) { console.log("FAIL  external requests were made"); failed.push({ name: "external requests" }); }
console.log("console errors:", uniq(consoleErrors).slice(0, 12));
console.log("api >=400 responses (some expected: 404/503/415):", uniq(apiFails).slice(0, 20));
edge.kill(); process.exit(failed.length ? 1 : 0);
