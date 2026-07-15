/* ============================================================
   RedSee — Security Operations Console (frontend)
   Talks to: /api/scans (spine), /scan/<id>/report (red PDF),
   /analyze-logs, /fetch-wazuh-alerts, /generate-blue-report.
   Vanilla JS, no dependencies.
   ============================================================ */

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

const SEV_ORDER = ["Critical", "High", "Medium", "Low"];
const SEV_ABBR = { Critical: "C", High: "H", Medium: "M", Low: "L" };

const state = {
  view: "red",
  scans: [],
  selectedId: null,
  blue: { events: [], analysisId: null },
};

/* ── utilities ─────────────────────────────────────────── */
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtClock(d) {
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}
function fmtTime(iso) {
  if (!iso) return "—";
  // Stored as "YYYY-MM-DDTHH:MM:SSZ" — show HH:MM:SS UTC, drop the date if today.
  const m = /T(\d{2}:\d{2}:\d{2})/.exec(iso);
  return m ? m[1] : iso;
}
async function api(path, opts) {
  const res = await fetch(path, opts);
  let body = {};
  try { body = await res.json(); } catch (_) { /* non-JSON */ }
  if (!res.ok) throw Object.assign(new Error(body.error || res.statusText), { status: res.status, body });
  return body;
}
function note(elId, msg, kind) {
  const n = $("#" + elId);
  n.textContent = msg || "";
  n.className = "form-note" + (kind ? " " + kind : "");
}

/* ── nav + clock ───────────────────────────────────────── */
function setView(view) {
  state.view = view;
  document.documentElement.dataset.view = view;
  $$(".nav-item").forEach((b) => {
    const on = b.dataset.nav === view;
    b.classList.toggle("is-active", on);
    b.setAttribute("aria-current", on ? "true" : "false");
  });
  $$(".view").forEach((v) => v.classList.toggle("is-active", v.dataset.viewPanel === view));
  const meta = view === "red"
    ? ["Red Ops", "Authorize a target, launch a scan, and read the unified result."]
    : ["Blue Ops", "Ingest SIEM telemetry, triage by severity, and export an incident report."];
  $("#viewTitle").textContent = meta[0];
  $("#viewSub").textContent = meta[1];
}
function startClock() {
  const tick = () => { $("#clock").textContent = fmtClock(new Date()); };
  tick();
  setInterval(tick, 1000);
}

/* ── severity helpers ──────────────────────────────────── */
function sevCounts(bySev) {
  const c = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  if (bySev) for (const k of SEV_ORDER) c[k] = bySev[k] || 0;
  return c;
}
function miniBar(bySev) {
  const c = sevCounts(bySev);
  const total = SEV_ORDER.reduce((a, k) => a + c[k], 0);
  if (!total) return `<span class="minibar-none">—</span>`;
  const seg = (k, cls) => c[k] ? `<i class="${cls}" style="height:${Math.min(14, 5 + c[k] * 2)}px" title="${k}: ${c[k]}"></i>` : "";
  return `<span class="minibar" title="${SEV_ORDER.map((k) => k + ": " + c[k]).join(", ")}">${
    seg("Critical", "b-crit")}${seg("High", "b-high")}${seg("Medium", "b-med")}${seg("Low", "b-low")}</span>`;
}
function statusPill(status) {
  return `<span class="status-pill st-${esc(status)}">${esc(status)}</span>`;
}
function modeChip(mode) {
  const m = (mode || "").toLowerCase();
  if (!["fast", "standard", "deep"].includes(m)) return `<span class="mode-pill mode-none">—</span>`;
  return `<span class="mode-pill mode-${m}">${esc(m)}</span>`;
}

/* ── RED: operations list ──────────────────────────────── */
async function refreshScans() {
  let data;
  try { data = await api("/api/scans?limit=100"); }
  catch (_) { return; }
  state.scans = data.scans || [];
  renderOps();
  updateStatusline();
  if (state.selectedId) {
    const row = state.scans.find((s) => s.scan_id === state.selectedId);
    // Keep the detail panel live while a scan runs.
    if (row && (row.status === "running" || row.status === "queued")) refreshDetail(state.selectedId, true);
  }
}
function renderOps() {
  const body = $("#opsBody");
  $("#opsCount").textContent = state.scans.length;
  if (!state.scans.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="6">No operations yet. Launch one to begin.</td></tr>`;
    return;
  }
  body.innerHTML = state.scans.map((s) => `
    <tr data-id="${esc(s.scan_id)}" class="${s.scan_id === state.selectedId ? "is-selected" : ""}">
      <td class="cell-id">${esc(s.scan_id)}</td>
      <td class="cell-target" title="${esc(s.target)}">${esc(s.target)}</td>
      <td>${modeChip(s.mode)}</td>
      <td>${statusPill(s.status)}</td>
      <td>${s.summary ? miniBar(s.summary.findings_by_severity) : `<span class="minibar-none">—</span>`}</td>
      <td class="cell-time">${fmtTime(s.started_at || s.created_at)}</td>
    </tr>`).join("");
  $$("#opsBody tr[data-id]").forEach((tr) =>
    tr.addEventListener("click", () => selectScan(tr.dataset.id)));
}

/* ── RED: operation detail ─────────────────────────────── */
function selectScan(id) {
  state.selectedId = id;
  renderOps();
  refreshDetail(id, false);
}
async function refreshDetail(id, quiet) {
  let row;
  try { row = await api("/api/scans/" + encodeURIComponent(id)); }
  catch (_) { return; }
  const panel = $("#detailPanel");
  panel.hidden = false;
  if (!quiet) panel.scrollIntoView({ behavior: "smooth", block: "nearest" });

  $("#detailId").textContent = row.scan_id;
  $("#detailStatus").className = "status-pill st-" + row.status;
  $("#detailStatus").textContent = row.status;
  $("#detailTarget").textContent = row.target;
  $("#detailMode").innerHTML = modeChip((row.scan && row.scan.mode) || row.mode ||
    (row.summary && row.summary.mode));
  $("#detailStarted").textContent = fmtTime(row.started_at);
  $("#detailFinished").textContent = fmtTime(row.finished_at);

  const rec = row.scan;              // full scan_<id>.json once done; null while pending
  const summary = (rec && rec.summary) || row.summary;
  $("#detailRecon").textContent = summary ? summary.recon_observations : "—";

  // Threat bar
  renderThreat(summary ? summary.findings_by_severity : null,
               summary ? summary.findings_total : 0);

  // Tools
  renderTools(rec ? rec.tools_run : null, row.status, row.error);

  // Findings + recon (only present once the record is on disk)
  renderFindings(rec ? rec.findings : null, row.status);
  renderRecon(rec ? rec.recon : null, row.status);

  // Report button — available once the scan is done, REGARDLESS of finding count.
  // A 0-finding scan still gets a real report ("no vulnerabilities confirmed" is a
  // legitimate deliverable, not an error) — only a scan that isn't done yet has
  // nothing to report on.
  const canReport = row.status === "done";
  const rbtn = $("#reportBtn");
  rbtn.hidden = !canReport;
  rbtn.onclick = canReport ? () => downloadRedReport(row.scan_id) : null;
  note("reportNote", "", "");
}
function renderThreat(bySev, total) {
  const c = sevCounts(bySev);
  const t = total || SEV_ORDER.reduce((a, k) => a + c[k], 0);
  $("#threatTotal").textContent = t;
  const bar = $("#threatBar");
  if (!t) {
    bar.innerHTML = `<div class="seg seg-empty"></div>`;
  } else {
    const seg = (k, cls) => c[k] ? `<div class="seg ${cls}" style="width:${(c[k] / t) * 100}%" title="${k}: ${c[k]}"></div>` : "";
    bar.innerHTML = seg("Critical", "seg-crit") + seg("High", "seg-high") + seg("Medium", "seg-med") + seg("Low", "seg-low");
  }
  $("#threatLegend").innerHTML = SEV_ORDER.map((k) => {
    const cls = { Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)", Low: "var(--low)" }[k];
    return `<span class="leg"><i style="background:${cls}"></i>${k} · ${c[k]}</span>`;
  }).join("");
}
function renderTools(tools, status, error) {
  const strip = $("#toolStrip");
  if (!tools || !tools.length) {
    const label = status === "error" ? (error || "scan errored before tools ran")
      : status === "done" ? "no tool data" : "waiting for the scan to run…";
    strip.innerHTML = `<span class="tool-chip"><span class="tdot"></span>${esc(label)}</span>`;
    return;
  }
  // "skipped"/"error" carry a WHY in .detail (e.g. "target appears unreachable —
  // crawl and httpx both got no live response..."). A hover-only tooltip is easy
  // to miss (and useless on touch), so show it as a visible sub-line for exactly
  // those two statuses — a "ran" tool's count already says enough on its own.
  strip.innerHTML = tools.map((t) => {
    const showReason = (t.status === "skipped" || t.status === "error") && t.detail;
    return `
    <span class="tool-chip t-${esc(t.status)}" title="${esc(t.detail || "")}">
      <span class="tdot"></span><b>${esc(t.name)}</b>
      <span class="tcount">${esc(t.status)}${t.count ? " · " + t.count : ""}</span>
      ${showReason ? `<span class="treason">${esc(t.detail)}</span>` : ""}
    </span>`;
  }).join("");
}
function renderFindings(findings, status) {
  const body = $("#findingsBody");
  const count = $("#findingsCount");
  if (findings == null) {
    count.textContent = "";
    body.innerHTML = `<tr class="no-rows"><td colspan="4">${
      status === "done" ? "None on disk." : "Available when the scan finishes."}</td></tr>`;
    return;
  }
  count.textContent = `(${findings.length})`;
  if (!findings.length) {
    body.innerHTML = `<tr class="no-rows"><td colspan="4">No confirmed findings — clean, or nothing in scope matched.</td></tr>`;
    return;
  }
  body.innerHTML = findings.map((f) => `
    <tr>
      <td class="cell-type">${esc(f.type)}</td>
      <td><span class="sev sev-${esc(f.severity)}">${esc(f.severity)}</span></td>
      <td class="cell-loc" title="${esc(f.url)} — ${esc(f.parameter)}">${esc(f.url)}${f.parameter ? " · " + esc(f.parameter) : ""}</td>
      <td class="cell-evidence" title="${esc(f.evidence)}">${esc(f.evidence)}</td>
    </tr>`).join("");
}
function renderRecon(recon, status) {
  const body = $("#reconBody");
  if (recon == null) {
    body.innerHTML = `<tr class="no-rows"><td colspan="4">${
      status === "done" ? "None." : "Available when the scan finishes."}</td></tr>`;
    return;
  }
  const rows = [];
  for (const c of (recon.nuclei || [])) {
    if (c.status !== "found") continue;
    rows.push({ tool: "nuclei", sev: capitalize(c.severity), cat: c.template_id || "template", detail: c.name || c.matched_at || c.evidence });
  }
  for (const o of (recon.observations || [])) {
    if (o.status !== "observed") continue;
    rows.push({ tool: o.tool, sev: o.severity, cat: o.category, detail: o.title });
  }
  if (!rows.length) {
    body.innerHTML = `<tr class="no-rows"><td colspan="4">No recon observations.</td></tr>`;
    return;
  }
  body.innerHTML = rows.map((r) => `
    <tr>
      <td class="cell-type">${esc(r.tool)}</td>
      <td>${r.sev ? `<span class="sev sev-${esc(r.sev)}">${esc(r.sev)}</span>` : `<span class="dim mono">—</span>`}</td>
      <td class="cell-loc">${esc(r.cat)}</td>
      <td class="cell-evidence" title="${esc(r.detail)}">${esc(r.detail)}</td>
    </tr>`).join("");
}
function capitalize(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : s; }

async function downloadRedReport(id) {
  const btn = $("#reportBtn");
  const prev = btn.textContent;
  btn.disabled = true; btn.textContent = "Building…";
  note("reportNote", "", "");
  try {
    const { report_url, format } = await api(`/scan/${encodeURIComponent(id)}/report`, { method: "POST" });
    window.open(report_url, "_blank");
    btn.textContent = "Red Report PDF";
    if (format && format !== "pdf") {
      note("reportNote", `Generated as ${format.toUpperCase()} (opened in a new tab — use your browser's Print to save as PDF).`, "info");
    }
  } catch (e) {
    btn.textContent = "Failed — retry";
    // Surface the SERVER's actual reason (e.g. "scan is still running", "no data
    // for this scan") — never leave the operator with just a dead-looking click.
    note("reportNote", e.message || "Report generation failed.", "err");
  } finally { btn.disabled = false; setTimeout(() => (btn.textContent = prev), 2500); }
}

/* ── RED: launch ───────────────────────────────────────── */
function initLaunch() {
  $("#scanForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const target = $("#targetUrl").value.trim();
    const authorized = $("#authorized").checked;
    const modeEl = document.querySelector('input[name="mode"]:checked');
    const mode = modeEl ? modeEl.value : "standard";
    if (!target) return note("launchNote", "Enter a target URL first.", "err");
    if (!authorized) return note("launchNote", "Confirm you are authorized to test this target.", "err");

    const btn = $("#launchBtn");
    btn.disabled = true; note("launchNote", "Queuing operation…", "info");
    try {
      const { scan_id } = await api("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: target, authorized, mode }),
      });
      note("launchNote", `Queued ${scan_id} (${mode}). Watch it in Operations →`, "ok");
      await refreshScans();
      selectScan(scan_id);
    } catch (err) {
      note("launchNote", err.status === 403 ? "Refused: " + err.message : (err.message || "Could not queue the scan."), "err");
    } finally { btn.disabled = false; }
  });
  $("#detailClose").addEventListener("click", () => {
    state.selectedId = null; $("#detailPanel").hidden = true; renderOps();
  });
}

/* ── BLUE: ingest + events ─────────────────────────────── */
function initBlue() {
  $("#uploadBtn").addEventListener("click", async () => {
    const file = $("#logFile").files[0];
    if (!file) return note("ingestNote", "Choose a log file to analyze.", "err");
    const btn = $("#uploadBtn"); btn.disabled = true;
    note("ingestNote", `Parsing ${file.name}…`, "info");
    const fd = new FormData(); fd.append("file", file);
    try {
      const data = await api("/analyze-logs", { method: "POST", body: fd });
      onEvents(data);
      note("ingestNote", `Normalized ${data.event_count} event${data.event_count === 1 ? "" : "s"} from ${file.name}.`, "ok");
    } catch (e) { note("ingestNote", e.message || "Could not parse that file.", "err"); }
    finally { btn.disabled = false; }
  });

  $("#alertsBtn").addEventListener("click", async () => {
    const lastN = parseInt($("#alertsLastN").value, 10) || 300;
    const btn = $("#alertsBtn"); btn.disabled = true;
    note("ingestNote", `Reading the last ${lastN} Wazuh alerts…`, "info");
    try {
      const data = await api("/analyze-logs", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ last_n: lastN }),
      });
      onEvents(data);
      note("ingestNote", `Normalized ${data.event_count} Wazuh alert${data.event_count === 1 ? "" : "s"} from alerts.json.`, "ok");
    } catch (e) { note("ingestNote", e.message || "Could not read alerts.json on the server.", "err"); }
    finally { btn.disabled = false; }
  });

  $("#wazuhBtn").addEventListener("click", async () => {
    const minutes = parseInt($("#wazuhMinutes").value, 10) || 30;
    const btn = $("#wazuhBtn"); btn.disabled = true;
    note("ingestNote", `Fetching Wazuh alerts from the last ${minutes} min…`, "info");
    try {
      const data = await api("/fetch-wazuh-alerts", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ minutes }),
      });
      onEvents(data);
      note("ingestNote", `Pulled ${data.event_count} alert${data.event_count === 1 ? "" : "s"} from Wazuh.`, "ok");
    } catch (e) { note("ingestNote", e.message || "Wazuh is unreachable right now.", "err"); }
    finally { btn.disabled = false; }
  });

  $("#blueReportBtn").addEventListener("click", async () => {
    if (!state.blue.events.length) return;
    const btn = $("#blueReportBtn"); const prev = btn.textContent;
    btn.disabled = true; btn.textContent = "Building…";
    try {
      const payload = state.blue.analysisId
        ? { analysis_id: state.blue.analysisId } : { events: state.blue.events };
      const { report_url } = await api("/generate-blue-report", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      window.open(report_url, "_blank"); btn.textContent = "Blue Report PDF";
    } catch (e) { btn.textContent = "Failed — retry"; }
    finally { btn.disabled = false; setTimeout(() => (btn.textContent = prev), 2500); }
  });
}
function onEvents(data) {
  state.blue.events = data.events || [];
  state.blue.analysisId = data.analysis_id || null;
  renderEvents();
  renderDist();
  $("#blueActions").hidden = state.blue.events.length === 0;
  updateStatusline();
}
function lvlClass(n) { return n >= 12 ? "Critical" : n >= 8 ? "High" : n >= 4 ? "Medium" : "Low"; }
// Web-attack alerts (Wazuh access-log rule 31xxx) — the class RedSee's own scans
// trigger; highlighted so scan-generated alerts stand out in the feed.
function isWebAttack(e) { return String(e.rule_id || "").startsWith("31"); }
function renderEvents() {
  const body = $("#eventsBody");
  const ev = state.blue.events;
  $("#eventCount").textContent = ev.length;
  if (!ev.length) {
    body.innerHTML = `<tr class="empty-row"><td colspan="6">Ingest a log file or fetch Wazuh alerts to populate the feed.</td></tr>`;
    return;
  }
  body.innerHTML = ev.map((e) => {
    const sev = lvlClass(e.severity_level || 0);
    const web = isWebAttack(e);
    const badge = web ? ` <span class="web-badge" title="web-attack alert (rule 31xxx) — matches RedSee scan traffic">WEB</span>` : "";
    return `<tr class="${web ? "web-attack" : ""}">
      <td><span class="lvl-pill sev-${sev}" title="severity level ${esc(e.severity_level)}">${esc(e.severity_level)}</span></td>
      <td class="cell-time">${fmtTime(e.timestamp)}</td>
      <td class="mono dim">${esc(e.rule_id)}${badge}</td>
      <td class="cell-evidence" title="${esc(e.description)}">${esc(e.description)}</td>
      <td class="mono">${esc(e.src_ip)}</td>
      <td class="cell-loc" title="${esc(e.target_url)}">${esc(e.target_url)}</td>
    </tr>`;
  }).join("");
}
function renderDist() {
  const buckets = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const e of state.blue.events) buckets[lvlClass(e.severity_level || 0)]++;
  const max = Math.max(1, ...Object.values(buckets));
  const box = $("#distBody");
  if (!state.blue.events.length) { box.innerHTML = `<p class="empty-note">No events ingested yet.</p>`; return; }
  const color = { Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)", Low: "var(--low)" };
  const webCount = state.blue.events.filter(isWebAttack).length;
  box.innerHTML = SEV_ORDER.map((k) => `
    <div class="dist-row">
      <span class="dist-k">${k}</span>
      <div class="dist-track"><div class="dist-fill" style="width:${(buckets[k] / max) * 100}%;background:${color[k]}"></div></div>
      <span class="dist-n">${buckets[k]}</span>
    </div>`).join("") +
    `<div class="dist-web"><span class="web-badge">WEB</span> ${webCount} web-attack alert${webCount === 1 ? "" : "s"} (rule 31xxx)</div>`;
}

/* ── Status line telemetry ─────────────────────────────── */
function updateStatusline() {
  const active = state.scans.filter((s) => s.status === "queued" || s.status === "running").length;
  let findings = 0; const sev = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const s of state.scans) {
    if (!s.summary) continue;
    findings += s.summary.findings_total || 0;
    const c = sevCounts(s.summary.findings_by_severity);
    for (const k of SEV_ORDER) sev[k] += c[k];
  }
  $("#slActive").textContent = `${active} active`;
  $("#slFindings").textContent = findings;
  $("#slCrit").textContent = "C " + sev.Critical;
  $("#slHigh").textContent = "H " + sev.High;
  $("#slMed").textContent = "M " + sev.Medium;
  $("#slLow").textContent = "L " + sev.Low;
  $("#slEvents").textContent = state.blue.events.length;
  $("#slTick").textContent = active ? "scanning" : "standby";
}

/* ── boot ──────────────────────────────────────────────── */
function init() {
  $$(".nav-item").forEach((b) => b.addEventListener("click", () => setView(b.dataset.nav)));
  startClock();
  initLaunch();
  initBlue();
  setView("red");
  refreshScans();
  setInterval(refreshScans, 3000);   // live queue + running-scan detail
}
document.addEventListener("DOMContentLoaded", init);
