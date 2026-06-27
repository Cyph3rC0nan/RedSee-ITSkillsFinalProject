/**
 * RedSee Pentest Dashboard — Frontend JavaScript
 *
 * Handles:
 *   - Tab switching (Red Team / Blue Team)
 *   - Scan lifecycle (start → poll → findings → report)
 *   - SIEM log upload + Wazuh alert fetch
 *   - Blue team event display + report generation
 *
 * All async operations use try/catch with showToast() error reporting.
 */

// ─── State ──────────────────────────────────────────────────
let currentScanId = null;
let currentAnalysisId = null;
let pollInterval = null;

// ─── Status Mappings ────────────────────────────────────────
const STATUS_PROGRESS = {
    "starting":      5,
    "crawling":     20,
    "testing_sqli": 40,
    "testing_xss":  55,
    "testing_idor": 70,
    "testing_auth": 85,
    "done":        100,
    "error":       100
};

const STATUS_LABELS = {
    "starting":      "Initializing scanner...",
    "crawling":      "🕷️ Crawling target...",
    "testing_sqli":  "💉 Testing SQL Injection...",
    "testing_xss":   "🔮 Testing XSS...",
    "testing_idor":  "🔑 Testing IDOR...",
    "testing_auth":  "🚪 Testing Broken Auth...",
    "done":          "✅ Scan Complete",
    "error":         "❌ Scan Error"
};

const SEVERITY_COLORS = {
    "Critical": { border: "#dc2626", bg: "#fef2f2", badgeBg: "#dc2626", badgeText: "#fff" },
    "High":     { border: "#ea580c", bg: "#fff7ed", badgeBg: "#ea580c", badgeText: "#fff" },
    "Medium":   { border: "#ca8a04", bg: "#fefce8", badgeBg: "#ca8a04", badgeText: "#fff" },
    "Low":      { border: "#16a34a", bg: "#f0fdf4", badgeBg: "#16a34a", badgeText: "#fff" }
};

// ─── DOMContentLoaded ───────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    // Set initial tab state — Red Team visible by default
    switchTab("red");
});

// ══════════════════════════════════════════════════════════════
//  Tab Switching
// ══════════════════════════════════════════════════════════════

function switchTab(tab) {
    const redContent  = document.getElementById("red-tab-content");
    const blueContent = document.getElementById("blue-tab-content");
    const tabBtns = document.querySelectorAll(".tab-btn");

    // Deactivate all tab buttons
    tabBtns.forEach(btn => btn.classList.remove("active"));

    // Hide all tab content
    if (redContent)  redContent.classList.add("hidden");
    if (blueContent) blueContent.classList.add("hidden");

    if (tab === "red") {
        const redBtn = document.querySelector('.tab-btn[data-tab="red"]');
        if (redBtn) redBtn.classList.add("active");
        if (redContent) redContent.classList.remove("hidden");
    } else if (tab === "blue") {
        const blueBtn = document.querySelector('.tab-btn[data-tab="blue"]');
        if (blueBtn) blueBtn.classList.add("active");
        if (blueContent) blueContent.classList.remove("hidden");
    }
}

// ══════════════════════════════════════════════════════════════
//  Red Team — Scan Lifecycle
// ══════════════════════════════════════════════════════════════

async function startScan() {
    const urlInput = document.getElementById("target-url");
    const scanBtn  = document.getElementById("start-scan-btn");

    if (!urlInput || !urlInput.value.trim()) {
        showToast("Please enter a target URL", "error");
        return;
    }

    const targetUrl = urlInput.value.trim();

    try {
        // Disable scan button during scan
        if (scanBtn) scanBtn.disabled = true;

        const response = await fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_url: targetUrl })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `Server error (${response.status})`);
        }

        const data = await response.json();
        currentScanId = data.scan_id;

        // Show progress panel, hide findings panel
        showPanel("progress-panel");
        hidePanel("findings-panel");

        // Hide red report download link if visible
        const redDownload = document.getElementById("red-download-link");
        if (redDownload) redDownload.classList.add("hidden");

        // Clear any existing poll interval
        if (pollInterval !== null) {
            clearInterval(pollInterval);
            pollInterval = null;
        }

        // Start polling every 2 seconds
        pollInterval = setInterval(pollScanStatus, 2000);
        // Also poll immediately for fast feedback
        pollScanStatus();

    } catch (error) {
        showToast(error.message || "Failed to start scan", "error");
        if (scanBtn) scanBtn.disabled = false;
    }
}

async function pollScanStatus() {
    if (!currentScanId) return;

    try {
        const response = await fetch(`/scan/${currentScanId}/status`);

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `Failed to fetch scan status (${response.status})`);
        }

        const data = await response.json();

        updateProgress(data.status, data.findings_count, data.current_module || "");

        if (data.status === "done") {
            stopPolling();
            await loadFindings();
            showToast("Scan completed successfully!", "success");
        } else if (data.status === "error") {
            stopPolling();
            showToast(data.error || "Scan encountered an error", "error");
        }

    } catch (error) {
        showToast(error.message || "Failed to poll scan status", "error");
        stopPolling();
    }
}

function stopPolling() {
    if (pollInterval !== null) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
    // Re-enable scan button
    const scanBtn = document.getElementById("start-scan-btn");
    if (scanBtn) scanBtn.disabled = false;
}

async function loadFindings() {
    if (!currentScanId) {
        showToast("No active scan", "error");
        return;
    }

    try {
        const response = await fetch(`/scan/${currentScanId}/findings`);

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `Failed to fetch findings (${response.status})`);
        }

        const data = await response.json();
        const findings = data.findings || [];

        renderFindings(findings);
        showPanel("findings-panel");

    } catch (error) {
        showToast(error.message || "Failed to load findings", "error");
    }
}

function renderFindings(findings) {
    const container = document.getElementById("findings-container");
    if (!container) return;

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="empty-findings">
                <p>No vulnerabilities found — target appears clean.</p>
            </div>`;
        return;
    }

    let html = "";
    for (const f of findings) {
        const colors = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS["Medium"];
        const evidence = f.evidence || "";
        const truncatedEvidence = evidence.length > 150
            ? evidence.substring(0, 147) + "..."
            : evidence;

        html += `
            <div class="finding-card" style="border-left: 4px solid ${colors.border}; background: ${colors.bg};">
                <div class="finding-header">
                    <span class="finding-type-badge" style="background: ${colors.badgeBg}; color: ${colors.badgeText};">
                        ${escapeHtml(f.type)}
                    </span>
                    <span class="finding-severity" style="color: ${colors.border}; font-weight: 600;">
                        ${escapeHtml(f.severity)}
                    </span>
                </div>
                <div class="finding-body">
                    <div class="finding-row">
                        <strong>URL:</strong>
                        <code>${escapeHtml(f.url)}</code>
                    </div>
                    <div class="finding-row">
                        <strong>Parameter:</strong>
                        <span>${escapeHtml(f.parameter || "—")}</span>
                    </div>
                    <div class="finding-row">
                        <strong>Payload:</strong>
                        <code>${escapeHtml(f.payload || "—")}</code>
                    </div>
                    <div class="finding-row">
                        <strong>Evidence:</strong>
                        <span class="evidence-text">${escapeHtml(truncatedEvidence)}</span>
                    </div>
                </div>
            </div>`;
    }

    container.innerHTML = html;
}

/**
 * Alias / compatibility wrapper — same as renderFindings but named
 * for callers that use updateScanResults(findings).
 */
function updateScanResults(findings) {
    renderFindings(findings);
}

async function generateRedReport() {
    if (!currentScanId) {
        showToast("No scan to report on — run a scan first", "error");
        return;
    }

    const btn = document.getElementById("generate-red-report-btn");
    const downloadLink = document.getElementById("red-download-link");

    try {
        // Show loading spinner
        if (btn) {
            btn.disabled = true;
            btn.dataset.originalText = btn.textContent;
            btn.innerHTML = '<span class="spinner"></span> Generating...';
        }

        const response = await fetch(`/scan/${currentScanId}/report`, {
            method: "POST"
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `Failed to generate report (${response.status})`);
        }

        const data = await response.json();

        if (downloadLink && data.report_url) {
            downloadLink.href = data.report_url;
            downloadLink.classList.remove("hidden");
            showToast("Red Team report generated!", "success");
        }

    } catch (error) {
        showToast(error.message || "Failed to generate red team report", "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            if (btn.dataset.originalText) {
                btn.textContent = btn.dataset.originalText;
                delete btn.dataset.originalText;
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════
//  Blue Team — File Upload & Drag-and-Drop
// ══════════════════════════════════════════════════════════════

function onFileSelected(input) {
    const filenameEl = document.getElementById("selected-filename");
    const analyzeBtn = document.getElementById("analyze-btn");

    if (input.files && input.files.length > 0) {
        const filename = input.files[0].name;
        if (filenameEl) filenameEl.textContent = filename;
        if (analyzeBtn) analyzeBtn.disabled = false;
    } else {
        if (filenameEl) filenameEl.textContent = "";
        if (analyzeBtn) analyzeBtn.disabled = true;
    }
}

function handleDragOver(event) {
    event.preventDefault();
    const dropZone = document.getElementById("drop-zone");
    if (dropZone) dropZone.classList.add("drag-active");
}

function handleDrop(event) {
    event.preventDefault();
    const dropZone = document.getElementById("drop-zone");
    if (dropZone) dropZone.classList.remove("drag-active");

    const fileInput = document.getElementById("log-file-input");
    if (!fileInput) return;

    const files = event.dataTransfer.files;
    if (files.length > 0) {
        // Create a new DataTransfer to set the file on the input
        const dt = new DataTransfer();
        dt.items.add(files[0]);
        fileInput.files = dt.files;

        // Update UI
        const filenameEl = document.getElementById("selected-filename");
        const analyzeBtn = document.getElementById("analyze-btn");
        if (filenameEl) filenameEl.textContent = files[0].name;
        if (analyzeBtn) analyzeBtn.disabled = false;
    }
}

// ══════════════════════════════════════════════════════════════
//  Blue Team — Fetch Wazuh Alerts & Analyze Logs
// ══════════════════════════════════════════════════════════════

async function fetchWazuhAlerts() {
    const timeframeSelect = document.getElementById("timeframe-select");
    const fetchBtn = document.getElementById("fetch-wazuh-btn");

    const minutes = timeframeSelect ? parseInt(timeframeSelect.value, 10) || 30 : 30;

    try {
        // Show loading
        showPanel("events-loading");
        hidePanel("events-panel");
        if (fetchBtn) fetchBtn.disabled = true;

        const response = await fetch("/fetch-wazuh-alerts", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ minutes })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `Failed to fetch alerts (${response.status})`);
        }

        const data = await response.json();

        if (data.analysis_id) {
            currentAnalysisId = data.analysis_id;
        }

        displayEvents(data.events || []);

    } catch (error) {
        showToast(error.message || "Failed to fetch Wazuh alerts", "error");
        hidePanel("events-loading");
    } finally {
        if (fetchBtn) fetchBtn.disabled = false;
    }
}

async function analyzeLogs() {
    const fileInput = document.getElementById("log-file-input");

    if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        showToast("Please select a log file first", "error");
        return;
    }

    const analyzeBtn = document.getElementById("analyze-btn");

    try {
        // Show loading
        showPanel("events-loading");
        hidePanel("events-panel");
        if (analyzeBtn) analyzeBtn.disabled = true;

        const formData = new FormData();
        formData.append("file", fileInput.files[0]);

        const response = await fetch("/analyze-logs", {
            method: "POST",
            body: formData
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `Failed to analyze logs (${response.status})`);
        }

        const data = await response.json();

        if (data.analysis_id) {
            currentAnalysisId = data.analysis_id;
        }

        displayEvents(data.events || []);

    } catch (error) {
        showToast(error.message || "Failed to analyze logs", "error");
        hidePanel("events-loading");
    } finally {
        if (analyzeBtn) analyzeBtn.disabled = false;
    }
}

// ══════════════════════════════════════════════════════════════
//  Blue Team — Display Events & Generate Report
// ══════════════════════════════════════════════════════════════

function displayEvents(events) {
    const tbody = document.getElementById("events-tbody");
    if (!tbody) return;

    if (!events || events.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="empty-events">
                    No events to display.
                </td>
            </tr>`;
    } else {
        let html = "";
        for (const ev of events) {
            const sourceBadgeColor = ev.source === "Wazuh" ? "#2563eb" : "#16a34a";
            const severityClass = ev.severity_level >= 12 ? "severity-high" : "";
            const timestamp = ev.timestamp
                ? new Date(ev.timestamp).toLocaleString()
                : "—";

            html += `
                <tr>
                    <td class="event-timestamp">${escapeHtml(timestamp)}</td>
                    <td>
                        <span class="source-badge" style="background: ${sourceBadgeColor};">
                            ${escapeHtml(ev.source || "—")}
                        </span>
                    </td>
                    <td><code>${escapeHtml(ev.rule_id || "—")}</code></td>
                    <td class="${severityClass}">${ev.severity_level ?? "—"}</td>
                    <td>${escapeHtml(ev.description || "—")}</td>
                    <td><code>${escapeHtml(ev.src_ip || "—")}</code></td>
                    <td><code class="target-url-cell">${escapeHtml(ev.target_url || "—")}</code></td>
                </tr>`;
        }
        tbody.innerHTML = html;
    }

    // Show events panel, hide loading
    showPanel("events-panel");
    hidePanel("events-loading");
}

async function generateBlueReport() {
    if (!currentAnalysisId) {
        showToast("No analysis to report on — fetch alerts or analyze logs first", "error");
        return;
    }

    const btn = document.getElementById("generate-blue-report-btn");
    const downloadLink = document.getElementById("blue-download-link");

    try {
        // Show loading spinner
        if (btn) {
            btn.disabled = true;
            btn.dataset.originalText = btn.textContent;
            btn.innerHTML = '<span class="spinner"></span> Generating...';
        }

        const response = await fetch("/generate-blue-report", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ analysis_id: currentAnalysisId })
        });

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error || `Failed to generate report (${response.status})`);
        }

        const data = await response.json();

        if (downloadLink && data.report_url) {
            downloadLink.href = data.report_url;
            downloadLink.classList.remove("hidden");
            showToast("Blue Team report generated!", "success");
        }

    } catch (error) {
        showToast(error.message || "Failed to generate blue team report", "error");
    } finally {
        if (btn) {
            btn.disabled = false;
            if (btn.dataset.originalText) {
                btn.textContent = btn.dataset.originalText;
                delete btn.dataset.originalText;
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════
//  UI Helpers
// ══════════════════════════════════════════════════════════════

function showToast(message, type) {
    const toast = document.getElementById("toast");
    if (!toast) return;

    type = type || "info";

    // Set background color based on type
    const bgColors = {
        info:    "#2563eb",
        success: "#16a34a",
        error:   "#dc2626"
    };
    const bgColor = bgColors[type] || bgColors.info;

    toast.textContent = message;
    toast.style.background = bgColor;
    toast.style.display = "block";
    toast.classList.remove("hidden");

    // Clear any existing auto-hide timer (clearTimeout no-ops on null/undefined)
    clearTimeout(toast._hideTimeout);

    // Auto-hide after 4 seconds
    toast._hideTimeout = setTimeout(() => {
        toast.style.display = "none";
        toast.classList.add("hidden");
    }, 4000);
}

function showPanel(id) {
    const panel = document.getElementById(id);
    if (panel) panel.classList.remove("hidden");
}

function hidePanel(id) {
    const panel = document.getElementById(id);
    if (panel) panel.classList.add("hidden");
}

function updateProgress(status, count, module) {
    const progressBar   = document.getElementById("progress-bar");
    const statusText    = document.getElementById("status-text");
    const currentModule = document.getElementById("current-module");
    const findingsCount = document.getElementById("findings-count");

    const pct = STATUS_PROGRESS[status] !== undefined ? STATUS_PROGRESS[status] : 0;
    const label = STATUS_LABELS[status] || status;

    if (progressBar) {
        progressBar.style.width = pct + "%";
        progressBar.setAttribute("aria-valuenow", String(pct));
    }
    if (statusText) statusText.textContent = label;
    if (currentModule && module) currentModule.textContent = module;
    if (findingsCount && count !== undefined && count !== null) {
        findingsCount.textContent = count;
    }
}

// ─── Utility ────────────────────────────────────────────────

function escapeHtml(str) {
    if (!str) return "";
    const div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
}
