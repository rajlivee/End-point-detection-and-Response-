/**
 * dashboard/static/js/dashboard.js
 * Main dashboard controller: SocketIO, alert feed, stats, filter, simulator.
 */

// ── State ─────────────────────────────────────────────────────────────────────
const state = {
  alerts:      [],
  activeFilter: "all",
  socket:       null,
};

// ── Toast ─────────────────────────────────────────────────────────────────────
function showToast(message, type = "success", duration = 4000) {
  const container = document.getElementById("toast-container");
  const icons = { success: "✅", error: "❌", info: "ℹ️" };

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span>${icons[type]}</span><span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.classList.add("toast-exit");
    toast.addEventListener("animationend", () => toast.remove());
  }, duration);
}

// ── Stats counter update ──────────────────────────────────────────────────────
function updateStats(counts) {
  const els = {
    total:    document.getElementById("stat-total"),
    critical: document.getElementById("stat-critical"),
    high:     document.getElementById("stat-high"),
    medium:   document.getElementById("stat-medium"),
    low:      document.getElementById("stat-low"),
  };
  if (els.total)    animateCounter(els.total,    counts.total    || 0);
  if (els.critical) animateCounter(els.critical, counts.CRITICAL || 0);
  if (els.high)     animateCounter(els.high,     counts.HIGH     || 0);
  if (els.medium)   animateCounter(els.medium,   counts.MEDIUM   || 0);
  if (els.low)      animateCounter(els.low,      counts.LOW      || 0);
}

function animateCounter(el, target) {
  const start = parseInt(el.textContent, 10) || 0;
  if (start === target) return;
  const step = target > start ? 1 : -1;
  const steps = Math.abs(target - start);
  const delay = Math.max(20, Math.min(60, 600 / steps));
  let current = start;
  const timer = setInterval(() => {
    current += step;
    el.textContent = current;
    if (current === target) clearInterval(timer);
  }, delay);
}

// ── Severity helpers ──────────────────────────────────────────────────────────
function sevBadgeClass(sev) {
  return {
    CRITICAL: "badge-critical",
    HIGH:     "badge-high",
    MEDIUM:   "badge-medium",
    LOW:      "badge-low",
  }[sev] || "badge-low";
}

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

// ── Alert Card Rendering ──────────────────────────────────────────────────────
function buildAlertCard(alert) {
  const sev     = (alert.severity || "LOW").toUpperCase();
  const type    = (alert.type || "").toLowerCase();
  const isSim   = alert.is_simulation;
  const score   = alert.score || 0;
  const fillPct = score + "%";

  const scoreColor = {
    CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#22c55e",
  }[sev] || "#22c55e";

  const card = document.createElement("div");
  card.className   = "alert-card";
  card.dataset.severity = sev;
  card.dataset.type     = type;
  card.dataset.sim      = isSim ? "1" : "0";

  card.innerHTML = `
    <div class="alert-top">
      <span class="alert-title">${escHtml(alert.title || "Alert")}</span>
      <span class="badge ${sevBadgeClass(sev)}">${sev}</span>
      ${isSim ? '<span class="badge badge-sim">SIM</span>' : ""}
      <span class="badge badge-type">${type.toUpperCase()}</span>
    </div>
    <div class="alert-desc">${escHtml(alert.description || "")}</div>
    <div class="score-bar">
      <div class="score-fill" style="width:${fillPct};background:${scoreColor}"></div>
    </div>
    <div class="alert-time">${fmtTime(alert.timestamp)} · Score: ${score}</div>
  `;

  // Map marker if network alert with geo
  if (type === "network" && alert.lat && alert.lng) {
    addMapMarker({
      ip:           alert.ip,
      lat:          alert.lat,
      lng:          alert.lng,
      country:      alert.country,
      process_name: alert.process,
      flagged:      true,
    });
  }

  return card;
}

function escHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// ── Alert Feed Management ─────────────────────────────────────────────────────
function prependAlert(alert) {
  state.alerts.unshift(alert);
  if (state.alerts.length > 500) state.alerts.pop();

  const feed = document.getElementById("alert-feed");
  if (!feed) return;

  const card = buildAlertCard(alert);
  if (feed.firstChild) {
    feed.insertBefore(card, feed.firstChild);
  } else {
    feed.appendChild(card);
  }

  applyFilter(state.activeFilter);

  // Keep feed from growing too large in DOM
  while (feed.children.length > 200) {
    feed.removeChild(feed.lastChild);
  }
}

function applyFilter(filter) {
  state.activeFilter = filter;
  const feed  = document.getElementById("alert-feed");
  if (!feed) return;

  const cards = feed.querySelectorAll(".alert-card");
  cards.forEach(card => {
    const sev  = card.dataset.severity?.toLowerCase();
    const type = card.dataset.type?.toLowerCase();
    const sim  = card.dataset.sim === "1";

    let show = false;
    switch (filter) {
      case "all":        show = true; break;
      case "critical":   show = sev === "critical"; break;
      case "high":       show = sev === "high"; break;
      case "medium":     show = sev === "medium"; break;
      case "low":        show = sev === "low"; break;
      case "file":       show = type === "file"; break;
      case "network":    show = type === "network"; break;
      case "process":    show = type === "process"; break;
      case "eventlog":   show = type === "eventlog"; break;
      case "simulation": show = sim; break;
      default:           show = true;
    }
    card.style.display = show ? "" : "none";
  });

  // Update active button
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.filter === filter);
  });
}

// ── Load initial alerts ───────────────────────────────────────────────────────
async function loadInitialAlerts() {
  try {
    const res    = await fetch("/api/alerts?limit=50");
    const alerts = await res.json();
    const feed   = document.getElementById("alert-feed");
    feed.innerHTML = "";
    if (alerts.length === 0) {
      feed.innerHTML = `
        <div class="empty-state">
          <div class="icon">🛡️</div>
          <div>No alerts yet — system is monitoring</div>
          <div style="font-size:0.7rem;color:#475569">Use the Attack Simulator to generate demo alerts</div>
        </div>`;
      return;
    }
    // Render newest first
    alerts.forEach(a => {
      const card = buildAlertCard(a);
      feed.appendChild(card);
    });
    state.alerts = alerts;
  } catch (err) {
    console.error("loadInitialAlerts:", err);
  }
}

// ── Load stats & charts ───────────────────────────────────────────────────────
async function loadStats() {
  try {
    const res  = await fetch("/api/stats");
    const data = await res.json();
    updateStats(data.counts || {});
    if (typeof updateTimelineChart === "function") updateTimelineChart(data.over_time || []);
    if (typeof updateDonutChart    === "function") updateDonutChart(data.by_type    || []);
    if (typeof updateBarChart      === "function") updateBarChart(data.top_procs   || []);
  } catch (err) {
    console.error("loadStats:", err);
  }
}

// ── Load process tree ─────────────────────────────────────────────────────────
async function loadProcessTree() {
  try {
    const res   = await fetch("/api/processes");
    const procs = await res.json();
    if (typeof renderProcessTree === "function") renderProcessTree(procs);
  } catch (err) {
    console.error("loadProcessTree:", err);
  }
}

// ── SocketIO ──────────────────────────────────────────────────────────────────
function initSocket() {
  const socket = io({ transports: ["websocket", "polling"] });
  state.socket  = socket;

  socket.on("connect", () => {
    console.log("SocketIO connected");
    document.getElementById("ws-status")?.classList.remove("hidden");
  });

  socket.on("disconnect", () => {
    console.warn("SocketIO disconnected");
  });

  socket.on("new_alert", alert => {
    prependAlert(alert);
    loadStats();   // refresh counters
    showToast(`🚨 ${alert.severity}: ${alert.title}`, "info", 5000);
  });

  socket.on("stats_update", counts => {
    updateStats(counts);
  });

  socket.on("simulation_cleared", () => {
    loadInitialAlerts();
    loadStats();
    showToast("Simulation data cleared.", "success");
  });
}

// ── Simulator Buttons ─────────────────────────────────────────────────────────
async function runSimulation(endpoint, label) {
  const btn = document.querySelector(`[data-sim="${endpoint}"]`);

  if (btn) {
    btn.disabled = true;
    const origHTML = btn.innerHTML;
    btn.innerHTML = `<span class="spinner"></span> Running…`;

    try {
      const res  = await fetch(`/api/simulate/${endpoint}`, { method: "POST" });
      const data = await res.json();
      if (data.status === "ok") {
        showToast(`${label} started! Watch the alert feed.`, "success");
      } else {
        showToast(`Error: ${data.message}`, "error");
      }
    } catch (err) {
      showToast(`Failed to run ${label}: ${err.message}`, "error");
    }

    setTimeout(() => {
      btn.disabled  = false;
      btn.innerHTML = origHTML;
    }, 3000);
  }
}

// ── Export helpers ────────────────────────────────────────────────────────────
function downloadCSV() {
  window.location.href = "/api/export/csv";
  showToast("Downloading CSV report…", "info");
}

function downloadPDF() {
  showToast("Generating PDF…", "info");
  setTimeout(() => { window.location.href = "/api/export/pdf"; }, 800);
}

// ── Filter buttons wiring ─────────────────────────────────────────────────────
function initFilters() {
  document.querySelectorAll(".filter-btn").forEach(btn => {
    btn.addEventListener("click", () => applyFilter(btn.dataset.filter));
  });
}

// ── Simulator buttons wiring ──────────────────────────────────────────────────
function initSimButtons() {
  const sims = [
    { endpoint: "ransomware",  label: "Ransomware Sim" },
    { endpoint: "process",     label: "Process Sim" },
    { endpoint: "network",     label: "Network Sim" },
    { endpoint: "bruteforce",  label: "Brute Force Sim" },
    { endpoint: "privilege",   label: "Privilege Escalation Sim" },
    { endpoint: "all",         label: "All Attacks" },
    { endpoint: "cleanup",     label: "Cleanup" },
  ];
  sims.forEach(({ endpoint, label }) => {
    const btn = document.querySelector(`[data-sim="${endpoint}"]`);
    if (btn) btn.addEventListener("click", () => runSimulation(endpoint, label));
  });
}

// ── Periodic refresh ──────────────────────────────────────────────────────────
function startPeriodicRefresh() {
  // Process tree every 15 s
  setInterval(loadProcessTree, 15_000);
  // Stats every 30 s (also triggered by SocketIO)
  setInterval(loadStats, 30_000);
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  initFilters();
  initSimButtons();
  initSocket();

  await loadInitialAlerts();
  await loadStats();
  await loadProcessTree();

  startPeriodicRefresh();

  // Export button handlers
  document.getElementById("btn-csv")?.addEventListener("click", downloadCSV);
  document.getElementById("btn-pdf")?.addEventListener("click", downloadPDF);
});
