/**
 * dashboard/static/js/charts.js
 * Chart.js graphs: timeline, donut (by type), bar (top processes)
 */

const CHART_DEFAULTS = {
  font: { family: "'Inter', sans-serif" },
  color: "#94a3b8",
};
Chart.defaults.font.family = CHART_DEFAULTS.font.family;
Chart.defaults.color       = CHART_DEFAULTS.color;

// Colour palette
const PALETTE = {
  blue:   "#3b82f6",
  cyan:   "#06b6d4",
  purple: "#8b5cf6",
  green:  "#10b981",
  orange: "#f97316",
  red:    "#ef4444",
  yellow: "#eab308",
};

const TYPE_COLORS = {
  file:     PALETTE.orange,
  process:  PALETTE.red,
  network:  PALETTE.blue,
  eventlog: PALETTE.purple,
};

// ── Timeline (line chart) ────────────────────────────────────────────────────

let timelineChart = null;

function initTimelineChart() {
  const ctx = document.getElementById("chart-timeline");
  if (!ctx) return;

  timelineChart = new Chart(ctx, {
    type: "line",
    data: {
      labels:   [],
      datasets: [{
        label:           "Alerts",
        data:            [],
        borderColor:     PALETTE.blue,
        backgroundColor: "rgba(59,130,246,0.12)",
        borderWidth:     2,
        fill:            true,
        tension:         0.4,
        pointRadius:     3,
        pointHoverRadius: 6,
        pointBackgroundColor: PALETTE.blue,
      }],
    },
    options: {
      responsive:         true,
      maintainAspectRatio: false,
      animation:          { duration: 600 },
      interaction:        { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(15,23,42,0.95)",
          borderColor:     "rgba(51,65,85,0.8)",
          borderWidth:     1,
          padding:         10,
        },
      },
      scales: {
        x: {
          grid:   { color: "rgba(51,65,85,0.4)" },
          ticks:  { font: { size: 11 } },
        },
        y: {
          grid:       { color: "rgba(51,65,85,0.4)" },
          ticks:      { font: { size: 11 }, stepSize: 1 },
          beginAtZero: true,
        },
      },
    },
  });
}

function updateTimelineChart(data) {
  if (!timelineChart) return;

  // data = [{ bucket, cnt }]
  const now    = Date.now();
  const labels = data.map(d => {
    const ms  = now - (data.length - 1 - data.indexOf(d)) * 5 * 60 * 1000;
    const dt  = new Date(ms);
    return `${dt.getHours().toString().padStart(2,"0")}:${dt.getMinutes().toString().padStart(2,"0")}`;
  });
  const counts = data.map(d => d.cnt);

  timelineChart.data.labels   = labels;
  timelineChart.data.datasets[0].data = counts;
  timelineChart.update("none");
}

// ── Donut (alerts by type) ───────────────────────────────────────────────────

let donutChart = null;

function initDonutChart() {
  const ctx = document.getElementById("chart-donut");
  if (!ctx) return;

  donutChart = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels:   [],
      datasets: [{
        data:            [],
        backgroundColor: [],
        borderColor:     "rgba(10,15,30,0.8)",
        borderWidth:     3,
        hoverBorderColor: "rgba(255,255,255,0.2)",
        hoverOffset:     8,
      }],
    },
    options: {
      responsive:         true,
      maintainAspectRatio: false,
      animation:          { duration: 700 },
      cutout:             "68%",
      plugins: {
        legend: {
          position: "bottom",
          labels:   { padding: 14, font: { size: 11 }, usePointStyle: true, pointStyleWidth: 10 },
        },
        tooltip: {
          backgroundColor: "rgba(15,23,42,0.95)",
          borderColor:     "rgba(51,65,85,0.8)",
          borderWidth:     1,
          padding:         10,
        },
      },
    },
  });
}

function updateDonutChart(data) {
  if (!donutChart) return;
  // data = [{ type, cnt }]
  donutChart.data.labels = data.map(d => (d.type || "other").toUpperCase());
  donutChart.data.datasets[0].data = data.map(d => d.cnt);
  donutChart.data.datasets[0].backgroundColor = data.map(
    d => TYPE_COLORS[d.type] || PALETTE.cyan
  );
  donutChart.update();
}

// ── Bar (top processes) ──────────────────────────────────────────────────────

let barChart = null;

function initBarChart() {
  const ctx = document.getElementById("chart-bar");
  if (!ctx) return;

  barChart = new Chart(ctx, {
    type: "bar",
    data: {
      labels:   [],
      datasets: [{
        label:           "Alert Count",
        data:            [],
        backgroundColor: data => {
          const idx = data.dataIndex;
          const colors = [PALETTE.red, PALETTE.orange, PALETTE.yellow, PALETTE.blue, PALETTE.purple];
          return colors[idx % colors.length] + "cc";
        },
        borderColor: "transparent",
        borderRadius: 6,
        borderSkipped: false,
      }],
    },
    options: {
      indexAxis:          "y",
      responsive:         true,
      maintainAspectRatio: false,
      animation:          { duration: 600 },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(15,23,42,0.95)",
          borderColor:     "rgba(51,65,85,0.8)",
          borderWidth:     1,
          padding:         10,
        },
      },
      scales: {
        x: {
          grid:        { color: "rgba(51,65,85,0.4)" },
          ticks:       { font: { size: 11 }, stepSize: 1 },
          beginAtZero: true,
        },
        y: { grid: { display: false }, ticks: { font: { size: 11, family: "'JetBrains Mono', monospace" } } },
      },
    },
  });
}

function updateBarChart(data) {
  if (!barChart) return;
  // data = [{ process, cnt }]
  barChart.data.labels = data.map(d => d.process || "unknown");
  barChart.data.datasets[0].data = data.map(d => d.cnt);
  barChart.update("none");
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initTimelineChart();
  initDonutChart();
  initBarChart();
});
