/**
 * dashboard/static/js/process_tree.js
 * Renders a collapsible process tree in the centre panel.
 */

/**
 * Build a tree structure from a flat list of process dicts.
 * @param {Array} procs
 * @returns {Object} tree — map of pid → { info, children: [] }
 */
function buildTree(procs) {
  const nodes  = {};
  const roots  = [];

  procs.forEach(p => { nodes[p.pid] = { info: p, children: [] }; });

  procs.forEach(p => {
    if (p.parent_pid && nodes[p.parent_pid]) {
      nodes[p.parent_pid].children.push(nodes[p.pid]);
    } else {
      roots.push(nodes[p.pid]);
    }
  });

  return roots;
}

// Processes that are suspicious (names found in alerts)
let _suspiciousNames = new Set();

function setSuspiciousNames(names) {
  _suspiciousNames = new Set(names.map(n => n.toLowerCase()));
}

function _isSuspicious(name) {
  return _suspiciousNames.has((name || "").toLowerCase());
}

const TEMP_HINTS = ["temp", "tmp", "downloads", "appdata\\local\\temp"];
function _isPathSuspicious(path) {
  if (!path) return false;
  const lower = path.toLowerCase();
  return TEMP_HINTS.some(h => lower.includes(h));
}

/**
 * Render a single tree node (and its children recursively).
 * @param {Object} node — { info, children }
 * @param {number} depth
 * @returns {HTMLElement}
 */
function renderNode(node, depth = 0) {
  const { info, children } = node;
  const sus  = _isSuspicious(info.name) || _isPathSuspicious(info.path);
  const wrap = document.createElement("div");

  const row = document.createElement("div");
  row.className = "proc-node" + (sus ? " suspicious" : "");
  row.style.paddingLeft = `${depth * 1}rem`;
  row.title = info.path || info.name;

  const toggle = document.createElement("span");
  toggle.className = "proc-toggle";
  toggle.textContent = children.length ? "▶" : " ";

  const icon = document.createElement("span");
  icon.className = "proc-icon";
  icon.textContent = sus ? "⚠️" : "⚙️";

  const label = document.createElement("span");
  label.style.flex = "1";
  label.innerHTML = `
    <span style="color:${sus ? "#fdba74" : "#cbd5e1"}">${info.name || "?"}</span>
    <span style="color:#475569;font-size:0.7rem;margin-left:0.4rem">PID ${info.pid}</span>
    ${info.username ? `<span style="color:#334155;font-size:0.65rem;margin-left:0.3rem">[${info.username}]</span>` : ""}
  `;

  row.append(toggle, icon, label);
  wrap.appendChild(row);

  // Children container (initially hidden)
  const childContainer = document.createElement("div");
  childContainer.className = "proc-children";
  childContainer.style.display = "none";

  children.forEach(child => {
    childContainer.appendChild(renderNode(child, depth + 1));
  });

  if (children.length) {
    row.addEventListener("click", () => {
      const hidden = childContainer.style.display === "none";
      childContainer.style.display = hidden ? "block" : "none";
      toggle.textContent = hidden ? "▼" : "▶";
    });
  }

  wrap.appendChild(childContainer);
  return wrap;
}

/**
 * Render the full process tree into #process-tree-container.
 * @param {Array} procs — flat process list from /api/processes
 */
function renderProcessTree(procs) {
  const container = document.getElementById("process-tree-container");
  if (!container) return;

  container.innerHTML = "";

  if (!procs || procs.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="icon">🌿</div>
        <div>No process data yet</div>
      </div>`;
    return;
  }

  const roots = buildTree(procs);

  if (roots.length === 0) {
    // Fallback: flat list if tree can't be built
    procs.slice(0, 50).forEach(p => {
      const fakeNode = { info: p, children: [] };
      container.appendChild(renderNode(fakeNode, 0));
    });
    return;
  }

  // Show top-level roots; auto-expand if ≤ 5
  roots.slice(0, 30).forEach((root, i) => {
    const el = renderNode(root, 0);
    if (i < 3) {
      // Auto-expand first few roots
      const childDiv = el.querySelector(".proc-children");
      const toggle   = el.querySelector(".proc-toggle");
      if (childDiv) { childDiv.style.display = "block"; }
      if (toggle && root.children.length) toggle.textContent = "▼";
    }
    container.appendChild(el);
  });
}

// Expose globally
window.renderProcessTree = renderProcessTree;
window.setSuspiciousNames = setSuspiciousNames;
