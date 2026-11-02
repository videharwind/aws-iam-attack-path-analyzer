// Frontend logic for IAM Attack Path Analyzer
// Pure DOM manipulation with textContent only. Works 100% offline.

let fullNetwork = null;
let attackNetwork = null;
let fullDataRaw = { nodes: [], edges: [] };
let attackDataRaw = { nodes: [], edges: [] };
let fullNodesDataSet = null;
let fullEdgesDataSet = null;
let attackNodesDataSet = null;
let attackEdgesDataSet = null;

const NODE_COLORS = {
  User: "#38bdf8",
  Group: "#f97316",
  Role: "#a855f7",
  Policy: "#34d399",
  Service: "#eab308",
  Wildcard: "#ef4444",
  External: "#94a3b8",
};

const NODE_SHAPES = {
  User: "dot",
  Group: "box",
  Role: "diamond",
  Policy: "hexagon",
  Service: "triangle",
  Wildcard: "star",
  External: "square",
};

const EDGE_CONFIG = {
  "can-assume": {
    color: "#f59e0b",
    highlight: "#fbbf24",
    hover: "#fbbf24",
    width: 2.4,
    dashes: false,
  },
  "trusted-to-assume": {
    color: "#818cf8",
    highlight: "#a5b4fc",
    hover: "#a5b4fc",
    width: 1.5,
    dashes: [5, 5],
  },
  "attached-policy": {
    color: "#34d399",
    highlight: "#6ee7b7",
    hover: "#6ee7b7",
    width: 1.2,
    dashes: [2, 4],
  },
  "member-of": {
    color: "#fb923c",
    highlight: "#fdba74",
    hover: "#fdba74",
    width: 1.5,
    dashes: [4, 4],
  },
};

async function apiCall(endpoint, options = {}) {
  const resp = await fetch(endpoint, options);
  if (!resp.ok) {
    let errorMsg = `Server error (${resp.status})`;
    try {
      const errJson = await resp.json();
      if (errJson.detail) errorMsg = errJson.detail;
    } catch (_) {}
    throw new Error(errorMsg);
  }
  return await resp.json();
}

function showError(msg) {
  const alertEl = document.getElementById("error-alert");
  if (!alertEl) return;
  alertEl.textContent = msg;
  alertEl.style.display = "block";
}

function clearError() {
  const alertEl = document.getElementById("error-alert");
  if (!alertEl) return;
  alertEl.textContent = "";
  alertEl.style.display = "none";
}

function getThemeColors() {
  const rootStyle = window.getComputedStyle(document.documentElement);
  const container = document.getElementById("full-network-container");
  const containerStyle = container ? window.getComputedStyle(container) : null;
  const bodyStyle = window.getComputedStyle(document.body);

  let canvasBg = containerStyle ? containerStyle.backgroundColor : "";
  if (!canvasBg || canvasBg === "transparent" || canvasBg === "rgba(0, 0, 0, 0)") {
    const viewport = document.querySelector(".canvas-viewport");
    canvasBg = viewport ? window.getComputedStyle(viewport).backgroundColor : "";
  }
  if (!canvasBg || canvasBg === "transparent" || canvasBg === "rgba(0, 0, 0, 0)") {
    canvasBg = rootStyle.getPropertyValue("--bg-page").trim() || bodyStyle.backgroundColor;
  }
  if (!canvasBg || canvasBg === "transparent" || canvasBg === "rgba(0, 0, 0, 0)") {
    canvasBg = "#ffffff";
  }

  let textColor = rootStyle.getPropertyValue("--text-primary").trim() || bodyStyle.color;
  if (!textColor) {
    textColor = "#1a1a1a";
  }

  return { canvasBg, textColor };
}

function getRelativeLuminance(colorStr) {
  let r = 0, g = 0, b = 0;
  if (colorStr.startsWith("#")) {
    const hex = colorStr.replace("#", "");
    if (hex.length === 3) {
      r = parseInt(hex[0] + hex[0], 16);
      g = parseInt(hex[1] + hex[1], 16);
      b = parseInt(hex[2] + hex[2], 16);
    } else {
      r = parseInt(hex.substring(0, 2), 16);
      g = parseInt(hex.substring(2, 4), 16);
      b = parseInt(hex.substring(4, 6), 16);
    }
  } else {
    const m = colorStr.match(/\d+/g);
    if (m && m.length >= 3) {
      r = parseInt(m[0], 10);
      g = parseInt(m[1], 10);
      b = parseInt(m[2], 10);
    }
  }
  const toLinear = (c) => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b);
}

function getContrastRatio(c1, c2) {
  const l1 = getRelativeLuminance(c1);
  const l2 = getRelativeLuminance(c2);
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return (lighter + 0.05) / (darker + 0.05);
}

function formatNode(node) {
  const color = NODE_COLORS[node.type] || "#94a3b8";
  const shape = NODE_SHAPES[node.type] || "dot";
  const theme = getThemeColors();

  if (node.type === "Group") {
    const groupFill = NODE_COLORS.Group || "#f97316";
    // Check contrast: dark (#1a1a1a) gives 6.21:1 on #f97316 (passes AA >= 4.5:1),
    // light (#ffffff) gives 2.80:1 (fails AA). Dark text is chosen.
    const darkText = "#1a1a1a";
    const lightText = "#ffffff";
    const groupTextColor = getContrastRatio(darkText, groupFill) >= 4.5 ? darkText : lightText;

    return {
      id: node.id,
      label: node.label,
      color: {
        background: groupFill,
        border: "#1e293b",
        highlight: { background: groupFill, border: "#1e293b" },
        hover: { background: groupFill, border: "#1e293b" },
      },
      borderWidth: 1.5,
      borderWidthSelected: 1.5,
      shape: "box",
      size: 18,
      margin: { top: 8, bottom: 8, left: 12, right: 12 },
      font: {
        face: '"Segoe UI", system-ui, -apple-system, Roboto, Arial, sans-serif',
        size: 15,
        color: groupTextColor,
        strokeWidth: 0,
        strokeColor: "transparent",
        background: "rgba(0, 0, 0, 0)",
        vadjust: 0,
        bold: { mod: "600" },
      },
      rawType: node.type,
      rawName: node.label,
      opacity: 1.0,
    };
  }

  // Non-Group nodes (User, Role, Policy, Service, Wildcard, External)
  return {
    id: node.id,
    label: node.label,
    color: {
      background: color,
      border: "#1e293b",
      highlight: { background: color, border: "#1e293b" },
      hover: { background: color, border: "#1e40af" },
    },
    shape: shape,
    size: node.type === "Policy" ? 14 : 20,
    font: {
      face: '"Segoe UI", system-ui, -apple-system, Roboto, Arial, sans-serif',
      size: 15,
      color: theme.textColor,
      strokeWidth: 0,
      strokeColor: "transparent",
      background: theme.canvasBg,
      vadjust: 2,
      bold: { mod: "600" },
    },
    rawType: node.type,
    rawName: node.label,
    opacity: 1.0,
  };
}

function formatEdge(edge) {
  const conf = EDGE_CONFIG[edge.type] || {
    color: "#475569",
    highlight: "#94a3b8",
    hover: "#cbd5e1",
    width: 1.5,
    dashes: false,
  };

  return {
    from: edge.from,
    to: edge.to,
    arrows: "to",
    color: {
      color: conf.color,
      highlight: conf.highlight,
      hover: conf.hover,
      inherit: false,
      opacity: 0.9,
    },
    width: conf.width,
    dashes: conf.dashes,
    rawType: edge.type,
    rawReason: edge.reason || "",
  };
}

function getNodePairKey(u, v) {
  return u < v ? `${u}<->${v}` : `${v}<->${u}`;
}

function initNetworks() {
  const fullContainer = document.getElementById("full-network-container");
  const attackContainer = document.getElementById("attack-network-container");

  const options = {
    physics: {
      stabilization: { iterations: 150 },
      barnesHut: { springLength: 110, springConstant: 0.04, damping: 0.09 },
    },
    interaction: {
      hover: true,
      hoverConnectedEdges: false,
      selectConnectedEdges: false,
    },
    nodes: {
      borderWidth: 1.5,
      borderWidthSelected: 2.5,
      font: {
        face: '"Segoe UI", system-ui, -apple-system, Roboto, Arial, sans-serif',
        size: 15,
        strokeWidth: 0,
        strokeColor: "transparent",
        vadjust: 0,
        bold: { mod: "600" },
      },
    },
  };

  fullNodesDataSet = new vis.DataSet([]);
  fullEdgesDataSet = new vis.DataSet([]);
  fullNetwork = new vis.Network(fullContainer, { nodes: fullNodesDataSet, edges: fullEdgesDataSet }, options);

  attackNodesDataSet = new vis.DataSet([]);
  attackEdgesDataSet = new vis.DataSet([]);
  attackNetwork = new vis.Network(attackContainer, { nodes: attackNodesDataSet, edges: attackEdgesDataSet }, options);

  fullNetwork.on("click", (params) => onNodeClicked(params, fullNodesDataSet, fullEdgesDataSet));
  attackNetwork.on("click", (params) => onNodeClicked(params, attackNodesDataSet, attackEdgesDataSet));
}

function onNodeClicked(params, dataSetNodes, dataSetEdges) {
  const panel = document.getElementById("node-details-panel");
  const typeEl = document.getElementById("detail-node-type");
  const nameEl = document.getElementById("detail-node-name");
  const arnEl = document.getElementById("detail-node-arn");

  if (params.nodes && params.nodes.length > 0) {
    const nodeId = params.nodes[0];
    const nodeObj = dataSetNodes.get(nodeId);
    if (nodeObj) {
      if (typeEl) typeEl.textContent = nodeObj.rawType;
      if (nameEl) nameEl.textContent = nodeObj.rawName;
      if (arnEl) arnEl.textContent = nodeObj.id;
      if (panel) panel.style.display = "block";
      highlightNodeNeighborhood(nodeId);
      return;
    }
  }

  // Clicked empty canvas or unselected
  if (panel) panel.style.display = "none";
  clearHighlight();
}

function highlightNodeNeighborhood(nodeId) {
  function applyNodeHighlight(dataSetNodes, dataSetEdges) {
    const allEdges = dataSetEdges.get();
    const connectedEdges = new Set();
    const connectedNodeIds = new Set([nodeId]);

    for (const e of allEdges) {
      if (e.from === nodeId || e.to === nodeId) {
        connectedEdges.add(e.id);
        connectedNodeIds.add(e.from);
        connectedNodeIds.add(e.to);
      }
    }

    const nodeUpdates = dataSetNodes.get().map((n) => ({
      id: n.id,
      opacity: connectedNodeIds.has(n.id) ? 1.0 : 0.50,
    }));
    dataSetNodes.update(nodeUpdates);

    const edgeUpdates = allEdges.map((e) => {
      const isConn = connectedEdges.has(e.id);
      const conf = EDGE_CONFIG[e.rawType] || {
        color: "#475569",
        highlight: "#94a3b8",
        hover: "#cbd5e1",
        width: 1.5,
      };
      return {
        id: e.id,
        color: isConn
          ? { color: conf.color, highlight: conf.highlight, hover: conf.hover, inherit: false, opacity: 1.0 }
          : { color: conf.color, highlight: conf.color, hover: conf.color, inherit: false, opacity: 0.50 },
        width: isConn ? Math.max(conf.width, 2.5) : 1,
      };
    });
    dataSetEdges.update(edgeUpdates);
  }

  applyNodeHighlight(fullNodesDataSet, fullEdgesDataSet);
  applyNodeHighlight(attackNodesDataSet, attackEdgesDataSet);
}

function renderGraphs(fullData, attackData) {
  fullDataRaw = fullData;
  attackDataRaw = attackData;

  // FIX 2: When the same two nodes have both a can-assume edge and a
  // trusted-to-assume edge, show only the can-assume edge in Full graph.
  // Match on node pair regardless of direction (A to B and B to A count as the same pair).
  const canAssumePairs = new Set();
  for (const e of fullData.edges) {
    if (e.type === "can-assume") {
      canAssumePairs.add(getNodePairKey(e.from, e.to));
    }
  }

  const fullEdgesWithoutDuplicateTrust = fullData.edges.filter((e) => {
    if (e.type === "trusted-to-assume") {
      const pairKey = getNodePairKey(e.from, e.to);
      if (canAssumePairs.has(pairKey)) {
        return false;
      }
    }
    return true;
  });

  const hidePolicies = document.getElementById("hide-policies-checkbox").checked;
  const filteredFullNodes = hidePolicies
    ? fullData.nodes.filter((n) => n.type !== "Policy")
    : fullData.nodes;

  const nodeIds = new Set(filteredFullNodes.map((n) => n.id));
  const filteredFullEdges = fullEdgesWithoutDuplicateTrust.filter(
    (e) => nodeIds.has(e.from) && nodeIds.has(e.to)
  );

  fullNodesDataSet.clear();
  fullEdgesDataSet.clear();
  fullNodesDataSet.add(filteredFullNodes.map(formatNode));
  fullEdgesDataSet.add(filteredFullEdges.map(formatEdge));

  attackNodesDataSet.clear();
  attackEdgesDataSet.clear();
  attackNodesDataSet.add(attackData.nodes.map(formatNode));
  attackEdgesDataSet.add(attackData.edges.map(formatEdge));

  if (fullNetwork) fullNetwork.unselectAll();
  if (attackNetwork) attackNetwork.unselectAll();
}

async function loadSnapshotByName(name) {
  try {
    clearError();
    await apiCall("/api/snapshots/load", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    await refreshLoadedData();
  } catch (err) {
    showError(`Could not load snapshot: ${err.message}`);
  }
}

async function refreshLoadedData() {
  const summary = await apiCall("/api/summary");
  document.getElementById("card-users").textContent = summary.users;
  document.getElementById("card-groups").textContent = summary.groups;
  document.getElementById("card-roles").textContent = summary.roles;
  document.getElementById("card-policies").textContent = summary.policies;
  document.getElementById("card-edges").textContent = summary.can_assume_edges;
  document.getElementById("card-snapshot").textContent = summary.snapshot_name || "-";
  document.getElementById("card-account").textContent =
    summary.meta && summary.meta.account_id ? summary.meta.account_id : "-";
  document.getElementById("card-created").textContent =
    summary.meta && summary.meta.created_at ? summary.meta.created_at.slice(0, 10) : "-";

  const identitiesData = await apiCall("/api/identities");
  const select = document.getElementById("identity-select");
  while (select.firstChild) {
    select.removeChild(select.firstChild);
  }

  for (const item of identitiesData.identities) {
    const opt = document.createElement("option");
    opt.value = item.arn;
    opt.textContent = `${item.name} (${item.type})`;
    select.appendChild(opt);
  }

  const hintMsg = document.getElementById("lookup-hint-msg");
  const emptyMsg = document.getElementById("empty-results-msg");
  const table = document.getElementById("reachable-table");
  if (hintMsg) {
    hintMsg.textContent = "Choose an identity and click Show reachable.";
    hintMsg.style.display = "block";
  }
  if (emptyMsg) emptyMsg.style.display = "none";
  if (table) table.style.display = "none";

  const panel = document.getElementById("node-details-panel");
  if (panel) panel.style.display = "none";

  const fullData = await apiCall("/api/graph/full");
  const attackData = await apiCall("/api/graph/attack");
  renderGraphs(fullData, attackData);
  clearHighlight();
}

async function fetchSnapshotsList() {
  try {
    clearError();
    const data = await apiCall("/api/snapshots");
    const select = document.getElementById("snapshot-select");
    while (select.firstChild) {
      select.removeChild(select.firstChild);
    }

    let sampleOption = null;
    for (const s of data.snapshots) {
      const opt = document.createElement("option");
      opt.value = s.name;
      opt.textContent = s.name;
      select.appendChild(opt);
      if (s.name === "sample_lab.json") {
        sampleOption = s.name;
      }
    }

    if (sampleOption) {
      select.value = sampleOption;
      await loadSnapshotByName(sampleOption);
    } else if (data.snapshots.length > 0) {
      select.value = data.snapshots[0].name;
      await loadSnapshotByName(data.snapshots[0].name);
    }
  } catch (err) {
    showError(`Failed to fetch snapshots: ${err.message}`);
  }
}

async function onShowReachable() {
  const select = document.getElementById("identity-select");
  const sourceArn = select.value;
  if (!sourceArn) return;

  const hopsVal = document.getElementById("max-hops-input").value;
  let url = `/api/reachable?source=${encodeURIComponent(sourceArn)}`;
  if (hopsVal !== "") {
    url += `&max_hops=${encodeURIComponent(hopsVal)}`;
  }

  try {
    clearError();
    const data = await apiCall(url);
    const tbody = document.getElementById("reachable-tbody");
    const emptyMsg = document.getElementById("empty-results-msg");
    const hintMsg = document.getElementById("lookup-hint-msg");
    const table = document.getElementById("reachable-table");

    if (hintMsg) {
      hintMsg.style.display = "none";
    }

    while (tbody.firstChild) {
      tbody.removeChild(tbody.firstChild);
    }

    if (!data.results || data.results.length === 0) {
      emptyMsg.style.display = "block";
      table.style.display = "none";
      clearHighlight();
      return;
    }

    emptyMsg.style.display = "none";
    table.style.display = "table";

    for (const row of data.results) {
      const tr = document.createElement("tr");

      const tdRole = document.createElement("td");
      tdRole.textContent = row.name;

      const tdHops = document.createElement("td");
      tdHops.textContent = row.hops;

      const tdPath = document.createElement("td");
      tdPath.textContent = row.path_names.join(" -> ");

      tr.appendChild(tdRole);
      tr.appendChild(tdHops);
      tr.appendChild(tdPath);

      tr.addEventListener("click", () => highlightPath(row));
      tbody.appendChild(tr);
    }
  } catch (err) {
    showError(`Reachable search failed: ${err.message}`);
  }
}

function highlightPath(row) {
  const pathSet = new Set(row.path);
  const pathEdges = new Set();
  for (let i = 0; i < row.path.length - 1; i++) {
    pathEdges.add(`${row.path[i]}->${row.path[i + 1]}`);
  }

  function applyHighlight(dataSetNodes, dataSetEdges) {
    const allNodes = dataSetNodes.get();
    const nodeUpdates = allNodes.map((n) => {
      const inPath = pathSet.has(n.id);
      return {
        id: n.id,
        opacity: inPath ? 1.0 : 0.50,
      };
    });
    dataSetNodes.update(nodeUpdates);

    const allEdges = dataSetEdges.get();
    const edgeUpdates = allEdges.map((e) => {
      const inPath = pathEdges.has(`${e.from}->${e.to}`);
      const conf = EDGE_CONFIG[e.rawType] || {
        color: "#475569",
        highlight: "#94a3b8",
        hover: "#cbd5e1",
        width: 1.5,
      };
      return {
        id: e.id,
        color: inPath
          ? { color: "#fbbf24", highlight: "#f59e0b", hover: "#f59e0b", inherit: false, opacity: 1.0 }
          : { color: conf.color, highlight: conf.color, hover: conf.color, inherit: false, opacity: 0.50 },
        width: inPath ? 4 : 1,
      };
    });
    dataSetEdges.update(edgeUpdates);
  }

  applyHighlight(fullNodesDataSet, fullEdgesDataSet);
  applyHighlight(attackNodesDataSet, attackEdgesDataSet);

  const reasonsContainer = document.getElementById("hop-reasons-container");
  const reasonsList = document.getElementById("hop-reasons-list");
  while (reasonsList.firstChild) {
    reasonsList.removeChild(reasonsList.firstChild);
  }

  for (let i = 0; i < row.hop_reasons.length; i++) {
    const div = document.createElement("div");
    const stepDesc = `${row.path_names[i]} -> ${row.path_names[i + 1]}: ${row.hop_reasons[i]}`;
    div.textContent = stepDesc;
    reasonsList.appendChild(div);
  }
  reasonsContainer.style.display = "block";
}

function clearHighlight() {
  function resetHighlight(dataSetNodes, dataSetEdges) {
    const allNodes = dataSetNodes.get();
    const nodeUpdates = allNodes.map((n) => ({ id: n.id, opacity: 1.0 }));
    dataSetNodes.update(nodeUpdates);

    const allEdges = dataSetEdges.get();
    const edgeUpdates = allEdges.map((e) => {
      const conf = EDGE_CONFIG[e.rawType] || {
        color: "#475569",
        highlight: "#94a3b8",
        hover: "#cbd5e1",
        width: 1.5,
      };
      return {
        id: e.id,
        color: { color: conf.color, highlight: conf.highlight, hover: conf.hover, inherit: false, opacity: 0.9 },
        width: conf.width,
      };
    });
    dataSetEdges.update(edgeUpdates);
  }

  if (fullNodesDataSet && fullEdgesDataSet) {
    resetHighlight(fullNodesDataSet, fullEdgesDataSet);
  }
  if (attackNodesDataSet && attackEdgesDataSet) {
    resetHighlight(attackNodesDataSet, attackEdgesDataSet);
  }

  const reasonsContainer = document.getElementById("hop-reasons-container");
  if (reasonsContainer) {
    reasonsContainer.style.display = "none";
  }
}

function setupEventListeners() {
  document.getElementById("load-btn").addEventListener("click", () => {
    const select = document.getElementById("snapshot-select");
    if (select.value) {
      loadSnapshotByName(select.value);
    }
  });

  document.getElementById("upload-input").addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (evt) => {
      try {
        clearError();
        const jsonContent = JSON.parse(evt.target.result);
        await apiCall("/api/snapshots/upload", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(jsonContent),
        });
        await refreshLoadedData();
      } catch (err) {
        showError(`Invalid snapshot file: ${err.message}`);
      }
    };
    reader.readAsText(file);
  });

  document.getElementById("tab-btn-full").addEventListener("click", () => {
    document.getElementById("tab-btn-full").classList.add("active");
    document.getElementById("tab-btn-full").setAttribute("aria-selected", "true");
    document.getElementById("tab-btn-attack").classList.remove("active");
    document.getElementById("tab-btn-attack").setAttribute("aria-selected", "false");
    document.getElementById("full-graph-view").classList.add("active");
    document.getElementById("attack-graph-view").classList.remove("active");
    if (fullNetwork) {
      fullNetwork.unselectAll();
      fullNetwork.fit();
    }
  });

  document.getElementById("tab-btn-attack").addEventListener("click", () => {
    document.getElementById("tab-btn-attack").classList.add("active");
    document.getElementById("tab-btn-attack").setAttribute("aria-selected", "true");
    document.getElementById("tab-btn-full").classList.remove("active");
    document.getElementById("tab-btn-full").setAttribute("aria-selected", "false");
    document.getElementById("attack-graph-view").classList.add("active");
    document.getElementById("full-graph-view").classList.remove("active");
    if (attackNetwork) {
      attackNetwork.unselectAll();
      attackNetwork.fit();
    }
  });

  document.getElementById("hide-policies-checkbox").addEventListener("change", () => {
    renderGraphs(fullDataRaw, attackDataRaw);
  });

  document.getElementById("show-reachable-btn").addEventListener("click", onShowReachable);
  document.getElementById("clear-highlight-btn").addEventListener("click", clearHighlight);
}

document.addEventListener("DOMContentLoaded", () => {
  initNetworks();
  setupEventListeners();
  fetchSnapshotsList();
});
