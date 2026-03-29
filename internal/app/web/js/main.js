/**
 * Entry: load graph JSON, update status, mount D3 view or empty state.
 */

import * as d3 from "https://cdn.jsdelivr.net/npm/d3@7/+esm";
import { fetchGraph } from "./api.js";
import { mountGraph } from "./graphView.js";
import { prepareNodes } from "./layout.js";

async function boot() {
  const status = document.getElementById("status");
  const container = document.getElementById("graph");
  const zoomLevel = document.getElementById("zoom-level");

  if (!status || !container || !zoomLevel) {
    return;
  }

  status.textContent = "Loading…";
  status.classList.remove("error");

  let result;
  try {
    result = await fetchGraph();
  } catch {
    status.textContent = "Failed to load graph";
    status.classList.add("error");
    return;
  }

  if (!result.ok) {
    status.textContent = `HTTP ${result.status}`;
    status.classList.add("error");
    return;
  }

  const nodes = result.data.nodes || [];
  const links = result.data.links || [];

  prepareNodes(nodes);

  const withCve = nodes.filter((n) => Number(n.cveCount) > 0).length;
  status.textContent = `${nodes.length} nodes · ${links.length} links · ${withCve} with CVEs`;

  container.innerHTML = "";

  if (nodes.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No nodes in this SBOM graph.";
    container.appendChild(empty);
    return;
  }

  mountGraph(d3, {
    container,
    zoomLevelEl: zoomLevel,
    nodes,
    links,
  });
}

document.addEventListener("DOMContentLoaded", boot);
