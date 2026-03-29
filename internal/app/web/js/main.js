/**
 * Entry: load graph JSON, update status, mount D3 view or empty state.
 */

import * as d3 from "https://cdn.jsdelivr.net/npm/d3@7/+esm";
import { fetchGraph } from "./api.js";
import { mountGraph } from "./graphView.js";
import { prepareNodes } from "./layout.js";

async function boot() {
  // get the elements from the DOM
  const status = document.getElementById("status");
  const container = document.getElementById("graph");
  const zoomLevel = document.getElementById("zoom-level");

  // if any of the elements are not found, return
  if (!status || !container || !zoomLevel) {
    return;
  }

  // set the status to loading
  status.textContent = "Loading…";
  status.classList.remove("error");

  // fetch the graph from the API
  let result;
  try {
    result = await fetchGraph();
  } catch {
    status.textContent = "Failed to load graph";
    status.classList.add("error");
    return;
  }

  // if the result is not ok, set the status to the HTTP status
  if (!result.ok) {
    status.textContent = `HTTP ${result.status}`;
    status.classList.add("error");
    return;
  }

  // get the nodes and links from the result
  const nodes = result.data.nodes || [];
  const links = result.data.links || [];

  // prepare the nodes
  prepareNodes(nodes);

  // get the number of nodes with CVEs
  const withCve = nodes.filter((n) => Number(n.cveCount) > 0).length;
  status.textContent = `${nodes.length} nodes · ${links.length} links · ${withCve} with CVEs`;

  // clear the container
  container.innerHTML = "";

  // if there are no nodes, show the empty state
  if (nodes.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No nodes in this SBOM graph.";
    container.appendChild(empty);
    return;
  }

  // mount the graph
  mountGraph(d3, {
    container,
    zoomLevelEl: zoomLevel,
    nodes,
    links,
  });
}

document.addEventListener("DOMContentLoaded", boot);
