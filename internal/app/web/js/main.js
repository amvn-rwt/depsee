/**
 * Entry: load graph JSON, update status, mount D3 view or empty state.
 */

import * as d3 from "https://cdn.jsdelivr.net/npm/d3@7/+esm";
import { fetchGraph, postSbomFile } from "./api.js";
import { hideDetail } from "./detailPanel.js";
import { mountGraph } from "./graphView.js";
import { prepareNodes } from "./layout.js";

function renderGraphFromData(d3mod, { status, container, zoomLevel, data }) {
  const nodes = data.nodes || [];
  const links = data.links || [];

  prepareNodes(nodes);

  const withCve = nodes.filter((n) => Number(n.cveCount) > 0).length;
  status.textContent = `${nodes.length} nodes · ${links.length} links · ${withCve} with CVEs`;

  hideDetail();
  container.innerHTML = "";

  if (nodes.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No nodes in this SBOM graph.";
    container.appendChild(empty);
    return;
  }

  mountGraph(d3mod, {
    container,
    zoomLevelEl: zoomLevel,
    nodes,
    links,
  });
}

async function boot() {
  const status = document.getElementById("status");
  const container = document.getElementById("graph");
  const zoomLevel = document.getElementById("zoom-level");
  const fileInput = document.getElementById("sbom-file");

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

  renderGraphFromData(d3, { status, container, zoomLevel, data: result.data });

  if (!fileInput) {
    return;
  }

  let uploadBusy = false;
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    fileInput.value = "";
    if (!file || uploadBusy) {
      return;
    }

    uploadBusy = true;
    fileInput.disabled = true;
    status.textContent = "Uploading…";
    status.classList.remove("error");

    try {
      const up = await postSbomFile(file);
      if (!up.ok) {
        status.textContent = `Upload failed · HTTP ${up.status} · ${up.error ?? ""}`.trim();
        status.classList.add("error");
        return;
      }
      renderGraphFromData(d3, {
        status,
        container,
        zoomLevel,
        data: up.data,
      });
    } catch {
      status.textContent = "Upload failed (network)";
      status.classList.add("error");
    } finally {
      uploadBusy = false;
      fileInput.disabled = false;
    }
  });
}

document.addEventListener("DOMContentLoaded", boot);
