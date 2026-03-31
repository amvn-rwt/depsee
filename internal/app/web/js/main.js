/**
 * Entry: load graph JSON, update status, mount D3 view or empty state.
 */

import * as d3 from "https://cdn.jsdelivr.net/npm/d3@7/+esm";
import { fetchGraph, postSbomFileWithProgress } from "./api.js";
import { hideDetail } from "./detailPanel.js";
import { mountGraph } from "./graphView.js";
import { prepareNodes } from "./layout.js";

const UPLOAD_RING_R = 26;
const UPLOAD_RING_LEN = 2 * Math.PI * UPLOAD_RING_R;

function setRingDeterminate(ringFill, svg, fraction) {
  if (!ringFill || !svg) return;
  svg.classList.remove("upload-ring-svg--indeterminate");
  const p = Math.max(0, Math.min(1, fraction));
  ringFill.style.strokeDasharray = String(UPLOAD_RING_LEN);
  ringFill.style.strokeDashoffset = String(UPLOAD_RING_LEN * (1 - p));
}

function setRingIndeterminate(svg, ringFill) {
  if (!svg) return;
  svg.classList.add("upload-ring-svg--indeterminate");
  ringFillClearStyles(ringFill);
}

function ringFillClearStyles(ringFill) {
  if (!ringFill) return;
  ringFill.style.strokeDasharray = "";
  ringFill.style.strokeDashoffset = "";
}

function showUploadOverlay(overlay, ringFill, svg) {
  if (!overlay) return;
  overlay.hidden = false;
  setRingIndeterminate(svg, ringFill);
}

function hideUploadOverlay(overlay, ringFill, svg) {
  if (!overlay) return;
  overlay.hidden = true;
  svg?.classList.remove("upload-ring-svg--indeterminate");
  ringFillClearStyles(ringFill);
}

function updateUploadUI(overlay, ringFill, svg, label, fraction, text) {
  if (!overlay || !label) return;
  if (fraction == null) {
    setRingIndeterminate(svg, ringFill);
    label.textContent = text ?? "Uploading…";
    overlay.setAttribute("aria-valuenow", "");
    return;
  }
  setRingDeterminate(ringFill, svg, fraction);
  const pct = Math.round(fraction * 100);
  label.textContent = text ?? `${pct}%`;
  overlay.setAttribute("aria-valuenow", String(pct));
}

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
  const uploadOverlay = document.getElementById("upload-overlay");
  const uploadRingFill = document.getElementById("upload-ring-fill");
  const uploadLabel = document.getElementById("upload-overlay-label");
  const uploadSvg = uploadOverlay?.querySelector(".upload-ring-svg") ?? null;

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
    status.classList.remove("error");
    status.textContent = "Uploading…";

    showUploadOverlay(uploadOverlay, uploadRingFill, uploadSvg);
    updateUploadUI(
      uploadOverlay,
      uploadRingFill,
      uploadSvg,
      uploadLabel,
      null,
      "Uploading…"
    );

    try {
      const up = await postSbomFileWithProgress(file, ({ loaded, total }) => {
        if (total > 0) {
          const frac = loaded / total;
          const waiting = loaded >= total;
          updateUploadUI(
            uploadOverlay,
            uploadRingFill,
            uploadSvg,
            uploadLabel,
            frac,
            waiting ? "Processing response…" : `${Math.round(frac * 100)}%`
          );
        } else {
          updateUploadUI(
            uploadOverlay,
            uploadRingFill,
            uploadSvg,
            uploadLabel,
            null,
            "Uploading…"
          );
        }
      });

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
    } catch (e) {
      const msg = e instanceof Error && e.message === "aborted" ? "Upload cancelled" : "Upload failed (network)";
      status.textContent = msg;
      status.classList.add("error");
    } finally {
      hideUploadOverlay(uploadOverlay, uploadRingFill, uploadSvg);
      uploadBusy = false;
      fileInput.disabled = false;
    }
  });
}

document.addEventListener("DOMContentLoaded", boot);
