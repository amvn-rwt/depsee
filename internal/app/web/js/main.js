/**
 * Entry: load graph JSON, update status, mount D3 view or empty state.
 */

import * as d3 from "https://cdn.jsdelivr.net/npm/d3@7/+esm";
import { fetchGraph, pollSbomJob, postSbomFileWithProgress } from "./api.js";
import { hideDetail } from "./detailPanel.js";
import { mountGraph } from "./graphView.js";
import { prepareNodes } from "./layout.js";

/** @type {{ findNodeByQuery: (q: string) => object | null; focusNode: (d: object) => void; destroy: () => void } | null} */
let graphController = null;

/** Toolbar status line to restore after a transient search message. */
let lastGraphStatusLine = "";

const UPLOAD_RING_R = 26;
const UPLOAD_RING_LEN = 2 * Math.PI * UPLOAD_RING_R;

/** Fraction of the ring (0–1) reserved for the HTTP upload; the rest tracks server job progress. */
const UPLOAD_SHARE = 0.42;

/**
 * Status line under the ring. `overallRingFraction` must match the stroke (0–1 of full circle).
 * @param {string} phase
 * @param {number} overallRingFraction
 */
function jobPhaseLabel(phase, overallRingFraction) {
  const p = Math.round(Math.max(0, Math.min(1, overallRingFraction)) * 100);
  switch (phase) {
    case "queued":
      return `Queued · ${p}%`;
    case "parsing":
      return `Parsing SBOM · ${p}%`;
    case "building":
      return `Building graph · ${p}%`;
    case "enriching":
      return `CVE lookup · ${p}%`;
    case "aggregating":
      return `Risk metrics · ${p}%`;
    case "done":
      return `${p}%`;
    default:
      return `Processing · ${p}%`;
  }
}

/**
 * Ring fill during HTTP upload (0 … {@link UPLOAD_SHARE}).
 * @param {number} loaded
 * @param {number} total
 */
function uploadRingFraction(loaded, total) {
  if (total <= 0) return null;
  return UPLOAD_SHARE * Math.min(1, loaded / total);
}

/**
 * Ring fill during server job ( {@link UPLOAD_SHARE} … 1 ) from server percent 0–100.
 * @param {number} jobPercent
 */
function jobRingFraction(jobPercent) {
  const t = Math.min(1, Math.max(0, jobPercent / 100));
  return UPLOAD_SHARE + (1 - UPLOAD_SHARE) * t;
}

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

/**
 * @param {number | null} fraction null = indeterminate
 */
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
  graphController?.destroy?.();
  graphController = null;

  const nodes = data.nodes || [];
  const links = data.links || [];

  prepareNodes(nodes);

  const withCve = nodes.filter((n) => Number(n.cveCount) > 0).length;
  status.textContent = `${nodes.length} nodes · ${links.length} links · ${withCve} with CVEs`;
  lastGraphStatusLine = status.textContent;

  hideDetail();
  container.innerHTML = "";

  if (nodes.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No nodes in this SBOM graph.";
    container.appendChild(empty);
    return;
  }

  graphController = mountGraph(d3mod, {
    container,
    zoomLevelEl: zoomLevel,
    nodes,
    links,
  });
}

/**
 * Submit on the canvas search form: match package, open detail, animate pan/zoom to center.
 * @param {HTMLElement} status
 */
function bindGraphSearch(status) {
  const form = document.getElementById("graph-search-form");
  const input = document.getElementById("graph-search-input");
  if (!form || !input) {
    return;
  }
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const trimmed = input.value.trim();
    if (!trimmed) {
      return;
    }
    if (!graphController) {
      return;
    }
    const n = graphController.findNodeByQuery(trimmed);
    if (!n) {
      status.textContent = `No match for "${trimmed}"`;
      window.setTimeout(() => {
        status.textContent = lastGraphStatusLine;
      }, 2800);
      return;
    }
    graphController.focusNode(n);
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
  bindGraphSearch(status);

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
          const frac = uploadRingFraction(loaded, total);
          const waiting = loaded >= total;
          const line = waiting ? "Sending…" : `Uploading · ${Math.round(frac * 100)}%`;
          status.textContent = line;
          updateUploadUI(
            uploadOverlay,
            uploadRingFill,
            uploadSvg,
            uploadLabel,
            frac,
            line
          );
        } else {
          status.textContent = "Uploading…";
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

      const jobId = up.jobId;
      if (!jobId) {
        status.textContent = "Upload failed · missing job id";
        status.classList.add("error");
        return;
      }

      // Upload finished; remainder of the ring tracks server job progress.
      {
        const frac = jobRingFraction(0);
        const line = jobPhaseLabel("queued", frac);
        status.textContent = line;
        updateUploadUI(
          uploadOverlay,
          uploadRingFill,
          uploadSvg,
          uploadLabel,
          frac,
          line
        );
      }

      const done = await pollSbomJob(jobId, {
        onJobProgress: ({ phase, percent }) => {
          const frac = jobRingFraction(percent);
          const line = jobPhaseLabel(phase, frac);
          status.textContent = line;
          updateUploadUI(
            uploadOverlay,
            uploadRingFill,
            uploadSvg,
            uploadLabel,
            frac,
            line
          );
        },
      });

      if (!done.ok) {
        status.textContent = `Processing failed · ${done.error ?? `HTTP ${done.status ?? ""}`}`.trim();
        status.classList.add("error");
        return;
      }

      renderGraphFromData(d3, {
        status,
        container,
        zoomLevel,
        data: done.data,
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
