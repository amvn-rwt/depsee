/* global d3 */

/** Node fill from NVD severity / exposure (PRD: critical … clean / gray no data). */
function severityFill(d) {
  if (d.vulnQueryError) return "#8b949e";
  const s = (d.severity || "").toUpperCase();
  if (s === "CRITICAL") return "#f85149";
  if (s === "HIGH") return "#f0883e";
  if (s === "MEDIUM") return "#d29922";
  if (s === "LOW") return "#9ece6a";
  if (s === "NONE") return "#3fb950";
  if (s === "EXPOSED") return "#58a6ff";
  if (s === "UNKNOWN") return "#6e7681";
  return "#6e7681";
}

function nodeRadius(d) {
  const br = Number(d.blastRadius) || 0;
  return DOT_R * (1 + Math.min(1.25, Math.sqrt(br) * 0.14));
}

/** Visual anchor: same size as the original graph dots. */
const DOT_R = 20;

/** Generic package/box glyph; centroid at (0,0) after PKG_ICON_TRANSLATE. */
const PKG_ICON_PATH =
  "M0,-6 L9,-2 L9,6 L0,10 L-9,6 L-9,-2 Z M0,-6 L0,10 M-9,-2 L0,2 L9,-2";
/** Nudge so the path’s geometric center (hexagon centroid ≈ (0,2)) sits on the node center. */
const PKG_ICON_TRANSLATE = "translate(0,-2)";
/** Must match `.links line` stroke-width in styles.css. */
const LINK_STROKE_PX = 1.5;
/** Must match `markerWidth` on `#depsee-arrow` (`markerUnits="strokeWidth"`). */
const LINK_MARKER_W = 6;
/** Base→tip length along the edge so the line stops at the arrow base, not the tip. */
const LINK_ARROW_LEN = LINK_MARKER_W * LINK_STROKE_PX;
const DOT_GUTTER = 6;
const NODE_PAD_X = 12;
const NODE_MAX_W = 320;
/** Padding from bottom of the node bbox to the last text baseline. */
const NODE_PAD_BOTTOM = 4;
/** Baseline step between the two lines (px, matches ~1.15em @ 11px). */
const NODE_LINE_STEP = 13;

const FONT_K11 = '500 11px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
const FONT_V11 = '600 11px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
const FONT_K10 = '500 10px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
const FONT_V10 = '400 10px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';

const PKG_PREFIX = "package: ";
const VER_PREFIX = "version: ";

function measureContext() {
  if (!measureContext._ctx) {
    const c = document.createElement("canvas");
    measureContext._ctx = c.getContext("2d");
  }
  return measureContext._ctx;
}

function truncateToFit(ctx, font, str, maxWidth) {
  if (str == null || str === "") return "";
  const s = String(str);
  ctx.font = font;
  if (ctx.measureText(s).width <= maxWidth) return s;
  const ell = "\u2026";
  if (ctx.measureText(ell).width > maxWidth) return ell;
  let lo = 0;
  let hi = s.length;
  while (lo < hi) {
    const mid = Math.ceil((lo + hi) / 2);
    const candidate = s.slice(0, mid) + ell;
    if (ctx.measureText(candidate).width <= maxWidth) lo = mid;
    else hi = mid - 1;
  }
  return lo > 0 ? s.slice(0, lo) + ell : ell;
}

function measurePrefixValueWidth(ctx, prefix, pFont, value, vFont) {
  ctx.font = pFont;
  const wp = ctx.measureText(prefix).width;
  ctx.font = vFont;
  const wv = ctx.measureText(value).width;
  return wp + wv;
}

/** Attaches _r, _pkgVal, _verVal, _textBlockW, _bboxW, _bboxH for layout and collision. */
function prepareNodes(nodes) {
  const ctx = measureContext();
  const innerMax = NODE_MAX_W - NODE_PAD_X * 2;

  for (const d of nodes) {
    d._r = nodeRadius(d);
    const r = d._r;
    const name = d.name && String(d.name).trim();
    const ver = d.version && String(d.version).trim();
    let rawPkg;
    let rawVer;
    if (name) {
      rawPkg = name;
      rawVer = ver || "\u2014";
    } else {
      rawPkg = String(d.label || d.id || "");
      rawVer = "\u2014";
    }
    if (rawPkg.length > 256) rawPkg = rawPkg.slice(0, 256);

    ctx.font = FONT_K11;
    const prefixW = ctx.measureText(PKG_PREFIX).width;
    const maxValW = Math.max(0, innerMax - prefixW);
    const pkgVal = truncateToFit(ctx, FONT_V11, rawPkg, maxValW);

    ctx.font = FONT_K10;
    const prefixVerW = ctx.measureText(VER_PREFIX).width;
    const maxVerValW = Math.max(0, innerMax - prefixVerW);
    const verVal = truncateToFit(ctx, FONT_V10, rawVer, maxVerValW);

    d._pkgVal = pkgVal;
    d._verVal = verVal;

    const w1 = measurePrefixValueWidth(
      ctx,
      PKG_PREFIX,
      FONT_K11,
      pkgVal,
      FONT_V11
    );
    const w2 = measurePrefixValueWidth(
      ctx,
      VER_PREFIX,
      FONT_K10,
      verVal,
      FONT_V10
    );
    d._textBlockW = Math.max(w1, w2);
    const textStackH = NODE_LINE_STEP * 2 + 6;
    d._bboxH = 2 * r + DOT_GUTTER + textStackH + NODE_PAD_BOTTOM;
    d._bboxW = Math.max(Math.ceil(d._textBlockW), 2 * r);
    /** Bottom edge of label bbox (y) when circle center is at origin. */
    d._bboxBottomY = r + DOT_GUTTER + textStackH + NODE_PAD_BOTTOM;
  }
}

/** Shorten link segment to node edges; line ends at arrow base (marker refX=0), not the tip. */
function linkEndpoints(d) {
  const sx = d.source.x;
  const sy = d.source.y;
  const tx = d.target.x;
  const ty = d.target.y;
  const rs = d.source._r ?? DOT_R;
  const rt = d.target._r ?? DOT_R;
  const dx = tx - sx;
  const dy = ty - sy;
  const len = Math.hypot(dx, dy);
  if (len < 1e-6) {
    return { x1: sx, y1: sy, x2: tx, y2: ty };
  }
  const ux = dx / len;
  const uy = dy / len;
  const pad = rs + 2;
  const padT = rt + 2;
  const edgeTx = tx - ux * padT;
  const edgeTy = ty - uy * padT;
  let x1 = sx + ux * pad;
  let y1 = sy + uy * pad;
  let x2 = edgeTx - ux * LINK_ARROW_LEN;
  let y2 = edgeTy - uy * LINK_ARROW_LEN;

  const minSeg = 0.75;
  if (Math.hypot(x2 - x1, y2 - y1) < minSeg) {
    const shrink = Math.max(0, (len - LINK_ARROW_LEN) * 0.15);
    x1 = sx + ux * shrink;
    y1 = sy + uy * shrink;
    x2 = tx - ux * (shrink + LINK_ARROW_LEN);
    y2 = ty - uy * (shrink + LINK_ARROW_LEN);
  }
  return { x1, y1, x2, y2 };
}

function hideDetail() {
  const panel = document.getElementById("detail");
  if (!panel) return;
  panel.hidden = true;
  panel.innerHTML = "";
}

function showDetail(d) {
  const panel = document.getElementById("detail");
  if (!panel) return;
  panel.hidden = false;
  const esc = (s) =>
    String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  const cves = Array.isArray(d.cves) ? d.cves : [];
  const cveBlock =
    cves.length === 0
      ? '<p class="detail-meta">No CVE rows (clean or not queried).</p>'
      : `<ul class="detail-cve-list">${cves
          .map(
            (c) =>
              `<li><strong>${esc(c.id)}</strong> · CVSS ${esc(
                c.baseScore ?? "\u2014"
              )} ${esc(c.baseSeverity || "")}</li>`
          )
          .join("")}</ul>`;

  panel.innerHTML = `
    <button type="button" class="detail-close" aria-label="Close panel">\u00d7</button>
    <h2>${esc(d.label || d.id)}</h2>
    <dl class="detail-meta">
      <dt>Severity</dt><dd>${esc(d.severity || "\u2014")}</dd>
      <dt>CVEs</dt><dd>${esc(d.cveCount ?? 0)}</dd>
      <dt>Max CVSS</dt><dd>${esc(d.maxCvss ?? "\u2014")}</dd>
      <dt>Blast radius</dt><dd>${esc(d.blastRadius ?? 0)} dependents</dd>
      <dt>Risk score</dt><dd>${esc(
        d.riskScore != null && !Number.isNaN(d.riskScore)
          ? d.riskScore.toFixed(1)
          : "\u2014"
      )}</dd>
      <dt>Exposure</dt><dd>${
        d.transitiveExposure
          ? "Transitive (via dependency)"
          : esc("\u2014")
      }</dd>
    </dl>
    ${cveBlock}
  `;
  const btn = panel.querySelector(".detail-close");
  if (btn) btn.addEventListener("click", hideDetail);
}

function dragBehavior(simulation) {
  function dragstarted(event) {
    if (!event.active) simulation.alphaTarget(0.25).restart();
    event.subject.fx = event.subject.x;
    event.subject.fy = event.subject.y;
  }
  function dragged(event) {
    event.subject.fx = event.x;
    event.subject.fy = event.y;
  }
  function dragended(event) {
    if (!event.active) simulation.alphaTarget(0);
    event.subject.fx = null;
    event.subject.fy = null;
  }
  return d3
    .drag()
    .on("start", dragstarted)
    .on("drag", dragged)
    .on("end", dragended);
}

async function loadGraph() {
  const status = document.getElementById("status");
  const container = document.getElementById("graph");
  status.textContent = "Loading…";
  status.classList.remove("error");

  let data;
  try {
    const res = await fetch("/api/graph");
    if (!res.ok) {
      status.textContent = `HTTP ${res.status}`;
      status.classList.add("error");
      return;
    }
    data = await res.json();
  } catch {
    status.textContent = "Failed to load graph";
    status.classList.add("error");
    return;
  }

  const nodes = data.nodes || [];
  const links = data.links || [];

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

  const zoomLevel = document.getElementById("zoom-level");

  const svg = d3
    .select(container)
    .append("svg")
    .attr("role", "img")
    .attr("aria-label", "Dependency graph");

  const defs = svg.append("defs");
  const dotStep = 20;
  defs
    .append("pattern")
    .attr("id", "depsee-dot-grid")
    .attr("width", dotStep)
    .attr("height", dotStep)
    .attr("patternUnits", "userSpaceOnUse")
    .append("circle")
    .attr("cx", dotStep / 2)
    .attr("cy", dotStep / 2)
    .attr("r", 1.25)
    .attr("fill", "#30363d");

  defs
    .append("marker")
    .attr("id", "depsee-arrow")
    .attr("viewBox", "0 0 10 10")
    .attr("refX", 0)
    .attr("refY", 5)
    .attr("markerWidth", LINK_MARKER_W)
    .attr("markerHeight", LINK_MARKER_W)
    .attr("orient", "auto")
    .attr("markerUnits", "strokeWidth")
    .append("path")
    .attr("class", "link-arrow-head")
    .attr("d", "M0,0 L10,5 L0,10 Z");

  const g = svg.append("g");

  const gridExtent = 4e6;
  g.append("rect")
    .attr("class", "graph-bg")
    .attr("x", -gridExtent / 2)
    .attr("y", -gridExtent / 2)
    .attr("width", gridExtent)
    .attr("height", gridExtent)
    .attr("fill", "url(#depsee-dot-grid)");

  function setZoomLabel(k) {
    zoomLevel.textContent = `${Math.round(k * 100)}%`;
  }

  function clearPanCursor() {
    svg.classed("panning", false);
  }

  const zoom = d3
    .zoom()
    .scaleExtent([0.15, 8])
    .filter((event) => {
      if (event.target?.closest?.(".nodes")) return false;
      return (!event.ctrlKey || event.type === "wheel") && !event.button;
    })
    .on("zoom", (event) => {
      g.attr("transform", event.transform);
      setZoomLabel(event.transform.k);
    });

  svg.call(zoom);
  setZoomLabel(1);

  svg.on("click.backdrop", (event) => {
    const t = event.target;
    if (t && t.classList && t.classList.contains("graph-bg")) {
      hideDetail();
    }
  });

  svg.on("mousedown.panCursor", (event) => {
    if (event.button !== 0) return;
    if (event.target?.closest?.(".nodes")) return;
    svg.classed("panning", true);
  });

  svg.on("touchstart.panCursor", (event) => {
    if (event.touches.length !== 1) return;
    if (event.target?.closest?.(".nodes")) return;
    svg.classed("panning", true);
  });

  d3.select(window)
    .on("mouseup.depseePanCursor", clearPanCursor)
    .on("touchend.depseePanCursor touchcancel.depseePanCursor", clearPanCursor)
    .on("blur.depseePanCursor", clearPanCursor);

  function size() {
    const r = container.getBoundingClientRect();
    return { w: Math.max(1, r.width), h: Math.max(1, r.height) };
  }

  let { w, h } = size();
  svg.attr("viewBox", [0, 0, w, h]);

  const ro = new ResizeObserver(() => {
    ({ w, h } = size());
    svg.attr("viewBox", [0, 0, w, h]);
    simulation.force("center", d3.forceCenter(w / 2, h / 2));
    simulation.alpha(0.2).restart();
  });
  ro.observe(container);

  const simulation = d3
    .forceSimulation(nodes)
    .force(
      "link",
      d3
        .forceLink(links)
        .id((d) => d.id)
        .distance(96)
        .strength(0.35)
    )
    .force("charge", d3.forceManyBody().strength(-280))
    .force("center", d3.forceCenter(w / 2, h / 2))
    .force(
      "collision",
      d3
        .forceCollide()
        .radius((d) => Math.hypot(d._bboxW / 2, d._bboxBottomY) + 8)
    );

  const link = g
    .append("g")
    .attr("class", "links")
    .selectAll("line")
    .data(links)
    .join("line")
    .attr("marker-end", "url(#depsee-arrow)");

  const node = g
    .append("g")
    .attr("class", "nodes")
    .selectAll("g")
    .data(nodes)
    .join("g")
    .call(dragBehavior(simulation))
    .on("click", (event, d) => {
      event.stopPropagation();
      showDetail(d);
    });

  node
    .append("circle")
    .attr("class", "node-dot")
    .attr("r", (d) => d._r)
    .attr("cx", 0)
    .attr("cy", 0)
    .attr("fill", (d) => severityFill(d))
    .attr("stroke", (d) => {
      if (d.transitiveExposure) return "#58a6ff";
      if (d.vulnQueryError) return "#f0883e";
      return "#0f1419";
    })
    .attr("stroke-width", (d) =>
      d.transitiveExposure || d.vulnQueryError ? 2.5 : 1.5
    );

  node
    .append("path")
    .attr("class", "node-pkg-icon")
    .attr("transform", PKG_ICON_TRANSLATE)
    .attr("d", PKG_ICON_PATH)
    .attr("fill", "none");

  node.each(function (d) {
    const x0 = -d._textBlockW / 2;
    const y2 = d._bboxBottomY - NODE_PAD_BOTTOM;
    const y1 = y2 - NODE_LINE_STEP;

    const text = d3
      .select(this)
      .append("text")
      .attr("class", "node-label");

    text
      .append("tspan")
      .attr("x", x0)
      .attr("y", y1)
      .attr("class", "node-k")
      .text(PKG_PREFIX);
    text.append("tspan").attr("class", "node-v-name").text(d._pkgVal);
    text
      .append("tspan")
      .attr("x", x0)
      .attr("dy", "1.15em")
      .attr("class", "node-k-ver")
      .text(VER_PREFIX);
    text.append("tspan").attr("class", "node-v-ver").text(d._verVal);
  });

  simulation.on("tick", () => {
    link.each(function (d) {
      const { x1, y1, x2, y2 } = linkEndpoints(d);
      d3.select(this).attr("x1", x1).attr("y1", y1).attr("x2", x2).attr("y2", y2);
    });

    node.attr("transform", (d) => `translate(${d.x},${d.y})`);
  });
}

document.addEventListener("DOMContentLoaded", loadGraph);
