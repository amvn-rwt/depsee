/**
 * D3 force-directed graph: SVG, zoom/pan, simulation, nodes, and links.
 */

import {
  LINK_MARKER_W,
  NODE_LABEL_BG_ASC,
  NODE_LABEL_BG_DESC,
  NODE_LABEL_BG_PAD_X,
  NODE_LABEL_BG_PAD_Y,
  NODE_LINE_STEP,
  NODE_PAD_BOTTOM,
  PKG_ICON_PATH,
  PKG_ICON_TRANSLATE,
  PKG_PREFIX,
  ROOT_DOT_SCALE,
  VER_PREFIX,
  severityFill,
} from "./config.js";
import { hideDetail, showDetail } from "./detailPanel.js";
import { linkEndpoints } from "./layout.js";

function dragBehavior(d3, simulation) {
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

/**
 * Renders the graph into `container` (clears it first; caller handles empty state).
 */
export function mountGraph(d3, { container, zoomLevelEl, nodes, links }) {
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
    zoomLevelEl.textContent = `${Math.round(k * 100)}%`;
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

  const ro = new ResizeObserver(() => {
    ({ w, h } = size());
    svg.attr("viewBox", [0, 0, w, h]);
    simulation.force("center", d3.forceCenter(w / 2, h / 2));
    simulation.alpha(0.2).restart();
  });
  ro.observe(container);

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
    .call(dragBehavior(d3, simulation))
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
    .attr("transform", (d) =>
      d.rootComponent
        ? `${PKG_ICON_TRANSLATE} scale(${Math.sqrt(ROOT_DOT_SCALE).toFixed(3)})`
        : PKG_ICON_TRANSLATE
    )
    .attr("d", PKG_ICON_PATH)
    .attr("fill", "none");

  node.each(function (d) {
    const x0 = -d._textBlockW / 2;
    const y2 = d._bboxBottomY - NODE_PAD_BOTTOM;
    const y1 = y2 - NODE_LINE_STEP;

    const bgTop = y1 - NODE_LABEL_BG_ASC - NODE_LABEL_BG_PAD_Y;
    const bgBottom = y2 + NODE_LABEL_BG_DESC + NODE_LABEL_BG_PAD_Y;
    d3.select(this)
      .append("rect")
      .attr("class", "node-label-bg")
      .attr("x", x0 - NODE_LABEL_BG_PAD_X)
      .attr("y", bgTop)
      .attr("width", d._textBlockW + 2 * NODE_LABEL_BG_PAD_X)
      .attr("height", bgBottom - bgTop)
      .attr("rx", 2)
      .attr("ry", 2);

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
