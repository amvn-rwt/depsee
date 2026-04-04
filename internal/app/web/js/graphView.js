/**
 * D3 force-directed graph: SVG, zoom/pan, simulation, nodes, and links.
 */

import {
  CVE_PIP_ARC_HALF,
  CVE_PIP_ORBIT,
  CVE_PIP_R,
  CVE_PIP_R_WIDE,
} from "./cvePips.js";
import {
  LINK_MARKER_W,
  NODE_LABEL_BG_ASC,
  NODE_LABEL_BG_DESC,
  NODE_LABEL_BG_PAD_X,
  NODE_LABEL_BG_PAD_Y,
  NODE_LINE_STEP,
  NODE_PAD_BOTTOM,
  PKG_ICON_TRANSLATE,
  PKG_PREFIX,
  ROOT_DOT_SCALE,
  VER_PREFIX,
  severityFill,
} from "./config.js";
import { hideDetail, showDetail } from "./detailPanel.js";
import { linkEndpoints } from "./layout.js";
import { nodeIconPath } from "./nodeIcons.js";

/**
 * @param {object[]} links Links with forceLink-resolved `source` / `target` (node objects with `.id`).
 * @returns {{ rev: Map<string, string[]>, fwd: Map<string, string[]> }}
 *   rev: targetId → sourceIds (dependents). fwd: sourceId → targetIds (dependencies).
 */
function buildAdjacencyIdMaps(links) {
  const rev = new Map();
  const fwd = new Map();
  for (const L of links) {
    const s = L.source && typeof L.source === "object" ? L.source.id : L.source;
    const t = L.target && typeof L.target === "object" ? L.target.id : L.target;
    if (s == null || t == null) continue;
    const sid = String(s);
    const tid = String(t);
    if (!rev.has(tid)) rev.set(tid, []);
    rev.get(tid).push(sid);
    if (!fwd.has(sid)) fwd.set(sid, []);
    fwd.get(sid).push(tid);
  }
  return { rev, fwd };
}

/**
 * All node ids that transitively depend on `id` (BFS along target → source), including `id`.
 * @param {string} id
 * @param {Map<string, string[]>} rev
 * @returns {Set<string>}
 */
function collectUpstreamIds(id, rev) {
  const anchor = String(id);
  const out = new Set([anchor]);
  const q = [anchor];
  for (let i = 0; i < q.length; i++) {
    const cur = q[i];
    const srcs = rev.get(cur);
    if (!srcs) continue;
    for (const s of srcs) {
      if (!out.has(s)) {
        out.add(s);
        q.push(s);
      }
    }
  }
  return out;
}

/**
 * All node ids reachable from `id` following source → target, including `id`.
 * @param {string} id
 * @param {Map<string, string[]>} fwd
 * @returns {Set<string>}
 */
function collectDownstreamIds(id, fwd) {
  const anchor = String(id);
  const out = new Set([anchor]);
  const q = [anchor];
  for (let i = 0; i < q.length; i++) {
    const cur = q[i];
    const tgts = fwd.get(cur);
    if (!tgts) continue;
    for (const t of tgts) {
      if (!out.has(t)) {
        out.add(t);
        q.push(t);
      }
    }
  }
  return out;
}

/**
 * @typedef {object} MountedGraphAPI
 * @property {(q: string) => object[]} findNodesByQuery
 * @property {(q: string) => object | null} findNodeByQuery
 * @property {(d: object) => void} focusNode
 * @property {() => void} destroy
 */

/**
 * Renders the graph into `container` (clears it first; caller handles empty state).
 * @returns {MountedGraphAPI}
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

  const PANNING_HTML_CLASS = "depsee-graph-panning";

  function clearPanCursor() {
    svg.classed("panning", false);
    document.documentElement.classList.remove(PANNING_HTML_CLASS);
  }

  function setPanningUi(on) {
    svg.classed("panning", on);
    document.documentElement.classList.toggle(PANNING_HTML_CLASS, on);
  }

  const zoom = d3
    .zoom()
    .scaleExtent([0.15, 8])
    .filter((event) => {
      if (event.target?.closest?.(".graph-search")) return false;
      if (event.target?.closest?.(".nodes")) return false;
      return (!event.ctrlKey || event.type === "wheel") && !event.button;
    })
    .on("zoom", (event) => {
      g.attr("transform", event.transform);
      setZoomLabel(event.transform.k);
    })
    .on("start", (event) => {
      const src = event.sourceEvent;
      if (!src) return;
      const t = src.type;
      if (t !== "mousedown" && t !== "touchstart") return;
      if (src.target?.closest?.(".nodes")) return;
      setPanningUi(true);
    })
    .on("end", () => {
      clearPanCursor();
    });

  svg.call(zoom);
  setZoomLabel(1);

  svg.on("click.backdrop", (event) => {
    const t = event.target;
    if (t && t.classList && t.classList.contains("graph-bg")) {
      hideDetail();
    }
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
        .radius((d) => {
          const halfX =
            d._cvePips?.length > 0
              ? Math.max(d._bboxW / 2, d._r + 14)
              : d._bboxW / 2;
          return Math.hypot(halfX, d._bboxBottomY) + 8;
        })
    );
  // Avoid the default timer; we settle with explicit tick() and sync the DOM once at the end.
  simulation.stop();

  const link = g
    .append("g")
    .attr("class", "links")
    .selectAll("line")
    .data(links)
    .join("line")
    .attr("marker-end", "url(#depsee-arrow)");

  const nodesLayer = g.append("g").attr("class", "nodes");
  const node = nodesLayer.selectAll("g").data(nodes).join("g");

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
    .attr("d", (d) => nodeIconPath(d))
    .attr("fill", "none");

  node.each(function (d) {
    const pips = d._cvePips;
    if (!pips?.length) return;
    const orbit = d._r + CVE_PIP_ORBIT;
    const pipRoot = d3
      .select(this)
      .append("g")
      .attr("class", "node-cve-pips")
      .attr("pointer-events", "none");
    const pipG = pipRoot
      .selectAll("g")
      .data(pips)
      .join("g")
      .attr("class", "node-cve-pip")
      .attr("transform", (_, i) => {
        const t = pips.length === 1 ? 0 : (i / (pips.length - 1)) * 2 - 1;
        const theta = t * CVE_PIP_ARC_HALF;
        return `translate(${Math.cos(theta) * orbit},${Math.sin(theta) * orbit})`;
      });
    pipG
      .append("circle")
      .attr("class", "node-cve-pip-disc")
      .attr("r", (p) => (p.label.length > 1 ? CVE_PIP_R_WIDE : CVE_PIP_R))
      .attr("fill", (p) => p.fill);
    pipG
      .append("text")
      .attr("class", "node-cve-pip-num")
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "central")
      .text((p) => p.label);
  });

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

  // Manual `simulation.tick()` does not dispatch "tick" (only the internal timer does), so we must push positions to the DOM ourselves after settling.
  function syncGraphPositions() {
    link.each(function (d) {
      const { x1, y1, x2, y2 } = linkEndpoints(d);
      d3.select(this).attr("x1", x1).attr("y1", y1).attr("x2", x2).attr("y2", y2);
    });
    node.attr("transform", (d) => `translate(${d.x},${d.y})`);
  }

  simulation.on("tick", syncGraphPositions);

  // Settle layout synchronously (no visible animation), then pin nodes so resize / panel toggle does not restart the sim.
  let settleSteps = 0;
  while (simulation.alpha() > 0.001 && settleSteps++ < 800) {
    simulation.tick();
  }
  syncGraphPositions();
  for (const n of nodes) {
    n.fx = n.x;
    n.fy = n.y;
  }
  simulation.stop();

  const { rev: graphPathRev, fwd: graphPathFwd } = buildAdjacencyIdMaps(links);

  /**
   * @param {object} L
   * @returns {{ sid: string, tid: string } | null}
   */
  function linkEndpointIds(L) {
    const s = L.source && typeof L.source === "object" ? L.source.id : L.source;
    const t = L.target && typeof L.target === "object" ? L.target.id : L.target;
    if (s == null || t == null) return null;
    return { sid: String(s), tid: String(t) };
  }

  function clearPathHighlight() {
    node
      .classed("graph-dim", false)
      .classed("graph-path-anchor", false)
      .classed("graph-path-up-node", false)
      .classed("graph-path-down-node", false)
      .classed("graph-path-vuln-direct", false)
      .classed("graph-path-vuln-transitive", false);
    link.classed("graph-dim", false).classed("graph-path-up", false).classed("graph-path-down", false);
  }

  /**
   * Highlights upstream (dependents) and downstream (dependencies) induced subgraphs for `anchorNode`.
   * Pass `null` to clear.
   * @param {object | null} anchorNode
   */
  function setPathHighlight(anchorNode) {
    if (anchorNode == null) {
      clearPathHighlight();
      return;
    }
    const aid = String(anchorNode.id);
    const upIds = collectUpstreamIds(aid, graphPathRev);
    const downIds = collectDownstreamIds(aid, graphPathFwd);
    const anyIds = new Set(upIds);
    for (const x of downIds) anyIds.add(x);

    node.each(function (d) {
      const id = String(d.id);
      const g = d3.select(this);
      g.classed("graph-dim", !anyIds.has(id));
      g.classed("graph-path-anchor", id === aid);
      g.classed("graph-path-up-node", upIds.has(id) && id !== aid);
      g.classed("graph-path-down-node", downIds.has(id) && id !== aid);
      const direct = Number(d.cveCount) > 0;
      const te = Boolean(d.transitiveExposure);
      g.classed("graph-path-vuln-direct", anyIds.has(id) && direct);
      g.classed("graph-path-vuln-transitive", anyIds.has(id) && te && !direct);
    });

    link.each(function (L) {
      const ends = linkEndpointIds(L);
      const el = d3.select(this);
      if (!ends) {
        el.classed("graph-dim", true).classed("graph-path-up", false).classed("graph-path-down", false);
        return;
      }
      const inUp = upIds.has(ends.sid) && upIds.has(ends.tid);
      const inDown = downIds.has(ends.sid) && downIds.has(ends.tid);
      const hl = inUp || inDown;
      el.classed("graph-dim", !hl).classed("graph-path-up", inUp).classed("graph-path-down", inDown);
    });
  }

  const nodesLayerEl = nodesLayer.node();
  /** @type {object | null} */
  let hoverPathNode = null;
  /** @type {object | null} */
  let focusPathNode = null;
  /** @type {object | null} */
  let detailPathNode = null;
  let pathPointerLeaveRafId = 0;
  let pathFocusOutRafId = 0;
  const pathInteractAbort = new AbortController();

  /**
   * @param {EventTarget | null} el
   * @returns {SVGGElement | null}
   */
  function graphNodeGroupFromEl(el) {
    if (!el || !("closest" in el) || typeof el.closest !== "function") return null;
    const g = el.closest(".nodes > g");
    return g instanceof SVGGElement ? g : null;
  }

  function cancelPathPointerLeaveRaf() {
    if (pathPointerLeaveRafId) {
      cancelAnimationFrame(pathPointerLeaveRafId);
      pathPointerLeaveRafId = 0;
    }
  }

  function cancelPathFocusOutRaf() {
    if (pathFocusOutRafId) {
      cancelAnimationFrame(pathFocusOutRafId);
      pathFocusOutRafId = 0;
    }
  }

  function syncPathHighlightFromState() {
    if (focusPathNode) {
      setPathHighlight(focusPathNode);
      return;
    }
    if (hoverPathNode) {
      setPathHighlight(hoverPathNode);
      return;
    }
    if (detailPathNode) {
      setPathHighlight(detailPathNode);
      return;
    }
    clearPathHighlight();
  }

  function onDetailHidden() {
    detailPathNode = null;
    syncPathHighlightFromState();
  }
  document.addEventListener("depsee:detail-hidden", onDetailHidden, {
    signal: pathInteractAbort.signal,
  });

  if (nodesLayerEl) {
    nodesLayerEl.addEventListener(
      "focusin",
      (ev) => {
        const grp = graphNodeGroupFromEl(ev.target);
        if (!grp || !nodesLayerEl.contains(grp)) return;
        focusPathNode = grp.__data__;
        syncPathHighlightFromState();
      },
      { signal: pathInteractAbort.signal }
    );
    nodesLayerEl.addEventListener(
      "focusout",
      (ev) => {
        const rt = ev.relatedTarget;
        if (graphNodeGroupFromEl(rt) && nodesLayerEl.contains(rt)) return;
        cancelPathFocusOutRaf();
        pathFocusOutRafId = requestAnimationFrame(() => {
          pathFocusOutRafId = 0;
          const ae = document.activeElement;
          if (graphNodeGroupFromEl(ae) && nodesLayerEl.contains(ae)) return;
          focusPathNode = null;
          syncPathHighlightFromState();
        });
      },
      { signal: pathInteractAbort.signal }
    );
  }

  node
    .attr("tabindex", 0)
    .on("click", (event, d) => {
      event.stopPropagation();
      detailPathNode = d;
      showDetail(d);
      syncPathHighlightFromState();
    })
    .on("pointerenter", (_event, d) => {
      cancelPathPointerLeaveRaf();
      hoverPathNode = d;
      syncPathHighlightFromState();
    })
    .on("pointerleave", (event) => {
      const rt = event.relatedTarget;
      if (graphNodeGroupFromEl(rt) && nodesLayerEl?.contains(rt)) return;
      const x = event.clientX;
      const y = event.clientY;
      cancelPathPointerLeaveRaf();
      pathPointerLeaveRafId = requestAnimationFrame(() => {
        pathPointerLeaveRafId = 0;
        const top = document.elementFromPoint(x, y);
        if (graphNodeGroupFromEl(top) && nodesLayerEl?.contains(top)) return;
        hoverPathNode = null;
        syncPathHighlightFromState();
      });
    });

  const ro = new ResizeObserver(() => {
    ({ w, h } = size());
    svg.attr("viewBox", [0, 0, w, h]);
  });
  ro.observe(container);

  /**
   * All nodes whose label, name, or id contains the query (stable graph order).
   * @param {string} q
   * @returns {object[]}
   */
  function findNodesByQuery(q) {
    const s = String(q ?? "").trim().toLowerCase();
    if (!s) return [];
    const out = [];
    for (const n of nodes) {
      const label = String(n.label ?? "").toLowerCase();
      const name = String(n.name ?? "").toLowerCase();
      const id = String(n.id ?? "").toLowerCase();
      if (label.includes(s) || name.includes(s) || id.includes(s)) {
        out.push(n);
      }
    }
    return out;
  }

  /**
   * @param {string} q
   * @returns {object | null}
   */
  function findNodeByQuery(q) {
    const m = findNodesByQuery(q);
    return m.length ? m[0] : null;
  }

  /**
   * Opens the detail panel and pans/zooms so the node sits in the graph viewport center
   * (after flex reflow when the panel is visible).
   * @param {object} d
   */
  function focusNode(d) {
    if (
      d == null ||
      typeof d.x !== "number" ||
      typeof d.y !== "number" ||
      Number.isNaN(d.x) ||
      Number.isNaN(d.y)
    ) {
      return;
    }
    detailPathNode = d;
    showDetail(d);
    const applyCenter = () => {
      const { w: rw, h: rh } = size();
      svg.attr("viewBox", [0, 0, rw, rh]);
      const el = svg.node();
      if (!el) return;
      const t = d3.zoomTransform(el);
      const k = t.k;
      const cx = rw / 2;
      const cy = rh / 2;
      const next = d3.zoomIdentity.translate(cx - k * d.x, cy - k * d.y).scale(k);
      svg.interrupt();
      svg
        .transition()
        .duration(650)
        .ease(d3.easeCubicOut)
        .call(zoom.transform, next);
    };
    requestAnimationFrame(() => requestAnimationFrame(applyCenter));
    syncPathHighlightFromState();
  }

  function destroy() {
    cancelPathPointerLeaveRaf();
    cancelPathFocusOutRaf();
    pathInteractAbort.abort();
    hoverPathNode = null;
    focusPathNode = null;
    detailPathNode = null;
    clearPathHighlight();
    clearPanCursor();
    ro.disconnect();
    d3.select(window)
      .on("mouseup.depseePanCursor", null)
      .on("touchend.depseePanCursor touchcancel.depseePanCursor", null)
      .on("blur.depseePanCursor", null);
  }

  return { findNodesByQuery, findNodeByQuery, focusNode, destroy };
}
