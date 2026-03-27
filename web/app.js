/* global d3 */

function uniqueTypes(nodes) {
  const set = new Set();
  for (const n of nodes) {
    const t = n.type && String(n.type).trim();
    if (t) set.add(t);
  }
  return [...set].sort();
}

function colorScale(types) {
  const scheme = d3.schemeTableau10;
  if (!types.length) {
    return () => "#6e7681";
  }
  return d3.scaleOrdinal(types, scheme);
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

  status.textContent = `${nodes.length} nodes · ${links.length} links`;

  container.innerHTML = "";

  if (nodes.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = "No nodes in this SBOM graph.";
    container.appendChild(empty);
    return;
  }

  const types = uniqueTypes(nodes);
  const fill = colorScale(types);

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

  const zoom = d3
    .zoom()
    .scaleExtent([0.15, 8])
    .on("zoom", (event) => {
      g.attr("transform", event.transform);
      setZoomLabel(event.transform.k);
    });

  svg.call(zoom);
  setZoomLabel(1);

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
        .distance(64)
        .strength(0.35)
    )
    .force("charge", d3.forceManyBody().strength(-220))
    .force("center", d3.forceCenter(w / 2, h / 2))
    .force("collision", d3.forceCollide().radius(28));

  const link = g
    .append("g")
    .attr("class", "links")
    .selectAll("line")
    .data(links)
    .join("line");

  const node = g
    .append("g")
    .attr("class", "nodes")
    .selectAll("g")
    .data(nodes)
    .join("g")
    .call(dragBehavior(simulation));

  node.append("circle").attr("r", 7).attr("fill", (d) => {
    const t = d.type && String(d.type).trim();
    return t ? fill(t) : "#6e7681";
  });

  node
    .append("text")
    .attr("dx", 10)
    .attr("dy", 4)
    .text((d) => d.label || d.id);

  simulation.on("tick", () => {
    link
      .attr("x1", (d) => d.source.x)
      .attr("y1", (d) => d.source.y)
      .attr("x2", (d) => d.target.x)
      .attr("y2", (d) => d.target.y);

    node.attr("transform", (d) => `translate(${d.x},${d.y})`);
  });
}

document.addEventListener("DOMContentLoaded", loadGraph);
