/** Right-hand node detail panel (#detail). */

const PANEL_ID = "detail";

/** Maps purl `pkg:` type segment to a short UI label. */
const PURL_TYPE_LABEL = {
  cargo: "crates",
  composer: "Composer",
  deb: "deb",
  gem: "RubyGems",
  generic: "Generic",
  golang: "Go",
  hex: "Hex",
  maven: "Maven",
  npm: "npm",
  nuget: "NuGet",
  pypi: "PyPI",
  rpm: "rpm",
};

/**
 * Escapes text for safe insertion into HTML.
 * @param {unknown} s
 * @returns {string}
 */
function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

/**
 * Derives a package-ecosystem label from a node id (often a purl) or component type.
 * @param {{ id?: string, type?: string }} d
 * @returns {string | null}
 */
function ecosystemLabel(d) {
  const id = String(d.id ?? "");
  const m = id.match(/^pkg:([^@/?#]+)/i);
  if (m) {
    const t = m[1].toLowerCase();
    return PURL_TYPE_LABEL[t] ?? t.toUpperCase();
  }
  const ty = String(d.type ?? "").trim();
  if (ty) {
    return ty.charAt(0).toUpperCase() + ty.slice(1);
  }
  return null;
}

/**
 * CSS class for the severity pill (depsee severity colors).
 * @param {string | undefined} severity
 * @returns {string}
 */
function severityPillClass(severity) {
  const s = String(severity ?? "UNKNOWN").toUpperCase();
  if (s === "CRITICAL") return "detail-pill-sev detail-pill-sev-critical";
  if (s === "HIGH") return "detail-pill-sev detail-pill-sev-high";
  if (s === "MEDIUM") return "detail-pill-sev detail-pill-sev-medium";
  if (s === "LOW") return "detail-pill-sev detail-pill-sev-low";
  if (s === "NONE") return "detail-pill-sev detail-pill-sev-none";
  if (s === "EXPOSED") return "detail-pill-sev detail-pill-sev-exposed";
  return "detail-pill-sev detail-pill-sev-unknown";
}

/**
 * Optional extra class for max CVSS metric value by score band.
 * @param {number | undefined} score
 * @returns {string}
 */
function cvssValueClass(score) {
  if (score == null || Number.isNaN(score)) return "";
  if (score >= 9) return " detail-metric-value-accent-critical";
  if (score >= 7) return " detail-metric-value-accent-high";
  if (score >= 4) return " detail-metric-value-accent-medium";
  if (score > 0) return " detail-metric-value-accent-low";
  return "";
}

/**
 * Hides the detail panel and clears its contents.
 */
export function hideDetail() {
  const panel = document.getElementById(PANEL_ID);
  if (!panel) return;
  panel.hidden = true;
  panel.innerHTML = "";
  document.dispatchEvent(new CustomEvent("depsee:detail-hidden"));
}

/**
 * Renders node detail: header, severity/ecosystem pills, 2×2 metrics, then CVE list.
 * @param {Record<string, unknown>} d Graph node payload from `/api/graph`.
 */
export function showDetail(d) {
  const panel = document.getElementById(PANEL_ID);
  if (!panel) return;
  panel.hidden = false;

  const esc = escapeHtml;
  const cves = Array.isArray(d.cves) ? d.cves : [];
  const sevRaw = String(d.severity ?? "").trim();
  const sevDisplay = sevRaw ? sevRaw.toUpperCase() : "UNKNOWN";

  const eco = ecosystemLabel(d);
  const pills = [
    `<span class="${severityPillClass(sevRaw)}">${esc(sevDisplay)}</span>`,
  ];
  if (eco) {
    pills.push(`<span class="detail-pill-type">${esc(eco)}</span>`);
  }

  const cveCount = Number(d.cveCount) || 0;
  const maxCvss = d.maxCvss;
  const maxCvssNum =
    typeof maxCvss === "number" && !Number.isNaN(maxCvss) ? maxCvss : null;
  const maxCvssStr =
    maxCvssNum != null ? String(maxCvssNum) : esc("\u2014");

  const blast = Number(d.blastRadius) || 0;
  const depWord = blast === 1 ? "dependent" : "dependents";

  const riskStr =
    d.riskScore != null && typeof d.riskScore === "number" && !Number.isNaN(d.riskScore)
      ? d.riskScore.toFixed(1)
      : esc("\u2014");

  const exposureLine = d.transitiveExposure
    ? '<p class="detail-exposure">Transitive exposure (via dependency)</p>'
    : "";

  const queryBanner =
    d.vulnQueryError === true
      ? '<p class="detail-banner detail-banner-warn">CVE lookup failed for this package.</p>'
      : "";

  const cveBlock =
    cves.length === 0
      ? '<p class="detail-cve-empty">No CVE rows (clean or not queried).</p>'
      : `<ul class="detail-cve-list">${cves
          .map(
            (c) =>
              `<li><span class="detail-cve-line"><strong>${esc(c.id)}</strong> · CVSS ${esc(
                c.baseScore ?? "\u2014"
              )} ${esc((c.baseSeverity || "").toUpperCase())}</span></li>`
          )
          .join("")}</ul>`;

  panel.innerHTML = `
    <div class="detail-head">
      <button type="button" class="detail-close" aria-label="Close panel">\u00d7</button>
      <h2 class="detail-title">${esc(d.label || d.id)}</h2>
      <div class="detail-pills" role="list">${pills
        .map((p) => `<span role="listitem">${p}</span>`)
        .join("")}</div>
    </div>
    ${queryBanner}
    <div class="detail-metrics" role="group" aria-label="Vulnerability metrics">
      <div class="detail-metric">
        <div class="detail-metric-label">Total CVEs</div>
        <div class="detail-metric-value">${esc(String(cveCount))}</div>
      </div>
      <div class="detail-metric">
        <div class="detail-metric-label">Max CVSS</div>
        <div class="detail-metric-value${cvssValueClass(maxCvssNum)}">${maxCvssStr}</div>
      </div>
      <div class="detail-metric">
        <div class="detail-metric-label">Blast radius</div>
        <div class="detail-metric-value">${esc(String(blast))}</div>
        <div class="detail-metric-sub">${esc(depWord)}</div>
      </div>
      <div class="detail-metric">
        <div class="detail-metric-label">Risk score</div>
        <div class="detail-metric-value detail-metric-value-risk">${riskStr}</div>
      </div>
    </div>
    ${exposureLine}
    <div class="detail-cve-section">
      <div class="detail-section-label">CVEs</div>
      ${cveBlock}
    </div>
  `;

  const btn = panel.querySelector(".detail-close");
  if (btn) btn.addEventListener("click", hideDetail);
}
