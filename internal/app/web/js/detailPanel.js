/** Right-hand node detail panel (#detail). */

const PANEL_ID = "detail";

function escapeHtml(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function hideDetail() {
  const panel = document.getElementById(PANEL_ID);
  if (!panel) return;
  panel.hidden = true;
  panel.innerHTML = "";
}

export function showDetail(d) {
  const panel = document.getElementById(PANEL_ID);
  if (!panel) return;
  panel.hidden = false;

  const esc = escapeHtml;
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
