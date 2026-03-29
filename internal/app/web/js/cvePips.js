/**
 * Per-severity CVE counts for on-node badges (digits only).
 * Matches CVSS-style labels from NVD; colors align with severityFill.
 */

const ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

const SEVERITY_FILL = {
  CRITICAL: "#f85149",
  HIGH: "#f0883e",
  MEDIUM: "#d29922",
  LOW: "#9ece6a",
};

function normalizeSeverity(raw) {
  const s = String(raw || "")
    .trim()
    .toUpperCase();
  if (s === "MODERATE") return "MEDIUM";
  return s;
}

/**
 * @returns {{ severity: string, count: number, fill: string, label: string }[]}
 */
export function buildCvePipList(node) {
  const fromApi = node.cveSeverityCounts;
  if (fromApi && typeof fromApi === "object") {
    const out = [];
    for (const sev of ORDER) {
      const n = Number(fromApi[sev]) || 0;
      if (n < 1) continue;
      out.push({
        severity: sev,
        count: n,
        fill: SEVERITY_FILL[sev],
        label: n > 9 ? "9+" : String(n),
      });
    }
    return out;
  }

  const cves = node.cves;
  if (!Array.isArray(cves) || cves.length === 0) {
    return [];
  }

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const c of cves) {
    const s = normalizeSeverity(c.baseSeverity);
    if (counts[s] !== undefined) counts[s]++;
  }

  const out = [];
  for (const sev of ORDER) {
    const n = counts[sev];
    if (n < 1) continue;
    out.push({
      severity: sev,
      count: n,
      fill: SEVERITY_FILL[sev],
      label: n > 9 ? "9+" : String(n),
    });
  }
  return out;
}

/** Gap from node circle edge to pip center (px). */
export const CVE_PIP_ORBIT = 4;
/** Circle radius for single-digit pips (px). */
export const CVE_PIP_R = 7;
/** Slightly larger for "9+". */
export const CVE_PIP_R_WIDE = 8;
/** Half arc (radians) on the right side of the node for spreading pips. */
export const CVE_PIP_ARC_HALF = (38 * Math.PI) / 180;
