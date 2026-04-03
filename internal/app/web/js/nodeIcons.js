/**
 * CycloneDX component type → SVG path for the glyph inside each node circle.
 * Paths are stroke-only, roughly centered for use with translate(0,-2) in graphView.
 */

import { PKG_ICON_PATH } from "./config.js";

/** @type {Record<string, string>} */
const TYPE_PATH = {
  // Default / SBOM package style (hex nut).
  library: PKG_ICON_PATH,

  // Window with title bar.
  application:
    "M-7,-4 L7,-4 L7,7 L-7,7 Z M-7,-1 L7,-1",

  // Three vertical rails.
  framework: "M-5,-8 L-5,8 M0,-9 L0,9 M5,-8 L5,8",

  // Shipping box.
  container: "M-7,-5 L7,-5 L7,6 L-7,6 Z M-7,-2 L7,-2",

  // Sheet with dog-ear.
  file: "M-5,-8 L2,-8 L5,-5 L5,8 L-5,8 Z M2,-8 L2,-5 L5,-5",

  // IC outline + pin stubs.
  firmware:
    "M-4,-5 L4,-5 L4,5 L-4,5 Z M-6,-3 L-4,-3 M-6,0 L-4,0 M-6,3 L-4,3 M6,-3 L4,-3 M6,0 L4,0 M6,3 L4,3",

  // Handheld rectangle.
  device: "M-4,-7 L4,-7 L4,8 L-4,8 Z M-2,5 L2,5",

  // Stacked tiers.
  platform: "M-8,-5 L8,-3 M-8,1 L8,3 M-8,6 L8,8",

  // Regular octagon (gear-like).
  "operating-system":
    "M0,-7 L5,-5 L7,0 L5,5 L0,7 L-5,5 L-7,0 L-5,-5 Z",

  // Simple connector block.
  "device-driver":
    "M-3,-6 L3,-6 L3,0 L5,0 L5,5 L-5,5 L-5,0 L-3,0 Z",

  // Triangle + stem (decision / model).
  "machine-learning-model": "M0,-7 L-6,5 L6,5 Z M0,-7 L0,7",

  // Cylinder side silhouette (top arc, sides, bottom arc).
  data:
    "M-5,-3 A5,2.2 0 1 1 5,-3 M-5,-3 L-5,4 M5,-3 L5,4 M-5,4 A5,2.2 0 1 0 5,4",

  // Diamond (generic service).
  service: "M0,-6 L5,0 L0,6 L-5,0 Z",
};

/**
 * Effective CycloneDX type for icon lookup (lowercase key).
 * @param {{ type?: string, rootComponent?: boolean }} d
 * @returns {string}
 */
function effectiveTypeKey(d) {
  const raw = String(d.type ?? "").trim().toLowerCase();
  if (raw) return raw;
  if (d.rootComponent) return "application";
  return "library";
}

/**
 * SVG path `d` for the node’s center icon.
 * @param {{ type?: string, rootComponent?: boolean }} d
 * @returns {string}
 */
export function nodeIconPath(d) {
  const key = effectiveTypeKey(d);
  return TYPE_PATH[key] ?? TYPE_PATH.library;
}
