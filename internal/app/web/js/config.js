/**
 * Visual and layout constants for the dependency graph.
 * Keep marker / stroke values in sync with styles.css where noted.
 */

export const DOT_R = 20;

/** Hex package glyph; centroid at (0,0) after PKG_ICON_TRANSLATE. */
export const PKG_ICON_PATH =
  "M0,-6 L9,-2 L9,6 L0,10 L-9,6 L-9,-2 Z M0,-6 L0,10 M-9,-2 L0,2 L9,-2";

export const PKG_ICON_TRANSLATE = "translate(0,-2)";

/** Must match `.links line` stroke-width in styles.css. */
export const LINK_STROKE_PX = 1.5;

/** Must match `markerWidth` on `#depsee-arrow` (`markerUnits="strokeWidth"`). */
export const LINK_MARKER_W = 6;

export const LINK_ARROW_LEN = LINK_MARKER_W * LINK_STROKE_PX;

export const DOT_GUTTER = 6;
export const NODE_PAD_X = 12;
export const NODE_MAX_W = 320;
export const NODE_PAD_BOTTOM = 4;
export const NODE_LINE_STEP = 13;

export const FONT_K11 =
  '500 11px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
export const FONT_V11 =
  '600 11px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
export const FONT_K10 =
  '500 10px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';
export const FONT_V10 =
  '400 10px system-ui, -apple-system, "Segoe UI", Roboto, sans-serif';

export const PKG_PREFIX = "package: ";
export const VER_PREFIX = "version: ";

/** Node fill from NVD severity / exposure. */
export function severityFill(d) {
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

export function nodeRadius(d) {
  const br = Number(d.blastRadius) || 0;
  return DOT_R * (1 + Math.min(1.25, Math.sqrt(br) * 0.14));
}
