/**
 * Canvas text measurement and per-node layout fields for D3 collision and labels.
 */

import {
  DOT_GUTTER,
  DOT_R,
  FONT_K10,
  FONT_K11,
  FONT_V10,
  FONT_V11,
  LINK_ARROW_LEN,
  NODE_LINE_STEP,
  NODE_MAX_W,
  NODE_PAD_BOTTOM,
  NODE_PAD_X,
  PKG_PREFIX,
  VER_PREFIX,
  nodeRadius,
} from "./config.js";

let measureCtx;

function getMeasureContext() {
  if (!measureCtx) {
    const c = document.createElement("canvas");
    measureCtx = c.getContext("2d");
  }
  return measureCtx;
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

/**
 * Sets _r, _pkgVal, _verVal, _textBlockW, _bboxW, _bboxH, _bboxBottomY on each node.
 */
export function prepareNodes(nodes) {
  const ctx = getMeasureContext();
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
    d._bboxBottomY = r + DOT_GUTTER + textStackH + NODE_PAD_BOTTOM;
  }
}

/** Shorten link segment to node edges; line ends at arrow base (marker refX=0). */
export function linkEndpoints(d, fallbackR = DOT_R) {
  const sx = d.source.x;
  const sy = d.source.y;
  const tx = d.target.x;
  const ty = d.target.y;
  const rs = d.source._r ?? fallbackR;
  const rt = d.target._r ?? fallbackR;
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
