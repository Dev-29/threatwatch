// Small dependency-free chart helpers (SVG/HTML). Every mark carries a `data-tip` tooltip handled by
// one global hover layer (installTooltips). Colors come from CSS tokens so light/dark both work.
import { html, raw, esc, fmtNum } from "./ui.js";

const SEV_VAR = { critical: "--sev-critical", high: "--sev-high", medium: "--sev-medium", low: "--sev-low", info: "--sev-info" };

/** Horizontal bar list (magnitude, single hue). items: [{label, value, sub?, link?}] */
export function barList(items, { max, unit = "", empty = "No data", color = "var(--series-1)" } = {}) {
  if (!items.length) return html`<div class="empty small">${empty}</div>`;
  const m = max ?? Math.max(...items.map((i) => i.value), 1);
  return html`<div class="barlist">${items.map((i) => {
    const pct = Math.max(1.5, (i.value / m) * 100);
    const label = i.link ? html`<a href="${i.link}">${i.label}</a>` : i.label;
    return html`<div class="barlist-row" data-tip="${i.tip || `${i.label}: ${fmtNum(i.value)}${unit}`}">
      <div class="barlist-label">${label}${i.sub ? html`<span class="muted"> ${i.sub}</span>` : ""}</div>
      <div class="barlist-track"><div class="barlist-bar" style="width:${pct}%;background:${color}"></div></div>
      <div class="barlist-value">${fmtNum(i.value)}</div></div>`;
  })}</div>`;
}

/** Stacked columns by severity over time. days: [{label, values:{sev:n}}] */
export function stackedColumns(days, keys, { height = 180 } = {}) {
  const W = 640, H = height, padL = 28, padB = 22, padT = 8;
  const totals = days.map((d) => keys.reduce((s, k) => s + (d.values[k] || 0), 0));
  const maxV = Math.max(4, ...totals);
  const niceMax = Math.ceil(maxV / 4) * 4;
  const plotH = H - padB - padT, plotW = W - padL - 4;
  const slot = plotW / days.length, bw = Math.min(28, slot * 0.62);
  const y = (v) => padT + plotH - (v / niceMax) * plotH;
  let grid = "";
  for (let i = 0; i <= 4; i++) {
    const v = (niceMax / 4) * i, yy = y(v);
    grid += `<line x1="${padL}" x2="${W - 4}" y1="${yy}" y2="${yy}" class="grid"/>`;
    grid += `<text x="${padL - 6}" y="${yy + 3}" class="axis" text-anchor="end">${v}</text>`;
  }
  let bars = "";
  days.forEach((d, i) => {
    const x = padL + i * slot + (slot - bw) / 2;
    let acc = 0;
    const present = keys.filter((k) => d.values[k]);
    present.forEach((k, j) => {
      const v = d.values[k];
      const y0 = y(acc), y1 = y(acc + v);
      const h = Math.max(1, y0 - y1 - (j > 0 ? 2 : 0)); // 2px surface gap between stacked fills
      const top = j === present.length - 1;
      const r = top ? Math.min(4, h, bw / 2) : 0;
      const yTop = y1, yBot = yTop + h;
      const path = r
        ? `M${x},${yBot}V${yTop + r}Q${x},${yTop} ${x + r},${yTop}H${x + bw - r}Q${x + bw},${yTop} ${x + bw},${yTop + r}V${yBot}Z`
        : `M${x},${yBot}V${yTop}H${x + bw}V${yBot}Z`;
      bars += `<path d="${path}" style="fill:var(${SEV_VAR[k]})"/>`;
      acc += v;
    });
    const tip = `${d.label}\n` + (totals[i] ? keys.filter((k) => d.values[k]).map((k) => `${k}: ${d.values[k]}`).join("\n") : "no alerts");
    bars += `<rect x="${padL + i * slot}" y="${padT}" width="${slot}" height="${plotH}" class="hit" data-tip="${esc(tip)}"/>`;
    if (i % 2 === 0 || days.length <= 8) {
      bars += `<text x="${x + bw / 2}" y="${H - 6}" class="axis" text-anchor="middle">${esc(d.short || d.label)}</text>`;
    }
  });
  return raw(`<svg viewBox="0 0 ${W} ${H}" class="chart" role="img" aria-label="Alerts per day by severity">${grid}${bars}</svg>`);
}

export function legend(keys, { swatch = (k) => `var(${SEV_VAR[k]})` } = {}) {
  return html`<div class="legend">${keys.map((k) => html`<span><i style="background:${swatch(k)}"></i>${k}</span>`)}</div>`;
}

/** Sequential ramp (one hue, light -> dark) for heat-map cells. t in [0,1]. */
const RAMP = ["var(--seq-100)", "var(--seq-200)", "var(--seq-300)", "var(--seq-400)", "var(--seq-500)", "var(--seq-600)", "var(--seq-700)"];
export function seqColor(t) {
  if (t <= 0) return "var(--surface-2)";
  return RAMP[Math.min(RAMP.length - 1, Math.floor(t * RAMP.length))];
}
export function seqInk(t) { return t >= 0.55 ? "var(--seq-ink-hi)" : "var(--text-1)"; }

/** Single stat tile. */
export function stat(label, value, { sub, tone, link } = {}) {
  const inner = html`<div class="stat-label">${label}</div><div class="stat-value ${tone ? "tone-" + tone : ""}">${value}</div>${sub ? html`<div class="stat-sub">${sub}</div>` : ""}`;
  return link ? html`<a class="stat" href="${link}">${inner}</a>` : html`<div class="stat">${inner}</div>`;
}

/** Proportional severity strip (e.g. findings by severity) with labels. */
export function sevStrip(counts, keys = ["critical", "high", "medium", "low", "info"]) {
  const total = keys.reduce((s, k) => s + (counts[k] || 0), 0);
  if (!total) return html`<div class="muted small">No findings</div>`;
  return html`<div class="sevstrip">${keys.filter((k) => counts[k]).map((k) =>
    html`<span style="flex:${counts[k]};background:var(${SEV_VAR[k]})" data-tip="${k}: ${counts[k]}"></span>`)}</div>
    <div class="legend small">${keys.filter((k) => counts[k]).map((k) => html`<span><i style="background:var(${SEV_VAR[k]})"></i>${k} ${counts[k]}</span>`)}</div>`;
}

export function installTooltips() {
  const tip = document.getElementById("tip");
  let active = null;
  document.addEventListener("mouseover", (e) => {
    const t = e.target.closest("[data-tip]");
    if (!t) { tip.hidden = true; active = null; return; }
    active = t;
    tip.textContent = t.getAttribute("data-tip");
    tip.hidden = false;
  });
  document.addEventListener("mousemove", (e) => {
    if (!active) return;
    const pad = 14, r = tip.getBoundingClientRect();
    let x = e.clientX + pad, y = e.clientY + pad;
    if (x + r.width > window.innerWidth - 8) x = e.clientX - r.width - pad;
    if (y + r.height > window.innerHeight - 8) y = e.clientY - r.height - pad;
    tip.style.transform = `translate(${x}px, ${y}px)`;
  });
  document.addEventListener("scroll", () => { tip.hidden = true; active = null; }, true);
}
