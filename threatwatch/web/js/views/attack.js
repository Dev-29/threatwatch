import { api } from "../api.js";
import { seqColor, seqInk } from "../charts.js";
import { html, mount, sectionHead } from "../ui.js";

export async function render(main) {
  const m = await api("/intel/attack/matrix");
  const max = Math.max(1, ...m.tactics.flatMap((t) => t.techniques.map((x) => x.count)));
  // log scale so a few huge techniques don't wash out the rest
  const t = (n) => Math.log1p(n) / Math.log1p(max);
  mount(main, html`
    ${sectionHead("MITRE ATT&CK coverage", `${m.total_techniques} techniques observed across active indicators. Click a technique to see its IOCs.`)}
    <div class="card">
      <div class="ramp" style="margin-bottom:12px"><span class="muted">Fewer indicators</span>
        ${[0.05, 0.2, 0.35, 0.5, 0.65, 0.8, 0.95].map((v) => html`<i style="background:${seqColor(v)}"></i>`)}
        <span class="muted">More (log scale)</span></div>
      ${m.total_techniques ? html`<div class="matrix" style="--cols:${m.tactics.length}">${m.tactics.map((col) => html`
        <div class="matrix-col"><h4>${col.name}<span>${col.techniques.length} techniques</span></h4>
          ${col.techniques.map((x) => html`<a class="tcell" href="#/intel?technique=${x.id}"
              style="background:${seqColor(t(x.count))};color:${seqInk(t(x.count))};border-color:transparent"
              data-tip="${x.id} ${x.name}\n${x.count.toLocaleString()} indicators\n${x.tactics.join(", ")}"><b>${x.id}</b>${x.name}</a>`)}
        </div>`)}</div>` : html`<div class="empty">No indicators mapped yet - collect feeds first.</div>`}
    </div>
    <p class="muted small">Mapping is rule-based and explainable: feed threat type (e.g. C2 → T1071/T1573), malware family behaviour
      (stealers → T1555.003/T1539, ransomware → T1486/T1490) and indicator type. Feeds that ship technique IDs (AlienVault OTX)
      are passed through. See docs/SCORING.md.</p>`);
}
