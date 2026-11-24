/* Stage 5 page: Supply-chain signals (M2). Backend: guardian/v2/stages/s05_signals.py */
G.page("signals", {
  title: "Supply-chain signals",
  async render(el, ctx) {
    G.header(el, ctx, { title: "Supply-chain signals", subtitle: "risks with no CVE: how packages, images and CI are pulled in" });
    const r = ctx.result;
    if (!r) { G.html(el, '<div class="note">Not run yet. Press <b>Run this stage</b> (needs stage 2).</div>'); return; }
    const c = r.counts, br = c.by_risk || {};
    G.tiles(el, [
      { label: "signals", value: c.total, tone: "info" }, { label: "critical / high", value: (br.critical || 0) + (br.high || 0), tone: "high" },
      { label: "medium", value: br.medium || 0, tone: "med" }, { label: "low", value: br.low || 0, tone: "low" },
      ...Object.entries(c.by_category || {}).map(([k, v]) => ({ label: `category: ${k}`, value: v })),
    ]);
    G.card(el, { title: "Rule sets that ran", body: Object.entries(r.sources).map(([k, v]) => `<div>${String(v).startsWith("ran") ? G.chip("verified", "ran") : G.chip("not-run", "not run")} <b>${G.esc(k.replace(/_/g, " "))}</b> <span class="muted">${G.esc(v)}</span></div>`).join("") + `<p class="muted">${G.esc(r.note)}</p>` });
    if (!r.signals.length) { G.html(el, '<div class="note">No signal fired. Every rule that ran is listed above, so this means "checked and nothing found", not "not checked".</div>'); }
    const groups = {};
    r.signals.forEach((s) => (groups[s.rule] = groups[s.rule] || []).push(s));
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    Object.entries(groups).sort((a, b) => (order[a[1][0].risk] ?? 9) - (order[b[1][0].risk] ?? 9)).forEach(([rule, list]) => {
      const sec = G.html(el, `<div class="section"><h2>${G.esc(rule.replace(/_/g, " "))} <span class="muted">(${list.length})</span></h2></div>`);
      list.forEach((s) => G.card(sec, {
        tone: G.sevTone(s.risk),
        body: `<div class="row">${G.badge(s.risk || "unknown", G.sevTone(s.risk))} ${G.chip(s.grade === "verified" ? "verified" : s.grade === "heuristic" ? "derived" : "unknown", s.grade)} <b>${G.esc(s.title)}</b> <span class="muted mono">${G.esc(s.id)}</span></div>
          <div class="muted mono">${G.esc(s.component || "")}</div>
          ${s.evidence.map((e) => `<pre>${G.esc(e.file || "")}${e.line ? ":" + e.line : ""}\n${G.esc(e.excerpt || "")}</pre>`).join("")}
          <div><b>Why it matters:</b> ${G.esc(s.why || "")}</div>
          ${s.component_id ? `<a href="#/graph?node=${encodeURIComponent(s.component_id)}">Show in the dependency graph →</a>` : ""}`,
      }));
    });
    G.sources(el, [{ label: "stages/signals/result.json", path: "stages/signals/result.json" }, { label: "v1 findings.json", path: G.workspace() && G.workspace().v1_run ? "v1/findings.json" : null }]);
  },
});
