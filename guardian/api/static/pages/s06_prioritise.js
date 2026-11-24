/* Stage 6 page: Prioritised risk report (M2). Backend: guardian/v2/stages/s06_prioritise.py */
G.page("prioritise", {
  title: "Prioritised risk",
  async render(el, ctx) {
    G.header(el, ctx, { title: "Prioritised risk", subtitle: "what to fix first, and exactly why: a formula, not an opinion" });
    const r = ctx.result;
    if (!r) { G.html(el, '<div class="note">Not run yet. Press <b>Run this stage</b> (needs stages 3, 4 and 5).</div>'); return; }
    const c = r.counts, ini = c.initial || {}, bb = c.by_band || {};
    G.tiles(el, [
      { label: "published critical", value: ini.critical || 0, tone: "crit" }, { label: "published high", value: ini.high || 0, tone: "high" },
      { label: "→ prioritised critical", value: bb.critical || 0, tone: "crit" }, { label: "→ prioritised high", value: bb.high || 0, tone: "high" },
      { label: "need attention now", value: c.need_attention, tone: "info" }, { label: "ranked items", value: c.items },
      { label: "deliberately demoted", value: r.demoted.length, tone: "ok" },
    ]);
    const w = r.weights, b = r.bands;
    G.card(el, {
      title: "How the score is computed (same formula for every ecosystem)",
      body: `<div class="mono" style="font-size:14px">score = ${w.severity}·severity + ${w.exploitability}·exploitability + ${w.reachability}·reachability + ${w.exposure}·exposure + ${w.fix_availability}·fix availability</div>
        <div class="split" style="margin-top:12px"><div><div><b>severity</b> CVSS base score / 10 (else the database label)</div>
          <div><b>exploitability</b> CISA KEV = 1.0, else EPSS: ≥50% → .9, ≥10% → .7, ≥1% → .4, else .15</div>
          <div><b>reachability</b> does your code load or call it? (npm: static import/call analysis; other ecosystems: <i>unknown</i>)</div>
          <div><b>exposure</b> dev-only .3 · production .6 · internet-facing 1.0</div>
          <div><b>fix availability</b> same-major fix 1.0 · major upgrade .7 · none .5</div></div>
          <div><div><b>bands</b> ${G.badge("critical ≥ " + b.critical, "crit")} ${G.badge("high ≥ " + b.high, "high")} ${G.badge("medium ≥ " + b.medium, "med")} ${G.badge("low ≥ " + b.low, "low")}</div>
          <div><b>guardrails</b> KEV_FLOOR ≥ 90 (known exploited) · NOT_LOADED_CAP ≤ 39 (code never loads it) · MALICIOUS_FLOOR ≥ 90</div>
          <div><b>unknown is never zero</b>: an unknown factor uses its prior (${Object.entries(r.priors).map(([k, v]) => `${k.replace("_availability", "")} ${v}`).join(", ")}), lowers <i>confidence</i> and widens the <i>range</i>.</div>
          <div>${G.chip("verified")} fact from a tool · ${G.chip("derived", "heuristic")} rule of thumb · ${G.chip("inferred")} AI · ${G.chip("unknown")}</div></div></div>`,
    });
    const tone = (bd) => ({ critical: "crit", high: "high", medium: "med", low: "low" }[bd] || "info");
    const gradeChip = (g) => G.chip(g === "verified" ? "verified" : g === "heuristic" ? "derived" : g === "inferred" ? "inferred" : "unknown", g);
    const bars = (it) => `<div class="row" style="gap:2px;flex-wrap:nowrap">${it.factor_rows.map((f) => `<span title="${G.esc(f.label)}: ${f.contribution}/${f.weight} (${f.grade})" style="display:inline-block;height:10px;width:${Math.max(2, f.contribution * 1.4)}px;border-radius:3px" class="badge tone-${f.grade === "unknown" ? "info" : tone(it.band)}"></span>`).join("")}</div>`;
    function report(it) {
      return `<div class="card tone-${tone(it.band)}">
        <div class="row"><b style="font-size:16px">#${it.rank}</b> ${G.badge(it.band + " · " + it.score, tone(it.band))} <b>${G.esc(it.title)}</b> ${G.badge(it.kind)} ${G.badge(it.ecosystem)}
          <span class="muted">range ${it.range[0]}–${it.range[1]} · confidence ${it.confidence}/100</span></div>
        <p></p><div><b>Why this rank:</b> ${G.esc(it.why)}</div>
        ${it.vs_next ? `<div><b>Versus the next item:</b> ${G.esc(it.vs_next)}</div>` : ""}
        <div><b>Published vs ours:</b> ${G.esc(it.initial_vs_final)}</div>
        <table class="table" style="margin-top:8px"><tr><th>Factor</th><th>Weight</th><th>Value</th><th>Points</th><th>Grade</th><th>Evidence</th></tr>
        ${it.factor_rows.map((f) => `<tr><td>${G.esc(f.label)}</td><td>${f.weight}</td><td>${f.value ?? '<span class="muted">unknown → prior</span>'}</td><td><b>${f.contribution}</b></td><td>${gradeChip(f.grade)}</td><td class="muted">${G.esc(f.evidence)}</td></tr>`).join("")}</table>
        ${it.guardrails.length ? `<div class="note">${it.guardrails.map((g) => `<b>${G.esc(g.name)}</b> ${G.esc(g.effect)}: ${G.esc(g.reason)}`).join("<br>")}</div>` : ""}
        <div class="muted">source: ${G.esc(it.source)} ${it.ref ? "· " + G.esc(it.ref) : ""} ${it.v1_id ? "· v1 " + G.esc(it.v1_id) : ""}
          ${it.component_id ? ` · <a href="#/graph?node=${encodeURIComponent(it.component_id)}">graph →</a>` : ""}</div></div>`;
    }
    const top = r.items.slice(0, 20);
    const sec = G.html(el, '<div class="section"><h2>Top 20, explained</h2><p class="muted">Every sentence below is generated by code from the factor values: no AI writes the reasons.</p></div>');
    G.html(sec, top.map(report).join(""));
    const all = G.html(el, '<div class="section"><h2>Full ranking</h2></div>');
    const box = G.html(all, "<div></div>");
    G.table(all, [
      { key: "rank", label: "#" }, { key: "score", label: "Score", render: (it) => G.badge(it.score, tone(it.band)) },
      { key: "title", label: "Item", render: (it) => `<b>${G.esc(it.title)}</b><div>${G.badge(it.kind)} ${G.badge(it.ecosystem)}</div>` },
      { key: "initial_severity", label: "Published", render: (it) => (it.initial_severity ? G.badge(it.initial_severity, G.sevTone(it.initial_severity)) : G.chip("unknown", "n/a")) },
      { key: "factors", label: "Factors", render: bars }, { key: "confidence", label: "Confidence" },
      { key: "range", label: "Range", render: (it) => `${it.range[0]}–${it.range[1]}` },
    ], r.items, { pageSize: 30, onRow: (it) => { box.innerHTML = report(it); box.scrollIntoView({ behavior: "smooth", block: "nearest" }); } });
    if (r.demoted.length) {
      const d = G.html(el, '<div class="section"><h2>Demoted: published critical/high, but not urgent here</h2><p class="muted">These are not hidden: each one shows the factor that pulled it down.</p></div>');
      G.table(d, [
        { key: "rank", label: "#" }, { key: "title", label: "Item", render: (x) => `<b>${G.esc(x.title)}</b>` },
        { key: "initial_severity", label: "Published", render: (x) => G.badge(x.initial_severity, G.sevTone(x.initial_severity)) },
        { key: "score", label: "Ours", render: (x) => G.badge(x.band + " · " + x.score, tone(x.band)) }, { key: "reason", label: "Why", render: (x) => G.esc(x.reason) },
      ], r.demoted, { search: false, pageSize: 20 });
    }
    G.sources(el, [{ label: "stages/prioritise/result.json", path: "stages/prioritise/result.json" }, { label: "v1 prioritised.json", path: r.v1 && r.v1.file },
      { label: "guardian.toml (weights, bands)", path: null }]);
  },
});
