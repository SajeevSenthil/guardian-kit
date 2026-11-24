/* Stage 10 page: Report (M3). Backend: guardian/v2/stages/s10_report.py */
G.page("report", {
  title: "Report",
  async render(el, ctx) {
    G.header(el, ctx, { title: "Report", subtitle: "everything this workspace produced, in one place, with downloads" });
    const r = ctx.result;
    if (!r) { G.html(el, '<div class="note">Press <b>Run this stage</b>: it collects whatever stages have run (missing ones are listed as not run).</div>'); return; }
    const v = r.verification || {};
    G.card(el, { title: "Snapshot", body: `<div><b>${G.esc(r.source.filename || r.source.value)}</b> · commit <span class="mono">${G.esc(r.sha)}</span> · consent ${G.esc((r.consent || {}).by)} · generated ${G.fmtTime(r.generated)}</div>
      <div>Audit chain: ${r.audit.ok ? G.badge("intact", "ok") : G.badge("NOT OK", "crit")} <span class="muted">${G.esc(r.audit.detail)}</span></div>` });
    G.card(el, { title: "Stages", body: r.stages.map((s) => `<div class="row"><span class="status ${s.status}"></span> <b style="min-width:200px">${G.esc(s.title)}</b> ${G.esc(s.status.replace("_", " "))} ${s.file ? `<a href="${G.fileUrl(s.file)}" target="_blank" rel="noopener">result.json</a>` : ""}</div>`).join("") });
    const vs = (r.vulnerabilities || {}).by_severity || {};
    G.tiles(el, [{ label: "components", value: (r.sbom || {}).components }, { label: "critical", value: vs.critical, tone: "crit" }, { label: "high", value: vs.high, tone: "high" },
      { label: "plans", value: r.plans.length }, { label: "approved", value: r.plans.filter((p) => p.decision.status === "approved").length, tone: "ok" },
      { label: "sandbox verdict", value: v.verdict, tone: { VERIFIED: "ok", PARTIAL: "med", FAILED: "crit" }[v.verdict] || "info" }]);
    if (v.headline) G.html(el, `<div class="note"><b>${G.esc(v.verdict)}</b>: ${G.esc(v.headline)}. ${G.esc(v.why_verdict || "")}</div>`);
    G.card(el, { title: "Top risks", body: r.top_risks.map((t) => `<div style="margin:6px 0"><b>#${t.rank}</b> ${G.badge(t.band + " " + t.score, G.sevTone(t.band))} <b>${G.esc(t.title)}</b><div class="muted">${G.esc(t.why)}</div></div>`).join("") || '<span class="muted">prioritise not run</span>' });
    G.card(el, { title: "Tools used", body: Object.entries(r.tool_versions).map(([k, x]) => `<div>${G.esc(k)} <span class="mono">${G.esc(x || "missing")}</span></div>`).join("") });
    const f = r.files || {};
    G.card(el, { title: "Downloads", body: `<div class="row">${[["Report (JSON)", f.json], ["Report (Markdown)", f.md], ["SBOM CycloneDX", f.sbom_cdx], ["SBOM SPDX", f.sbom_spdx], ["Audit log", f.audit]].filter((x) => x[1]).map(([l, p]) => `<a class="btn" href="${G.fileUrl(p)}" target="_blank" rel="noopener">${G.esc(l)}</a>`).join("")}</div>` });
    G.sources(el, [{ label: "stages/report/result.json", path: "stages/report/result.json" }, { label: "report.md", path: f.md }, { label: "audit.jsonl", path: "audit.jsonl" }]);
  },
});
