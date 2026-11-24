/* Stage 9 page: Sandbox verification, the proof (M3). Backend: guardian/v2/stages/s09_verify.py */
G.page("verify", {
  title: "Sandbox verification",
  async render(el, ctx) {
    G.header(el, ctx, { title: "Sandbox verification", subtitle: "approved fixes applied to a throwaway clone, then rescanned with the same tools" });
    const r = ctx.result;
    if (!r) { G.html(el, `<div class="note">${ctx.status === "running" ? "Running: applying the approved fixes and rescanning…" : 'Nothing verified yet. Approve plans on the <a href="#/remedies">Remedies</a> page and press <b>Send to the sandbox</b>.'}</div>`); return; }
    const tone = { VERIFIED: "ok", PARTIAL: "med", FAILED: "crit" }[r.verdict];
    G.card(el, { tone, body: `<div class="row"><span class="badge tone-${tone}" style="font-size:20px;padding:6px 16px">${G.esc(r.verdict)}</span><b style="font-size:16px">${G.esc(r.headline)}</b></div><p class="muted" style="margin-top:8px">${G.esc(r.why_verdict)}</p>` });
    const st = { pass: ["ok", "pass"], fail: ["crit", "FAIL"], warn: ["med", "warning"], "not-run": ["info", "not run"] };
    G.card(el, {
      title: "Checks (in order)",
      body: r.checks.map((c) => `<div class="row" style="margin:6px 0">${G.badge(st[c.status][1], st[c.status][0])} <b style="min-width:170px">${G.esc(c.name.replace(/_/g, " "))}</b><span>${G.esc(c.detail)}</span>${c.log ? ` <a href="${G.fileUrl(c.log)}" target="_blank" rel="noopener">log</a>` : ""}</div>`).join(""),
    });
    const sec = G.html(el, '<div class="section"><h2>Before → after, per approved plan</h2></div>');
    G.table(sec, [
      { key: "plan", label: "Plan" }, { key: "package", label: "Package", render: (x) => `<b>${G.esc(x.package)}</b> <span class="mono">${G.esc(x.from)} → ${G.esc(x.to)}</span>` },
      { key: "targets", label: "Targeted" }, { key: "gone", label: "Gone after fix", render: (x) => G.badge(x.gone.length, x.gone.length === x.targets ? "ok" : "med") },
      { key: "still_present", label: "Still present", render: (x) => (x.still_present.length ? G.badge(x.still_present.length, "crit") + ` <span class="mono">${G.esc(x.still_present.join(", "))}</span>` : G.badge("0", "ok")) },
    ], r.per_plan, { search: false });
    G.tiles(el, [{ label: "new vulnerabilities introduced", value: r.new_vulnerabilities.length, tone: r.new_vulnerabilities.length ? "crit" : "ok" },
      { label: "remaining (no approved plan)", value: r.remaining.length, tone: "med" }]);
    if (r.new_vulnerabilities.length) G.card(el, { title: "New on the upgraded packages", tone: "crit", body: r.new_vulnerabilities.map((n) => `<div class="mono">${G.esc(n.package)} ${G.esc(n.version || "")}: ${G.esc(n.ids.join(", "))} (${G.esc(n.tool)})</div>`).join("") });
    if (r.remaining.length) {
      const s2 = G.html(el, '<div class="section"><h2>Remaining: not covered by an approved plan</h2><p class="muted">Listed, never hidden.</p></div>');
      G.table(s2, [{ key: "severity", label: "Severity", render: (x) => G.badge(x.severity, G.sevTone(x.severity)) }, { key: "name", label: "Package", render: (x) => `<b>${G.esc(x.name)}</b> <span class="mono">${G.esc(x.version || "")}</span>` }, { key: "advisory", label: "Advisory", render: (x) => `<span class="mono">${G.esc(x.advisory)}</span>` }], r.remaining, { pageSize: 15 });
    }
    G.sources(el, [{ label: "stages/verify/result.json", path: "stages/verify/result.json" }, { label: "applied.diff", path: "stages/verify/applied.diff" },
      { label: "rescan-osv-scanner.json", path: "stages/verify/rescan-osv-scanner.json" }, { label: "rescan-grype.json", path: "stages/verify/rescan-grype.json" }, { label: "approved_set.json", path: r.approved_set }]);
  },
});
