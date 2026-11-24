/* Stage 4 page: Vulnerabilities (M2). Backend: guardian/v2/stages/s04_vulns.py */
G.page("vulns", {
  title: "Vulnerabilities",
  async render(el, ctx) {
    G.header(el, ctx, { title: "Vulnerabilities", subtitle: "OSV-Scanner + Grype (+ v1 OSV for npm), merged per advisory across tools" });
    const r = ctx.result;
    if (!r) { G.html(el, '<div class="note">Not run yet. Press <b>Run this stage</b> (needs stage 2).</div>'); return; }
    const c = r.counts, s = c.by_severity;
    G.tiles(el, [
      { label: "critical", value: s.critical, tone: "crit" }, { label: "high", value: s.high, tone: "high" },
      { label: "medium", value: s.medium, tone: "med" }, { label: "low", value: s.low, tone: "low" },
      { label: "advisories (package × advisory)", value: c.rows, tone: "info" }, { label: "affected packages", value: c.affected_packages },
      { label: "in CISA KEV (exploited)", value: c.kev, tone: c.kev ? "crit" : "ok" }, { label: "unpinned: cannot be matched", value: c.unpinned, tone: c.unpinned ? "med" : "ok" },
    ]);
    const TOOLNAME = { osv_scanner: "OSV-Scanner", grype: "Grype", v1_osv: "v1 OSV (npm)" };
    const split = G.html(el, '<div class="split"><div data-l></div><div data-r></div></div>');
    const L = split.querySelector("[data-l]"), R = split.querySelector("[data-r]");
    G.card(R, {
      title: "Tools that looked",
      body: Object.entries(r.tools).map(([k, t]) => `<div class="section">${t.status === "ran" ? G.chip("verified", "ran") : G.chip("not-run", t.status)} <b>${TOOLNAME[k] || k}</b> <span class="mono">${G.esc(t.version || "")}</span>
        ${t.status === "ran" ? `<div class="muted">ecosystems: ${G.esc((t.ecosystems || []).join(", ") || "all in the SBOM")}${t.files ? " · files: " + t.files.map(G.esc).join(", ") : ""}${t.db_built ? " · DB built " + G.esc(t.db_built) : ""}</div>` : `<div class="muted">${G.esc(t.reason || "")}</div>`}
        ${t.raw ? `<a href="${G.fileUrl(t.raw)}" target="_blank" rel="noopener">raw output</a>` : ""}</div>`).join(""),
    });
    const ag = c.agreement || {};
    G.card(R, {
      title: "Do the tools agree?", tone: (ag.some || ag.one) ? "med" : "ok",
      body: `<div class="col"><div>${G.badge("all tools that looked", "ok")} <b>${ag.all || 0}</b></div><div>${G.badge("some", "med")} <b>${ag.some || 0}</b></div><div>${G.badge("only one", "high")} <b>${ag.one || 0}</b></div>
        <p class="muted">A ✗ means the tool looked at that ecosystem and did <i>not</i> report it (worth a human look). "not run" means it did not look, and is never counted as safe.</p></div>`,
    });
    const en = r.enrichment || {};
    G.card(R, { title: "Exploit data", body: `<div>EPSS: <b>${G.esc((en.epss || {}).status)}</b></div><div>CISA KEV: <b>${G.esc((en.kev || {}).status)}</b> ${G.esc((en.kev || {}).catalogVersion || "")}</div>` });
    if ((r.unpinned || []).length) G.card(R, { title: "Not pinned: cannot be matched", tone: "med", body: r.unpinned.map((u) => `<div>${G.badge(u.ecosystem)} <b>${G.esc(u.name)}</b> <span class="mono">${G.esc(u.declared || "any")}</span> <span class="muted mono">${G.esc(u.file || "")}</span></div>`).join("") });
    const eco = ["all", ...Object.keys(c.by_ecosystem || {})];
    const sec = G.html(L, `<div class="section"><h2>All findings</h2><div class="row section"><select data-eco>${eco.map((e) => `<option>${G.esc(e)}</option>`).join("")}</select>
      <select data-sev><option value="">all severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select>
      <label><input type="checkbox" data-dis> tools disagree</label><label><input type="checkbox" data-kev> KEV only</label></div></div>`);
    let fe = "all", fs = "", fd = false, fk = false;
    const mark = (v) => (v === true ? G.chip("verified", "✓") : v === false ? '<span class="chip chip-unknown">✗</span>' : G.chip("not-run", v === "not-applicable" ? "n/a" : "not run"));
    const detail = G.html(L, '<div data-detail></div>');
    const tbl = G.table(sec, [
      { key: "severity", label: "Severity", render: (x) => G.badge(x.severity, G.sevTone(x.severity)) + (x.kev ? " " + G.badge("KEV", "crit") : "") },
      { key: "name", label: "Package", render: (x) => `<b>${G.esc(x.name)}</b> <span class="mono">${G.esc(x.version || "")}</span><div>${G.badge(x.ecosystem)} ${x.direct === true ? G.badge("direct", "ok") : x.direct === false ? G.badge("transitive", "info") : ""} ${x.dev ? G.badge("dev", "low") : ""}</div>` },
      { key: "advisory", label: "Advisory", render: (x) => `<a href="https://osv.dev/vulnerability/${encodeURIComponent(x.advisory)}" target="_blank" rel="noopener" class="mono">${G.esc(x.advisory)}</a><div class="muted">${G.esc((x.summary || "").slice(0, 110))}</div>` },
      { key: "cvss_score", label: "CVSS", render: (x) => (x.cvss_score ?? G.chip("unknown")) },
      { key: "epss", label: "EPSS", render: (x) => (x.epss ? (x.epss.score * 100).toFixed(1) + "%" : G.chip("unknown")) },
      { key: "fixed", label: "Fixed in", render: (x) => (x.fixed.length ? `<span class="mono">${G.esc(x.fixed.slice(0, 3).join(", "))}</span>` : G.chip("unknown", "no fix")) },
      { key: "reported_by", label: "OSV-Scanner · Grype · v1", render: (x) => ["osv_scanner", "grype", "v1_osv"].map((k) => mark(x.reported_by[k])).join(" ") },
    ], r.rows, {
      pageSize: 40,
      filter: (x) => (fe === "all" || x.ecosystem === fe) && (!fs || x.severity === fs) && (!fd || x.disagreement) && (!fk || x.kev),
      onRow: (x) => {
        detail.innerHTML = "";
        G.card(detail, {
          title: `${x.advisory} · ${x.name} ${x.version || ""}`, tone: G.sevTone(x.severity),
          body: `<div class="row">${G.badge(x.severity, G.sevTone(x.severity))} ${G.chip("verified", "tool output")} <span class="muted">severity from ${G.esc(x.severity_source)}</span></div>
            <p></p><div><b>Aliases:</b> <span class="mono">${G.esc([x.advisory, ...x.aliases].join(", "))}</span></div>
            <div><b>CVSS:</b> ${G.esc(x.cvss_score ?? "unknown")} <span class="mono muted">${G.esc(x.cvss_vector || "")}</span></div>
            <div><b>EPSS:</b> ${x.epss ? `${(x.epss.score * 100).toFixed(2)}% (${G.esc(x.epss.cve)})` : "unknown"} · <b>KEV:</b> ${x.kev ? "yes, added " + G.esc(x.kev.dateAdded) : x.kev === false ? "no" : "not evaluated"}</div>
            <div><b>Fixed in:</b> <span class="mono">${G.esc(x.fixed.join(", ") || "no fixed version published")}</span></div>
            <div><b>Why it is installed:</b> ${(x.introduced_via || []).map((p) => `<div>${G.path(p)}</div>`).join("") || '<span class="muted">run the graph stage</span>'}</div>
            <div><b>Found in:</b> <span class="mono">${G.esc(x.files.join(", "))}${x.lock_line ? ":" + x.lock_line : ""}</span></div>
            <p></p><b>Advisory summary</b> <span class="muted">(third-party text, shown as data)</span><pre></pre>
            ${x.references.map((u) => `<div><a href="${G.esc(u)}" target="_blank" rel="noopener noreferrer" class="mono">${G.esc(u)}</a></div>`).join("")}
            <p></p><a href="#/graph?node=${encodeURIComponent(x.component_id)}">Show in the dependency graph →</a>`,
        }).querySelector("pre").textContent = x.summary || "(none)";
        detail.scrollIntoView({ behavior: "smooth", block: "nearest" });
      },
    });
    sec.querySelector("[data-eco]").addEventListener("change", (e) => { fe = e.target.value; tbl.redraw(); });
    sec.querySelector("[data-sev]").addEventListener("change", (e) => { fs = e.target.value; tbl.redraw(); });
    sec.querySelector("[data-dis]").addEventListener("change", (e) => { fd = e.target.checked; tbl.redraw(); });
    sec.querySelector("[data-kev]").addEventListener("change", (e) => { fk = e.target.checked; tbl.redraw(); });
    G.html(L, `<p class="muted">${G.esc(r.note)} Click a row for details.</p>`);
    G.sources(el, [{ label: "stages/vulns/result.json", path: "stages/vulns/result.json" },
      ...Object.values(r.tools).filter((t) => t.raw).map((t) => ({ label: t.raw.split("/").pop(), path: t.raw }))]);
  },
});
