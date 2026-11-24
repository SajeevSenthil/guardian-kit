/* Stage 2 page: Inventory & SBOM (M1). Backend: guardian/v2/stages/s02_sbom.py */
G.page("sbom", {
  title: "Inventory & SBOM",
  async render(el, ctx) {
    G.header(el, ctx, { title: "Inventory & SBOM", subtitle: "Syft builds the SBOM for every ecosystem; the v1 npm parser cross-checks it" });
    const r = ctx.result;
    if (!r) { G.html(el, '<div class="note">Not run yet. Press <b>Run this stage</b> (needs stage 1).</div>'); return; }
    const t = r.totals;
    G.tiles(el, [
      { label: "components", value: t.components, tone: "info" },
      { label: "ecosystems", value: Object.keys(t.ecosystems).length },
      { label: "direct", value: t.direct },
      { label: "transitive", value: t.transitive },
      { label: "direct/transitive unknown", value: t.direct_unknown },
      { label: "dev / test only", value: t.dev },
      { label: "unpinned (no exact version)", value: t.unpinned, tone: t.unpinned ? "med" : "ok" },
      { label: "distinct licences", value: t.licenses },
    ]);

    const split = G.html(el, '<div class="split"><div data-l></div><div data-r></div></div>');
    const L = split.querySelector("[data-l]"), R = split.querySelector("[data-r]");
    const tools = r.tools || {};
    G.card(R, {
      title: "Tools that produced this",
      body: `<div class="col">
        <div>${G.chip("verified", "ran")} <b>Syft</b> <span class="mono">${G.esc((tools.syft || {}).version)}</span><div class="mono muted">${G.esc((tools.syft || {}).command || "")}</div></div>
        <div>${(tools.v1_npm || {}).status === "ran" ? G.chip("verified", "ran") : G.chip("not-run", "not applicable")} <b>v1 npm lockfile parser</b> <span class="muted">${G.esc((tools.v1_npm || {}).reason || "adds lockfile-line evidence and reachability for npm")}</span></div>
      </div>`,
    });
    G.card(R, {
      title: "Ecosystems",
      body: Object.entries(t.ecosystems).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<div class="row"><span style="flex:1">${G.badge(k)}</span><b>${v}</b></div>`).join(""),
    });
    const cc = r.crosscheck;
    if (cc) {
      G.card(R, {
        title: "Cross-check: Syft vs v1 parser (npm)", tone: cc.only_v1_count || cc.only_syft_count ? "med" : "ok",
        body: `<div class="col"><div>Syft: <b>${cc.syft_npm}</b> · v1 parser: <b>${cc.v1_npm_unique}</b> unique (${cc.v1_npm_installs} installed copies) · agree: <b>${cc.agree}</b></div>
          <div>only Syft: <b>${cc.only_syft_count}</b> · only v1: <b>${cc.only_v1_count}</b></div>
          <p class="muted">${G.esc(cc.explanation)}</p>
          ${[...cc.only_syft.map((x) => ["only Syft", x]), ...cc.only_v1.map((x) => ["only v1", x])].slice(0, 30).map(([w, x]) => `<div class="mono">${G.badge(w, "med")} ${G.esc(x)}</div>`).join("")}</div>`,
      });
    } else {
      G.card(R, { title: "Cross-check", body: `${G.chip("not-run", "not applicable")} <span class="muted">Only one source for this repo (no package-lock.json for the v1 npm parser).</span>` });
    }
    G.card(R, { title: "Top licences", body: (r.licenses || []).slice(0, 12).map(([k, v]) => `<div class="row"><span class="mono" style="flex:1">${G.esc(k)}</span><b>${v}</b></div>`).join("") });

    // introduced-via from the graph stage when it exists
    let via = {};
    try { const g = await G.api(`/api/ws/${ctx.wsId}/stages/graph`); (g.result ? g.result.nodes : []).forEach((n) => { if (n.paths && n.paths[0]) via[n.id] = n.paths[0]; }); } catch { /* graph not run */ }
    const names = {}; (r.components || []).forEach((c) => (names[c.id] = c.name));
    const ecos = ["all", ...Object.keys(t.ecosystems)];
    const sec = G.html(L, '<div class="section"><h2>Components</h2><div class="row" data-f></div></div>');
    let eco = "all", scope = "all";
    sec.querySelector("[data-f]").innerHTML = `<select data-eco>${ecos.map((e) => `<option>${G.esc(e)}</option>`).join("")}</select>
      <select data-scope><option value="all">direct + transitive</option><option value="direct">direct only</option><option value="transitive">transitive only</option><option value="dev">dev/test only</option><option value="unpinned">unpinned</option></select>`;
    const tbl = G.table(sec, [
      { key: "name", label: "Package", render: (c) => `<b title="${G.esc(c.purl || "")}">${G.esc(c.name)}</b>` },
      { key: "version", label: "Version", render: (c) => c.version ? `<span class="mono">${G.esc(c.version)}</span>` : `${G.chip("unknown", "not pinned")} <span class="mono muted">${G.esc(c.declared || "")}</span>` },
      { key: "ecosystem", label: "Ecosystem", render: (c) => G.badge(c.ecosystem) },
      { key: "direct", label: "Scope", render: (c) => (c.direct === true ? G.badge("direct", "ok") : c.direct === false ? G.badge("transitive", "info") : G.chip("unknown")) + (c.dev ? " " + G.badge("dev", "low") : "") },
      { key: "licenses", label: "Licence", render: (c) => G.esc((c.licenses || []).join(", ")) || '<span class="muted">—</span>' },
      { key: "via", label: "Introduced via", render: (c) => (via[c.id] ? G.path(via[c.id].slice(1), (x) => names[x] || x) : '<span class="muted">—</span>') },
      { key: "locations", label: "Found in", render: (c) => (c.lock && c.lock.line ? `<span class="mono">${G.esc(c.lock.file)}:${c.lock.line}</span>` : `<span class="mono">${G.esc((c.locations || [])[0] || "")}</span>`) },
    ], r.components, {
      pageSize: 50,
      filter: (c) => (eco === "all" || c.ecosystem === eco) && (scope === "all" || (scope === "direct" && c.direct) || (scope === "transitive" && c.direct === false) || (scope === "dev" && c.dev) || (scope === "unpinned" && c.unpinned)),
      onRow: (c) => { location.hash = `#/graph?node=${encodeURIComponent(c.id)}`; },
    });
    sec.querySelector("[data-eco]").addEventListener("change", (e) => { eco = e.target.value; tbl.redraw(); });
    sec.querySelector("[data-scope]").addEventListener("change", (e) => { scope = e.target.value; tbl.redraw(); });
    G.html(L, '<p class="muted">Click a row to open it in the dependency graph.</p>');

    const f = r.files || {};
    G.card(el, {
      title: "Download the SBOM",
      body: `<div class="row">${[["CycloneDX JSON (Syft)", f.syft_cdx], ["SPDX JSON (Syft)", f.syft_spdx], ["Syft native JSON", f.syft_json], ["CycloneDX (v1 npm parser)", f.v1_cdx]]
        .filter((x) => x[1]).map(([l, p]) => `<a class="btn" href="${G.fileUrl(p)}" target="_blank" rel="noopener">${G.esc(l)}</a>`).join("")}</div>`,
    });
    G.sources(el, [{ label: "stages/sbom/result.json", path: "stages/sbom/result.json" }, { label: "syft.json", path: f.syft_json }, { label: "syft.cdx.json", path: f.syft_cdx },
      { label: "syft.spdx.json", path: f.syft_spdx }, { label: "v1.cdx.json", path: f.v1_cdx }, { label: "relationships.json", path: f.relationships }]);
  },
});
