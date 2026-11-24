/* Stage 3 page: Dependency graph (M1). Backend: guardian/v2/stages/s03_graph.py */
G.page("graph", {
  title: "Dependency graph",
  async render(el, ctx) {
    G.header(el, ctx, { title: "Dependency graph", subtitle: "who pulls in what: every package's path from your project, with evidence" });
    const r = ctx.result;
    if (!r) { G.html(el, '<div class="note">Not run yet. Press <b>Run this stage</b> (needs stage 2).</div>'); return; }
    const byId = {}; r.nodes.forEach((n) => (byId[n.id] = n));
    const label = (id) => (byId[id] ? (byId[id].kind === "root" ? byId[id].name : byId[id].name) : id);
    const parents = {}, children = {};
    r.edges.forEach((e) => { (parents[e.to] = parents[e.to] || []).push(e); (children[e.from] = children[e.from] || []).push(e); });

    // marks from later stages (best effort; those stages may not exist yet)
    const marks = {};
    for (const [stage, tone] of [["vulns", "crit"], ["signals", "med"]]) {
      try {
        const s = await G.api(`/api/ws/${ctx.wsId}/stages/${stage}`);
        const res = s.result || {};
        const rows = res.rows || res.items || res.vulns || res.signals || res.findings || [];
        rows.forEach((x) => {
          const key = x.node_id || x.component_id || x.id_component || x.purl || x.component;
          const hit = r.nodes.find((n) => n.id === key || (n.purl && n.purl === key) || (x.name && n.name === x.name && n.version === x.version));
          if (hit) (marks[hit.id] = marks[hit.id] || { tone, items: [] }).items.push(x.advisory || x.id || x.title || x.rule || "");
          if (hit && tone === "crit") marks[hit.id].tone = "crit";
        });
      } catch { /* not built or not run */ }
    }

    const s = r.stats;
    G.tiles(el, [
      { label: "packages", value: s.nodes, tone: "info" }, { label: "dependency edges", value: s.edges },
      { label: "direct", value: s.direct, tone: "ok" }, { label: "transitive", value: s.transitive },
      { label: "max depth", value: s.max_depth }, { label: "not connected to root", value: s.not_connected, tone: s.not_connected ? "med" : "ok" },
    ]);
    Object.entries(r.ecosystems || {}).forEach(([eco, info]) => {
      if (!info.transitives_resolved) G.html(el, `<div class="note">${G.badge(eco)} transitive dependencies are <b>not resolved</b> for this ecosystem (its files list only direct dependencies and deps.dev could not resolve them). Those packages hang directly off the project.</div>`);
      else if (info.edge_sources["deps.dev"]) G.html(el, `<div class="note">${G.badge(eco)} transitive dependencies were resolved by <b>deps.dev</b> (labelled on each edge). A real install can differ; nothing was installed.</div>`);
    });

    const body = G.html(el, "<div></div>");
    G.tabs(body.parentElement.insertBefore(document.createElement("div"), body), ["Graph", "Direct", "Transitive", "Statistics"], (t) => {
      body.innerHTML = "";
      ({ Graph: drawGraph, Direct: drawDirect, Transitive: drawTransitive, Statistics: drawStats })[t](body);
    });

    function sideHtml(id) {
      const n = byId[id]; if (!n) return "";
      const ev = (parents[id] || []).slice(0, 8).map((e) => `<div class="card"><div class="row">${G.esc(label(e.from))} <span class="muted">→</span> <b>${G.esc(n.name)}</b> ${e.sources.map((x) => G.chip(x === "deps.dev" ? "inferred" : "verified", x)).join(" ")}</div>
        ${e.evidence.map((v) => `<div class="mono muted">${G.esc(v.file || "")}${v.line ? ":" + v.line : ""} ${G.esc(v.excerpt || "")}</div>`).join("")}</div>`).join("");
      const m = marks[id];
      return `<h3>${G.esc(n.name)} <span class="mono">${G.esc(n.version || n.assumed_version || "")}</span></h3>
        <div class="row">${G.badge(n.ecosystem)} ${n.kind === "root" ? G.badge("your project", "ok") : n.direct ? G.badge("direct", "ok") : n.direct === false ? G.badge("transitive", "info") : G.chip("unknown")} ${n.dev ? G.badge("dev", "low") : ""} ${n.in_sbom === false ? G.chip("inferred", "resolved by deps.dev, not in your files") : ""} ${n.assumed_version ? G.chip("inferred", "version assumed") : ""}</div>
        ${n.purl ? `<div class="mono muted">${G.esc(n.purl)}</div>` : ""}
        <p></p><b>Why it is installed</b> <span class="muted">(shortest paths from your project)</span>
        ${(n.paths || []).map((p) => `<div>${G.path(p, label)}</div>`).join("") || '<div class="muted">not connected to the project root</div>'}
        <p></p><div>depth <b>${n.depth ?? "—"}</b> · required by <b>${n.fan_in}</b> package(s) · requires <b>${(children[id] || []).length}</b></div>
        ${n.licenses && n.licenses.length ? `<div>licence: <span class="mono">${G.esc(n.licenses.join(", "))}</span></div>` : ""}
        ${m ? `<div class="card tone-${m.tone}"><b>Flagged in later stages:</b> ${m.items.slice(0, 6).map((x) => G.esc(x)).join(", ")}</div>` : ""}
        <p></p><b>Evidence for each edge into it</b>${ev || '<div class="muted">root-level</div>'}`;
    }

    function drawGraph(box) {
      const big = r.nodes.length > 600;
      const ecos = [...new Set(r.nodes.filter((n) => n.kind === "pkg").map((n) => n.ecosystem))];
      box.innerHTML = `<div class="row section">
        <input type="search" data-q placeholder="Find a package…" style="max-width:260px">
        <select data-eco><option value="">all ecosystems</option>${ecos.map((e) => `<option>${G.esc(e)}</option>`).join("")}</select>
        <select data-scope><option value="all">prod + dev</option><option value="prod">prod only</option><option value="dev">dev only</option></select>
        <label class="muted">depth ≤ <select data-depth>${[1, 2, 3, 4, 6, 99].map((d) => `<option value="${d}" ${d === (big ? 2 : 99) ? "selected" : ""}>${d === 99 ? "all" : d}</option>`).join("")}</select></label>
        <label><input type="checkbox" data-flag> flagged only</label>
        <span class="muted" data-count></span></div>
        <div class="split"><div><div class="graph-box" data-g></div><p class="muted">${big ? "Large graph: showing the first levels. Search for a package, raise the depth, or click a node to focus on it." : "Click a node for its paths and evidence. Drag to move, scroll to zoom."}</p></div><div class="card" data-side><p class="muted">Select a package.</p></div></div>`;
      const side = box.querySelector("[data-side]"), gbox = box.querySelector("[data-g]");
      const css = getComputedStyle(document.documentElement), v = (k) => css.getPropertyValue(k).trim();
      let network = null, focus = G.params().get("node");
      function color(n) {
        if (n.kind === "root") return v("--accent");
        const m = marks[n.id]; if (m) return v(m.tone === "crit" ? "--crit" : "--med");
        if (n.in_sbom === false) return v("--inferred");
        return n.direct ? v("--ok") : v("--info");
      }
      function build() {
        const q = box.querySelector("[data-q]").value.trim().toLowerCase();
        const eco = box.querySelector("[data-eco]").value, scope = box.querySelector("[data-scope]").value;
        const depth = Number(box.querySelector("[data-depth]").value), flagged = box.querySelector("[data-flag]").checked;
        let keep = new Set();
        if (focus && byId[focus]) {
          (byId[focus].paths || []).forEach((p) => p.forEach((x) => keep.add(x)));
          (children[focus] || []).forEach((e) => keep.add(e.to)); keep.add(focus); keep.add(r.root);
        } else if (q) {
          r.nodes.filter((n) => n.name.toLowerCase().includes(q)).slice(0, 40).forEach((n) => (n.paths || [[n.id]]).forEach((p) => p.forEach((x) => keep.add(x))));
          keep.add(r.root);
        } else {
          r.nodes.forEach((n) => {
            if (n.kind === "root") return keep.add(n.id);
            if (eco && n.ecosystem !== eco) return;
            if (scope === "prod" && n.dev) return; if (scope === "dev" && !n.dev) return;
            if (flagged && !marks[n.id]) return;
            if ((n.depth ?? 99) <= depth || flagged) keep.add(n.id);
          });
          if (flagged) [...keep].forEach((id) => ((byId[id] || {}).paths || []).slice(0, 1).forEach((p) => p.forEach((x) => keep.add(x))));
        }
        const nodes = [...keep].map((id) => byId[id]).filter(Boolean).map((n) => ({
          id: n.id, label: n.kind === "root" ? n.name : `${n.name}\n${n.version || n.assumed_version || "?"}`, shape: n.kind === "root" ? "box" : "dot",
          size: n.kind === "root" ? 20 : n.direct ? 12 : 7, color: { background: color(n), border: color(n), highlight: { background: v("--accent"), border: v("--accent") } },
          font: { color: v("--text"), size: n.kind === "root" ? 14 : 11, face: "system-ui" }, borderWidth: n.id === focus ? 4 : 1,
        }));
        const edges = r.edges.filter((e) => keep.has(e.from) && keep.has(e.to)).map((e) => ({
          from: e.from, to: e.to, arrows: { to: { enabled: true, scaleFactor: 0.4 } }, dashes: e.sources.length === 1 && e.sources[0] === "deps.dev",
          color: { color: v("--border"), highlight: v("--accent") }, width: 1,
        }));
        box.querySelector("[data-count]").textContent = `${nodes.length} nodes · ${edges.length} edges shown${focus ? " · focused on " + label(focus) : ""}`;
        if (network) network.destroy();
        if (!window.vis) { gbox.innerHTML = '<p class="err">vis-network did not load (offline?). Use the Direct / Transitive tabs.</p>'; return; }
        network = new vis.Network(gbox, { nodes, edges }, {
          layout: { improvedLayout: nodes.length < 300 }, interaction: { hover: true, tooltipDelay: 150 },
          physics: { solver: "forceAtlas2Based", stabilization: { iterations: 180 }, forceAtlas2Based: { gravitationalConstant: -40, springLength: 90 } },
        });
        network.once("stabilizationIterationsDone", () => network.setOptions({ physics: false }));
        network.on("click", (p) => { if (p.nodes[0]) { side.innerHTML = sideHtml(p.nodes[0]); } });
        network.on("doubleClick", (p) => { if (p.nodes[0]) { focus = p.nodes[0]; build(); side.innerHTML = sideHtml(focus); } });
        if (focus) side.innerHTML = sideHtml(focus) + '<p></p><button class="btn" data-clear>Show the whole graph</button>';
        const clr = side.querySelector("[data-clear]"); if (clr) clr.addEventListener("click", () => { focus = null; history.replaceState(null, "", "#/graph"); build(); side.innerHTML = '<p class="muted">Select a package. Double-click to focus on it.</p>'; });
      }
      box.querySelectorAll("select,input").forEach((x) => x.addEventListener(x.type === "search" ? "input" : "change", () => { focus = null; build(); }));
      build();
    }

    function drawDirect(box) {
      const rows = r.nodes.filter((n) => n.kind === "pkg" && n.direct).map((n) => ({ ...n, under: r.nodes.filter((m) => m.cluster === n.id && m.id !== n.id).length, requires: (children[n.id] || []).length }));
      G.html(box, '<p class="muted">Packages your project declares itself. "Brings in" = transitive packages whose first path goes through it.</p>');
      G.table(box, [
        { key: "name", label: "Package", render: (n) => `<b>${G.esc(n.name)}</b>` }, { key: "version", label: "Version", render: (n) => `<span class="mono">${G.esc(n.version || n.assumed_version || "not pinned")}</span>` },
        { key: "ecosystem", label: "Ecosystem", render: (n) => G.badge(n.ecosystem) }, { key: "dev", label: "Scope", render: (n) => (n.dev ? G.badge("dev", "low") : G.badge("prod", "ok")) },
        { key: "requires", label: "Requires" }, { key: "under", label: "Brings in" },
        { key: "evidence", label: "Declared at", render: (n) => { const e = (parents[n.id] || []).find((x) => x.from === r.root); const v = e && e.evidence[0]; return v ? `<span class="mono">${G.esc(v.file)}${v.line ? ":" + v.line : ""}</span>` : ""; } },
        { key: "flag", label: "Flags", render: (n) => (marks[n.id] ? G.badge(marks[n.id].items.length + " finding(s)", marks[n.id].tone) : "") },
      ], rows.sort((a, b) => b.under - a.under), { onRow: (n) => { location.hash = `#/graph?node=${encodeURIComponent(n.id)}`; G.rerender(); } });
    }

    function drawTransitive(box) {
      const rows = r.nodes.filter((n) => n.kind === "pkg" && n.direct === false);
      G.html(box, '<p class="muted">Packages you never declared: they come in through other packages. The path shows how.</p>');
      G.table(box, [
        { key: "name", label: "Package", render: (n) => `<b>${G.esc(n.name)}</b>` }, { key: "version", label: "Version", render: (n) => `<span class="mono">${G.esc(n.version || "")}</span>` },
        { key: "ecosystem", label: "Ecosystem", render: (n) => G.badge(n.ecosystem) }, { key: "depth", label: "Depth" }, { key: "fan_in", label: "Required by" },
        { key: "paths", label: "Path from your project", render: (n) => (n.paths && n.paths[0] ? G.path(n.paths[0], label) : G.chip("unknown", "not connected")) },
        { key: "src", label: "Source", render: (n) => (n.in_sbom === false ? G.chip("inferred", "deps.dev") : G.chip("verified", "your files")) },
        { key: "flag", label: "Flags", render: (n) => (marks[n.id] ? G.badge(marks[n.id].items.length + " finding(s)", marks[n.id].tone) : "") },
      ], rows.sort((a, b) => (a.depth ?? 99) - (b.depth ?? 99)), { onRow: (n) => { location.hash = `#/graph?node=${encodeURIComponent(n.id)}`; G.rerender(); } });
    }

    function drawStats(box) {
      G.card(box, { title: "Most depended-on packages", body: s.top_depended_on.map((x) => `<div class="row"><span style="flex:1"><b>${G.esc(x.name)}</b> <span class="mono">${G.esc(x.version || "")}</span></span>${G.badge("required by " + x.fan_in)}</div>`).join("") });
      G.card(box, { title: "Same package, several versions installed", body: s.duplicate_versions.map((x) => `<div><b>${G.esc(x.name)}</b> ${G.badge(x.ecosystem)} <span class="mono">${x.versions.map(G.esc).join(", ")}</span></div>`).join("") || '<span class="muted">none</span>' });
      const src = r.sources || {}, dd = src["deps.dev"] || {};
      G.card(box, { title: "Where the edges come from", body: `<div class="col">
        <div>${G.chip("verified", "Syft")} relationships from lockfiles: <b>${src.syft}</b></div>
        <div>${src.v1_npm === "ran" ? G.chip("verified", "v1 npm") : G.chip("not-run", "v1 npm")} package-lock.json parser with line numbers: <b>${G.esc(src.v1_npm)}</b></div>
        <div>${dd.status === "ran" ? G.chip("inferred", "deps.dev") : G.chip("not-run", "deps.dev")} resolver for unlocked manifests: <b>${G.esc(dd.status)}</b> · resolved ${dd.resolved || 0} · failed ${dd.failed || 0} · versions assumed ${dd.assumed_versions || 0}</div>
        ${Object.entries(r.ecosystems || {}).map(([k, x]) => `<div>${G.badge(k)} ${x.nodes} packages · edges from ${Object.entries(x.edge_sources).map(([a, b]) => `${G.esc(a)} ${b}`).join(", ") || "none"}</div>`).join("")}
        <p class="muted">${G.esc(r.note)}</p></div>` });
    }

    G.sources(el, [{ label: "stages/graph/result.json", path: "stages/graph/result.json" }, { label: "Syft relationships", path: "stages/sbom/relationships.json" }, { label: "v1 graph.json", path: ctx.result && G.workspace() && G.workspace().v1_run ? "v1/graph.json" : null }]);
  },
});
