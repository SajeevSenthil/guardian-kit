/* Stage 1 page: Start & intake (M1). */
G.page("ingest", {
  title: "Start & intake",
  async render(el, ctx) {
    if (ctx.isNew || !ctx.wsId) return renderForm(el);
    G.header(el, ctx, { title: "Start & intake", subtitle: "fetch the repo safely and detect every ecosystem" });
    const r = ctx.result;
    const ws = G.workspace() || {};
    G.card(el, {
      title: "Run the pipeline",
      body: `<p class="muted">Each stage can also be run on its own from its page. A stage needs the stages before it.</p>
        <div class="row">
          <button class="btn btn-primary" data-until="graph">Run discovery (1–3)</button>
          <button class="btn" data-until="investigate">Run detection & investigation (1–7)</button>
          <button class="btn" data-until="remedies">Run everything up to remedies (1–8)</button>
        </div><div class="section"></div><div data-stages></div>`,
    }).addEventListener("click", (e) => { const s = e.target.dataset.until; if (s) G.runUntil(s); });
    drawStages(el.querySelector("[data-stages]"), ws);
    if (!r) { G.html(el, '<div class="note">This workspace has not been fetched yet: press <b>Run this stage</b>.</div>'); howItWorks(el); return; }

    const eco = r.ecosystems || {};
    G.tiles(el, [
      { label: "ecosystems detected", value: Object.keys(eco).length, tone: "info" },
      { label: "manifests + lockfiles", value: Object.values(eco).reduce((a, v) => a + v.manifests.length + v.lockfiles.length, 0) },
      { label: "Dockerfiles", value: (r.dockerfiles || []).length },
      { label: "CI workflows", value: (r.workflows || []).length },
      { label: "repo size (MB)", value: r.size_mb },
      { label: "deep npm layer", value: r.deep_npm ? "yes" : "no", tone: r.deep_npm ? "ok" : "info" },
    ]);
    const src = r.source || {};
    G.card(el, {
      title: "Snapshot",
      body: `<div class="col"><div><b>Source:</b> ${G.esc(src.kind)} · <span class="mono">${G.esc(src.filename || src.value)}</span></div>
        <div><b>Ref:</b> <span class="mono">${G.esc(r.ref || "default")}</span> · <b>commit:</b> <span class="mono">${G.esc(r.sha)}</span></div>
        <div><b>Consent:</b> ${G.esc((r.consent || {}).by)} at ${G.fmtTime((r.consent || {}).at)} ${G.chip("verified", "audited")}</div></div>`,
    });
    (r.notes || []).forEach((n) => G.html(el, `<div class="note">${G.esc(n)}</div>`));
    const rows = Object.entries(eco).map(([k, v]) => ({ ecosystem: k, manifests: v.manifests, lockfiles: v.lockfiles, pinned: v.pinned }));
    const sec = G.html(el, '<div class="section"><h2>Ecosystems and the files they came from</h2></div>');
    G.table(sec, [
      { key: "ecosystem", label: "Ecosystem", render: (x) => G.badge(x.ecosystem, "info") },
      { key: "manifests", label: "Manifests", render: (x) => x.manifests.map((m) => `<div class="mono">${G.esc(m)}</div>`).join("") || '<span class="muted">—</span>' },
      { key: "lockfiles", label: "Lockfiles", render: (x) => x.lockfiles.map((m) => `<div class="mono">${G.esc(m)}</div>`).join("") || G.chip("unknown", "no lockfile") },
      { key: "pinned", label: "Pinning", render: (x) => G.esc(x.pinned) },
    ], rows, { search: false });
    if ((r.dockerfiles || []).length || (r.workflows || []).length) {
      G.card(el, { title: "Build and CI files (checked in stage 5)", body: [...(r.dockerfiles || []), ...(r.workflows || [])].map((f) => `<div class="mono">${G.esc(f)}</div>`).join("") });
    }
    howItWorks(el);
    G.sources(el, [{ label: "stages/ingest/result.json", path: "stages/ingest/result.json" }, { label: "workspace.json", path: "workspace.json" }, { label: "audit.jsonl", path: "audit.jsonl" }]);
  },
});

function drawStages(box, ws) {
  if (!box || !ws.stages) return;
  box.innerHTML = `<div class="flow">${Object.entries(ws.stages).map(([k, v]) => `<span class="step"><span class="status ${v.status}"></span> ${G.esc(k)} <span class="muted">${G.esc((v.status || "").replace("_", " "))}</span></span>`).join("")}</div>`;
}

function howItWorks(el) {
  G.card(el, {
    title: "How Guardian works: who decides at each step",
    body: `<div class="flow">
      <span class="step code">1 Intake · code</span><span class="arrow">→</span>
      <span class="step code">2 SBOM · Syft</span><span class="arrow">→</span>
      <span class="step code">3 Graph · Syft + deps.dev</span><span class="arrow">→</span>
      <span class="step code">4 Vulns · OSV-Scanner + Grype</span><span class="arrow">→</span>
      <span class="step code">5 Signals · rules</span><span class="arrow">→</span>
      <span class="step code">6 Prioritise · formula</span><span class="arrow">→</span>
      <span class="step ai">7 Investigate · AI agents</span><span class="arrow">→</span>
      <span class="step code">8 Remedies · tested candidates</span><span class="arrow">→</span>
      <span class="step human">Human approves each fix</span><span class="arrow">→</span>
      <span class="step code">9 Sandbox proof</span><span class="arrow">→</span>
      <span class="step code">10 Report</span></div>
      <p class="muted" style="margin-top:8px">Solid = deterministic code or a standard tool · dashed = AI judgement (labelled inferred, never sets a score) · green = human decision.</p>`,
  });
}

function renderForm(el) {
  G.html(el, `<div class="stage-head"><div class="col"><h1>New analysis</h1><div class="meta">Analyse any repository: npm, pip, Go, Maven, Cargo, Ruby, PHP, .NET…</div></div></div>`);
  const f = G.card(el, {
    title: "Repository",
    body: `<form class="col" data-f>
      <div class="row"><label><input type="radio" name="kind" value="git" checked> Git URL</label>
        <label><input type="radio" name="kind" value="path"> Local folder</label>
        <label><input type="radio" name="kind" value="zip"> Upload .zip</label></div>
      <div data-val><input type="text" name="value" placeholder="https://github.com/owner/repo" required></div>
      <div data-zip hidden><input type="file" name="zip" accept=".zip"></div>
      <div><label>Branch, tag or commit (optional)</label><input type="text" name="ref" placeholder="default branch"></div>
      <div><label>Your name (recorded as consent)</label><input type="text" name="by" required></div>
      <label><input type="checkbox" name="consent" required> I am authorised to analyse this repository</label>
      <p class="muted">Git URLs must be on the allow-list in <span class="mono">guardian.toml [sources] allow</span>. Guardian never runs code from the repository (tests run only in the sandbox stage, inside a locked-down container).</p>
      <div class="row"><button class="btn btn-primary" type="submit">Create and run discovery (1–3)</button><span data-msg class="muted"></span></div>
    </form>`,
  });
  const form = f.querySelector("[data-f]");
  form.addEventListener("change", () => {
    const k = form.kind.value;
    form.querySelector("[data-val]").hidden = k === "zip";
    form.querySelector("[data-zip]").hidden = k !== "zip";
    form.value.required = k !== "zip";
    form.value.placeholder = k === "git" ? "https://github.com/owner/repo" : "E:\\path\\to\\repo";
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const msg = form.querySelector("[data-msg]");
    msg.textContent = "Creating…";
    try {
      let res;
      if (form.kind.value === "zip") {
        const fd = new FormData();
        if (!form.zip.files[0]) throw new Error("choose a .zip file");
        fd.append("file", form.zip.files[0]); fd.append("consent_by", form.by.value); fd.append("consent", form.consent.checked ? "true" : "false");
        if (form.ref.value) fd.append("ref", form.ref.value);
        res = await G.api("/api/ws/upload", { method: "POST", body: fd });
      } else {
        res = await G.api("/api/ws", { method: "POST", body: { kind: form.kind.value, value: form.value.value, ref: form.ref.value || null, consent_by: form.by.value, consent: form.consent.checked } });
      }
      await G.selectWorkspace(res.id);
      location.hash = "#/ingest";
      await G.runUntil("graph");
      G.rerender();
    } catch (err) { msg.innerHTML = `<span class="err">${G.esc(err.message)}</span>`; }
  });
  howItWorks(el);
}
