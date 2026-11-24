/* Guardian v2 shared UI helpers (M1). Contract §6: every page uses these; do not re-implement them. */
(function () {
  "use strict";
  const G = (window.G = {});
  const PAGES = {};
  const GROUPS = { ingest: "Discover", vulns: "Detect & investigate", remedies: "Fix & prove" };
  let META = null, WS = null, WSMETA = null, CURRENT = null, LAST_STATUS = {};

  // ---------- basics ----------
  G.esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  G.api = async (path, opts = {}) => {
    const o = { ...opts, headers: { ...(opts.headers || {}) } };
    if (o.body && typeof o.body !== "string" && !(o.body instanceof FormData)) { o.body = JSON.stringify(o.body); o.headers["Content-Type"] = "application/json"; }
    const r = await fetch(path, o);
    const t = await r.text();
    let j; try { j = t ? JSON.parse(t) : null; } catch { j = t; }
    if (!r.ok) throw new Error((j && j.detail) || r.statusText || "request failed");
    return j;
  };
  G.wsId = () => WS;
  G.fileUrl = (path) => `/api/ws/${encodeURIComponent(WS)}/file?path=${encodeURIComponent(path)}`;
  G.badge = (text, tone = "info") => `<span class="badge tone-${tone}">${G.esc(text)}</span>`;
  G.chip = (kind, text) => `<span class="chip chip-${kind}">${G.esc(text || kind.replace("-", " "))}</span>`;
  G.sevTone = (s) => ({ critical: "crit", high: "high", medium: "med", moderate: "med", low: "low" }[String(s || "").toLowerCase()] || "info");
  G.fmtTime = (s) => (s ? new Date(s).toLocaleString() : "—");
  G.html = (el, h) => { el.insertAdjacentHTML("beforeend", h); return el.lastElementChild; };
  G.go = (stage) => { location.hash = `#/${stage}`; };

  // ---------- components ----------
  G.tiles = (el, items) => G.html(el, `<div class="tiles">${items.map((t) =>
    `<div class="tile tone-${t.tone || "none"}"><b>${t.value === null || t.value === undefined ? G.chip("unknown") : G.esc(t.value)}</b><span>${G.esc(t.label)}</span></div>`).join("")}</div>`);
  G.card = (el, { title, body, tone }) => G.html(el, `<div class="card ${tone ? "tone-" + tone : ""}">${title ? `<h3>${G.esc(title)}</h3>` : ""}${body || ""}</div>`);
  G.sources = (el, items) => G.html(el, `<div class="sources"><b>Source files:</b> ${items.filter((i) => i && i.path).map((i) =>
    `<a href="${G.fileUrl(i.path)}" target="_blank" rel="noopener" class="mono">${G.esc(i.label || i.path)}</a>`).join("") || '<span class="muted">none yet</span>'}</div>`);
  G.json = (el, obj, label = "Raw JSON") => {
    const d = G.html(el, `<details class="card"><summary>${G.esc(label)}</summary><pre></pre></details>`);
    d.querySelector("pre").textContent = JSON.stringify(obj, null, 2).slice(0, 400000);
    return d;
  };
  G.path = (ids, labelOf) => `<span class="path">${ids.map((x) => G.esc(labelOf ? labelOf(x) : x)).join('<span class="arrow">→</span>')}</span>`;

  /** columns: [{key, label, render?(row) -> html, sort?}] ; opts: {search, pageSize, onRow(row), filter?(row)} */
  G.table = (el, columns, rows, opts = {}) => {
    const box = G.html(el, `<div class="col">${opts.search !== false ? '<input type="search" placeholder="Search…">' : ""}<div class="table-wrap"><table class="table"><thead><tr>${columns.map((c) => `<th>${G.esc(c.label)}</th>`).join("")}</tr></thead><tbody></tbody></table></div><div class="pager muted"></div></div>`);
    const tbody = box.querySelector("tbody"), pager = box.querySelector(".pager"), search = box.querySelector("input");
    const size = opts.pageSize || 50; let page = 0, view = rows;
    const text = (r) => columns.map((c) => (typeof r[c.key] === "object" ? JSON.stringify(r[c.key]) : r[c.key])).join(" ").toLowerCase();
    function draw() {
      const q = (search && search.value.trim().toLowerCase()) || "";
      view = rows.filter((r) => (!opts.filter || opts.filter(r)) && (!q || text(r).includes(q)));
      const pages = Math.max(1, Math.ceil(view.length / size)); page = Math.min(page, pages - 1);
      tbody.innerHTML = view.slice(page * size, page * size + size).map((r, i) =>
        `<tr data-i="${page * size + i}" class="${opts.onRow ? "clickable" : ""}">${columns.map((c) => `<td>${c.render ? c.render(r) : G.esc(r[c.key] ?? "")}</td>`).join("")}</tr>`).join("") ||
        `<tr><td colspan="${columns.length}" class="muted">No rows.</td></tr>`;
      pager.innerHTML = `${view.length} row(s) · page ${page + 1}/${pages} <button class="btn" data-p="-1">‹</button><button class="btn" data-p="1">›</button>`;
    }
    pager.addEventListener("click", (e) => { const p = e.target.dataset.p; if (p) { page = Math.max(0, page + Number(p)); draw(); } });
    if (search) search.addEventListener("input", () => { page = 0; draw(); });
    if (opts.onRow) tbody.addEventListener("click", (e) => { const tr = e.target.closest("tr[data-i]"); if (tr && !e.target.closest("a")) opts.onRow(view[Number(tr.dataset.i)]); });
    draw();
    box.redraw = draw;
    return box;
  };

  G.tabs = (el, names, onPick) => {
    const bar = G.html(el, `<div class="tabs">${names.map((n, i) => `<button data-t="${G.esc(n)}" class="${i ? "" : "active"}">${G.esc(n)}</button>`).join("")}</div>`);
    bar.addEventListener("click", (e) => { const b = e.target.closest("button"); if (!b) return; bar.querySelectorAll("button").forEach((x) => x.classList.toggle("active", x === b)); onPick(b.dataset.t); });
    onPick(names[0]);
    return bar;
  };

  /** Standard stage header: title, status, Run/Re-run, last run, summary chips, error. Every page calls this first. */
  G.header = (el, ctx, opts = {}) => {
    const st = ctx.status || "not_run";
    const sum = ctx.summary ? Object.entries(ctx.summary).filter(([, v]) => v !== null && typeof v !== "object").map(([k, v]) => `<span class="chip">${G.esc(k.replace(/_/g, " "))}: <b>${G.esc(v)}</b></span>`).join(" ") : "";
    const label = st === "not_run" ? "Run this stage" : "Re-run";
    const h = G.html(el, `<div><div class="stage-head">
      <div class="col"><div class="row"><span class="status ${st}"></span><h1>${G.esc(opts.title || ctx.title || ctx.stage)}</h1><span class="badge tone-${{ ok: "ok", failed: "crit", stale: "med", running: "info", awaiting_approval: "info" }[st] || "info"}">${G.esc(st.replace("_", " "))}</span></div>
        <div class="meta">${opts.subtitle ? G.esc(opts.subtitle) + " · " : ""}last run: ${G.fmtTime(ctx.finished || ctx.started)}${ctx.seconds ? ` · ${ctx.seconds}s` : ""}</div></div>
      <div class="row">${opts.noRun ? "" : `<button class="btn btn-primary" data-run>${st === "running" ? "Running…" : label}</button>`}</div>
    </div>${sum ? `<div class="row section">${sum}</div>` : ""}${ctx.error ? `<div class="err">${G.esc(ctx.error)}</div>` : ""}${st === "stale" ? '<div class="note">An earlier stage was re-run after this one: re-run this stage to refresh it.</div>' : ""}</div>`);
    const b = h.querySelector("[data-run]");
    if (b) { b.disabled = st === "running"; b.addEventListener("click", () => G.runStage(ctx.stage, opts.runOpts || {})); }
    return h;
  };

  G.runStage = async (stage, body = {}) => {
    try { await G.api(`/api/ws/${WS}/stages/${stage}/run`, { method: "POST", body }); }
    catch (e) { alert(e.message); return; }
    LAST_STATUS[stage] = "running"; await refreshNav(); render();
  };
  G.runUntil = async (stage, body = {}) => {
    try { await G.api(`/api/ws/${WS}/run-until/${stage}`, { method: "POST", body }); } catch (e) { alert(e.message); return; }
    await refreshNav();
  };

  // ---------- page registry + router ----------
  G.page = (id, def) => { PAGES[id] = def; };
  function route() {
    const m = location.hash.match(/^#\/([\w-]+)(\?.*)?$/);
    const q = new URLSearchParams((m && m[2]) || "");
    return { stage: (m && m[1]) || "ingest", params: q };
  }
  G.params = () => route().params;

  async function render() {
    const { stage, params } = route();
    CURRENT = stage;
    document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.stage === stage));
    const el = document.getElementById("page");
    const isNew = params.get("new") === "1" || !WS;
    let ctx = { stage, wsId: WS, status: "not_run" };
    if (WS && !isNew) {
      try { ctx = { ...(await G.api(`/api/ws/${WS}/stages/${stage}`)), wsId: WS }; } catch (e) { ctx.error = e.message; }
    }
    ctx.isNew = isNew;
    el.innerHTML = "";
    const p = PAGES[stage];
    if (!p) {
      G.header(el, { ...ctx, title: (META && META.stages.find((s) => s.id === stage) || {}).title || stage });
      G.card(el, { title: "Not built yet", body: `<p class="muted">The page for <b>${G.esc(stage)}</b> has not been written yet. Its raw output (if any) is shown below.</p>` });
      if (ctx.result) G.json(el, ctx.result);
      return;
    }
    try { await p.render(el, ctx); }
    catch (e) { console.error(e); G.html(el, `<div class="err">This page failed to render: ${G.esc(e.message)}</div>`); if (ctx.result) G.json(el, ctx.result); }
  }
  G.rerender = render;

  async function refreshNav() {
    if (!META) META = await G.api("/api/meta");
    if (WS) { try { WSMETA = await G.api(`/api/ws/${WS}`); } catch { WSMETA = null; } }
    const nav = document.getElementById("nav");
    nav.innerHTML = META.stages.map((s, i) => {
      const st = (WSMETA && WSMETA.stages[s.id] && WSMETA.stages[s.id].status) || "not_run";
      const built = !WSMETA || (WSMETA.stages[s.id] || {}).built !== false;
      return `${GROUPS[s.id] ? `<div class="group">${GROUPS[s.id]}</div>` : ""}<a href="#/${s.id}" data-stage="${s.id}" title="${G.esc(st.replace("_", " "))}${built ? "" : " · not built yet"}">
        <span class="num">${i + 1}</span><span class="lbl">${G.esc(s.title)}${built ? "" : ' <span class="muted">(soon)</span>'}</span><span class="status ${st}"></span></a>`;
    }).join("");
    document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.stage === CURRENT));
    // re-render the open page when its stage finishes
    if (WSMETA) {
      const now = (WSMETA.stages[CURRENT] || {}).status;
      if (LAST_STATUS[CURRENT] && LAST_STATUS[CURRENT] !== now && LAST_STATUS[CURRENT] === "running") render();
      for (const [k, v] of Object.entries(WSMETA.stages)) LAST_STATUS[k] = v.status;
    }
  }
  G.workspace = () => WSMETA;

  async function loadWorkspaces(selectId) {
    const list = await G.api("/api/ws");
    const pick = document.getElementById("ws-pick");
    pick.innerHTML = list.length ? list.map((w) => `<option value="${G.esc(w.id)}">${G.esc(w.id)} · ${G.esc(String(w.source.filename || w.source.value).split(/[\\/]/).slice(-2).join("/"))}</option>`).join("") : '<option value="">(none yet)</option>';
    WS = selectId || localStorageGet("guardian.ws") || (list[0] && list[0].id) || null;
    if (WS && !list.find((w) => w.id === WS)) WS = list[0] ? list[0].id : null;
    if (WS) pick.value = WS;
  }
  function localStorageGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
  function localStorageSet(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } }
  G.selectWorkspace = async (id) => { localStorageSet("guardian.ws", id); await loadWorkspaces(id); LAST_STATUS = {}; await refreshNav(); };

  G.boot = async () => {
    await loadWorkspaces();
    document.getElementById("ws-pick").addEventListener("change", async (e) => { await G.selectWorkspace(e.target.value); location.hash = "#/ingest"; render(); });
    window.addEventListener("hashchange", render);
    await refreshNav();
    render();
    setInterval(() => refreshNav().catch(() => {}), 2500);
  };
})();
