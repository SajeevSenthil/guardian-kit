/* Stage 7 page: Agent investigation (M2). */
G.page("investigate", {
  title: "Agent investigation",
  async render(el, ctx) {
    const top = Number(localGet("guardian.top") || 3);
    G.header(el, ctx, { title: "Agent investigation", subtitle: "AI agents investigate the top items; code checks every claim", runOpts: { top, mode: "live" } });
    G.card(el, {
      title: "Run options",
      body: `<div class="row"><label>Top items <select data-top>${[1, 3, 5, 10].map((n) => `<option ${n === top ? "selected" : ""}>${n}</option>`).join("")}</select></label>
        <button class="btn" data-live>Run with AI (live)</button><button class="btn" data-off>Run offline (no AI)</button>
        <span class="muted">A live run calls Gemini and can take several minutes; nothing on the other pages depends on it.</span></div>`,
    }).addEventListener("click", (e) => {
      const n = Number(el.querySelector("[data-top]").value); localSet("guardian.top", n);
      if (e.target.dataset.live !== undefined) G.runStage("investigate", { top: n, mode: "live" });
      if (e.target.dataset.off !== undefined) G.runStage("investigate", { top: n, mode: "offline" });
    });
    G.card(el, {
      title: "How the agents work together",
      body: `<div class="flow"><span class="step code">Code finds & scores (stages 2–6)</span><span class="arrow">→</span>
        <span class="step ai">Agent investigates with read-only tools</span><span class="arrow">→</span>
        <span class="step code">Code checks quotes + JSON schema</span><span class="arrow">→</span>
        <span class="step ai">Refuter argues against it</span><span class="arrow">→</span>
        <span class="step code">Code applies fixed rules</span><span class="arrow">→</span><span class="step code">Saved to a file</span></div>
        <p class="muted" style="margin-top:8px">Agents never talk to each other: Guardian's code calls each one, checks its answer and writes it to the run folder for the next step. Every AI sentence is labelled <i>inferred</i>; a quote that is not word-for-word in the evidence is dropped by code.</p>`,
    });
    const r = ctx.result;
    if (!r) { G.html(el, '<div class="note">Not run yet. Choose the number of items and a mode above (needs stage 6).</div>'); return; }
    G.tiles(el, [
      { label: "mode", value: r.mode, tone: r.mode === "live" ? "ok" : "info" }, { label: "items investigated", value: r.top },
      { label: "agent runs ok", value: r.agents.reduce((a, x) => a + x.runs.ok, 0), tone: "ok" },
      { label: "skipped (shown, not hidden)", value: r.agents.reduce((a, x) => a + x.runs.skipped, 0), tone: "med" },
      { label: "quotes kept / dropped", value: r.quotes_kept !== undefined ? `${r.quotes_kept} / ${r.quotes_dropped}` : null },
      { label: "API keys configured", value: r.keys_configured },
    ]);
    if (r.models) G.html(el, `<div class="note">Provider ${G.esc(r.provider)} · models ${G.esc(JSON.stringify(r.models))} · tokens ${G.esc(r.tokens)}</div>`);
    (r.flow || []).slice(0, 1).forEach((f) => G.html(el, `<p class="muted">${G.esc(f)}</p>`));
    r.agents.forEach((a) => {
      const outs = a.outputs || [];
      const card = G.card(el, {
        title: `${a.name}  ·  ${a.runs.ok} ran, ${a.runs.skipped} skipped`,
        body: `<div class="muted">${G.esc(a.when)}</div>
          <div class="split"><div><div><b>Method:</b> ${G.esc(a.method)}</div><div><b>Produces:</b> ${G.esc(a.output)}</div></div>
          <div><div><b>How code uses it:</b> ${G.esc(a.how_code_uses_it)}</div>${a.tools && a.tools.length ? `<div><b>Read-only tools:</b> <span class="mono">${G.esc(a.tools.join(", "))}</span></div>` : ""}</div></div>
          <div data-o></div>`,
      });
      const box = card.querySelector("[data-o]");
      if (!outs.length) { box.innerHTML = '<p class="muted">Not used at this stage in this run.</p>'; return; }
      outs.slice(0, 10).forEach((o) => {
        const who = `${G.esc(o.finding || o.plan || "")} ${o.component ? `<span class="mono muted">${G.esc(o.component)}</span>` : ""}`;
        if (o.status !== "ok") { G.html(box, `<div class="row" style="margin-top:6px">${G.chip("not-run", "skipped")} ${who} <span class="muted">${G.esc(o.reason || "")}</span></div>`); return; }
        const facts = ["summary", "resembles", "suggested_risk", "confirmed_symbols", "app_reaches", "tier_change", "verdict", "effective_verdict", "applied"]
          .filter((k) => o[k] !== undefined && o[k] !== null && o[k] !== "").map((k) => `<div><b>${G.esc(k.replace(/_/g, " "))}:</b> ${G.esc(typeof o[k] === "object" ? JSON.stringify(o[k]) : o[k])}</div>`).join("");
        const claims = (o.claims || []).map((c) => `<li>${c.support_checked === true ? G.chip("verified", "quote checked") : c.support_checked === false ? G.chip("unknown", "quote dropped") : G.chip("unknown", "no quote")} ${G.esc(c.text)}</li>`).join("");
        G.html(box, `<div class="ai-box"><div class="row">${who} <span class="muted">${G.esc(o.model || "")}</span></div>${facts}${claims ? `<ul>${claims}</ul>` : ""}
          ${(o.tool_calls || []).length ? `<details><summary>tool calls (${o.tool_calls.length})</summary>${o.tool_calls.map((t) => `<div class="mono">${G.esc(t)}</div>`).join("")}</details>` : ""}</div>`);
      });
    });
    G.sources(el, [{ label: "stages/investigate/result.json", path: "stages/investigate/result.json" }, { label: "investigations.json", path: r.investigations }, { label: "v1 prioritised.json (agent fields)", path: r.v1_prioritised }]);
  },
});

function localGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function localSet(k, v) { try { localStorage.setItem(k, String(v)); } catch { /* private mode */ } }
