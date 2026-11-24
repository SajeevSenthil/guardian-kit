/* Stage 8 page: Remedies, the human gate (M3). */
G.page("remedies", {
  title: "Remedies (approval)",
  async render(el, ctx) {
    G.header(el, ctx, { title: "Remedies: you decide", subtitle: "code proposes one fix per package; only plans a human approves go to the sandbox" });
    const r = ctx.result;
    if (!r) { G.html(el, '<div class="note">Not run yet. Press <b>Run this stage</b> (needs stage 6).</div>'); return; }
    const act = r.plans.filter((p) => p.kind !== "manual");
    const decided = act.filter((p) => p.decision.status !== "pending").length;
    const approved = act.filter((p) => p.decision.status === "approved").length;
    G.tiles(el, [
      { label: "plans", value: r.plans.length, tone: "info" }, { label: "can be applied", value: act.length },
      { label: "decided", value: `${decided} / ${act.length}`, tone: decided === act.length ? "ok" : "med" },
      { label: "approved", value: approved, tone: "ok" }, { label: "manual (no automatic edit)", value: r.plans.length - act.length },
    ]);
    const nameKey = "guardian.approver";
    let who = ""; try { who = localStorage.getItem(nameKey) || ""; } catch { /* */ }
    const bar = G.card(el, {
      title: r.sent ? "Sent to the sandbox" : "Your decision",
      tone: r.sent ? "ok" : "info",
      body: r.sent ? `<p>The approved set is frozen (<a href="${G.fileUrl(r.approved_set)}" target="_blank" rel="noopener">approved_set.json</a>). Re-run this stage to make new plans.</p><a class="btn btn-primary" href="#/verify">Open Sandbox verification →</a>`
        : `<div class="row"><label>Your name <input type="text" data-who value="${G.esc(who)}" style="width:220px"></label>
           <button class="btn btn-primary" data-send ${decided === act.length && approved ? "" : "disabled"}>Send ${approved} approved remedy(ies) to the sandbox →</button>
           <span class="muted">${decided < act.length ? `decide ${act.length - decided} more plan(s) first` : approved ? "" : "approve at least one plan"}</span></div>
           <p class="muted">${G.esc(r.note)}</p>`,
    });
    const send = bar.querySelector("[data-send]");
    if (send) send.addEventListener("click", async () => {
      try { await G.api(`/api/ws/${ctx.wsId}/remedies/send-to-sandbox`, { method: "POST" }); location.hash = "#/verify"; }
      catch (e) { alert(e.message); }
    });
    const tone = { approved: "ok", rejected: "crit", deferred: "med", pending: "info" };
    r.plans.forEach((p) => {
      const d = p.decision;
      const card = G.card(el, {
        tone: p.kind === "manual" ? "med" : tone[d.status],
        body: `<div class="row"><b style="font-size:15px">${G.esc(p.id)}</b> ${G.badge(p.ecosystem)} <b>${G.esc(p.name)}</b>
            <span class="mono">${G.esc(p.from_version || "?")} → ${G.esc(p.to_version || "no fix")}</span>
            ${G.badge("#" + p.priority.rank + " · " + p.priority.band + " " + p.priority.score, G.sevTone(p.priority.band))}
            ${p.kind === "manual" ? G.badge("manual", "med") : G.badge(d.status, tone[d.status])}</div>
          <p></p><div><b>Why:</b> ${G.esc(p.why)}</div>
          ${p.reason ? `<div class="note">${G.esc(p.reason)}</div>` : ""}
          ${p.breaking_risk ? `<div class="note">${G.badge("major upgrade", "high")} ${G.esc(p.breaking_risk)}</div>` : ""}
          ${p.edits.map((e) => `<div><b>Change:</b> <span class="mono">${G.esc(e.file)}</span> · ${G.esc(e.note || (e.kind === "replace_line" ? `line ${e.line}: ${e.old.trim()} → ${e.new.trim()}` : ""))}</div>`).join("")}
          ${p.lockfile_note ? `<div class="muted">${G.esc(p.lockfile_note)}</div>` : ""}
          <div class="muted">Rollback: ${G.esc(p.rollback)}</div>
          ${p.unfixable && p.unfixable.length ? `<div class="muted">No fix published yet for: ${G.esc(p.unfixable.join(", "))}</div>` : ""}
          <details><summary>Fixes ${p.targets.length} advisory(ies)</summary><div class="mono">${G.esc(p.targets.join(", "))}</div></details>
          ${p.patch ? `<details><summary>Patch (exact change)</summary><pre data-patch>loading…</pre></details>` : ""}
          <div class="muted mono">plan_hash ${G.esc(p.plan_hash)}${p.patch_sha256 ? " · patch sha256 " + G.esc(p.patch_sha256.slice(0, 16)) + "…" : ""}</div>
          ${d.status !== "pending" ? `<div><b>${G.esc(d.status)}</b> by ${G.esc(d.by)} at ${G.fmtTime(d.at)} ${G.chip("verified", "audited")}</div>` : ""}
          ${!r.sent && p.kind !== "manual" ? `<div class="row" style="margin-top:8px"><button class="btn btn-primary" data-d="approve">Approve</button><button class="btn" data-d="defer">Defer</button><button class="btn btn-danger" data-d="reject">Reject</button></div>` : ""}`,
      });
      const pre = card.querySelector("[data-patch]");
      if (pre) card.querySelector("details:last-of-type").addEventListener("toggle", async () => { try { pre.textContent = await (await fetch(G.fileUrl(p.patch))).text(); } catch { pre.textContent = "could not load"; } }, { once: true });
      card.querySelectorAll("[data-d]").forEach((b) => b.addEventListener("click", async () => {
        const name = (el.querySelector("[data-who]") || {}).value || "";
        if (!name.trim()) { alert("Type your name first: the decision is recorded under it."); return; }
        try { localStorage.setItem(nameKey, name); } catch { /* */ }
        if (b.dataset.d === "approve" && !confirm(`Approve ${p.id}: ${p.name} ${p.from_version} → ${p.to_version}?\n\nplan_hash ${p.plan_hash}`)) return;
        try { await G.api(`/api/ws/${ctx.wsId}/plans/${p.id}/decision`, { method: "POST", body: { decision: b.dataset.d, approver: name, plan_hash: p.plan_hash } }); G.rerender(); }
        catch (e) { alert(e.message); }
      }));
    });
    G.sources(el, [{ label: "stages/remedies/result.json", path: "stages/remedies/result.json" }, { label: "approved_set.json", path: r.approved_set },
      ...r.plans.filter((p) => p.patch).map((p) => ({ label: p.id + ".patch", path: p.patch })), { label: "audit.jsonl", path: "audit.jsonl" }]);
  },
});
