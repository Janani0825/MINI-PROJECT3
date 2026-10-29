/* Renders a scan (with its detection result) as an "evidence report". Used by the scan page and the history page. */
(function () {
  const ICONS = { "Verified owner": "bi-award", "Blacklist": "bi-slash-circle", "Trusted list": "bi-patch-check", "Look-alike": "bi-fonts", "ML model": "bi-cpu", "Deep scan": "bi-globe2" };
  const STATUS_ICON = { safehit: "bi-patch-check-fill", pass: "bi-check-circle-fill", hit: "bi-exclamation-octagon-fill", skip: "bi-dash-circle", run: "bi-arrow-repeat" };

  /* The detection layers as a row of steps. `layers` = [{layer,status,note}] */
  function pipeline(layers) {
    const { esc } = UI;
    return `<div class="pipe">${layers.map(l => {
      const cls = l.status === "hit" && (l.layer === "Trusted list" || l.layer === "Verified owner") ? "hit-safe" : l.status;
      return `<div class="step ${cls}"><i class="bi ${STATUS_ICON[cls === "hit-safe" ? "safehit" : l.status] || "bi-circle"} st"></i><i class="bi ${ICONS[l.layer] || "bi-circle"} ic"></i>
        <b>${esc(l.layer)}</b><small>${esc(l.note || "")}</small></div>`; }).join("")}</div>`;
  }

  function layersFor(r) {
    const out = (r.pipeline || []).slice();
    const pg = r.page;
    out.push(pg && pg.checked
      ? { layer: "Deep scan", status: pg.points > 0 ? "hit" : "pass", note: pg.points > 0 ? "Suspicious page content" : "Page content looks normal" }
      : { layer: "Deep scan", status: "skip", note: pg && pg.note ? "Not available for this page" : "Not selected (optional)" });
    return out;
  }

  /* "What pushed the score": bars to the right raise the risk, bars to the left lower it. */
  function signals(list) {
    const { esc } = UI;
    if (!list || !list.length) return "";
    const max = Math.max(...list.map(s => Math.abs(s.share)), 1);
    return `<div class="card-title-sm mb-2">What pushed the score (ML model)</div>
      <div class="sig-axis"><div></div><div><span>&larr; lowers risk</span><span>raises risk &rarr;</span></div><div></div></div>
      ${list.map(s => { const w = Math.abs(s.share) / max * 50, up = s.share > 0;
        return `<div class="sig"><div class="text-truncate" title="${esc(s.label)}">${esc(s.label)}</div>
          <div class="track"><span class="mid"></span><span class="fill ${up ? "up" : "down"}" style="width:${w}%"></span></div>
          <div class="v">${up ? "+" : ""}${s.share}%</div></div>`; }).join("")}
      <div class="small text-muted mt-2">Each bar shows how much the model's score changes when that one feature is replaced by a harmless value. It is the model's own view, learned from training data.</div>`;
  }

  function verifiedCard(v) {
    const { esc, fmtDate } = UI;
    if (!v) return "";
    return `<div class="col-12"><div class="card verified-card"><div class="card-body d-flex gap-3 align-items-start">
      <div class="seal"><i class="bi bi-patch-check-fill"></i></div>
      <div><div class="card-title-sm mb-1">Verified website</div>
        <div class="fs-5 fw-bold">${esc(v.org_name)}</div>
        <div class="text-muted small mb-2">${esc(v.category)} &middot; verified by the portal administrator on ${fmtDate(v.verified_on)}</div>
        <div><b>Used for:</b> ${esc(v.purpose)}</div><div><b>Registered owner:</b> ${esc(v.owner_name)}</div>
      </div></div></div></div>`;
  }

  function securityCard(sec, verified) {
    const { esc } = UI;
    if (!sec) return "";
    const col = sec.score >= 70 ? "var(--safe)" : sec.score >= 40 ? "var(--warn)" : "var(--fake)";
    const ic = { pass: "bi-check-circle-fill good", fail: "bi-x-circle-fill bad", na: "bi-dash-circle text-muted" };
    const missing = sec.items.filter(i => i.status === "fail");
    return `<div class="col-12"><div class="card"><div class="card-body">
      <div class="d-flex justify-content-between align-items-start flex-wrap gap-2 mb-2">
        <div><div class="card-title-sm"><i class="bi bi-shield-lock me-1"></i>Website security checks</div>
          <div class="small text-muted">Standard protections the website sends to browsers. This is information only and does not change the risk score.</div></div>
        <div class="grade" style="--col:${col}"><b>${esc(sec.grade)}</b><span>${sec.passed}/${sec.total}</span></div></div>
      <div class="sec-grid">${sec.items.map(i => `<div class="sec-item"><i class="bi ${ic[i.status]}"></i><span>${esc(i.label)}</span></div>`).join("")}</div>
      ${missing.length ? `<div class="card-title-sm mt-3 mb-1">${verified ? "Recommendations for the website owner" : "What is missing"}</div>
        <ul class="reason-list mb-0">${missing.map(i => `<li><b>${esc(i.label)}:</b> ${esc(i.tip)}</li>`).join("")}</ul>` : `<div class="small text-success mt-3"><i class="bi bi-check2-circle me-1"></i>All standard protections are present.</div>`}
    </div></div></div>`;
  }

  function pageCard(pg) {
    const { esc } = UI;
    if (!pg) return "";
    if (!pg.checked || !("has_password_form" in pg)) return pg.note ? `<div class="col-12"><div class="card"><div class="card-body small text-muted"><i class="bi bi-globe2 me-1"></i><b>Deep scan:</b> ${esc(pg.note)}</div></div></div>` : "";
    const yn = (v) => `<b class="${v ? "bad" : "good"}">${v ? "Yes" : "No"}</b>`;
    return `<div class="col-12"><div class="card"><div class="card-body">
      <div class="card-title-sm mb-2"><i class="bi bi-globe2 me-1"></i>Page content analysis</div>
      <div class="feature-grid">
        <div class="feature"><small>Page title</small><b>${esc(pg.title || "-")}</b></div>
        <div class="feature"><small>Asks for a password</small>${yn(pg.has_password_form)}</div>
        <div class="feature"><small>Form sends data to another site</small>${yn(pg.form_to_other_domain)}</div>
        <div class="feature"><small>Files loaded from the real brand</small><b class="${pg.hotlinked_from_brand ? "bad" : "good"}">${pg.hotlinked_from_brand || 0}</b></div>
        <div class="feature"><small>Similar to the real site</small><b>${pg.similarity_to_real != null ? Math.round(pg.similarity_to_real * 100) + "%" : "-"}</b></div>
        <div class="feature"><small>Domain age</small><b>${pg.domain_age_days != null ? pg.domain_age_days + " days" : "unknown"}</b></div>
      </div></div></div></div>`;
  }

  window.scanningPipeline = function (deep) {
    return pipeline([
      { layer: "Verified owner", status: "skip", note: "Checking the verified registry" }, { layer: "Blacklist", status: "skip", note: "Checking known bad domains" }, { layer: "Trusted list", status: "skip", note: "Checking top-100k domains" },
      { layer: "Look-alike", status: "skip", note: "Comparing with popular names" }, { layer: "ML model", status: "skip", note: "Reading 37 URL features" },
      { layer: "Deep scan", status: "skip", note: deep ? "Inspecting the page safely" : "Not selected (optional)" }]);
  };

  window.renderReport = function (scan) {
    const { esc, fmtDate, badge } = UI;
    const r = scan.result || {}, f = scan.features || {};
    const cls = (r.classification || "Safe").toLowerCase();
    const icon = { safe: "bi-shield-check", suspicious: "bi-exclamation-triangle", fake: "bi-shield-x" }[cls];
    const msg = { safe: "This website looks safe", suspicious: "This website is suspicious", fake: "This is likely a fake / phishing website" }[cls];
    const col = { safe: "var(--safe)", suspicious: "var(--warn)", fake: "var(--fake)" }[cls];
    const reasons = r.reasons || (r.detection_reason ? r.detection_reason.split(/(?<=\.)\s+/) : []);
    const yn = (v, badWhenTrue) => `<b class="${(v && badWhenTrue) || (!v && !badWhenTrue) ? "bad" : "good"}">${v ? "Yes" : "No"}</b>`;
    const hasPipe = r.pipeline && r.pipeline.length;

    return `
    <div class="result-banner ${cls} mb-3"><i class="bi ${icon}"></i>
      <div class="flex-grow-1"><div class="fw-bold fs-4">${msg}</div><div class="small text-break">${esc(scan.submitted_url)}</div></div>
      ${CONFIG.USE_MOCK ? "" : `<button class="btn btn-outline-light btn-sm pdf-btn" data-pdf="${esc(scan.scan_id)}"><i class="bi bi-file-earmark-pdf me-1"></i>Download report</button>`}</div>
    ${scan.notice ? `<div class="alert alert-warning d-flex align-items-center mb-3"><i class="bi bi-shield-exclamation me-2 fs-5"></i><div>${esc(scan.notice)}</div></div>` : ""}
    ${hasPipe ? `<div class="card mb-3"><div class="card-body"><div class="card-title-sm mb-2">Detection layers ${r.decided_by ? `<span class="text-muted text-lowercase fw-normal">&middot; decided by ${esc(r.decided_by)}</span>` : ""}</div>${pipeline(layersFor(r))}</div></div>` : ""}
    <div class="row g-3">
      <div class="col-md-4"><div class="card h-100"><div class="card-body text-center">
        <div class="card-title-sm mb-3">Risk score</div>
        <div class="gauge" style="--pct:${r.risk_score || 0};--col:${col}"><span>${r.risk_score || 0}%</span></div>
        <div class="mt-3">${badge(r.classification)}</div>
        <div class="small text-muted mt-2">Scan ${esc(scan.scan_id)} &middot; ${fmtDate(scan.scan_date)}</div>
      </div></div></div>
      <div class="col-md-8"><div class="card h-100"><div class="card-body">
        <div class="card-title-sm mb-2">Why this result?</div>
        <ul class="reason-list">${reasons.map(x => `<li>${esc(x)}</li>`).join("")}</ul>
        <div class="reco"><i class="bi bi-lightbulb me-1"></i><b>Recommendation:</b> ${esc(r.recommendation)}</div>
      </div></div></div>
      ${r.signals && r.signals.length ? `<div class="col-12"><div class="card"><div class="card-body">${signals(r.signals)}</div></div></div>` : ""}
      ${verifiedCard(r.verified_site)}
    ${pageCard(r.page)}
      ${securityCard(r.security, !!r.verified_site)}
      <div class="col-12"><div class="card"><div class="card-body">
        <div class="card-title-sm mb-2">Extracted features</div>
        <div class="feature-grid">
          <div class="feature"><small>Domain</small><b>${esc(scan.domain)}</b></div>
          <div class="feature"><small>Protocol</small><b class="${scan.protocol === "https" ? "good" : "bad"}">${esc(scan.protocol)}</b></div>
          <div class="feature"><small>URL length</small><b>${f.url_length}</b></div>
          <div class="feature"><small>IP address in URL</small>${yn(f.has_ip_address, true)}</div>
          <div class="feature"><small>'@' symbol</small>${yn(f.has_at_symbol, true)}</div>
          <div class="feature"><small>Number of dots</small><b>${f.num_dots}</b></div>
          <div class="feature"><small>Number of hyphens</small><b>${f.num_hyphens}</b></div>
          <div class="feature"><small>Suspicious keywords</small>${yn(f.has_suspicious_keywords, true)}</div>
          <div class="feature"><small>Blacklisted</small>${yn(f.is_blacklisted, true)}</div>
          <div class="feature"><small>Closest legit domain</small><b>${esc(r.matched_legit_domain || "-")}</b></div>
          <div class="feature"><small>Name similarity</small><b>${r.similarity_score != null ? r.similarity_score + "%" : "-"}</b></div>
          ${r.ml_probability != null ? `<div class="feature"><small>ML model probability</small><b>${r.ml_probability}%</b></div>` : ""}
          ${r.lookalike ? `<div class="feature"><small>Look-alike type</small><b>${esc(r.lookalike.kind)}</b></div>` : ""}
        </div>
      </div></div></div>
    </div>`;
  };
  document.addEventListener("click", async e => {
    const b = e.target.closest("[data-pdf]"); if (!b) return;
    b.disabled = true;
    try { await API.downloadPdf(b.dataset.pdf); } catch (err) { UI.toast(err.message, "danger"); }
    b.disabled = false;
  });
})();
