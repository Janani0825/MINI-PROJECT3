UI.guard("admin"); UI.navbar("admin.html");
const { esc, fmtDate, badge } = UI;
const $ = id => document.getElementById(id);
const empty = (cols, text) => `<tr><td colspan="${cols}"><div class="empty"><i class="bi bi-inbox"></i>${text}</div></td></tr>`;
let scans = [];

function fail(err) {
  if (err.status === 401 || err.status === 403) { API.logout(); location.href = "index.html"; return; }
  UI.toast(err.message, "danger");
}

async function loadStats() {
  try {
    const s = await API.admin.stats();
    const card = (ico, cls, n, l) => `<div class="col-6 col-lg-2"><div class="card stat"><div class="ico ${cls}"><i class="bi ${ico}"></i></div><div><div class="num">${n}</div><div class="lbl">${l}</div></div></div></div>`;
    $("stats").innerHTML = card("bi-people", "ico-blue", s.users, "Users") + card("bi-search", "ico-gray", s.scans, "Total scans") +
      card("bi-shield-check", "ico-green", s.safe, "Safe") + card("bi-exclamation-triangle", "ico-amber", s.suspicious, "Suspicious") +
      card("bi-shield-x", "ico-red", s.fake, "Fake") + card("bi-slash-circle", "ico-gray", s.blacklist, "Blacklisted");
    const sb = $("siteBadge"); sb.textContent = s.sites_pending || ""; sb.classList.toggle("d-none", !s.sites_pending);
    const ob = $("incBadge"); ob.textContent = s.incidents_open || ""; ob.classList.toggle("d-none", !s.incidents_open);
  } catch (e) { fail(e); }
}

async function loadTrends() {
  try {
    const t = await API.admin.trends();
    const max = Math.max(1, ...t.daily.map(d => d.safe + d.suspicious + d.fake));
    $("trend").innerHTML = t.daily.map(d => {
      const h = v => (v / max * 130) + "px";
      return `<div class="col"><div class="stack" title="${d.date}: ${d.safe} safe, ${d.suspicious} suspicious, ${d.fake} fake">
        <div class="s" style="height:${h(d.safe)}"></div><div class="w" style="height:${h(d.suspicious)}"></div><div class="f" style="height:${h(d.fake)}"></div></div>
        <div class="lab">${d.date.slice(5)}</div></div>`; }).join("");
    const L = t.layers || {}, tot = Math.max(1, Object.values(L).reduce((a, b) => a + b, 0));
    const names = { blacklist: "Blacklist", whitelist: "Trusted list", lookalike: "Look-alike", ml: "ML model" };
    $("layerBars").innerHTML = Object.keys(L).length ? Object.entries(L).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
      `<div class="lay"><div>${esc(names[k] || k)}</div><div class="track"><div class="fill" style="width:${v / tot * 100}%"></div></div><div class="text-end">${v}</div></div>`).join("")
      : `<div class="text-muted small">No scans yet.</div>`;
    $("topFake").innerHTML = t.top_fake_domains.length
      ? t.top_fake_domains.map(x => `<li class="mb-1"><span class="text-break">${esc(x.domain)}</span> <span class="badge text-bg-danger">${x.count}</span></li>`).join("")
      : `<li class="list-unstyled text-muted ms-n3">No fake domains detected yet.</li>`;
  } catch (e) { fail(e); }
}

function drawScans() {
  const q = $("sq").value.toLowerCase(), f = $("sf").value;
  const list = scans.filter(s => (!f || (s.result && s.result.classification === f)) &&
    (!q || [s.submitted_url, s.domain, s.user_name, s.user_id].join(" ").toLowerCase().includes(q)));
  $("scanRows").innerHTML = list.length ? list.map(s => `<tr><td>${esc(s.scan_id)}</td><td>${esc(s.user_name || s.user_id)}</td>
    <td><div class="url-cell" title="${esc(s.submitted_url)}">${esc(s.submitted_url)}</div></td><td class="small">${fmtDate(s.scan_date)}</td>
    <td><b>${s.result ? s.result.risk_score : "-"}%</b></td><td>${s.result ? badge(s.result.classification) : "-"}</td></tr>`).join("") : empty(6, "No scans yet.");
}

async function loadScans() { try { scans = await API.admin.scans(); drawScans(); } catch (e) { fail(e); } }

async function loadUsers() {
  try {
    const u = await API.admin.users();
    $("userRows").innerHTML = u.length ? u.map(x => `<tr><td>${esc(x.user_id)}</td><td>${esc(x.name)}</td><td>${esc(x.email)}</td>
      <td><span class="badge text-bg-${x.role === "admin" ? "primary" : "secondary"}">${esc(x.role)}</span></td><td>${x.scan_count != null ? x.scan_count : "-"}</td>
      <td class="small">${fmtDate(x.created_at)}</td><td class="small">${fmtDate(x.last_login)}</td></tr>`).join("") : empty(7, "No users.");
  } catch (e) { fail(e); }
}

async function loadBlacklist() {
  try {
    const b = await API.admin.blacklist();
    $("blRows").innerHTML = b.length ? b.map(x => `<tr><td>${esc(x.blacklist_id)}</td><td><code>${esc(x.domain)}</code></td><td>${esc(x.source)}</td>
      <td class="small">${fmtDate(x.added_date)}</td><td class="text-end"><button class="btn btn-sm btn-outline-danger" data-rm="${esc(x.blacklist_id)}"><i class="bi bi-trash"></i></button></td></tr>`).join("") : empty(5, "Blacklist is empty.");
  } catch (e) { fail(e); }
}

const KIND = { campaign: ["Campaign", "danger"], crowd: ["Many users", "danger"], repeat: ["Repeated", "warning"], risky_user: ["Risky user", "warning"] };
async function loadIncidents() {
  try {
    const list = await API.admin.incidents();
    $("incRows").innerHTML = list.length ? list.map(i => { const k = KIND[i.kind] || [i.kind, "secondary"];
      return `<tr><td>${esc(i.incident_id)}</td><td><span class="badge text-bg-${k[1]}">${esc(k[0])}</span></td>
      <td><div class="fw-semibold">${esc(i.title)}</div><div class="small text-muted">${esc(i.details)}</div>
        <div class="small mt-1">${(i.domains || []).map(d => `<code class="me-1">${esc(d)}</code>`).join("")}</div></td>
      <td class="small">${esc(i.auto_action || "-")}</td><td class="small">${fmtDate(i.updated_at)}</td>
      <td><span class="badge text-bg-${i.status === "open" ? "danger" : "secondary"}">${esc(i.status)}</span></td>
      <td class="text-end text-nowrap">${i.status === "open" ? `<button class="btn btn-sm btn-outline-secondary" data-inc="${esc(i.incident_id)}" data-st="reviewed">Reviewed</button>
        ${i.auto_action && /blacklist/i.test(i.auto_action) ? `<button class="btn btn-sm btn-outline-danger ms-1" data-inc="${esc(i.incident_id)}" data-st="dismissed" data-unblock="1" title="False alarm: dismiss and remove the auto-blacklisted domains">Undo block</button>` : `<button class="btn btn-sm btn-outline-secondary ms-1" data-inc="${esc(i.incident_id)}" data-st="dismissed">Dismiss</button>`}` : ""}</td></tr>`; }).join("")
      : empty(7, "No incidents. The monitor is watching scans.");
  } catch (e) { fail(e); }
}
$("incRows").addEventListener("click", async e => {
  const b = e.target.closest("[data-inc]"); if (!b) return;
  if (b.dataset.unblock && !confirm("Dismiss this incident and remove the domains that were auto-blacklisted?")) return;
  try { await API.admin.updateIncident(b.dataset.inc, b.dataset.st, !!b.dataset.unblock); loadIncidents(); loadStats(); loadBlacklist(); } catch (err) { UI.toast(err.message, "danger"); }
});

const SST = { pending: "warning", approved: "success", rejected: "danger", revoked: "secondary" };
let siteList = [], siteModal = null, curSite = null;
async function loadSites() {
  try {
    siteList = await API.admin.sites($("siteFlt").value);
    $("siteRows").innerHTML = siteList.length ? siteList.map(r => `<tr><td>${esc(r.verified_id)}</td>
      <td><code>${esc(r.domain)}</code><div class="small text-muted">${esc(r.org_name)}</div></td>
      <td>${esc(r.owner_name)}<div class="small text-muted">${esc(r.contact_email)}</div></td><td class="small">${esc(r.category)}</td>
      <td>${(r.flags || []).map(f => `<span class="chip ${f.level}" title="${esc(f.text)}">${esc(f.text.length > 38 ? f.text.slice(0, 36) + "..." : f.text)}</span>`).join("")}</td>
      <td><span class="badge text-bg-${SST[r.status] || "secondary"}">${esc(r.status)}</span></td>
      <td class="text-end"><button class="btn btn-sm btn-outline-primary" data-site="${esc(r.verified_id)}"><i class="bi bi-eye me-1"></i>Review</button></td></tr>`).join("")
      : empty(7, "No requests here.");
  } catch (e) { fail(e); }
}
function siteDetail(r) {
  const a = r.analysis || {}, tc = r.token_check;
  const pend = r.status === "pending", appr = r.status === "approved";
  const risky = a.blacklisted || a.lookalike;
  return `<div class="d-flex justify-content-between align-items-start mb-2"><div><div class="fs-5 fw-bold">${esc(r.org_name)}</div><code>${esc(r.domain)}</code></div>
      <span class="badge text-bg-${SST[r.status] || "secondary"}">${esc(r.status)}</span></div>
    <div class="row g-2 small mb-3">
      <div class="col-sm-6"><b>Category:</b> ${esc(r.category)}</div><div class="col-sm-6"><b>Requested:</b> ${fmtDate(r.requested_at)}</div>
      <div class="col-sm-6"><b>Requested by:</b> ${esc(r.owner_name)}</div><div class="col-sm-6"><b>Contact e-mail:</b> ${esc(r.contact_email)}</div>
      <div class="col-12"><b>Used for:</b> ${esc(r.purpose)}</div><div class="col-12"><b>Proof given:</b> ${esc(r.evidence)}</div></div>
    <div class="card-title-sm mb-2">Automatic checks</div>
    ${(r.flags || []).map(f => `<div class="flag ${f.level}">${esc(f.text)}</div>`).join("")}
    <div class="mt-3 mb-1 card-title-sm">Verification code</div><div class="token-box small">${esc(r.token)}</div>
    <div class="small mt-2">${tc ? `<i class="bi bi-${tc.found ? "check-circle text-success" : "x-circle text-danger"} me-1"></i>Code check: ${esc(tc.note)} (${fmtDate(tc.at)})` : "Code not checked yet."}
      <button class="btn btn-sm btn-outline-secondary ms-2" id="chkTok"><i class="bi bi-globe2 me-1"></i>Check code on website</button></div>
    ${r.admin_note ? `<div class="mt-3 small"><b>Earlier note:</b> ${esc(r.admin_note)}</div>` : ""}
    ${pend ? `<hr><div class="card-title-sm mb-2">Verification checklist</div>
      <div class="flag ${r.proof && r.proof.proven ? "ok" : "warn"} mb-2">${r.proof && r.proof.proven ? "Automatic proof: the code was found on the website." : "No automatic proof yet. Complete at least one manual check below before approving."}</div>
      <div class="form-check"><input class="form-check-input" type="checkbox" id="ck_documents"><label class="form-check-label small" for="ck_documents">I checked the official documents / proof given by the requester</label></div>
      <div class="form-check mb-2"><input class="form-check-input" type="checkbox" id="ck_contacted"><label class="form-check-label small" for="ck_contacted">I contacted the organisation on its official phone number or e-mail</label></div>` : ""}
    ${pend || appr ? `<hr><label class="form-label small">Note to the owner (optional)</label><input id="siteNote" class="form-control mb-2" maxlength="300">
      ${pend && risky ? `<div class="form-check mb-2"><input class="form-check-input" type="checkbox" id="siteOver"><label class="form-check-label small text-warning" for="siteOver">This domain is blacklisted or looks like a popular brand. I am completely sure the owner is genuine (override).</label></div>` : ""}
      <div class="d-flex gap-2">${pend ? `<button class="btn btn-success" data-act="approve"><i class="bi bi-patch-check me-1"></i>Approve</button><button class="btn btn-outline-danger" data-act="reject"><i class="bi bi-x-circle me-1"></i>Reject</button>` : ""}
        ${appr ? `<button class="btn btn-outline-danger" data-act="revoke"><i class="bi bi-slash-circle me-1"></i>Revoke verification</button>` : ""}</div>` : ""}`;
}
function openSite(r) { curSite = r; $("siteBody").innerHTML = siteDetail(r); siteModal = siteModal || new bootstrap.Modal($("siteModal")); siteModal.show(); }
$("siteFlt").onchange = loadSites;
$("siteRows").addEventListener("click", e => { const b = e.target.closest("[data-site]"); if (b) openSite(siteList.find(x => x.verified_id === b.dataset.site)); });
$("siteBody").addEventListener("click", async e => {
  if (!curSite) return;
  if (e.target.closest("#chkTok")) {
    const b = e.target.closest("#chkTok"); b.disabled = true;
    try { openSite(await API.admin.checkSite(curSite.verified_id)); loadSites(); } catch (err) { UI.toast(err.message, "danger"); b.disabled = false; }
    return;
  }
  const b = e.target.closest("[data-act]"); if (!b) return;
  try {
    const checks = ["documents", "contacted"].filter(k => $("ck_" + k) && $("ck_" + k).checked);
    await API.admin.reviewSite(curSite.verified_id, b.dataset.act, $("siteNote").value, $("siteOver") && $("siteOver").checked, checks);
    siteModal.hide(); UI.toast("Request " + b.dataset.act + "d", "success"); loadSites(); loadStats(); loadBlacklist();
  } catch (err) { UI.toast(err.message, "danger"); }
});

async function loadReports() {
  try {
    const r = await API.admin.reports();
    $("repRows").innerHTML = r.length ? r.map(x => `<tr><td>${esc(x.report_id)}</td><td>${esc(x.report_type)}</td><td>${esc(x.date_range)}</td><td class="small">${fmtDate(x.generated_at)}</td><td><code>${esc(x.file_path)}</code></td></tr>`).join("") : empty(5, "No reports generated yet.");
  } catch (e) { fail(e); }
}

$("sq").oninput = drawScans; $("sf").onchange = drawScans;

$("blForm").addEventListener("submit", async e => {
  e.preventDefault();
  try { await API.admin.addBlacklist($("blDomain").value, $("blSource").value); $("blDomain").value = $("blSource").value = "";
    UI.toast("Domain blacklisted", "success"); loadBlacklist(); loadStats(); } catch (err) { UI.toast(err.message, "danger"); }
});
$("blRows").addEventListener("click", async e => {
  const b = e.target.closest("[data-rm]"); if (!b || !confirm("Remove this domain from the blacklist?")) return;
  try { await API.admin.removeBlacklist(b.dataset.rm); loadBlacklist(); loadStats(); } catch (err) { UI.toast(err.message, "danger"); }
});

/* Report: log it through the API, then export matching rows as CSV in the browser. */
$("repBtn").addEventListener("click", async () => {
  const type = $("repType").value, days = +$("repRange").value, label = days ? "Last " + days + " days" : "All time";
  try {
    await API.admin.createReport(type, label);
    const since = days ? Date.now() - days * 864e5 : 0;
    let rows = scans.filter(s => new Date(s.scan_date).getTime() >= since);
    if (type === "Fake Websites") rows = rows.filter(s => s.result && s.result.classification === "Fake");
    UI.downloadCSV(type.toLowerCase().replace(/\s+/g, "-") + ".csv", rows.map(s => ({
      scan_id: s.scan_id, user: s.user_name || s.user_id, url: s.submitted_url, domain: s.domain, date: s.scan_date,
      risk_score: s.result && s.result.risk_score, classification: s.result && s.result.classification, reason: s.result && s.result.detection_reason })));
    loadReports();
  } catch (err) { UI.toast(err.message, "danger"); }
});

loadStats(); loadTrends(); loadIncidents(); loadSites(); loadScans(); loadUsers(); loadBlacklist(); loadReports();
