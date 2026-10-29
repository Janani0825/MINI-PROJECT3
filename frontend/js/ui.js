/* Shared UI helpers: navbar, page guard, toasts, formatting. */
(function () {
  const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtDate = iso => iso ? new Date(iso).toLocaleString("en-IN", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }) : "-";
  const badge = c => `<span class="verdict verdict-${esc((c || "").toLowerCase())}">${esc(c)}</span>`;

  function toast(msg, type) {
    let box = document.getElementById("toasts");
    if (!box) { box = document.createElement("div"); box.id = "toasts"; box.className = "toast-container position-fixed top-0 end-0 p-3"; document.body.appendChild(box); }
    const el = document.createElement("div");
    el.className = "toast align-items-center border-0 text-bg-" + (type || "dark");
    el.setAttribute("role", "alert");
    el.innerHTML = `<div class="d-flex"><div class="toast-body">${esc(msg)}</div><button class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div>`;
    box.appendChild(el);
    const t = new bootstrap.Toast(el, { delay: 3500 }); t.show();
    el.addEventListener("hidden.bs.toast", () => el.remove());
  }

  function showError(container, msg) {
    container.innerHTML = `<div class="alert alert-danger py-2 mb-0" role="alert"><i class="bi bi-exclamation-triangle me-1"></i>${esc(msg)}</div>`;
  }

  /* role: "user" | "admin" | null (public). Redirects when not allowed. */
  function guard(role) {
    const u = API.currentUser();
    if (role && !u) { location.href = "index.html"; return null; }
    if (role === "admin" && u.role !== "admin") { location.href = "scan.html"; return null; }
    if (role === "user" && u.role === "admin") { location.href = "admin.html"; return null; }
    return u;
  }

  function navbar(active) {
    const u = API.currentUser(); if (!u) return;
    const links = u.role === "admin"
      ? [["admin.html", "bi-grid-1x2", "Dashboard"]]
      : [["scan.html", "bi-radar", "Scan a URL"], ["history.html", "bi-clock-history", "History"], ["verify.html", "bi-patch-check", "Verify my website"], ["profile.html", "bi-person", "Profile"]];
    document.body.classList.add("has-side");
    document.getElementById("nav").innerHTML = `
      <aside class="side">
        <a class="brand" href="${u.role === "admin" ? "admin.html" : "scan.html"}"><span class="logo"><i class="bi bi-shield-check"></i></span><span>PhishGuard</span></a>
        <div class="lbl">${u.role === "admin" ? "Administration" : "Workspace"}</div>
        ${links.map(l => `<a class="item ${l[0] === active ? "active" : ""}" href="${l[0]}"><i class="bi ${l[1]}"></i><span>${l[2]}</span></a>`).join("")}
        <div class="me"><div class="avatar">${esc((u.name || "?").trim().charAt(0).toUpperCase())}</div>
          <div><div class="n">${esc(u.name)}</div><div class="r">${esc(u.role)}</div></div>
          <button id="logoutBtn" class="out" title="Log out"><i class="bi bi-box-arrow-right"></i></button></div>
      </aside>`;
    document.getElementById("logoutBtn").onclick = () => { API.logout(); location.href = "index.html"; };
  }

  function setLoading(btn, on, label) {
    if (on) { btn.dataset.label = btn.innerHTML; btn.disabled = true; btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span>${label || "Please wait..."}`; }
    else { btn.disabled = false; btn.innerHTML = btn.dataset.label || btn.innerHTML; }
  }

  /* Download rows as CSV (used for reports) */
  function downloadCSV(filename, rows) {
    if (!rows.length) return toast("Nothing to export.", "warning");
    const cols = Object.keys(rows[0]);
    const q = v => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
    const csv = [cols.join(",")].concat(rows.map(r => cols.map(c => q(r[c])).join(","))).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" })); a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }

  window.UI = { esc, fmtDate, badge, toast, showError, guard, navbar, setLoading, downloadCSV };
})();
