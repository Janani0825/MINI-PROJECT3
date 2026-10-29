/* API client: one place that talks to Flask (or the mock). */
(function () {
  const TOKEN_KEY = "fwd_token", USER_KEY = "fwd_user";
  const store = {
    // sessionStorage = one login per browser tab, so a user and the admin can be logged in side by side in two tabs
    get(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } },
    set(k, v) { try { sessionStorage.setItem(k, v); } catch (e) {} },
    del(k) { try { sessionStorage.removeItem(k); } catch (e) {} }
  };

  async function request(method, path, body) {
    const token = store.get(TOKEN_KEY);
    if (CONFIG.USE_MOCK) return MockAPI.request(method, path, body, token);
    let res;
    try {
      res = await fetch(CONFIG.API_BASE + path, {
        method,
        headers: Object.assign({ "Content-Type": "application/json" }, token ? { Authorization: "Bearer " + token } : {}),
        body: body ? JSON.stringify(body) : undefined
      });
    } catch (e) { throw new Error("Cannot reach the server. Is the Flask backend running at " + CONFIG.API_BASE + " ?"); }
    let data = {}; try { data = await res.json(); } catch (e) {}
    if (!res.ok) { const err = new Error(data.error || data.message || "Request failed (" + res.status + ")"); err.status = res.status; throw err; }
    return data;
  }

  window.API = {
    register: (name, email, password) => request("POST", "/register", { name, email, password }),
    async login(email, password) {
      const d = await request("POST", "/login", { email, password });
      store.set(TOKEN_KEY, d.token); store.set(USER_KEY, JSON.stringify(d.user)); return d.user;
    },
    logout() { store.del(TOKEN_KEY); store.del(USER_KEY); },
    currentUser() { try { return JSON.parse(store.get(USER_KEY)); } catch (e) { return null; } },
    async updateProfile(data) { const u = await request("PUT", "/profile", data); store.set(USER_KEY, JSON.stringify(u)); return u; },
    scan: (url, deep) => request("POST", "/scan", { url, deep: !!deep }),
    async downloadPdf(id) {
      const res = await fetch(CONFIG.API_BASE + "/scans/" + id + "/report.pdf", { headers: { Authorization: "Bearer " + store.get(TOKEN_KEY) } });
      if (!res.ok) throw new Error("Could not create the report.");
      const url = URL.createObjectURL(await res.blob()), a = document.createElement("a");
      a.href = url; a.download = "PhishGuard-" + id + ".pdf"; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000);
    },
    scans: () => request("GET", "/scans"),
    sites: {
      categories: () => request("GET", "/sites/categories"),
      request: data => request("POST", "/sites/request", data),
      checkCode: id => request("POST", "/sites/" + id + "/check"),
      mine: () => request("GET", "/sites/mine"),
      verified: () => request("GET", "/sites/verified")
    },
    deleteScan: id => request("DELETE", "/scans/" + id),
    admin: {
      stats: () => request("GET", "/admin/stats"),
      users: () => request("GET", "/admin/users"),
      scans: () => request("GET", "/admin/scans"),
      trends: () => request("GET", "/admin/trends"),
      blacklist: () => request("GET", "/admin/blacklist"),
      addBlacklist: (domain, source) => request("POST", "/admin/blacklist", { domain, source }),
      removeBlacklist: id => request("DELETE", "/admin/blacklist/" + id),
      sites: status => request("GET", "/admin/sites" + (status ? "?status=" + status : "")),
      reviewSite: (id, action, note, override, checks) => request("PUT", "/admin/sites/" + id, { action, note, override: !!override, checks: checks || [] }),
      checkSite: id => request("POST", "/admin/sites/" + id + "/check"),
      incidents: () => request("GET", "/admin/incidents"),
      updateIncident: (id, status, unblock) => request("PUT", "/admin/incidents/" + id, { status, unblock: !!unblock }),
      reports: () => request("GET", "/admin/reports"),
      createReport: (report_type, date_range) => request("POST", "/admin/reports", { report_type, date_range })
    }
  };
})();
