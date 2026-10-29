/* ------------------------------------------------------------------
   MOCK BACKEND (browser only). Mimics the Flask API using localStorage.
   Implements the same rule-based scoring + Levenshtein idea from the
   review slides so the UI can be demonstrated without the server.
   Default admin:  admin@portal.com / Admin@123
------------------------------------------------------------------- */
(function () {
  const KEY = "fwd_mock_db_v1";
  const LEGIT = ["google.com","facebook.com","amazon.com","paypal.com","microsoft.com","apple.com",
    "instagram.com","netflix.com","twitter.com","linkedin.com","sbi.co.in","hdfcbank.com",
    "icicibank.com","flipkart.com","youtube.com","whatsapp.com","github.com","wikipedia.org"];
  const KEYWORDS = ["login","verify","secure","account","update","bank","confirm","signin","password","wallet","free","bonus","gift","urgent","suspend"];

  function load() {
    let db = null;
    try { db = JSON.parse(localStorage.getItem(KEY)); } catch (e) {}
    if (!db) {
      db = { users: [{ user_id:"U001", name:"Administrator", email:"admin@portal.com", password:"Admin@123",
                       role:"admin", created_at:new Date().toISOString(), last_login:null }],
             scans: [], results: [], blacklist: [
               { blacklist_id:"B001", domain:"paypa1-secure-login.com", added_date:new Date().toISOString(), source:"PhishTank" },
               { blacklist_id:"B002", domain:"sbi-kyc-update.in", added_date:new Date().toISOString(), source:"OpenPhish" }],
             reports: [] };
      save(db);
    }
    return db;
  }
  function save(db) { try { localStorage.setItem(KEY, JSON.stringify(db)); } catch (e) {} }
  const pad = (p, n) => p + String(n).padStart(3, "0");
  const err = (m, code) => { const e = new Error(m); e.status = code || 400; return e; };

  function lev(a, b) {
    const m = a.length, n = b.length, d = Array.from({ length: m + 1 }, (_, i) => [i]);
    for (let j = 1; j <= n; j++) d[0][j] = j;
    for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++)
      d[i][j] = Math.min(d[i-1][j] + 1, d[i][j-1] + 1, d[i-1][j-1] + (a[i-1] === b[j-1] ? 0 : 1));
    return d[m][n];
  }

  function parseUrl(raw) {
    let u = raw.trim();
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) u = "http://" + u;
    let x; try { x = new URL(u); } catch (e) { return null; }
    if (!x.hostname.includes(".") && !/^\[/.test(x.hostname)) return null;
    return x;
  }

  function analyse(raw, db) {
    const x = parseUrl(raw);
    if (!x) throw err("Invalid URL. Example: https://example.com/login");
    const domain = x.hostname.replace(/^www\./, "").toLowerCase();
    const protocol = x.protocol.replace(":", "");
    const f = {
      url_length: raw.trim().length,
      has_ip_address: /^\d{1,3}(\.\d{1,3}){3}$/.test(domain),
      has_at_symbol: raw.includes("@"),
      num_dots: (raw.match(/\./g) || []).length,
      num_hyphens: (raw.match(/-/g) || []).length,
      has_suspicious_keywords: KEYWORDS.some(k => raw.toLowerCase().includes(k)),
      is_blacklisted: db.blacklist.some(b => b.domain === domain)
    };
    // similarity to well-known domains (Levenshtein)
    let best = { d: "", s: 0 };
    LEGIT.forEach(l => {
      const s = 1 - lev(domain, l) / Math.max(domain.length, l.length);
      if (s > best.s) best = { d: l, s };
    });
    const similarity = Math.round(best.s * 100);
    const lookalike = domain !== best.d && similarity >= 75;

    let score = 0; const reasons = [];
    if (f.is_blacklisted)            { score += 70; reasons.push("Domain is present in the blacklist of known malicious sites."); }
    if (f.has_ip_address)            { score += 25; reasons.push("An IP address is used instead of a domain name."); }
    if (f.has_at_symbol)             { score += 15; reasons.push("The URL contains an '@' symbol, which can hide the real destination."); }
    if (f.url_length > 75)           { score += 15; reasons.push("The URL is unusually long (" + f.url_length + " characters)."); }
    else if (f.url_length > 54)      { score += 7;  reasons.push("The URL is longer than typical (" + f.url_length + " characters)."); }
    if (f.num_dots > 4)              { score += 12; reasons.push("Too many dots (" + f.num_dots + "), suggesting nested sub-domains."); }
    if (f.num_hyphens > 2)           { score += 10; reasons.push("Many hyphens (" + f.num_hyphens + ") in the URL."); }
    if (f.has_suspicious_keywords)   { score += 15; reasons.push("Contains phishing-related keywords (login, verify, secure ...)."); }
    if (protocol !== "https")        { score += 10; reasons.push("The connection is not encrypted (HTTP instead of HTTPS)."); }
    if (lookalike)                   { score += 35; reasons.push("Domain closely resembles the legitimate site '" + best.d + "' (" + similarity + "% similar)."); }
    if (LEGIT.includes(domain))      { score = Math.max(0, score - 40); reasons.length = 0; }
    score = Math.min(100, score);

    const C = window.CONFIG;
    const classification = score >= C.RISK_FAKE_MIN ? "Fake" : score >= C.RISK_SAFE_MAX ? "Suspicious" : "Safe";
    if (!reasons.length) reasons.push("No suspicious characteristics were found in this URL.");
    const recommendation = {
      Safe: "This URL looks safe, but always check the address bar before entering personal details.",
      Suspicious: "Proceed with caution. Do not enter passwords or payment details until you verify the site.",
      Fake: "Do not open this website or share any information. Report it to your administrator."
    }[classification];

    return { domain, protocol, features: f,
      result: { risk_score: score, classification, detection_reason: reasons.join(" "), reasons,
                similarity_score: similarity, matched_legit_domain: best.d, recommendation } };
  }

  function needUser(token, db) {
    const u = db.users.find(u => u.user_id === token);
    if (!u) throw err("Session expired. Please log in again.", 401);
    return u;
  }
  const pub = u => ({ user_id:u.user_id, name:u.name, email:u.email, role:u.role, created_at:u.created_at, last_login:u.last_login });
  const join = (db, s) => Object.assign({}, s, { result: db.results.find(r => r.scan_id === s.scan_id) || null });

  const routes = {
    "POST /register": (b, t, db) => {
      if (!b.name || !b.email || !b.password) throw err("All fields are required.");
      if (db.users.some(u => u.email.toLowerCase() === b.email.toLowerCase())) throw err("Email already registered.", 409);
      const u = { user_id: pad("U", db.users.length + 1), name:b.name, email:b.email, password:b.password,
                  role:"user", created_at:new Date().toISOString(), last_login:null };
      db.users.push(u); return { message: "Registered" };
    },
    "POST /login": (b, t, db) => {
      const u = db.users.find(u => u.email.toLowerCase() === (b.email||"").toLowerCase() && u.password === b.password);
      if (!u) throw err("Invalid email or password.", 401);
      u.last_login = new Date().toISOString(); return { token: u.user_id, user: pub(u) };
    },
    "GET /profile": (b, t, db) => pub(needUser(t, db)),
    "PUT /profile": (b, t, db) => {
      const u = needUser(t, db);
      if (b.name) u.name = b.name;
      if (b.password) u.password = b.password;
      return pub(u);
    },
    "POST /scan": (b, t, db) => {
      const u = needUser(t, db);
      const a = analyse(b.url, db);
      const scan = { scan_id: pad("S", db.scans.length + 1), user_id: u.user_id, user_name: u.name, submitted_url: b.url.trim(),
                     domain: a.domain, protocol: a.protocol, scan_date: new Date().toISOString(),
                     status: "completed", features: a.features };
      db.scans.push(scan);
      db.results.push(Object.assign({ scan_id: scan.scan_id }, a.result));
      return join(db, scan);
    },
    "GET /scans": (b, t, db) => { const u = needUser(t, db);
      return db.scans.filter(s => s.user_id === u.user_id).reverse().map(s => join(db, s)); },
    "DELETE /scans": (b, t, db, id) => { const u = needUser(t, db);
      db.scans = db.scans.filter(s => !(s.scan_id === id && (s.user_id === u.user_id || u.role === "admin")));
      db.results = db.results.filter(r => db.scans.some(s => s.scan_id === r.scan_id)); return { message: "Deleted" }; },

    "GET /admin/stats": (b, t, db) => { adminOnly(t, db);
      const c = k => db.results.filter(r => r.classification === k).length;
      return { users: db.users.filter(u => u.role === "user").length, scans: db.scans.length,
               safe: c("Safe"), suspicious: c("Suspicious"), fake: c("Fake"), blacklist: db.blacklist.length }; },
    "GET /admin/users": (b, t, db) => { adminOnly(t, db);
      return db.users.map(u => Object.assign(pub(u), { scan_count: db.scans.filter(s => s.user_id === u.user_id).length })); },
    "GET /admin/scans": (b, t, db) => { adminOnly(t, db); return db.scans.slice().reverse().map(s => join(db, s)); },
    "GET /admin/trends": (b, t, db) => { adminOnly(t, db);
      const days = []; for (let i = 6; i >= 0; i--) { const d = new Date(); d.setDate(d.getDate() - i); days.push(d.toISOString().slice(0, 10)); }
      const out = days.map(d => ({ date: d, safe: 0, suspicious: 0, fake: 0 }));
      db.scans.forEach(s => { const row = out.find(o => o.date === s.scan_date.slice(0, 10)); const r = db.results.find(r => r.scan_id === s.scan_id);
        if (row && r) row[r.classification.toLowerCase()]++; });
      const dom = {}; db.scans.forEach(s => { const r = db.results.find(r => r.scan_id === s.scan_id);
        if (r && r.classification === "Fake") dom[s.domain] = (dom[s.domain] || 0) + 1; });
      return { daily: out, top_fake_domains: Object.entries(dom).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([domain, count]) => ({ domain, count })) }; },
    "GET /admin/blacklist": (b, t, db) => { adminOnly(t, db); return db.blacklist.slice().reverse(); },
    "POST /admin/blacklist": (b, t, db) => { adminOnly(t, db);
      const d = (b.domain || "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
      if (!d) throw err("Enter a domain."); if (db.blacklist.some(x => x.domain === d)) throw err("Already blacklisted.", 409);
      db.blacklist.push({ blacklist_id: pad("B", db.blacklist.length + 1), domain: d, added_date: new Date().toISOString(), source: b.source || "Admin" });
      return { message: "Added" }; },
    "DELETE /admin/blacklist": (b, t, db, id) => { adminOnly(t, db); db.blacklist = db.blacklist.filter(x => x.blacklist_id !== id); return { message: "Removed" }; },
    "GET /admin/sites": (b, t, db) => { adminOnly(t, db); return []; },
    "GET /sites/categories": () => ["College / School / University", "Government / Public service", "Bank / Finance", "Shop / Business", "Healthcare", "NGO / Community", "Personal / Portfolio", "Other"],
    "GET /sites/mine": () => [],
    "GET /sites/verified": () => [],
    "GET /admin/incidents": (b, t, db) => { adminOnly(t, db); return []; },
    "GET /admin/reports": (b, t, db) => { adminOnly(t, db); return db.reports.slice().reverse(); },
    "POST /admin/reports": (b, t, db) => { const a = adminOnly(t, db);
      const rep = { report_id: pad("R", db.reports.length + 1), generated_by: a.user_id, report_type: b.report_type || "Summary",
                    date_range: b.date_range || "All time", generated_at: new Date().toISOString(),
                    file_path: "reports/" + pad("R", db.reports.length + 1) + ".csv" };
      db.reports.push(rep); return rep; }
  };
  function adminOnly(t, db) { const u = needUser(t, db); if (u.role !== "admin") throw err("Admin access required.", 403); return u; }

  window.MockAPI = {
    request(method, path, body, token) {
      return new Promise((resolve, reject) => {
        setTimeout(() => {
          try {
            const db = load();
            let key = method + " " + path, id = null;
            if (!routes[key]) { const i = path.lastIndexOf("/"); id = path.slice(i + 1); key = method + " " + path.slice(0, i); }
            if (!routes[key]) throw err("Not found: " + method + " " + path, 404);
            const out = routes[key](body || {}, token, db, id);
            save(db); resolve(JSON.parse(JSON.stringify(out)));
          } catch (e) { reject(e); }
        }, 350);   // small delay so the loading animation is visible
      });
    }
  };
})();
