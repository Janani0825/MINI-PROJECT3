# PhishGuard – Frontend
Fake Website Detection Portal (HTML5, CSS3, Bootstrap 5, JavaScript).
Bootstrap and icons are bundled in `vendor/`, so it works **fully offline**.

## 1. Run it (demo mode – no backend needed)
Open a terminal in this folder and run ONE of these:

    python -m http.server 8000        # Python (recommended)
    # or: npx serve .                 # Node
    # or: VS Code -> install "Live Server" -> right-click index.html -> Open with Live Server

Then open **http://localhost:8000** in Chrome/Edge.

Demo mode keeps data in the browser (localStorage) and uses the same rules as your slides
(URL length, IP, '@', dots, hyphens, keywords, blacklist, Levenshtein similarity).
- Admin login: `admin@portal.com` / `Admin@123`
- Users: click "Create an account".

## 2. Connect your Flask + MongoDB backend
1. Open `js/config.js` and set:

       USE_MOCK: false,
       API_BASE: "http://127.0.0.1:5000/api"

2. In Flask enable CORS (when frontend runs on a different port):

       pip install flask flask-cors
       from flask_cors import CORS
       CORS(app)

   Or serve this folder from Flask itself: `app = Flask(__name__, static_folder="frontend", static_url_path="")`
   and set `API_BASE: "/api"`.

3. Implement these endpoints (JSON in/out, `Authorization: Bearer <token>` header; errors as `{"error": "message"}`):

| Method | Path | Body | Returns |
|---|---|---|---|
| POST | /api/register | name, email, password | `{message}` |
| POST | /api/login | email, password | `{token, user:{user_id,name,email,role,created_at,last_login}}` |
| PUT | /api/profile | name?, password? | updated user |
| POST | /api/scan | url | scan object (below) |
| GET | /api/scans | – | list of scan objects (current user, newest first) |
| DELETE | /api/scans/<scan_id> | – | `{message}` |
| GET | /api/admin/stats | – | `{users,scans,safe,suspicious,fake,blacklist}` |
| GET | /api/admin/users | – | users + `scan_count` |
| GET | /api/admin/scans | – | all scan objects (+ `user_name`) |
| GET | /api/admin/trends | – | `{daily:[{date,safe,suspicious,fake}], top_fake_domains:[{domain,count}]}` |
| GET/POST | /api/admin/blacklist | domain, source | list / `{message}` |
| DELETE | /api/admin/blacklist/<blacklist_id> | – | `{message}` |
| GET/POST | /api/admin/reports | report_type, date_range | list / report doc |

**Scan object** (joins your `scans` and `detection_result` collections):

    {
      "scan_id": "S001", "user_id": "U002", "submitted_url": "http://...", "domain": "...",
      "protocol": "http", "scan_date": "2026-10-18T07:30:00Z", "status": "completed",
      "features": { "url_length":42, "has_ip_address":false, "has_at_symbol":false, "num_dots":2,
                    "num_hyphens":1, "has_suspicious_keywords":true, "is_blacklisted":false },
      "result":   { "risk_score":65, "classification":"Fake", "detection_reason":"...",
                    "reasons":["...", "..."],            // optional; falls back to splitting detection_reason
                    "similarity_score":88, "matched_legit_domain":"paypal.com", "recommendation":"..." }
    }

## 3. Files
    index.html      login (user + admin)          register.html   sign up
    scan.html       URL submission + result       history.html    scan history, search, export
    profile.html    profile management            admin.html      admin dashboard (stats, trends, scans, users, blacklist, reports)
    js/config.js    switch mock / real API        js/api.js       all API calls
    js/mock.js      browser-only fake backend     js/result.js    result report renderer
    js/ui.js        navbar, toasts, helpers       js/admin.js     admin page logic
    css/style.css   styling                       vendor/         Bootstrap 5.3 + Icons (offline)

> Note: the frontend only hides pages by role. Your Flask backend must also check the
> token and the `admin` role on every `/api/admin/*` route, and hash passwords (e.g. bcrypt).
