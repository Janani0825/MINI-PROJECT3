# Fake Website Detection Portal

Web application that analyses a website URL and classifies it as **Safe / Suspicious / Fake**
with a risk score and the reasons. Runs fully offline on your own computer.

    frontend/   HTML5, CSS3, Bootstrap 5, JavaScript (Bootstrap is bundled, no internet needed)
    backend/    Python Flask API + MongoDB
    ml/         Detection engine (XGBoost model + rules + blacklist/whitelist)

## Run it (Windows / Linux / Mac)
1. Install **Python 3.10+** and **MongoDB Community Server** (also install *MongoDB Compass* to view the data).
   Make sure MongoDB is running (Windows: Services -> "MongoDB Server" is Running).
2. Open a terminal in the `backend` folder:

       python -m venv venv
       venv\Scripts\activate            (Linux/Mac: source venv/bin/activate)
       pip install -r requirements.txt
       python app.py

3. Open **http://localhost:5000** in Chrome or Edge.

Default admin: `admin@portal.com` / `Admin@123`  (created automatically on first start).
Change it:  `set ADMIN_PASSWORD=YourStrongPassword` (Linux/Mac: `export ...`) BEFORE the first start (it is only read when the admin is first created).
New users register on the Register page.

No MongoDB yet? Try the app anyway with an in-memory test database (data is lost when you stop):
`set USE_MOCK_DB=1` then `python app.py`.

Demo without any backend: in `frontend/js/config.js` set `USE_MOCK: true` and open the folder with
`python -m http.server 8000`.

## Database (MongoDB: `fake_website_portal`)
| Collection | Purpose |
|---|---|
| users | name, email, bcrypt password hash, role (user/admin), created_at, last_login |
| scans | submitted URL, domain, protocol, date, status, extracted features |
| detection_result | risk_score, classification, reasons, ML probability, matched legit domain, recommendation |
| blacklist | malicious domains managed by the admin |
| reports | generated reports (CSV files saved in `backend/generated_reports/`) |
| verified_sites | website-verification requests (pending / approved / rejected / revoked) with the owner's evidence and automatic checks |
| incidents | threat-monitor alerts: campaigns, repeated attempts, many-user hits, risky users |
| admin_logs | audit trail of admin actions (blacklist changes, reports, incident decisions) |
| counters | produces readable IDs: U001, S001, B001, R001, I001, L001 |

Open Compass -> connect to `mongodb://localhost:27017` -> database `fake_website_portal` to see it.

## How it works
1. User enters a URL -> `POST /api/scan` (login token required).
2. Backend checks the URL text: **verified owner** -> blacklist -> trusted-domain whitelist -> ML model (37 URL features) ->
   **look-alike check** -> reasons from the rule layer.
3. Scan + result are saved in MongoDB and shown with risk score, reasons and recommendation.
4. **Threat monitor** runs after every scan (behaviour over time, see below).
5. Optional **Deep scan** (switch on the scan page) looks inside the page and checks its security headers.
6. Admin dashboard: statistics, trends, threat monitor, scans, users, blacklist, CSV reports.

### What is new in this version (novelty points for the review)
- **Explainable detection layers:** every result shows which of the six layers (verified owner, blacklist, trusted list, look-alike, ML model,
  page check) fired and which one decided the verdict.
- **Per-URL ML explanation:** a bar chart of which URL features pushed this particular score up or down (occlusion method).
- **Look-alike detector** against 20,000 popular domains, **threat monitor** (auto-blocking over time) and optional **page check**.
- **Verified Website Registry:** site owners request verification (category, purpose, proof, contact e-mail). The admin sees
  automatic flags (free e-mail, look-alike of a popular brand, blacklisted, scanner verdict, token on the site) and approves or rejects.
  Other users who scan that address see a *Verified website* card: organisation, category, what it is used for, owner.
- Dark "security console" interface with sidebar navigation and an animated scan.

### Look-alike detection (typosquatting)
`ml/lookalike.py` compares the domain with the 20,000 most popular domains using Damerau-Levenshtein distance
(a swap of two letters is one edit), look-alike characters (`1`=l, `0`=o, `rn`=m), added hyphens and same-name-other-ending.
`fristcry.com`, `fristfry.com`, `fristtry.com` -> *"looks like firstcry.com"*. Try it: `python ml/lookalike.py fristcry.com`.

### Threat monitor (automatic blocking)  `backend/threat.py`
| Rule | Default | Action |
|---|---|---|
| repeat | same user scans the same fake site 3x in 10 min | domain auto-blacklisted |
| crowd | 2 different users hit the same fake site in 24 h | domain auto-blacklisted |
| campaign | 3 look-alike domains of one brand in 24 h | all of them auto-blacklisted |
| risky user | one user scans 5 different fake sites in 10 min | admin alerted |

Each action creates an **incident** (admin dashboard -> *Threat monitor*). The admin can mark it reviewed, or press
**Undo block** if it was a false alarm (the auto-added domains are removed). Limits can be changed with environment
variables (`REPEAT_COUNT`, `CROWD_USERS`, `CAMPAIGN_DOMAINS`, `RISKY_DOMAINS`, ...) in `backend/config.py`.

### Verified Website Registry  `backend/sites.py`
User menu -> **Verify my website**; admin -> **Site verification** tab. Approving needs an explicit *override* tick if the domain
is blacklisted or looks like a popular brand. A blacklisted domain always beats a verified one (a verified site that is later
reported is still blocked). The admin can **revoke** a verification at any time. Subdomain tricks such as
`mepcoeng.ac.in.evil-login.com` are not treated as verified: only the exact registered domain matches.

**Ownership proof.** The owner adds the verification code to the website (page text, `<meta>` tag or `/.well-known/phishguard.txt`)
and presses **Check my code**; the admin can also check it. An e-mail address on the domain is only a hint, never proof. The admin
cannot approve until either the code was found or a manual check is ticked (*official documents checked* / *organisation contacted*).
The ticked checks are saved with the decision.

**Sessions.** The login is kept per browser tab (sessionStorage), so a user and the admin can be logged in in two tabs of the
same browser at the same time.

### False-alarm control for unknown sites
The ML model was trained on data where many safe URLs had paths and many phishing URLs were bare home pages, so it tends to
over-flag unfamiliar home pages. Therefore (`ML_ONLY_CAP=1`, default) a verdict that rests on the ML model alone is capped at
*Suspicious* unless another signal agrees (look-alike, blacklist, rules). Government / education endings (`.ac.in`, `.edu`,
`.gov.in` ...) are trusted as restricted domains. Set `ML_ONLY_CAP=0` to see the raw model. Retraining with more benign home
pages would remove the need for this cap.

### Deep scan: page content + security headers, PDF report
Tick **Deep scan** on the scan page. Besides the page-content analysis below, the portal reads the website's HTTP response
headers and shows a **security grade (A-F)**: HTTPS, HSTS, Content-Security-Policy, clickjacking protection, X-Content-Type-Options,
Referrer-Policy and cookie flags, with a fix for every missing item. For **verified websites** these are shown as recommendations
for the owner. The grade is information only and never changes the phishing risk score (many genuine small sites miss headers).
Every result has a **Download report** button (PDF, `backend/report_pdf.py`, needs `reportlab`).

### Page check ("deep scan")  `backend/pagecheck.py`
Only when the user ticks **Also check the page content**. The page HTML is downloaded safely (public IPs only, 6 s timeout,
1 MB limit, redirects re-checked, JavaScript never run) and checked for: password box, form sending data to another
domain, images loaded from the real brand's site, text/structure similarity to the real site's home page, and very new
domains (RDAP). If there is no internet, the result simply says the page could not be checked.

## Evaluation of the hybrid detector (`ml/evaluate_hybrid.py`)
`python evaluate_hybrid.py --data-dir <folder with the feeds>` rebuilds five test sets and writes `ml/reports/hybrid_evaluation.md`.
Result on 1,500 URLs per set (portal default settings):

| Test set | ML only: Fake | Portal: Fake | Portal: flagged (Suspicious + Fake) |
|---|---|---|---|
| phishing feed URLs | 97.1% | 42.9% | 90.1% |
| phishing, home page only | 98.7% | 19.4% | 89.4% |
| legitimate unknown sites, home page | 94.4% | 3.7% | 96.0% |
| legitimate unknown sites, with path | 0.4% | 0.3% | 4.1% |
| typosquats of the top brands | 97.7% | 91.1% | 99.9% |

How to read it: the ML model alone calls almost every unknown home page "Fake" (94%), so its high phishing score is not meaningful.
The hybrid keeps the verdict *Suspicious* for those, and the **look-alike layer** is what separates typosquats (91% Fake) from genuine unknown
sites (3.7% Fake). The look-alike layer finds 87% of generated typosquats with 2% strong false alarms on real, unrelated domains.
Weak point (state it honestly): a phishing *home page* on a brand-new domain with no look-alike is only caught as Suspicious
(Fake only 19%). A URL-only model cannot separate unknown home pages; page content (deep scan) and retraining with more benign
home pages are the way to improve it.

## Security features (mention these in your review)
- Passwords hashed with **bcrypt**; login uses signed **JWT tokens** that expire in 8 hours.
- **Role-based access**: every `/api/admin/*` route is checked on the server, not just hidden in the page.
- A user can only read and delete **their own** scans.
- **Rate limiting** on login (8/min) and scanning (30/min); input validation and length limits.
- The same error message for wrong email and wrong password (no user enumeration).
- Page output is HTML-escaped to prevent XSS; the scanned URL is only fetched in the optional page check, which blocks private/local addresses.

## Troubleshooting
- *"Cannot connect to MongoDB"* -> start the MongoDB service, or use `USE_MOCK_DB=1` to test.
- *ModuleNotFoundError* -> activate the venv and run `pip install -r requirements.txt` again.
- Port 5000 busy -> `set PORT=5001` then `python app.py`.
- Reset everything: drop the `fake_website_portal` database in Compass.

## Known limits
- Tested here with an in-memory MongoDB simulator (mongomock), not a real MongoDB server; if something
  behaves differently on your MongoDB, tell me the error message.
- Detection uses the URL text (plus the optional page check); see `ml/README.md` for accuracy numbers and limitations.
- Look-alike matching can wrongly match a small genuine site whose name is close to a popular one (about 7% of a random
  sample of genuine mid-ranked sites in my test). It therefore only raises the score; the admin can undo auto-blocks.
- The page check and domain-age lookup were tested with local test pages, not against live websites (no internet in my
  test environment).
- This runs on one machine for development (Flask's built-in server). It is not a production deployment.
