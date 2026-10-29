# Code Explanation (for the project discussion)

## 1. The big idea
The user sends a URL. We never open it. We only read the *characters* of the URL, run 7 simple
checks, add up points, and return an explained report. Everything is offline and deterministic:
the same URL always gives the same result.

## 2. Files
| File | Job |
|---|---|
| `app.py` | Web layer. Defines `/`, `/health`, `/api/scan`; turns errors into JSON; adds CORS headers. Contains no analysis logic. |
| `analyzer/url_validator.py` | Decides if the input is acceptable and cleans it up. |
| `analyzer/url_checks.py` | The 7 checks. Each returns the same `CheckResult` shape. |
| `analyzer/risk_scoring.py` | The only place with scoring numbers and thresholds. |
| `analyzer/scanner.py` | Calls the three steps in order and builds the final dict. |
| `tests/` | Automated tests for validation, analysis/scoring, and the API. |
| `Procfile`, `requirements*.txt` | Deployment and dependencies. |

## 3. Important functions
- `validate_url(raw)` — trims, checks length, rejects spaces/control chars/backslashes, requires `http(s)://`, rejects `user:pass@`, checks port, decides IP vs. domain, validates each hostname label, converts international names to punycode, builds `normalized`. Raises `ValidationError(code, message)` on any problem. Returns a `ParsedURL`.
- `check_*` functions — each takes a `ParsedURL`, returns `CheckResult(name, title, passed, severity, message, limitation, recommendation)`.
- `run_all_checks(parsed)` — runs every check in `ALL_CHECKS`.
- `score_checks(checks)` — looks up points for each failed check in `POINTS`, sums, caps at 100, builds the `indicators` list.
- `get_risk_level(score)` — Low / Medium / High from the thresholds.
- `build_summary`, `build_recommendations` — human-readable text; the summary never says "safe".
- `scan_url(raw)` — runs the whole pipeline.
- `create_app()` — Flask application factory (lets tests create a fresh app with different config).

## 4. Life of a request
1. Browser sends `POST /api/scan` with JSON.
2. `app.py` checks: body not empty -> Content-Type is JSON -> JSON parses -> is an object -> has `url`.
3. `scan_url` -> `validate_url` (errors become HTTP 400 with a code).
4. `run_all_checks` produces 7 results.
5. `score_checks` adds points -> `get_risk_level`.
6. Report dict -> `jsonify` -> HTTP 200. The `after_request` hook adds CORS headers.
7. Any unexpected exception is caught by the global handler: logged on the server, generic 500 JSON to the client.

## 5. Score calculation (example)
`http://paypal.com.evil.example:8080/login`
- HTTP, not HTTPS: +20
- Subdomain label `com` (decoy): +20
- Port 8080: +8
- Total 48 -> **Medium** (25–54).

Each check contributes at most once; checks that would describe the same problem are "not applicable"
(an IP host is not also judged on subdomains). Cap = 100.

## 6. Why we can't promise a URL is safe
- We never load the page, so we can't see its content, redirects or downloads.
- We never contact the server, so the certificate is not validated.
- No blocklists, domain-age or reputation data.
- Attackers can easily make a URL look "clean" (HTTPS, short, normal domain). Heuristics only catch some careless patterns.
- Legitimate URLs can trigger indicators (long tracking links, ports, IDN domains).
So the output is a *preliminary heuristic estimate*, and a zero score means "nothing found by these checks".

## 7. Likely instructor questions
1. **Why not fetch the URL to check it?** Security (SSRF, malware, tracking), speed, and it is outside the assignment; text analysis is safe and deterministic.
2. **Why reject `user:pass@host`?** It is a classic trick (`https://google.com@evil.test`) and the assignment requires rejecting it. `@` after the hostname is flagged separately.
3. **Why is HTTPS not "safe"?** HTTPS encrypts traffic; it does not prove the owner is honest. Free certificates are available to attackers.
4. **How do you avoid double counting?** One check = one contribution; overlapping checks return "not applicable".
5. **How would you tune the thresholds?** Edit `POINTS`/`LOW_MAX`/`MEDIUM_MAX` and re-run tests; boundaries are tested.
6. **Why a Flask app factory?** Tests can create isolated apps with custom config.
7. **Why handwritten CORS?** Fewer dependencies; ~10 lines; also tested.
8. **What are the false positives/negatives?** FP: long legit links, IDN domains. FN: look-alike domains like `paypa1.com`, hacked legitimate sites.
9. **How would you improve it?** Public Suffix List, brand look-alike detection, Safe Browsing/VirusTotal, rate limiting, database history.
10. **How is it deployed?** Gunicorn runs `app:app`; the platform provides `PORT`; `/health` is the monitor endpoint.
11. **How do you prevent leaking internals?** Global error handler returns a fixed message; details go to server logs only.
12. **Why Low/Medium/High thresholds 24/54?** A single weak signal (HTTP only = 20) stays Low; several signals or an IP host together push it to Medium/High. They are a design choice and easy to change.
