# PhishGuard — Smart URL Security Scanner (Backend)

A small Flask REST API for a university Cloud Computing project. It takes a URL,
inspects the **text** of the URL, and returns an explainable, *preliminary* risk
score as JSON.

> **Educational tool.** PhishGuard never visits the URL and never says a URL is
> "safe" or "malicious". A score is a heuristic estimate, not a verified probability.

## Features
- `GET /` and `GET /health` (cloud health check), `POST /api/scan`
- Strict validation: only `http`/`https`, no credentials in the URL, max 2048 characters, valid hostnames/IPs
- 7 independent checks: HTTPS, IP-address host, URL length, subdomain count, suspicious patterns (`@`, encoded characters, embedded URLs), misleading hostnames (punycode, decoy `.com` labels), non-default port
- Transparent score 0–100 (Low / Medium / High), all rules in `analyzer/risk_scoring.py`
- Consistent JSON errors, no tracebacks ever returned
- No database, no external APIs, no API keys

## Technologies
Python 3.11+ (developed on 3.12) · Flask · Gunicorn · pytest · standard library (`urllib.parse`, `ipaddress`, `re`).
CORS is a ~10-line handler in `app.py`, so Flask-CORS is not needed.

## Folder structure
```
phishguard-backend/
├── app.py                  Flask app: routes, error handlers, CORS
├── analyzer/
│   ├── __init__.py
│   ├── url_validator.py    validation + normalization -> ParsedURL
│   ├── url_checks.py       the 7 checks -> CheckResult
│   ├── risk_scoring.py     points, thresholds, levels, recommendations
│   └── scanner.py          glue: validate -> checks -> score -> report
├── tests/                  test_validation.py, test_analysis.py, test_api.py
├── docs/
│   ├── CODE_EXPLANATION.md  study guide + likely instructor questions
│   └── FRONTEND_GUIDE.md    API contract + fetch() example for the frontend dev
├── requirements.txt        runtime deps       requirements-dev.txt  + pytest
├── Procfile                production start command
├── pytest.ini  .gitignore  README.md
```

## Install and run locally
```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements-dev.txt
python app.py                     # http://127.0.0.1:5000
```
Try it:
```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "http://example.com:8080/login"}'
```

## Run the tests
```bash
pytest -v
```
Tests are deterministic and use no network.

## API documentation
Base URL: `http://127.0.0.1:5000` locally, or your deployed URL.

### `GET /`
```json
{"name":"PhishGuard","version":"1.0.0","description":"...","message":"PhishGuard API is running."}
```
### `GET /health`
```json
{"status":"ok","service":"PhishGuard","version":"1.0.0"}
```
### `POST /api/scan`
Header: `Content-Type: application/json`. Body: `{"url": "<http or https URL>"}`

Success (`200`), shortened:
```json
{
  "success": true,
  "url": "http://paypal.com.evil.example:8080/login",
  "normalized_url": "http://paypal.com.evil.example:8080/login",
  "risk_score": 48,
  "risk_level": "Medium",
  "summary": "Preliminary heuristic estimate: 48/100 (Medium risk) based on 3 indicator(s). This is not a verified probability that the URL is malicious.",
  "indicators": [
    {"name":"https_usage","title":"HTTPS usage","severity":"medium","points":20,
     "message":"The URL uses plain HTTP, ...","recommendation":"Prefer the https:// version ..."}
  ],
  "recommendations": ["...", "..."],
  "checks": [
    {"name":"https_usage","title":"HTTPS usage","passed":false,"severity":"medium",
     "message":"...","limitation":"...","recommendation":"..."}
  ],
  "limitations": ["..."],
  "parsed": {"scheme":"http","hostname":"paypal.com.evil.example","is_ip_address":false,"port":8080,"path":"/login"}
}
```
`checks` always lists all 7 checks (passed or not). `indicators` lists only failed checks, with points.

Error (`4xx/5xx`):
```json
{"success": false, "error": {"code": "unsupported_scheme", "message": "Only http:// and https:// URLs are supported."}}
```

| Situation | Status | `error.code` |
|---|---|---|
| Empty body | 400 | `missing_body` |
| Not JSON | 400 | `invalid_json` |
| JSON is not an object | 400 | `invalid_body` |
| No `url` key | 400 | `missing_url` |
| `url` not a string | 400 | `invalid_url_type` |
| Empty / too long (>2048) | 400 | `empty_url` / `url_too_long` |
| Wrong Content-Type | 415 | `unsupported_media_type` |
| Body > 16 KB | 413 | `payload_too_large` |
| Bad scheme / malformed / credentials / host / port / characters | 400 | `missing_scheme`, `unsupported_scheme`, `malformed_url`, `credentials_not_allowed`, `invalid_hostname`, `invalid_port`, `invalid_characters` |
| Unknown route / wrong method | 404 / 405 | `not_found` / `method_not_allowed` |
| Unexpected bug | 500 | `internal_error` |

### How the score works
Each check adds points **once**; the total is capped at 100.

| Check | Points |
|---|---|
| HTTP instead of HTTPS | 20 |
| IP address as host | 30 |
| URL length > 100 / > 200 | 5 / 10 |
| Subdomains: 3 / 4+ | 5 / 12 |
| Suspicious patterns low / medium | 8 / 20 |
| Misleading hostname | 20 |
| Non-default port | 8 |

Levels: **Low 0–24**, **Medium 25–54**, **High 55–100**. Change `POINTS`, `LOW_MAX`, `MEDIUM_MAX` in `analyzer/risk_scoring.py` to tune. Overlaps are avoided: an IP host is "not applicable" for the subdomain and hostname checks. Hyphens and digits are never flagged.

## Cloud deployment (example: Render, free tier)
1. Push this folder to a GitHub repository.
2. Render → **New → Web Service** → connect the repo.
3. Runtime **Python 3**, Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2`
5. Health Check Path: `/health`
6. Environment variable: `CORS_ALLOWED_ORIGINS` = your frontend origin (e.g. `https://yourteam.github.io`). Without it, any origin is allowed (`*`), fine for a demo only.

The included `Procfile` also works as-is on Heroku and Railway. Any platform that can run `gunicorn app:app` and provides `PORT` will work.

Test the deployed API:
```bash
curl https://YOUR-APP.onrender.com/health
curl -X POST https://YOUR-APP.onrender.com/api/scan -H "Content-Type: application/json" -d '{"url":"https://example.com"}'
```
(Free instances may take ~30–60 s to wake up on the first request.)

## Security considerations
- The submitted URL is **never fetched**; no redirects, downloads or JavaScript are touched, so the service cannot be used for SSRF.
- URLs with embedded credentials, control characters, backslashes or non-http(s) schemes are rejected.
- Request body limited to 16 KB, URL to 2048 characters.
- Unexpected errors are logged on the server only; responses contain a generic message.
- No secrets in code. The only setting is `CORS_ALLOWED_ORIGINS`.
- The frontend must render returned text with `textContent`, not `innerHTML` (the URL is user-controlled).
- There is no rate limiting; add one (e.g. Flask-Limiter) before real public use.

## Known limitations
- Text-only analysis: no page content, redirects, certificate, domain age or blocklists.
- Look-alike brand spellings (`paypa1.com`) are not detected.
- Subdomain counting uses a small hand-written suffix list, not the Public Suffix List.
- Scores are heuristic; a Low score is not a guarantee of safety.

## Future improvements
Public Suffix List for domain parsing · brand look-alike detection (edit distance) · Google Safe Browsing / VirusTotal integration (needs API keys) · rate limiting · scan history in a database · Docker.

## Verification note
The backend test suite was run locally using pytest on Python 3.11.9.

Result: 87 tests passed in 0.28 seconds.

The Flask API was also tested locally using its health endpoint and the URL scanning endpoint.

Gunicorn deployment and cloud hosting still need to be verified in the target cloud environment.
