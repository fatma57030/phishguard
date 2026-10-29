# Frontend Integration Guide

| Item | Value |
|---|---|
| Endpoint | `POST {BASE_URL}/api/scan` |
| Header | `Content-Type: application/json` (required) |
| Body | `{"url": "https://example.com"}` |
| Success | HTTP 200, `success: true` |
| Failure | HTTP 4xx/5xx, `success: false`, `error.code`, `error.message` |

## CORS
The backend answers browser preflight (`OPTIONS`) requests and allows the `Content-Type` header.
Set `CORS_ALLOWED_ORIGINS` on the server to the exact frontend origin (e.g. `https://team.github.io`, no trailing slash). Multiple origins: comma-separated. Default is `*`.

## Example
```js
const BASE_URL = "https://YOUR-APP.onrender.com";

async function scan(url) {
  const res = await fetch(`${BASE_URL}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  const data = await res.json();
  if (!data.success) throw new Error(data.error.message);
  return data;
}
```

## Fields to render
- `risk_score` (0–100) and `risk_level` ("Low" | "Medium" | "High") -> badge/gauge
- `summary` -> text under the badge (always show it; it contains the "not a guarantee" wording)
- `indicators[]` -> `title`, `severity`, `message`, `recommendation`, `points`
- `checks[]` -> all 7 checks, `passed` true/false (green/red tick), `message`, `limitation`
- `recommendations[]` and `limitations[]` -> bullet lists (show the limitations!)
- `normalized_url` -> show if different from `url`

**Security:** insert all strings with `element.textContent = ...`, never `innerHTML`.
Do not label a Low result "Safe". Suggested wording: "No suspicious characteristics found by our basic checks".
