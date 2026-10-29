# PhishGuard Frontend
Static site (HTML/CSS/JS, no build step): index.html (Home), results.html (Scan Results), about.html (About).

## Run locally
1. Start the backend: `python app.py` (http://127.0.0.1:5000)
2. In this folder: `python -m http.server 8080`, then open http://localhost:8080

## Connect to the deployed backend
Edit js/config.js -> API_BASE_URL = your Render/Railway URL (no trailing slash).
On the backend set CORS_ALLOWED_ORIGINS to the frontend origin (e.g. https://yourteam.github.io).

## Deploy
Any static host (GitHub Pages / Netlify / Cloudflare Pages / S3): upload this folder as-is.

## Notes
- Backend text is inserted with textContent only. A Low result is never labelled "Safe".
- "Recent scans" lives in the browser's localStorage only.
- UI supports Arabic/English; report text from the backend stays English.
