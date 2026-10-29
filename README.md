# PhishGuard (Backend + Frontend)

phishguard/
  backend/    Flask API  (POST /api/scan)
  frontend/   static site (Home / Results / About)

## Run on Windows
1. Double-click run-backend.bat   (keep the window open, API on http://127.0.0.1:5000)
2. Double-click run-frontend.bat  (opens http://localhost:8080)

## Run manually
Terminal 1:  cd backend  &&  python -m venv venv  &&  venv\Scripts\activate  &&  pip install -r requirements.txt  &&  python app.py
Terminal 2:  cd frontend &&  python -m http.server 8080   ->  open http://localhost:8080

## Deploy
- Backend: Render/Railway (start: gunicorn app:app --bind 0.0.0.0:$PORT), set CORS_ALLOWED_ORIGINS to the frontend URL.
- Frontend: any static host; set API_BASE_URL in frontend/js/config.js to the backend URL.
