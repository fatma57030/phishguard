"""Flask API for PhishGuard. Run locally: python app.py  | Production: gunicorn app:app"""
import json
import os

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from analyzer.scanner import scan_url
from analyzer.url_validator import ValidationError

APP_NAME = "PhishGuard"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = ("Smart URL Security Scanner: analyses the text of a URL and returns "
                   "an explainable, preliminary risk score. Educational use only.")

HTTP_ERRORS = {
    404: ("not_found", "The requested endpoint does not exist."),
    405: ("method_not_allowed", "This HTTP method is not allowed for this endpoint."),
    413: ("payload_too_large", "The request body is too large."),
}


def error_response(code: str, message: str, status: int):
    """One consistent error format for the whole API."""
    return jsonify({"success": False, "error": {"code": code, "message": message}}), status


def create_app(test_config: dict = None) -> Flask:
    app = Flask(__name__)
    app.json.sort_keys = False
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB is plenty for one URL
    # Comma-separated list of allowed frontend origins, or "*" for any.
    app.config["CORS_ALLOWED_ORIGINS"] = os.environ.get("CORS_ALLOWED_ORIGINS", "*")
    if test_config:
        app.config.update(test_config)

    # ---- CORS (small hand-written version, no extra dependency) ----------
    @app.after_request
    def add_headers(response):
        origins = [o.strip() for o in app.config["CORS_ALLOWED_ORIGINS"].split(",") if o.strip()]
        origin = request.headers.get("Origin")
        if "*" in origins:
            response.headers["Access-Control-Allow-Origin"] = "*"
        elif origin and origin in origins:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
        if "Access-Control-Allow-Origin" in response.headers:
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            response.headers["Access-Control-Max-Age"] = "600"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    # ---- routes -----------------------------------------------------------
    @app.get("/")
    def index():
        return jsonify({
            "name": APP_NAME,
            "version": APP_VERSION,
            "description": APP_DESCRIPTION,
            "message": "PhishGuard API is running.",
        })

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": APP_NAME, "version": APP_VERSION})

    @app.post("/api/scan")
    def scan():
        body = request.get_data()
        if not body.strip():
            return error_response("missing_body", "The request body is empty. Send JSON like {\"url\": \"https://example.com\"}.", 400)
        if request.mimetype != "application/json":
            return error_response("unsupported_media_type", "Content-Type must be application/json.", 415)
        try:
            data = json.loads(body.decode("utf-8"))
        except ValueError:
            return error_response("invalid_json", "The request body is not valid JSON.", 400)
        if not isinstance(data, dict):
            return error_response("invalid_body", "The JSON body must be an object.", 400)
        if "url" not in data:
            return error_response("missing_url", "The 'url' field is required.", 400)
        try:
            report = scan_url(data["url"])
        except ValidationError as err:
            return error_response(err.code, err.message, 400)
        return jsonify(report), 200

    # ---- error handlers (never leak tracebacks) ---------------------------
    @app.errorhandler(Exception)
    def handle_any_error(err):
        if isinstance(err, HTTPException):
            code, message = HTTP_ERRORS.get(err.code, ("http_error", "The request could not be processed."))
            response, status = error_response(code, message, err.code)
            allowed = getattr(err, "valid_methods", None)
            if allowed:
                response.headers["Allow"] = ", ".join(allowed)
            return response, status
        app.logger.exception("Unexpected error")  # full details go to the server log only
        return error_response("internal_error", "An unexpected error occurred. Please try again later.", 500)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
