import os
import secrets
from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge


def _resolve_secret_key() -> str:
    configured = os.environ.get("FLASK_SECRET_KEY", "").strip()
    if not configured or configured == "replace-with-a-long-random-secret":
        return secrets.token_hex(32)
    return configured


def _resolve_max_content_length() -> int:
    raw = os.environ.get("MAX_CONTENT_LENGTH", str(15 * 1024 * 1024))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("MAX_CONTENT_LENGTH must be a positive integer.") from exc
    if value <= 0:
        raise ValueError("MAX_CONTENT_LENGTH must be a positive integer.")
    return value


from .telemetry import SecurityTelemetry


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=_resolve_secret_key(),
        MAX_CONTENT_LENGTH=_resolve_max_content_length(),
    )
    app.json.sort_keys = False
    if test_config:
        app.config.update(test_config)
    app.extensions["telemetry"] = SecurityTelemetry()

    from .routes import api
    app.register_blueprint(api, url_prefix="/api")

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/health")
    def health():
        return jsonify(status="ok", service="SecureDoc")

    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        return jsonify(error="File too large. Maximum upload size is 10 MB."), 413

    @app.errorhandler(404)
    def not_found(error):
        if request.path.startswith("/api/"):
            return jsonify(error="API endpoint not found."), 404
        return error

    @app.errorhandler(405)
    def method_not_allowed(error):
        if request.path.startswith("/api/"):
            return jsonify(error="Method not allowed for this API endpoint."), 405
        return error

    @app.errorhandler(Exception)
    def unhandled_error(error):
        if isinstance(error, HTTPException):
            if request.path.startswith("/api/"):
                return jsonify(error=error.description or "Request failed."), error.code
            return error
        app.logger.exception("Unhandled error on %s %s", request.method, request.path)
        if request.path.startswith("/api/"):
            return jsonify(error="An internal server error occurred."), 500
        return jsonify(error="An internal server error occurred."), 500

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; script-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        else:
            response.headers["Cache-Control"] = "no-cache"
        return response

    return app
