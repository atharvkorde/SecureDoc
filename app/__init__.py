import os
import secrets
from flask import Flask, jsonify, render_template
from werkzeug.exceptions import RequestEntityTooLarge


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", 15 * 1024 * 1024)),
        JSON_SORT_KEYS=False,
    )
    if test_config:
        app.config.update(test_config)

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
        return response

    return app
