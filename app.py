"""CYRO - Intelligent Cybersecurity Platform (entry point)."""
from flask import Flask, abort, jsonify, render_template, request

import config
from backend import db, security
from backend.api import bp as api_bp

# slug -> (template, title i18n key, icon)
PAGES = {
    "url-scanner": ("url.html", "nav_url", "link"),
    "phishing": ("phishing.html", "nav_phish", "mail"),
    "password": ("password.html", "nav_pass", "key"),
    "file-checker": ("file.html", "nav_file", "file"),
    "quiz": ("quiz.html", "nav_quiz", "quiz"),
    "soc": ("soc.html", "nav_soc", "soc"),
    "comm": ("comm.html", "nav_comm", "comm"),
    "lab": ("lab.html", "nav_lab", "lab"),
    "reports": ("reports.html", "nav_reports", "report"),
}


def create_app():
    app = Flask(__name__, template_folder="frontend/templates",
                static_folder="frontend/static")
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH
    db.init_db()
    app.register_blueprint(api_bp)

    @app.context_processor
    def inject():
        return {"csrf_token": security.CSRF_TOKEN, "max_file_mb": config.MAX_FILE_MB, "lab_geo": config.LAB_SERVER_GEO}

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; "
            "style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(413)
    def too_big(_):
        return security.api_error("file_too_large", 413)

    @app.errorhandler(404)
    def not_found(_):
        if request.path.startswith("/api/"):
            return security.api_error("not_found", 404)
        return render_template("tool_stub.html", active="", key="err_404", icon="shield"), 404

    @app.errorhandler(500)
    def server_error(_):
        if request.path.startswith("/api/"):
            return security.api_error("server", 500)
        return render_template("tool_stub.html", active="", key="err_500", icon="shield"), 500

    @app.route("/")
    def dashboard():
        return render_template("dashboard.html", active="dashboard")

    @app.route("/<slug>")
    def page(slug):
        if slug not in PAGES:
            abort(404)
        tpl, key, icon = PAGES[slug]
        return render_template(tpl, active=slug, key=key, icon=icon)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
