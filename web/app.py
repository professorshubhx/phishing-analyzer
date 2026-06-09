"""
web/app.py
──────────
Flask web interface for Phishing Email Analyzer.
Routes:
  GET  /           — Upload form
  POST /analyze    — Analyze uploaded .eml file
  GET  /report/<id> — View specific report
  GET  /api/analyze — JSON API endpoint
"""

import os
import json
from pathlib import Path
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from analyzer import (
    EmailParser, HeaderAnalyzer, IOCExtractor,
    URLAnalyzer, AttachmentAnalyzer, ThreatScorer, ReportGenerator
)
from config import (
    UPLOAD_FOLDER, REPORT_FOLDER, MAX_FILE_SIZE,
    ALLOWED_EXTENSIONS, SECRET_KEY, FLASK_DEBUG
)


def create_app():
    app = Flask(__name__)
    app.secret_key    = SECRET_KEY
    app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

    Path(UPLOAD_FOLDER).mkdir(exist_ok=True)
    Path(REPORT_FOLDER).mkdir(exist_ok=True)

    # ── Helper ────────────────────────────────────────────────────────
    def allowed_file(filename):
        return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

    def run_pipeline(filepath, use_vt=False):
        parsed     = EmailParser().parse_file(filepath)
        headers    = HeaderAnalyzer().analyze(parsed)
        iocs       = IOCExtractor().extract(parsed)
        urls       = URLAnalyzer().analyze_urls(iocs["urls"], use_virustotal=use_vt)
        atts       = AttachmentAnalyzer().analyze(parsed.attachments, use_virustotal=use_vt)
        score      = ThreatScorer().score(parsed, headers, iocs, urls, atts)
        report     = ReportGenerator().generate(parsed, headers, iocs, urls, atts, score)
        return report

    # ── Routes ────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        # List recent reports
        reports = []
        for f in sorted(Path(REPORT_FOLDER).glob("*.json"), reverse=True)[:20]:
            try:
                with open(f) as jf:
                    r = json.load(jf)
                    reports.append({
                        "id":      r["report_id"],
                        "subject": r["email_metadata"]["subject"],
                        "verdict": r["threat_assessment"]["verdict"],
                        "score":   r["threat_assessment"]["score"],
                        "date":    r["generated_at"][:10],
                    })
            except Exception:
                pass
        return render_template("index.html", reports=reports)

    @app.route("/analyze", methods=["POST"])
    def analyze():
        if "email_file" not in request.files:
            flash("No file uploaded", "error")
            return redirect(url_for("index"))

        f = request.files["email_file"]
        if not f.filename or not allowed_file(f.filename):
            flash("Invalid file type. Upload a .eml, .msg, or .txt file", "error")
            return redirect(url_for("index"))

        filename = secure_filename(f.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        f.save(filepath)

        use_vt = request.form.get("use_vt") == "on"

        try:
            report = run_pipeline(filepath, use_vt=use_vt)
            return redirect(url_for("view_report", report_id=report["report_id"]))
        except Exception as e:
            flash(f"Analysis failed: {str(e)}", "error")
            return redirect(url_for("index"))

    @app.route("/report/<report_id>")
    def view_report(report_id):
        json_path = Path(REPORT_FOLDER) / f"{report_id}.json"
        if not json_path.exists():
            flash("Report not found", "error")
            return redirect(url_for("index"))
        with open(json_path) as f:
            report = json.load(f)
        return render_template("report.html", report=report)

    @app.route("/api/analyze", methods=["POST"])
    def api_analyze():
        """JSON API: POST raw email body as text/plain or multipart"""
        if request.content_type == "text/plain":
            raw = request.get_data(as_text=True)
            tmp = os.path.join(UPLOAD_FOLDER, "api_temp.eml")
            with open(tmp, "w") as f:
                f.write(raw)
            filepath = tmp
        elif "email_file" in request.files:
            f = request.files["email_file"]
            filepath = os.path.join(UPLOAD_FOLDER, secure_filename(f.filename))
            f.save(filepath)
        else:
            return jsonify({"error": "No email provided"}), 400

        try:
            report = run_pipeline(filepath, use_vt=False)
            # Return sanitized JSON (exclude raw payload bytes)
            report.pop("_files", None)
            return jsonify(report)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/reports")
    def api_reports():
        reports = []
        for f in sorted(Path(REPORT_FOLDER).glob("*.json"), reverse=True)[:50]:
            try:
                with open(f) as jf:
                    r = json.load(jf)
                    reports.append({
                        "id":      r["report_id"],
                        "verdict": r["threat_assessment"]["verdict"],
                        "score":   r["threat_assessment"]["score"],
                    })
            except Exception:
                pass
        return jsonify(reports)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=FLASK_DEBUG, host="0.0.0.0", port=5000)
