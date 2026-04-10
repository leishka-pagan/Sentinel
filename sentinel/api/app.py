"""
sentinel/api/app.py

Flask backend API for Sentinel.
Exposes endpoints to:
- Create and authorize scan sessions
- Start scans
- Poll for results
- Retrieve audit logs
- Download reports

All scan endpoints require an authorized session token.
"""

import os
import uuid
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

from sentinel.core import ScanMode, ScanSession
from sentinel.core.audit import get_session_log, get_full_log
from sentinel.agents import run_orchestrator, generate_report


app = Flask(__name__, template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-key-change-in-prod")

CORS(app, resources={r"/api/*": {"origins": "*"}})

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://",
)

# In-memory session store (Phase 4: replace with Redis/Cosmos)
_sessions: dict[str, ScanSession] = {}
# In-memory results store
_results: dict[str, dict] = {}


# ── UI ────────────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "sentinel"})


# ── Sessions ──────────────────────────────────────────────────────────────────

@app.route("/api/sessions", methods=["POST"])
@limiter.limit("20 per hour")
def create_session():
    """
    Create a new scan session.
    Body: { "target": "localhost", "mode": "CODE", "approved_targets": [...] }
    Returns: { "session_id": "...", "requires_second_confirm": bool }
    """
    body = request.get_json(silent=True) or {}
    target = body.get("target", "").strip()
    mode_str = body.get("mode", "CODE").upper()
    extra_targets = body.get("approved_targets", [])

    if not target:
        return jsonify({"error": "target is required"}), 400

    try:
        mode = ScanMode(mode_str)
    except ValueError:
        return jsonify({"error": f"Invalid mode. Must be one of: {[m.value for m in ScanMode]}"}), 400

    session = ScanSession(
        target=target,
        mode=mode,
        approved=False,
        approved_targets=extra_targets,
    )
    _sessions[session.session_id] = session

    return jsonify({
        "session_id":             session.session_id,
        "target":                 target,
        "mode":                   mode,
        "approved":               False,
        "requires_second_confirm": mode == ScanMode.ACTIVE,
        "message": (
            "Session created. Call /api/sessions/{id}/authorize to approve it. "
            + ("ACTIVE mode requires a second confirmation after authorization." if mode == ScanMode.ACTIVE else "")
        ),
    }), 201


@app.route("/api/sessions/<session_id>/authorize", methods=["POST"])
@limiter.limit("20 per hour")
def authorize_session(session_id: str):
    """
    First authorization — user confirms they own/have permission to scan the target.
    Body: { "confirmed": true }
    """
    session = _get_session_or_404(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404

    body = request.get_json(silent=True) or {}
    if not body.get("confirmed", False):
        return jsonify({"error": "confirmed must be true to authorize the session"}), 400

    session.approved = True
    return jsonify({
        "session_id": session_id,
        "approved": True,
        "message": (
            "Session authorized. "
            + ("Call /api/sessions/{id}/confirm-active to proceed with ACTIVE mode."
               if session.mode == ScanMode.ACTIVE
               else "Call /api/scans to start the scan.")
        ),
    })


@app.route("/api/sessions/<session_id>/confirm-active", methods=["POST"])
@limiter.limit("10 per hour")
def confirm_active(session_id: str):
    """
    Second confirmation required for ACTIVE mode only.
    User must explicitly acknowledge active probing.
    Body: { "confirmed": true, "acknowledgement": "I confirm I have authorization to actively probe this target" }
    """
    session = _get_session_or_404(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404

    if session.mode != ScanMode.ACTIVE:
        return jsonify({"error": "Second confirmation only required for ACTIVE mode"}), 400

    body = request.get_json(silent=True) or {}
    ack = body.get("acknowledgement", "")
    required_phrase = "I confirm I have authorization to actively probe this target"

    if not body.get("confirmed") or required_phrase.lower() not in ack.lower():
        return jsonify({
            "error": "Must confirm=true and include the required acknowledgement phrase.",
            "required_phrase": required_phrase,
        }), 400

    session.active_confirmed = True
    return jsonify({
        "session_id": session_id,
        "active_confirmed": True,
        "message": "ACTIVE mode confirmed. You may now start the scan.",
    })


# ── Scans ─────────────────────────────────────────────────────────────────────

@app.route("/api/scans", methods=["POST"])
@limiter.limit("10 per hour")
def start_scan():
    """
    Start a scan for an authorized session.
    Body: { "session_id": "...", "source_path": "/path/to/code" }

    Note: This runs synchronously for now.
    Phase 4 will move this to a background task queue.
    """
    body = request.get_json(silent=True) or {}
    session_id = body.get("session_id", "")
    source_path = body.get("source_path", None)

    session = _get_session_or_404(session_id)
    if session is None:
        return jsonify({"error": "Session not found"}), 404

    if not session.approved:
        return jsonify({"error": "Session must be authorized before scanning"}), 403

    if session.mode == ScanMode.ACTIVE and not session.active_confirmed:
        return jsonify({"error": "ACTIVE mode requires second confirmation"}), 403

    try:
        result = run_orchestrator(session, source_path=source_path)
        report = generate_report(result)

        _results[session_id] = {
            "result": result.model_dump(),
            "json_path": report["json_path"],
            "md_path":   report["md_path"],
        }

        return jsonify({
            "session_id":     session_id,
            "total_findings": result.total,
            "by_severity":    result.by_severity,
            "summary":        result.summary,
            "report_json":    report["json"],
            "agents_run":     [a.value for a in result.agents_run],
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scans/<session_id>/report", methods=["GET"])
def get_report(session_id: str):
    """Get the full scan report for a completed session."""
    if session_id not in _results:
        return jsonify({"error": "No results found for this session"}), 404
    return jsonify(_results[session_id]["result"])


# ── Audit ─────────────────────────────────────────────────────────────────────

@app.route("/api/audit/<session_id>", methods=["GET"])
def get_audit(session_id: str):
    """Get the full audit log for a session."""
    entries = get_session_log(session_id)
    return jsonify({"session_id": session_id, "entries": entries, "count": len(entries)})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_session_or_404(session_id: str) -> ScanSession | None:
    return _sessions.get(session_id)


if __name__ == "__main__":
    port = int(os.getenv("FLASK_PORT", 5000))
    debug = os.getenv("FLASK_ENV", "development") == "development"
    print(f"\n🛡️  Sentinel starting on http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
