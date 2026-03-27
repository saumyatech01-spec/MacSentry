"""MacSentry Web Dashboard — Enhanced Flask API for React UI"""

import json, subprocess, sys
from pathlib import Path
from flask import Flask, Response, send_from_directory, jsonify

app = Flask(__name__)
ROOT = Path(__file__).resolve().parent.parent
REACT_DIST = Path(__file__).resolve().parent / "react-dashboard" / "dist"
SCANS_DIR = Path.home() / "Library" / "Application Support" / "MacSentry" / "scans"


# ── Serve React build ────────────────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_react(path):
    if path.startswith("api/"):
        return jsonify({"error": "not found"}), 404
    target = REACT_DIST / path
    if path and target.exists():
        return send_from_directory(REACT_DIST, path)
    return send_from_directory(REACT_DIST, "index.html")


# ── SSE scan stream ──────────────────────────────────────────────────────────
@app.route("/api/scan")
def scan():
    def generate():
        cmd = [
            sys.executable,
            str(ROOT / "core/scanner_engine.py"),
            "--mode",
            "full",
            "--no-cve",
        ]
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        for line in proc.stdout:
            if line.strip():
                yield f"data: {line.strip()}\n\n"
        yield 'data: {"done": true}\n\n'

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Scan history ─────────────────────────────────────────────────────────────
@app.route("/api/history")
def history():
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    scans = []
    for f in sorted(SCANS_DIR.glob("*.json"), reverse=True)[:10]:
        try:
            d = json.loads(f.read_text())
            scans.append(
                {
                    "filename": f.name,
                    "timestamp": d.get("timestamp", ""),
                    "score": d.get("overall_score", 0),
                    "total_findings": d.get("total_findings", 0),
                }
            )
        except Exception:
            pass
    return jsonify(scans)


# ── Single scan result ────────────────────────────────────────────────────────
@app.route("/api/history/<filename>")
def get_scan(filename):
    fp = SCANS_DIR / filename
    if not fp.exists():
        return jsonify({"error": "Not found"}), 404
    return jsonify(json.loads(fp.read_text()))


if __name__ == "__main__":
    if not REACT_DIST.exists():
        print("⚠️  React build not found.")
        print("   Run:  cd ui/react-dashboard && npm install && npm run build")
        print(
            "   Dev mode:  npm run dev  (proxies /api → port 5001 via vite.config.js)\n"
        )
    print("=" * 60)
    print("🛡️  MacSentry Web Dashboard")
    print("=" * 60)
    print("  Dashboard  → http://localhost:5001")
    print("  Scan API   → http://localhost:5001/api/scan   (SSE)")
    print("  History    → http://localhost:5001/api/history")
    print("=" * 60)
    app.run(debug=True, port=5001, use_reloader=False)
