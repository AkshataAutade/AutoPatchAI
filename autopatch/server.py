"""Developer Review Web Server (Flow step X).
Provides a lightweight local HTTP server with REST APIs for running scans,
inspecting the architectural flow, reviewing diffs, and applying verified patches.
Uses only Python standard library.
"""
import http.server
import json
import os
import shutil
import socketserver
import sys
import threading
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .orchestrator import run
from .validator import NotAuthorized, validate_project


class AutoPatchAPIHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler for AutoPatch Developer Review Dashboard."""

    project_dir: Path = Path.cwd()
    output_dir: Path = Path.cwd() / "autopatch-out"
    latest_report: Optional[dict] = None

    def end_headers(self):
        # Enable CORS for development
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            self._send_json(200, {"status": "ok", "service": "AutoPatch AI Review Server"})
            return

        if path == "/api/report":
            report = self._get_latest_report()
            if report:
                self._send_json(200, report)
            else:
                self._send_json(404, {"error": "No scan report available yet. Run a scan first."})
            return

        if path == "/api/flow":
            report = self._get_latest_report()
            if report and "flow_execution" in report:
                self._send_json(200, {
                    "project": report.get("project"),
                    "flow_execution": report.get("flow_execution"),
                    "counts": report.get("counts"),
                    "metrics": report.get("metrics"),
                })
            else:
                self._send_json(200, {"status": "idle", "message": "No active or completed flow execution."})
            return

        if path == "/api/project/validate":
            query = parse_qs(parsed.query)
            target = query.get("path", [str(self.project_dir)])[0]
            val = validate_project(Path(target))
            self._send_json(200, val.to_dict())
            return

        # Fallback to static files in web/dist if present
        dist_dir = Path(__file__).resolve().parent.parent / "web" / "dist"
        if dist_dir.exists():
            req_file = dist_dir / (path.lstrip("/") if path.lstrip("/") else "index.html")
            if req_file.is_file():
                self._serve_file(req_file)
                return
            index_file = dist_dir / "index.html"
            if index_file.is_file():
                self._serve_file(index_file)
                return

        # Default fallback HTML if web/dist is not built yet
        self._serve_minimal_review_page()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"

        try:
            data = json.loads(body)
        except Exception:
            data = {}

        if path == "/api/scan":
            target = data.get("project", str(self.project_dir / "examples" / "vulnerable_app"))
            apply = bool(data.get("apply", False))
            enable_dast = bool(data.get("enable_dast", True))
            enable_ai = bool(data.get("enable_ai", True))

            try:
                report = run(
                    repo=target,
                    out=self.output_dir,
                    apply=apply,
                    enable_dast=enable_dast,
                    enable_ai=enable_ai,
                )
                AutoPatchAPIHandler.latest_report = report
                self._send_json(200, {"status": "success", "report": report})
            except NotAuthorized as e:
                self._send_json(403, {"status": "unauthorized", "error": str(e)})
            except Exception as e:
                self._send_json(500, {"status": "error", "error": str(e)})
            return

        if path == "/api/apply":
            # Apply accepted patches back to the source repository
            report = self._get_latest_report()
            if not report:
                self._send_json(400, {"error": "No scan report available to apply patches from."})
                return

            repo_path = Path(report.get("repo_path", ""))
            work_path = self.output_dir / "work"
            originals_path = self.output_dir / "originals"

            if not repo_path.exists() or not work_path.exists():
                self._send_json(400, {"error": "Repository or working copy paths not found."})
                return

            applied_count = 0
            for orig in originals_path.rglob("*"):
                if orig.is_file():
                    rel = orig.relative_to(originals_path)
                    work_f = work_path / rel
                    repo_f = repo_path / rel
                    if work_f.exists() and work_f.read_text(encoding="utf-8") != orig.read_text(encoding="utf-8"):
                        shutil.copyfile(work_f, repo_f)
                        applied_count += 1

            self._send_json(200, {
                "status": "applied",
                "applied_files_count": applied_count,
                "message": f"Successfully applied {applied_count} verified patch file(s) to source.",
            })
            return

        self._send_json(404, {"error": "Not found"})

    def _get_latest_report(self) -> Optional[dict]:
        if AutoPatchAPIHandler.latest_report:
            return AutoPatchAPIHandler.latest_report
        rep_file = self.output_dir / "report.json"
        if rep_file.is_file():
            try:
                AutoPatchAPIHandler.latest_report = json.loads(rep_file.read_text(encoding="utf-8"))
                return AutoPatchAPIHandler.latest_report
            except Exception:
                pass
        return None

    def _send_json(self, status: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, file_path: Path):
        content = file_path.read_bytes()
        mime = "text/html"
        if file_path.suffix == ".js":
            mime = "application/javascript"
        elif file_path.suffix == ".css":
            mime = "text/css"
        elif file_path.suffix == ".json":
            mime = "application/json"
        elif file_path.suffix == ".svg":
            mime = "image/svg+xml"

        self.send_response(200)
        self.send_header("Content-Type", f"{mime}; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _serve_minimal_review_page(self):
        html = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>AutoPatch AI - Developer Review Dashboard</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; background: #0f172a; color: #f8fafc; }
    h1 { color: #38bdf8; }
    .card { background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }
    button { background: #0284c7; color: white; border: none; border-radius: 6px; padding: 0.6rem 1.2rem; cursor: pointer; font-size: 1rem; }
    button:hover { background: #0369a1; }
    pre { background: #020617; padding: 1rem; border-radius: 6px; overflow-x: auto; color: #a5f3fc; }
  </style>
</head>
<body>
  <h1>AutoPatch AI Developer Review Dashboard</h1>
  <div class="card">
    <h3>Run Security Pipeline</h3>
    <p>Triggers SAST & DAST scanning, risk classification, RAG/AI patch generation, and automated verification.</p>
    <button onclick="runScan()">Execute AutoPatch Scan</button>
  </div>
  <div class="card">
    <h3>Latest Scan Results</h3>
    <pre id="output">Loading report...</pre>
  </div>
  <script>
    async function loadReport() {
      try {
        const res = await fetch('/api/report');
        if (res.ok) {
          const data = await res.json();
          document.getElementById('output').textContent = JSON.stringify(data, null, 2);
        } else {
          document.getElementById('output').textContent = 'No scan run yet. Click above to scan.';
        }
      } catch(e) {
        document.getElementById('output').textContent = 'Error: ' + e;
      }
    }
    async function runScan() {
      document.getElementById('output').textContent = 'Running scan and verification pipeline...';
      const res = await fetch('/api/scan', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({}) });
      const data = await res.json();
      document.getElementById('output').textContent = JSON.stringify(data, null, 2);
    }
    loadReport();
  </script>
</body>
</html>"""
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_server(port: int = 8765, project_dir: Optional[Path] = None, output_dir: Optional[Path] = None):
    """Start local review dashboard server."""
    AutoPatchAPIHandler.project_dir = Path(project_dir or Path.cwd()).resolve()
    AutoPatchAPIHandler.output_dir = Path(output_dir or (Path.cwd() / "autopatch-out")).resolve()

    with socketserver.TCPServer(("", port), AutoPatchAPIHandler) as httpd:
        print(f"\n=======================================================")
        print(f" AutoPatch AI Developer Review Server Running")
        print(f" URL: http://localhost:{port}")
        print(f" API Endpoints: /api/report, /api/flow, /api/scan, /api/apply")
        print(f" Press Ctrl+C to stop the server.")
        print(f"=======================================================\n")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
            httpd.server_close()

