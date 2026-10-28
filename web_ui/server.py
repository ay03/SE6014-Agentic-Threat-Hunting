"""Loopback-only demo UI. Live execution is explicitly enabled by the operator."""
from __future__ import annotations
import argparse
import json
import mimetypes
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
sys.path.insert(0, str(REPO))
from web_ui.recording import read_json
from web_ui.reports import collect, archive

RUN_ID = re.compile(r'^[a-f0-9]{32}$')


class RunManager:
    def __init__(self, *, runtime=None, enable_live=False, provider_env=None, hunt_python=None):
        self.runtime = Path(runtime or ROOT / 'runtime')
        self.provider_env = Path(provider_env).resolve() if provider_env else None
        self.hunt_python = Path(hunt_python).absolute() if hunt_python else None
        self.enable_live = enable_live
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.process = None
        self.active_id = None

    def availability(self):
        if not self.enable_live:
            return False, 'Live execution is disabled. Start the server with --enable-live to use your local provider.'
        if not self.provider_env or not self.provider_env.is_file():
            return False, 'Configure a private provider file on the server.'
        if not self.hunt_python or not self.hunt_python.is_file():
            return False, 'Configure the separate Group C Python environment on the server.'
        if not (REPO / 'group_B/.venv/bin/python').is_file():
            return False, 'The Group B environment is missing. Follow the local setup guide.'
        return True, 'Runs the real local pipeline using the server-configured provider.'

    def start(self):
        ready, reason = self.availability()
        if not ready:
            raise ValueError(reason)
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                raise RuntimeError('An investigation is already running.')
            identifier = uuid4().hex
            job = self.runtime / identifier
            job.mkdir(parents=True, mode=0o700)
            args = [str(REPO / 'group_B/.venv/bin/python'), '-m', 'web_ui.runner', '--job-dir', str(job),
                    '--hunt-python', str(self.hunt_python), '--provider-env', str(self.provider_env)]
            # A path is passed, never key contents. Logs and artifacts are not publicly served.
            with (job / 'runner.log').open('wb') as log:
                self.process = subprocess.Popen(args, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            self.active_id = identifier
            return {'id': identifier, 'status': 'running', 'stage': 'services', 'elapsed': 0}

    def state(self, identifier):
        if not RUN_ID.fullmatch(identifier):
            raise FileNotFoundError
        job = self.runtime / identifier
        if not job.is_dir():
            raise FileNotFoundError
        state = read_json(job / 'state.json', {'id': identifier, 'status': 'running', 'stage': 'services', 'elapsed': 0})
        if identifier == self.active_id and self.process is not None and self.process.poll() is not None and state['status'] == 'running':
            state.update(status='failed', stage='failed', error='The local runner exited before finishing. Check its server log.')
        return state

    def reports(self, identifier):
        self.state(identifier)  # Validate the ID and require an existing owned runtime directory.
        job = self.runtime / identifier
        private = []
        if self.provider_env and self.provider_env.is_file():
            for line in self.provider_env.read_text().splitlines():
                name, separator, value = line.partition('=')
                if separator and name.strip() in {'LLM_API_KEY', 'ES_API_KEY'}:
                    private.append(value.strip().strip("\"'"))
        return collect(job / 'artifacts', run_id=identifier, mode='live', secrets=private,
                       console=job / 'runner.log')

    def cancel(self, identifier):
        with self.lock:
            if identifier != self.active_id:
                raise FileNotFoundError
            if self.process is not None and self.process.poll() is None:
                self.process.send_signal(signal.SIGTERM)
            return {'id': identifier, 'status': 'stopping'}


def make_server(manager, port=8767):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # Deliberately omit request bodies, configuration, tokens and query strings.
            pass

        def send(self, status, payload, content_type='application/json; charset=utf-8', *, policy=None):
            body = json.dumps(payload).encode() if not isinstance(payload, bytes) else payload
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy', policy or "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
            self.end_headers()
            self.wfile.write(body)

        def local_request(self):
            port = self.server.server_port
            allowed = {f'127.0.0.1:{port}', f'localhost:{port}'}
            host = self.headers.get('Host', '')
            origin = self.headers.get('Origin')
            return host in allowed and (origin is None or origin in {f'http://{h}' for h in allowed})

        def do_GET(self):
            if not self.local_request():
                return self.send(403, {'error': 'Local origin required.'})
            path = urlsplit(self.path).path
            if path == '/api/status':
                ready, reason = manager.availability()
                return self.send(200, {'live_ready': ready, 'reason': reason, 'token': manager.token,
                                       'active_id': manager.active_id})
            if path == '/api/recording':
                return self.send(200, read_json(ROOT / 'data/recorded-run.json', {}))
            html_route = re.fullmatch(r'/api/(recording|runs/[a-f0-9]{32})/reports/(c3-html)/view', path)
            if html_route:
                try:
                    bundle = read_json(ROOT / 'data/recorded-reports.json', {}) if html_route.group(1) == 'recording' else manager.reports(html_route.group(1).split('/')[1])
                    file = next((f for f in bundle.get('files', []) if f['id'] == html_route.group(2) and f['kind'] == 'html'), None)
                    if file is None:
                        raise FileNotFoundError
                    return self.send(200, file['content'].encode(), 'text/html; charset=utf-8',
                        policy="default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox; base-uri 'none'; form-action 'none'")
                except FileNotFoundError:
                    return self.send(404, {'error': 'Report not available.'})
            if path in {'/api/recording/reports', '/api/recording/reports.zip'}:
                bundle = read_json(ROOT / 'data/recorded-reports.json', {})
                if not bundle:
                    return self.send(404, {'error': 'Recorded reports are unavailable.'})
                return self.send(200, archive(bundle), 'application/zip') if path.endswith('.zip') else self.send(200, bundle)
            report_route = re.fullmatch(r'/api/runs/([a-f0-9]{32})/reports(\.zip)?', path)
            if report_route:
                try:
                    bundle = manager.reports(report_route.group(1))
                    return self.send(200, archive(bundle), 'application/zip') if report_route.group(2) else self.send(200, bundle)
                except FileNotFoundError:
                    return self.send(404, {'error': 'Run not found.'})
            if path.startswith('/api/runs/'):
                try:
                    return self.send(200, manager.state(path.removeprefix('/api/runs/')))
                except FileNotFoundError:
                    return self.send(404, {'error': 'Run not found.'})
            static = {'/': 'index.html', '/index.html': 'index.html',
                       '/tokens.css': 'tokens.css',
                      '/story.css': 'story.css', '/story.js': 'story.js',
                      '/reports.css': 'reports.css', '/reports.js': 'reports.js'}
            target = ROOT / static[path] if path in static else None
            if path.startswith('/assets/fonts/') and re.fullmatch(r'/assets/fonts/[A-Za-z0-9_.-]+', path):
                target = ROOT / path.lstrip('/')
            if target is None or not target.is_file():
                return self.send(404, {'error': 'Not found.'})
            return self.send(200, target.read_bytes(), mimetypes.guess_type(str(target))[0] or 'application/octet-stream')

        def do_POST(self):
            if not self.local_request() or not secrets.compare_digest(self.headers.get('X-Trace-Token', ''), manager.token):
                return self.send(403, {'error': 'Local session token required.'})
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                return self.send(415, {'error': 'JSON required.'})
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 1024:
                    raise ValueError
                body = json.loads(self.rfile.read(size))
                if not isinstance(body, dict) or body:
                    raise ValueError
            except (ValueError, TypeError):
                return self.send(400, {'error': 'Expected an empty JSON object.'})
            path = urlsplit(self.path).path
            try:
                if path == '/api/runs':
                    return self.send(202, manager.start())
                match = re.fullmatch(r'/api/runs/([a-f0-9]{32})/cancel', path)
                if match:
                    return self.send(202, manager.cancel(match.group(1)))
                return self.send(404, {'error': 'Not found.'})
            except ValueError as error:
                return self.send(503, {'error': str(error)})
            except RuntimeError as error:
                return self.send(409, {'error': str(error)})
            except FileNotFoundError:
                return self.send(404, {'error': 'Run not found.'})
            except OSError:
                return self.send(500, {'error': 'Could not start the local runner. Check the server configuration.'})
    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=8767)
    parser.add_argument('--enable-live', action='store_true')
    parser.add_argument('--provider-env', type=Path)
    parser.add_argument('--hunt-python', type=Path)
    args = parser.parse_args()
    manager = RunManager(enable_live=args.enable_live, provider_env=args.provider_env, hunt_python=args.hunt_python)
    server = make_server(manager, args.port)
    print(f'TRACE: http://127.0.0.1:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        if manager.active_id:
            manager.cancel(manager.active_id)
            if manager.process:
                try:
                    manager.process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    print('Runner is still cleaning up; inspect its local log.', flush=True)
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
