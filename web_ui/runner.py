"""Presentation adapter for the unchanged, tested B3/A3/C2/C3 demo."""
from __future__ import annotations
import argparse
import functools
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from web_ui.recording import project_run, read_json


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data))
    temp.replace(path)


def tool_receipts(path):
    """Read completed JSONL rows; return presentation metadata only."""
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append({k: row.get(k) for k in ('seq', 'server', 'tool', 'call_id', 'ok', 'total', 'request_hash')})
    return rows


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--job-dir', type=Path, required=True)
    parser.add_argument('--hunt-python', type=Path, required=True)
    parser.add_argument('--provider-env', type=Path)
    parser.add_argument('--rules', action='store_true', help='non-billed integration test of the adapter')
    args = parser.parse_args(argv)
    if not args.rules and args.provider_env is None:
        parser.error('Live mode requires a private provider file')
    job = args.job_dir.resolve()
    job.mkdir(parents=True, exist_ok=True)
    artifacts = job / 'artifacts'
    sys.path.insert(0, str(REPO / 'group_B/scripts'))
    import check_onboarding_hunt_demo as demo

    started = time.perf_counter()
    events = []
    current = {'demo': None, 'stage': 'services', 'status': 'running', 'error': None}
    lock = threading.RLock()
    stopped = threading.Event()
    cancelled = False
    children = []
    original_popen = subprocess.Popen

    def tracked_popen(*a, **kw):
        child = original_popen(*a, **kw)
        if kw.get('start_new_session'):
            children.append(child)
        return child
    subprocess.Popen = tracked_popen

    def cancel(signum, frame):
        nonlocal cancelled
        if cancelled:
            return
        cancelled = True
        for child in children:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                    child.wait(timeout=3)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)

    def publish():
        with lock:
            elapsed = time.perf_counter() - started
            view = project_run(artifacts, elapsed=elapsed, phase_events=list(events))
            instance = current['demo']
            if instance is not None:
                view['source'].update({
                    'records': instance.report.get('onboarding', {}).get('record_count', view['source']['records']),
                    'indexed': instance.report.get('onboarding', {}).get('indexed_count', view['source']['indexed'])})
                c2 = getattr(instance, 'c2_root', None)
                if c2 is not None:
                    live_audit = c2 / 'runs/attack/llm.jsonl'
                    if live_audit.exists():
                        calls = []
                        for line in live_audit.read_text().splitlines():
                            try:
                                row = json.loads(line)
                                calls.append({k: row.get(k) for k in ('seq', 'role', 'ms', 'tokens_in', 'tokens_out')})
                            except ValueError:
                                continue
                        if calls:
                            view['llm_calls'] = calls
                    receipts = tool_receipts(c2 / 'runs/attack/trace.jsonl')
                    if receipts:
                        view['trace'] = receipts
            atomic_json(job / 'state.json', {'id': job.name, 'status': current['status'],
                'stage': current['stage'], 'elapsed': round(elapsed, 3), 'error': current['error'], 'data': view})

    def heartbeat():
        while not stopped.wait(.6):
            try:
                publish()
            except OSError:
                pass
    thread = threading.Thread(target=heartbeat, daemon=True)

    stage_for = {'source_files': 'services', 'certificates': 'services', 'start_es': 'services',
                 'credentials': 'services', 'c2_snapshot': 'services', 'start_logstash': 'services',
                 'ingest': 'onboarding', 'run_hunt': 'hunt', 'verify_c3': 'verification', 'cleanup': 'complete'}
    def timed(name, fn):
        @functools.wraps(fn)
        def call(self, *a, **kw):
            current['demo'] = self
            begin = time.perf_counter()
            row = {'stage': name, 'start_seconds': round(begin-started, 6), 'status': 'running'}
            with lock:
                current['stage'] = stage_for[name]
                events.append(row)
            publish()
            try:
                result = fn(self, *a, **kw)
                row['status'] = 'passed'
                return result
            except BaseException:
                row['status'] = 'failed'
                raise
            finally:
                end = time.perf_counter()
                row.update(end_seconds=round(end-started, 6), duration_seconds=round(end-begin, 6))
                # The harness report contains no credentials; preserve its real partial state.
                atomic_json(artifacts / 'summary.json', self.report)
                publish()
        return call
    for name in stage_for:
        setattr(demo.HuntDemo, name, timed(name, getattr(demo.HuntDemo, name)))

    def single_attack(self, output):
        hypothesis = ('An external IP brute-forced SSH on DEMO-SSH and then logged in successfully '
                      'between 2026-10-25T00:00:00Z and 2026-10-25T01:00:00Z.')
        self.run_hunt('attack', hypothesis, output)
    demo.HuntDemo.hunts = single_attack
    # Keep the live presentation to one hunt; the full validation runner remains unchanged.
    demo.HuntDemo.extra_stream_cases = lambda self: None
    demo.HuntDemo.year_policy_cases = lambda self: None

    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    sys.argv = ['demo', '--hunt-python', str(args.hunt_python.absolute()), '--c2-ref', head,
                '--c3-ref', head, '--es-mcp-module', 'es_mcp_server.server', '--require-c3-agreement',
                '--a3-stream', '--output-dir', str(artifacts)]
    if not args.rules:
        sys.argv += ['--llm-env', str(args.provider_env.resolve())]
    code = 1
    thread.start()
    try:
        code = demo.main()
        summary = read_json(artifacts / 'summary.json', {})
        current['status'] = 'completed' if code == 0 else 'failed'
        current['error'] = 'The local runner could not finish. Check its private server log.' if code else None
    except KeyboardInterrupt:
        current['status'] = 'cancelled'
        current['error'] = 'Run stopped. Owned test resources were cleaned up.'
    except Exception:
        current['status'] = 'failed'
        current['error'] = 'The local runner could not finish. Check the server run log.'
    finally:
        current['stage'] = 'complete' if code == 0 else current['status']
        stopped.set()
        thread.join(timeout=2)
        publish()
        subprocess.Popen = original_popen
    return code


if __name__ == '__main__':
    raise SystemExit(main())
