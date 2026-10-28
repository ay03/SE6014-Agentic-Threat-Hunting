"""Allowlisted, credential-redacted C2/C3 report and audit exports."""
from __future__ import annotations
import io
import json
from pathlib import Path
import re
import zipfile

SPECS = [
 ('c2-result', 'C2 investigation', 'C2', 'attack/result.json', 'json'),
 ('c2-plan', 'Hunt plan', 'C2', 'attack/plan.json', 'json'),
 ('c2-timings', 'Phase timings', 'C2', 'attack/timings.json', 'json'),
 ('c2-response', 'Response draft', 'C2', 'attack/actions/response.json', 'json'),
 ('c3-html', 'Full C3 report', 'C3', 'attack/c3/hunt_report_attack.html', 'html'),
 ('c3-markdown', 'C3 report Markdown', 'C3', 'attack/c3/hunt_report_attack.md', 'markdown'),
 ('c3-json', 'C3 report JSON', 'C3', 'attack/c3/hunt_report_attack.json', 'json'),
 ('c3-bundle', 'Evidence bundle', 'C3', 'attack/c3/bundle.json', 'json'),
 ('log-tools', 'Tool trace', 'Logs', 'attack/trace.jsonl', 'jsonl'),
 ('log-model', 'Model audit', 'Logs', 'attack/llm.jsonl', 'jsonl'),
 ('log-mcp', 'Elasticsearch MCP audit', 'Logs', 'attack/mcp-audit.jsonl', 'jsonl'),
 ('log-analytics', 'Analytics audit', 'Logs', 'attack/analytics-audit.jsonl', 'jsonl'),
 ('run-summary', 'Run summary', 'Logs', 'summary.json', 'json'),
 ('run-timing', 'Wall-clock timing', 'Logs', 'wall-timing.json', 'json'),
]
SECRET_KEYS = {'api_key', 'llm_api_key', 'es_api_key', 'authorization', 'password', 'passwd',
               'access_token', 'refresh_token', 'client_secret', 'secret', 'credentials'}


def redact(text, secrets=()):
    for value in secrets:
        if value:
            text = text.replace(value, '[REDACTED]')
    text = re.sub(r'\bsk-[A-Za-z0-9_-]{16,}', '[REDACTED]', text)
    text = re.sub(r'(?i)\b(Bearer|ApiKey)\s+[A-Za-z0-9_+./=-]{8,}', r'\1 [REDACTED]', text)
    text = re.sub(r'(?i)\b((?:LLM_|ES_)?API_KEY|PASSWORD|ACCESS_TOKEN|CLIENT_SECRET)(\s*[=:]\s*)[^\s,;"\']+',
                  r'\1\2[REDACTED]', text)
    text = re.sub(r'''(?i)(["'](?:api_key|llm_api_key|es_api_key|authorization|password|passwd|access_token|refresh_token|client_secret|secret)["']\s*:\s*["'])[^"'\n]*''', r'\1[REDACTED]', text)
    return text


def clean(value, secrets=()):
    if isinstance(value, dict):
        return {key: '[REDACTED]' if key.casefold().replace('-', '_') in SECRET_KEYS else clean(item, secrets)
                for key, item in value.items()}
    if isinstance(value, list):
        return [clean(item, secrets) for item in value]
    return redact(value, secrets) if isinstance(value, str) else value


def sanitize(text, kind, secrets=()):
    if kind == 'json':
        try:
            return json.dumps(clean(json.loads(text), secrets), indent=2, ensure_ascii=False) + '\n'
        except ValueError:
            pass
    if kind == 'jsonl':
        lines = []
        for line in text.splitlines():
            try:
                lines.append(json.dumps(clean(json.loads(line), secrets), ensure_ascii=False))
            except ValueError:
                lines.append(redact(line, secrets))
        return '\n'.join(lines) + ('\n' if lines else '')
    return redact(text, secrets)


def safe_file(root, relative):
    candidate = root / relative
    # Do not follow a link to private or unrelated files, even inside runtime.
    if any(part.is_symlink() for part in [candidate, *candidate.parents]):
        return None
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    return candidate if candidate.is_file() else None


def collect(root: Path, *, run_id, mode, secrets=(), console=None):
    specs = list(SPECS)
    detections = root / 'attack/actions/detections'
    if detections.is_dir() and not detections.is_symlink():
        for path in sorted(detections.glob('*.yml')):
            if re.fullmatch(r'[A-Za-z0-9_.-]+\.yml', path.name):
                specs.append(('detection-' + path.stem, 'Detection: ' + path.stem, 'C2',
                              'attack/actions/detections/' + path.name, 'yaml'))
    result = {'schema': 1, 'run_id': run_id, 'mode': mode, 'redacted': True, 'files': [], 'missing': []}
    for identifier, title, group, relative, kind in specs:
        path = safe_file(root, relative)
        if path is None:
            result['missing'].append({'id': identifier, 'title': title, 'group': group})
            continue
        try:
            content = sanitize(path.read_text(), kind, secrets)
        except (OSError, UnicodeError):
            result['missing'].append({'id': identifier, 'title': title, 'group': group})
            continue
        result['files'].append({'id': identifier, 'title': title, 'group': group,
                                'path': relative, 'kind': kind, 'bytes': len(content.encode()), 'content': content})
    if console is not None:
        path = safe_file(console.parent, console.name)
        if path is not None:
            try:
                text = sanitize(path.read_text(), 'text', secrets)
                result['files'].append({'id': 'run-console', 'title': 'Runner console', 'group': 'Logs',
                    'path': 'runner.log', 'kind': 'text', 'bytes': len(text.encode()), 'content': text})
            except (OSError, UnicodeError):
                pass
    return result


def archive(bundle):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as z:
        manifest = {key: value for key, value in bundle.items() if key != 'files'}
        manifest['files'] = [{key: value for key, value in f.items() if key != 'content'} for f in bundle['files']]
        z.writestr('manifest.json', json.dumps(manifest, indent=2))
        for file in bundle['files']:
            z.writestr(file['path'], file['content'])
    return output.getvalue()
