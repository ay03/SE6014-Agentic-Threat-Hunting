"""Project only presentation-safe evidence; never expose provider settings or raw audits."""
from __future__ import annotations
import json
from pathlib import Path


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def fixture_preview():
    """The exact synthetic input from HuntDemo.ingest; positions are not ES IDs."""
    rows = []
    for i in range(30):
        rows.append((f"00:10:{i:02d}", "DEMO-SSH", "203.0.113.99", "failure", f"Failed password for demo from 203.0.113.99 port {40000+i} ssh2", 123))
    rows.append(("00:11:00", "DEMO-SSH", "203.0.113.99", "success", "Accepted password for demo from 203.0.113.99 port 41000 ssh2", 123))
    for i in range(3):
        rows.append((f"00:10:{i:02d}", "BENIGN-SSH", "198.51.100.20", "failure", f"Failed password for demo from 198.51.100.20 port {42000+i} ssh2", 456))
    rows.append(("00:11:00", "BENIGN-SSH", "198.51.100.20", "success", "Accepted password for demo from 198.51.100.20 port 43000 ssh2", 456))
    return [{"position": i+1, "time": t, "host": host, "ip": ip, "outcome": outcome,
             "message": f"2026-10-25T{t}Z {host} sshd[{pid}]: {message}"}
            for i, (t, host, ip, outcome, message, pid) in enumerate(rows)]


def project_run(root: Path, *, mode="live", elapsed=0.0, phase_events=None):
    summary = read_json(root / "summary.json", {})
    result = read_json(root / "attack/result.json", {})
    reports = sorted((root / "attack/c3").glob("hunt_report*.json"))
    report = read_json(reports[0], {}) if reports else {}
    wall = read_json(root / "wall-timing.json", {})
    events = phase_events if phase_events is not None else wall.get("events", [])
    duration = wall.get("total_wall_seconds", elapsed)
    findings = {c["claim_id"]: c for c in report.get("findings", [])}
    claims = []
    for c in result.get("claims", []):
        finding = findings.get(c["claim_id"], {})
        claims.append({"id": c["claim_id"], "text": c["text"], "technique": c["technique"],
                       "origin": c.get("origin", "playbook"), "facts": c.get("facts", {}),
                       "status": finding.get("status", "awaiting_verification"),
                       "citations": c.get("event_ids", []), "step": c.get("step_id")})
    source = summary.get("onboarding", {})
    checks = report.get("verification", {})
    replay = checks.get("replay", {})
    llm_path = root / "attack/llm.jsonl"
    calls = []
    if llm_path.exists():
        for line in llm_path.read_text().splitlines():
            try:
                r = json.loads(line)
                calls.append({k: r.get(k) for k in ("seq", "role", "ms", "tokens_in", "tokens_out")})
            except ValueError:
                continue
    trace_path = root / "attack/trace.jsonl"
    trace = []
    if trace_path.exists():
        for line in trace_path.read_text().splitlines():
            try:
                r = json.loads(line)
                trace.append({k: r.get(k) for k in ("seq", "server", "tool", "call_id", "ok", "total", "request_hash")})
            except ValueError:
                continue
    cited = sorted({e for c in claims for e in c["citations"]})
    verdict = result.get("verdict", {})
    return {"schema": 1, "mode": mode, "duration": round(duration, 3),
            "provenance": {"commit": summary.get("code_head", ""), "c2_commit": summary.get("c2_commit", ""),
                           "recorded_at": wall.get("started_at", summary.get("started_at", "")),
                           "model": (summary.get("llm") or {}).get("model") or (result.get("manifest", {}).get("llm") or {}).get("model", "Rule-based" if result.get("manifest", {}).get("backend", "").startswith("rules") else "Configured provider"),
                           "fixture": "35-record synthetic SSH fixture"},
            "hypothesis": result.get("hypothesis", "An external IP brute-forced SSH on DEMO-SSH and then logged in successfully between 2026-10-25T00:00:00Z and 2026-10-25T01:00:00Z."),
            "source": {"name": "ssh-demo.log", "format": "Linux authentication", "records": source.get("record_count", 0),
                       "indexed": source.get("indexed_count", 0), "pipeline": source.get("pipeline_id", "linux-auth"),
                       "parse_failures": source.get("parse_failure_count", 0), "source_id": source.get("source_id", ""),
                       "replay_submitted": next((c.get("replay_submitted") for c in summary.get("cases", []) if c.get("name") == "b3_a2_real_b1_https_ingestion"), None)},
            "verdict": {"label": verdict.get("label"), "confidence": verdict.get("confidence"),
                        "review_required": verdict.get("requires_analyst_review", True),
                        "reasons": verdict.get("reasons", [])},
            "verification": {"claims": checks.get("claims", 0), "verified": checks.get("verified", 0),
                             "replayed": replay.get("replayed", 0), "identical": replay.get("identical", 0),
                             "verdict": report.get("decision", {}).get("verdict"), "flags": report.get("flags", [])},
            "claims": claims, "citation_count": len(cited), "citations": cited,
            "events": fixture_preview(), "trace": trace, "llm_calls": calls,
            "phases": read_json(root / "attack/timings.json", {}), "timeline": events,
            "status": summary.get("status", "running"), "cleanup": summary.get("cleanup")}
