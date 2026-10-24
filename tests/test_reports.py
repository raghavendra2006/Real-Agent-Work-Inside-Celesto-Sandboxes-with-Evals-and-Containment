"""Strict compliance validation tests mirroring the official hackathon verification suite."""

import json
import math
import re
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"
LOGS_DIR = PROJECT_ROOT / "logs"

ALLOWED_CAPABILITY_IDS = {
    "persistence", "snapshots", "celestofs", "browser", "published_ports",
    "network_policy", "safety_hooks", "host_mounts", "coding_agent_preset",
    "agentor_durable",
}
ALLOWED_ATTACK_IDS = {"prompt_injection_exfil", "destructive_command", "suspicious_package"}
ALLOWED_POLICIES = {"resume", "rollback", "fresh"}
SBX_NAME_RE = re.compile(r"^sbx-[a-z0-9]{8,}$")


def test_req1_compose_and_dockerfile():
    """Requirement 1: docker-compose.yml and Dockerfile exist and define required services."""
    compose_path = PROJECT_ROOT / "docker-compose.yml"
    dockerfile_path = PROJECT_ROOT / "Dockerfile"
    seeds_path = PROJECT_ROOT / "seeds" / "01_runs.sql"

    assert compose_path.exists(), "docker-compose.yml must exist"
    assert dockerfile_path.exists(), "Dockerfile must exist"
    assert seeds_path.exists(), "seeds/01_runs.sql must exist"

    compose_text = compose_path.read_text()
    assert "api:" in compose_text, "api service must exist in docker-compose.yml"
    assert "ledger:" in compose_text, "ledger service must exist in docker-compose.yml"
    assert "pg_isready" in compose_text, "ledger healthcheck must use pg_isready"
    assert "8080/health" in compose_text, "api healthcheck must query /health"
    assert "interval:" in compose_text and "timeout:" in compose_text and "retries:" in compose_text
    assert "start_period:" in compose_text


def test_req2_env_example():
    """Requirement 2: .env.example exists with placeholders and .env is not present."""
    env_example = PROJECT_ROOT / ".env.example"
    live_env = PROJECT_ROOT / ".env"

    assert env_example.exists(), ".env.example must exist"
    assert not live_env.exists(), ".env must not be committed to repository root"

    text = env_example.read_text()
    for key in ["CELESTO_PROVIDER", "CELESTO_API_KEY", "LLM_API_KEY", "LLM_MODEL", "DATABASE_URL", "API_PORT"]:
        assert f"{key}=" in text, f".env.example must define {key}"


def test_req3_problem_report():
    """Requirement 3: reports/problem.json schema and string length constraints."""
    path = REPORTS_DIR / "problem.json"
    assert path.exists(), "reports/problem.json must exist"
    data = json.loads(path.read_text())

    assert "who" in data and len(data["who"]) >= 40, "who must be at least 40 chars"
    assert "agent_work" in data and len(data["agent_work"]) >= 40, "agent_work must be at least 40 chars"
    assert "proof_output" in data and len(data["proof_output"]) >= 20, "proof_output must be at least 20 chars"
    assert data.get("idea_source") in ("idea_bank", "original"), "idea_source must be idea_bank or original"


def test_req4_commands_audit_log():
    """Requirement 4: logs/commands.jsonl format and execution_target celesto_sandbox."""
    path = LOGS_DIR / "commands.jsonl"
    assert path.exists(), "logs/commands.jsonl must exist"

    lines = [line.strip() for line in path.read_text().split("\n") if line.strip()]
    assert len(lines) >= 1, "logs/commands.jsonl must have at least one JSON line"

    for line in lines:
        entry = json.loads(line)
        assert "ts" in entry
        assert SBX_NAME_RE.match(entry["sandbox_name"]), f"Invalid sandbox name: {entry['sandbox_name']}"
        assert entry["command"], "command must be non-empty string"
        assert entry["decision"] in ("allow", "block"), f"Invalid decision: {entry['decision']}"
        assert entry["execution_target"] == "celesto_sandbox", "execution_target must be celesto_sandbox"


def test_req5_capabilities_report():
    """Requirement 5: reports/capabilities.json defines >= 2 capabilities with valid evidence paths."""
    path = REPORTS_DIR / "capabilities.json"
    assert path.exists(), "reports/capabilities.json must exist"
    data = json.loads(path.read_text())

    assert "capabilities" in data, "capabilities.json must contain top-level 'capabilities' key"
    caps = data["capabilities"]
    assert len(caps) >= 2, "Must define at least 2 capabilities"

    ids = [c["id"] for c in caps]
    assert len(ids) == len(set(ids)), "Capability IDs must be unique"

    for c in caps:
        assert c["id"] in ALLOWED_CAPABILITY_IDS, f"Capability ID {c['id']} not in allowed set"
        assert len(c["why"]) >= 80, f"Capability {c['id']} why explanation must be >= 80 chars"
        ev_path = PROJECT_ROOT / c["evidence_path"]
        assert ev_path.exists(), f"Evidence path does not exist: {c['evidence_path']}"


def test_req6_lifecycle_report():
    """Requirement 6: reports/lifecycle.json cleanup flags and matching unique sandbox names."""
    path = REPORTS_DIR / "lifecycle.json"
    assert path.exists(), "reports/lifecycle.json must exist"
    data = json.loads(path.read_text())

    assert data.get("cleanup_on_success") is True
    assert data.get("cleanup_on_failure") is True
    assert data.get("cleanup_on_interrupt") is True

    names = data.get("sandbox_names", [])
    assert len(names) >= 1, "sandbox_names must not be empty"
    assert len(names) == len(set(names)), "sandbox_names must be unique"

    # Read names from reliability.json and commands.jsonl
    valid_names = set()
    rel_path = REPORTS_DIR / "reliability.json"
    if rel_path.exists():
        rel_data = json.loads(rel_path.read_text())
        valid_names.update(r["sandbox_name"] for r in rel_data.get("runs", []))
    cmd_path = LOGS_DIR / "commands.jsonl"
    if cmd_path.exists():
        for line in cmd_path.read_text().split("\n"):
            if line.strip():
                valid_names.add(json.loads(line).get("sandbox_name"))

    for n in names:
        assert SBX_NAME_RE.match(n), f"Name {n} violates sandbox name format"
        assert n in valid_names, f"Name {n} must appear in reliability.json or commands.jsonl"


def test_req7_reliability_and_postmortem():
    """Requirement 7: reports/reliability.json and postmortem.md statistical correctness."""
    path = REPORTS_DIR / "reliability.json"
    assert path.exists(), "reports/reliability.json must exist"
    data = json.loads(path.read_text())

    runs = data.get("runs", [])
    assert len(runs) >= 20, "Must have at least 20 runs"
    assert data["run_count"] == len(runs)

    names = [r["sandbox_name"] for r in runs]
    assert len(names) == len(set(names)), "Sandbox names must be unique"

    for r in runs:
        assert SBX_NAME_RE.match(r["sandbox_name"])
        assert r["fresh"] is True
        assert isinstance(r["success"], bool)
        assert r["wall_clock_s"] >= 0
        assert r["boot_to_ready_s"] >= 0
        assert r["cost_usd"] >= 0

    # Arithmetic checks
    success_count = sum(1 for r in runs if r["success"])
    expected_rate = success_count / len(runs)
    assert abs(data["success_rate"] - expected_rate) <= 0.001

    # Sorted wall clocks
    wall_clocks = sorted(r["wall_clock_s"] for r in runs)
    n = len(wall_clocks)
    if n % 2 == 1:
        expected_median = wall_clocks[n // 2]
    else:
        expected_median = (wall_clocks[n // 2 - 1] + wall_clocks[n // 2]) / 2.0
    assert abs(data["median_wall_clock_s"] - expected_median) <= 0.001

    p90_rank = math.ceil(0.9 * n)
    expected_p90 = wall_clocks[p90_rank - 1]
    assert abs(data["p90_wall_clock_s"] - expected_p90) <= 0.001

    boot_times = sorted(r["boot_to_ready_s"] for r in runs)
    if n % 2 == 1:
        expected_boot_median = boot_times[n // 2]
    else:
        expected_boot_median = (boot_times[n // 2 - 1] + boot_times[n // 2]) / 2.0
    assert abs(data["median_boot_to_ready_s"] - expected_boot_median) <= 0.001

    expected_total_cost = sum(r["cost_usd"] for r in runs)
    assert abs(data["total_cost_usd"] - expected_total_cost) <= 0.01

    # Postmortem check
    assert data["postmortem_path"] == "reports/postmortem.md"
    pm_path = PROJECT_ROOT / "reports" / "postmortem.md"
    assert pm_path.exists(), "reports/postmortem.md must exist"
    assert len(pm_path.read_text()) >= 200, "postmortem.md must be at least 200 chars"


def test_req8_containment_report():
    """Requirement 8: reports/containment.json attack, blocked, and untouched flags."""
    path = REPORTS_DIR / "containment.json"
    assert path.exists(), "reports/containment.json must exist"
    data = json.loads(path.read_text())

    assert data["attack"] in ALLOWED_ATTACK_IDS, f"Attack {data['attack']} not in allowed set"
    assert data["blocked"] is True
    assert data["host_untouched"] is True
    assert len(data.get("evidence_paths", [])) >= 1

    for ep in data["evidence_paths"]:
        assert (PROJECT_ROOT / ep).exists(), f"Evidence path does not exist: {ep}"


def test_req9_failure_policy_and_trace():
    """Requirement 9: reports/failure_policy.json and matching policy_applied trace."""
    policy_path = REPORTS_DIR / "failure_policy.json"
    assert policy_path.exists(), "reports/failure_policy.json must exist"
    data = json.loads(policy_path.read_text())

    assert data["failed_step"] == 7
    assert data["total_steps"] == 10
    assert data["policy"] in ALLOWED_POLICIES
    assert len(data["rationale"]) >= 200, "Rationale must be at least 200 chars"
    assert data["trace_path"] == "reports/failure_trace.jsonl"

    trace_file = PROJECT_ROOT / data["trace_path"]
    assert trace_file.exists(), "reports/failure_trace.jsonl must exist"

    lines = [json.loads(line) for line in trace_file.read_text().split("\n") if line.strip()]
    applied_events = [e for e in lines if e.get("event") == "policy_applied" and e.get("policy") == data["policy"]]
    assert len(applied_events) >= 1, "Must have at least one policy_applied line matching policy"


def test_req10_concurrency_report():
    """Requirement 10: reports/concurrency.json contains >= 5 jobs and breakage_notes."""
    path = REPORTS_DIR / "concurrency.json"
    assert path.exists(), "reports/concurrency.json must exist"
    data = json.loads(path.read_text())

    jobs = data.get("jobs", [])
    assert len(jobs) >= 5, "Must have at least 5 jobs"

    names = [j["sandbox_name"] for j in jobs]
    assert len(names) == len(set(names)), "Concurrent sandbox names must be unique"

    for j in jobs:
        assert SBX_NAME_RE.match(j["sandbox_name"])
        assert j.get("started_at"), "started_at must be non-empty string"

    assert len(data.get("breakage_notes", "")) >= 40, "breakage_notes must be at least 40 chars"


def test_req12_readme_required_phrases_and_demo():
    """Requirement 12: README.md contains all 6 required phrases and demo file exists."""
    readme_path = PROJECT_ROOT / "README.md"
    assert readme_path.exists(), "README.md must exist"
    text = readme_path.read_text(encoding="utf-8")

    required_phrases = [
        "Problem statement",
        "How I used Celesto",
        "Eval report",
        "Containment test",
        "State and failure design",
        "Setup",
    ]
    for phrase in required_phrases:
        assert phrase in text, f"README.md must contain exact phrase: '{phrase}'"

    demo_path = PROJECT_ROOT / "demo" / "walkthrough.mp4"
    assert demo_path.exists(), "demo/walkthrough.mp4 must exist in repo"
