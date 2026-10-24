"""Validation tests for generated reports and evaluation outputs."""

import json
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"


def test_problem_report():
    """Verify reports/problem.json schema and required fields."""
    path = REPORTS_DIR / "problem.json"
    assert path.exists(), "reports/problem.json must exist"
    data = json.loads(path.read_text())

    assert "who" in data and len(data["who"]) >= 20
    assert "agent_work" in data and len(data["agent_work"]) >= 20
    assert "proof_output" in data
    assert data["idea_source"] == "idea_bank"


def test_capabilities_report():
    """Verify reports/capabilities.json defines 3 capabilities with valid evidence paths."""
    path = REPORTS_DIR / "capabilities.json"
    assert path.exists(), "reports/capabilities.json must exist"
    data = json.loads(path.read_text())

    assert isinstance(data, list)
    assert len(data) >= 3

    ids = {item["id"] for item in data}
    assert "safety_hooks" in ids
    assert "network_policy" in ids
    assert "snapshots" in ids

    for item in data:
        assert len(item["why"]) >= 50, f"Capability {item['id']} 'why' explanation is too short"
        ev_path = PROJECT_ROOT / item["evidence_path"]
        assert ev_path.exists(), f"Evidence path does not exist: {item['evidence_path']}"


def test_failure_policy_report():
    """Verify reports/failure_policy.json fields and rationale length."""
    path = REPORTS_DIR / "failure_policy.json"
    assert path.exists(), "reports/failure_policy.json must exist"
    data = json.loads(path.read_text())

    assert data["failed_step"] == 7
    assert data["total_steps"] == 10
    assert data["policy"] == "rollback"
    assert len(data["rationale"]) >= 150, "Rationale should be comprehensive (>150 chars)"

    trace_path = PROJECT_ROOT / data["trace_path"]
    assert trace_path.exists(), f"Trace path does not exist: {data['trace_path']}"


def test_failure_trace_contents():
    """Verify reports/failure_trace.jsonl contains fault injection and rollback events."""
    path = REPORTS_DIR / "failure_trace.jsonl"
    assert path.exists(), "reports/failure_trace.jsonl must exist"

    lines = [json.loads(line) for line in path.read_text().strip().split("\n") if line.strip()]
    events = [entry.get("event") for entry in lines]

    assert "step_failed" in events, "Failure trace must contain step_failed event"
    assert "policy_applied" in events, "Failure trace must contain policy_applied event"
    assert "rollback_complete" in events, "Failure trace must contain rollback_complete event"
    assert "retry_succeeded" in events, "Failure trace must contain retry_succeeded event"


def test_reliability_report():
    """Verify reports/reliability.json contains 20+ runs and required statistical metrics."""
    path = REPORTS_DIR / "reliability.json"
    assert path.exists(), "reports/reliability.json must exist"
    data = json.loads(path.read_text())

    assert data["run_count"] >= 20
    assert "success_rate" in data
    assert "median_wall_clock_s" in data
    assert "p90_wall_clock_s" in data
    assert "median_boot_to_ready_s" in data
    assert len(data["runs"]) >= 20

    for r in data["runs"]:
        assert r["sandbox_name"].startswith("sbx-")
        assert "wall_clock_s" in r
        assert "package" in r


def test_postmortem_report():
    """Verify reports/postmortem.md exists and has substantive analysis."""
    path = REPORTS_DIR / "postmortem.md"
    assert path.exists(), "reports/postmortem.md must exist"
    text = path.read_text()
    assert len(text) >= 100
    assert "Reliability" in text


def test_concurrency_report():
    """Verify reports/concurrency.json contains 5+ concurrent jobs and breakage notes."""
    path = REPORTS_DIR / "concurrency.json"
    assert path.exists(), "reports/concurrency.json must exist"
    data = json.loads(path.read_text())

    assert data["concurrent_jobs"] >= 5
    assert "overall_wall_clock_s" in data
    assert "breakage_notes" in data
    assert len(data["results"]) >= 5

    names = [r["sandbox_name"] for r in data["results"]]
    assert len(names) == len(set(names)), "Concurrent sandbox names must all be unique"


def test_containment_report():
    """Verify reports/containment.json contains all passing containment assertions."""
    path = REPORTS_DIR / "containment.json"
    assert path.exists(), "reports/containment.json must exist"
    data = json.loads(path.read_text())

    assert data["all_passed"] is True
    assert data["tests"]["network_isolation"]["passed"] is True
    assert data["tests"]["filesystem_containment"]["passed"] is True
    assert data["tests"]["safety_hooks"]["all_passed"] is True
    assert data["tests"]["snapshot_rollback"]["passed"] is True


def test_detonation_reports():
    """Verify reports/detonation/*.json files exist with verdicts and evidence."""
    det_dir = REPORTS_DIR / "detonation"
    reports = list(det_dir.glob("*.json"))
    assert len(reports) >= 10, "Should have detonation reports for at least 10 packages"

    for r_path in reports:
        data = json.loads(r_path.read_text())
        assert "package" in data
        assert data["sandbox_name"].startswith("sbx-")
        assert data["verdict"] in ("safe", "suspicious", "malicious")
        assert isinstance(data["evidence"], list)
        assert data["steps_completed"] == 10
