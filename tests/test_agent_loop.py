"""Unit and functional tests for the 10-step agent loop and fault recovery."""

import json
from pathlib import Path
import pytest

from agent_loop import (
    run_detonation,
    _heuristic_risk_analysis,
)


def test_agent_loop_ten_steps():
    """Verify that a standard detonation completes all 10 steps."""
    report = run_detonation("safemath", simulate=True)
    assert report["steps_completed"] == 10
    assert report["package"] == "safemath"
    assert report["sandbox_name"].startswith("sbx-")
    assert report["verdict"] == "safe"
    assert report["boot_to_ready_s"] is not None
    assert report["wall_clock_s"] is not None
    assert len(report["evidence"]) >= 3


def test_agent_loop_fault_injection_and_rollback():
    """Verify fault injection at step 7 triggers rollback policy and succeeds."""
    report = run_detonation("sneakywrite", fault_inject=True, simulate=True)
    assert report["steps_completed"] == 10
    assert report["fault_injected"] is True
    assert report["verdict"] == "suspicious"

    # Evidence must contain fault injection rollback proof
    rollback_ev = [e for e in report["evidence"] if e.get("type") == "fault_injection_rollback"]
    assert len(rollback_ev) == 1
    assert "rolled back" in rollback_ev[0]["detail"]


def test_heuristic_analysis_benign():
    """Test heuristic analysis marks clean package as safe."""
    res = _heuristic_risk_analysis(
        "cleantest",
        {
            "new_files": [],
            "process_list": "python3",
            "network_attempts": "none",
        },
    )
    assert res["verdict"] == "safe"
    assert "Clean" in res["reasoning"]


def test_heuristic_analysis_suspicious_files():
    """Test heuristic analysis flags hidden file writes."""
    res = _heuristic_risk_analysis(
        "sneakytest",
        {
            "new_files": ["/tmp/.sneaky_marker"],
            "process_list": "python3",
            "network_attempts": "none",
        },
    )
    assert res["verdict"] == "suspicious"


def test_heuristic_analysis_network():
    """Test heuristic analysis flags outbound network socket attempts."""
    res = _heuristic_risk_analysis(
        "nettest",
        {
            "new_files": [],
            "process_list": "python3",
            "network_attempts": "Socket connect blocked (Network is unreachable)",
        },
    )
    assert res["verdict"] == "suspicious"


def test_heuristic_analysis_malicious():
    """Test heuristic analysis classifies root directory modifications as malicious."""
    res = _heuristic_risk_analysis(
        "trojantest",
        {
            "new_files": ["/root/.ssh/authorized_keys"],
            "process_list": "python3",
            "network_attempts": "none",
        },
    )
    assert res["verdict"] == "malicious"
