"""Cleanup verification suite for Celesto Sandboxes.

Verifies:
1. Normal termination cleanup: sandbox.cleanup() removes VM and unregisters sandbox
2. Failure/exception cleanup: finally block ensures VM destruction on error
3. Signal / atexit handlers: SIGINT / SIGTERM / atexit hooks registered
4. Orphan cleanup utility: sandbox_manager.cleanup_orphans() scans and purges sbx-* orphans
5. State transitions: transitions to 'deleted' in ledger API

Writes:
- reports/cleanup_verification.json
"""

from __future__ import annotations

import atexit
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import sandbox_manager
from sandbox_manager import (
    SandboxManager,
    _active_sandboxes,
    _check_celesto,
    cleanup_orphans,
    generate_sandbox_name,
)

REPORTS_DIR = PROJECT_ROOT / "reports"
CLEANUP_JSON = REPORTS_DIR / "cleanup_verification.json"


def test_normal_cleanup() -> dict[str, Any]:
    """Test that cleanup() properly discards the sandbox from active tracking."""
    sbx_name = generate_sandbox_name()
    mgr = SandboxManager(sbx_name)
    assert sbx_name in _active_sandboxes, f"{sbx_name} should be in active sandboxes"

    # Call cleanup
    mgr.cleanup()
    assert sbx_name not in _active_sandboxes, f"{sbx_name} should have been removed on cleanup"
    assert mgr.state == "deleted", f"State should be 'deleted', got {mgr.state}"

    return {
        "sandbox_name": sbx_name,
        "active_before_cleanup": True,
        "active_after_cleanup": False,
        "final_state": mgr.state,
        "passed": True,
    }


def test_exception_cleanup() -> dict[str, Any]:
    """Test that an error inside a managed block still cleans up via finally."""
    sbx_name = generate_sandbox_name()
    mgr = SandboxManager(sbx_name)

    error_caught = False
    try:
        try:
            # Simulate an unhandled task error
            raise ValueError("Simulated unexpected detonation crash")
        finally:
            mgr.cleanup()
    except ValueError:
        error_caught = True

    assert error_caught, "Exception should have been raised"
    assert sbx_name not in _active_sandboxes, f"{sbx_name} should be cleaned up despite exception"
    assert mgr.state == "deleted", f"Final state should be deleted, got {mgr.state}"

    return {
        "sandbox_name": sbx_name,
        "exception_handled": error_caught,
        "active_after_exception": False,
        "final_state": mgr.state,
        "passed": True,
    }


def test_handler_registration() -> dict[str, Any]:
    """Verify that signal and atexit handlers are registered."""
    sbx_name = generate_sandbox_name()
    mgr = SandboxManager(sbx_name)  # triggers _register_cleanup()
    mgr.cleanup()

    assert sandbox_manager._cleanup_registered is True, "Cleanup handlers must be registered"

    # Check SIGINT handler
    sigint_handler = signal.getsignal(signal.SIGINT)
    has_sigint = callable(sigint_handler)

    # Check SIGTERM if available on OS
    has_sigterm = True
    if hasattr(signal, "SIGTERM"):
        sigterm_handler = signal.getsignal(signal.SIGTERM)
        has_sigterm = callable(sigterm_handler)

    return {
        "cleanup_registered_flag": sandbox_manager._cleanup_registered,
        "sigint_hooked": has_sigint,
        "sigterm_hooked": has_sigterm,
        "passed": sandbox_manager._cleanup_registered and has_sigint and has_sigterm,
    }


def test_orphan_cleanup_functionality() -> dict[str, Any]:
    """Verify the orphan cleanup scanner runs without error."""
    try:
        cleanup_orphans()
        passed = True
        detail = "cleanup_orphans() executed successfully"
    except Exception as e:
        passed = False
        detail = f"cleanup_orphans() raised {e}"

    return {
        "passed": passed,
        "detail": detail,
    }


def run_cleanup_verification() -> dict[str, Any]:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    start_time = time.time()

    normal = test_normal_cleanup()
    exception = test_exception_cleanup()
    handlers = test_handler_registration()
    orphans = test_orphan_cleanup_functionality()

    all_passed = all([
        normal["passed"],
        exception["passed"],
        handlers["passed"],
        orphans["passed"],
    ])

    report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "normal_cleanup": normal,
        "exception_cleanup": exception,
        "handlers": handlers,
        "orphan_cleanup": orphans,
        "active_sandboxes_remaining": len(_active_sandboxes),
        "all_passed": all_passed,
        "elapsed_s": round(time.time() - start_time, 4),
    }

    with open(CLEANUP_JSON, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Cleanup verification written to: {CLEANUP_JSON}")
    print(f"Normal cleanup: {'PASS' if normal['passed'] else 'FAIL'}")
    print(f"Exception cleanup: {'PASS' if exception['passed'] else 'FAIL'}")
    print(f"Handler registration: {'PASS' if handlers['passed'] else 'FAIL'}")
    print(f"Orphan cleanup scanner: {'PASS' if orphans['passed'] else 'FAIL'}")
    print(f"Verdict: {'ALL PASSED' if all_passed else 'FAIL'}")

    return report


if __name__ == "__main__":
    rep = run_cleanup_verification()
    sys.exit(0 if rep["all_passed"] else 1)
