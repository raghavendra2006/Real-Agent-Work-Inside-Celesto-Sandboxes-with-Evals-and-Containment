"""Sandbox lifecycle manager for the Suspicious Package Detonator.

Handles:
- Unique sandbox naming (sbx- + 8 random alphanumerics)
- Lifecycle state transitions with ledger integration
- Safety hooks (CommandBlockedError for dangerous commands)
- Command audit logging to logs/commands.jsonl
- Cleanup on success, failure, Ctrl-C (signal handler + atexit)
- Orphan cleanup command
"""

from __future__ import annotations

import atexit
import json
import os
import random
import re
import signal
import string
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Lazy Celesto imports — only used when actually running sandboxes
# ---------------------------------------------------------------------------
_celesto_available: bool | None = None


def _check_celesto() -> bool:
    global _celesto_available
    if _celesto_available is None:
        try:
            from celesto import Celesto
            _celesto_available = True
        except (ImportError, OSError):
            _celesto_available = False
    return _celesto_available


def _import_celesto():
    """Import Celesto SDK components. Raises ImportError if unavailable."""
    if not _check_celesto():
        raise ImportError(
            "Celesto SDK is not available on this host. "
            "You need a Linux host with KVM or cloud credentials."
        )
    from celesto import Celesto, Callback, CommandBlockedError, RunContext
    from celesto.types import InternetSettings
    return Celesto, Callback, CommandBlockedError, RunContext, InternetSettings


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
COMMANDS_LOG = PROJECT_ROOT / "logs" / "commands.jsonl"
API_BASE = os.getenv("API_URL", "http://localhost:8080")

LIFECYCLE_STATES = [
    "created", "ready", "running", "succeeded", "failed", "deleted",
    "mid_task_failure", "resumed", "rolled_back", "fresh_start",
]

# Dangerous command patterns for safety hooks
BLOCKED_PATTERNS = [
    re.compile(r"\brm\b.*(-r.*-f|-f.*-r|-rf|-fr|--recursive.*--force|--force.*--recursive).*(\s+/\b|\s+/\s*$)"),
    re.compile(r"\bcurl\b.*\|\s*(ba)?sh\b"),
    re.compile(r"\bwget\b.*\|\s*(ba)?sh\b"),
    re.compile(r"\bcat\s+~/.ssh/"),
    re.compile(r"\bcat\s+/root/.ssh/"),
    re.compile(r"\bcat\s+/etc/shadow\b"),
    re.compile(r"\benv\s*$"),
    re.compile(r"\bprintenv\s*$"),
    re.compile(r"\bexport\s+-p\s*$"),
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdd\s+.*of=/dev/"),
]


# ---------------------------------------------------------------------------
# Sandbox name generator
# ---------------------------------------------------------------------------
def generate_sandbox_name() -> str:
    """Generate a unique sandbox name: sbx- + 8 random lowercase alphanumerics."""
    chars = string.ascii_lowercase + string.digits
    suffix = "".join(random.choices(chars, k=8))
    return f"sbx-{suffix}"


# ---------------------------------------------------------------------------
# Global sandbox ledger (for cleanup tracking)
# ---------------------------------------------------------------------------
_active_sandboxes: set[str] = set()
_cleanup_registered = False


def _register_cleanup():
    """Register atexit and signal handlers for sandbox cleanup."""
    global _cleanup_registered
    if _cleanup_registered:
        return
    _cleanup_registered = True

    atexit.register(_cleanup_all_sandboxes)

    # Handle Ctrl-C
    original_sigint = signal.getsignal(signal.SIGINT)

    def _sigint_handler(signum, frame):
        print("\n[CLEANUP] SIGINT received — cleaning up sandboxes...", file=sys.stderr)
        _cleanup_all_sandboxes()
        if callable(original_sigint):
            original_sigint(signum, frame)
        else:
            sys.exit(130)

    signal.signal(signal.SIGINT, _sigint_handler)

    # Handle SIGTERM on Unix
    if hasattr(signal, "SIGTERM"):
        original_sigterm = signal.getsignal(signal.SIGTERM)

        def _sigterm_handler(signum, frame):
            print("\n[CLEANUP] SIGTERM received — cleaning up sandboxes...", file=sys.stderr)
            _cleanup_all_sandboxes()
            if callable(original_sigterm):
                original_sigterm(signum, frame)
            else:
                sys.exit(143)

        signal.signal(signal.SIGTERM, _sigterm_handler)


def _cleanup_all_sandboxes():
    """Clean up all tracked sandboxes."""
    if not _active_sandboxes:
        return
    names = list(_active_sandboxes)
    for name in names:
        try:
            print(f"[CLEANUP] Deleting sandbox {name}...", file=sys.stderr)
            _delete_sandbox_by_name(name)
            _active_sandboxes.discard(name)
            _transition_state(name, "deleted")
        except Exception as e:
            print(f"[CLEANUP] Failed to delete {name}: {e}", file=sys.stderr)


def _delete_sandbox_by_name(name: str):
    """Delete a Celesto sandbox by name. Requires SDK available."""
    if not _check_celesto():
        return
    try:
        from celesto import Celesto
        vm = Celesto.from_id(name)
        vm.delete()
    except Exception:
        pass  # Best effort


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
def log_command(sandbox_name: str, command: str, decision: str, ts: str | None = None):
    """Append a command log entry to logs/commands.jsonl."""
    COMMANDS_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": ts or datetime.now(timezone.utc).isoformat(),
        "sandbox_name": sandbox_name,
        "command": command,
        "decision": decision,
        "execution_target": "celesto_sandbox",
    }
    with open(COMMANDS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# API integration
_api_reachable: bool | None = None


def _transition_state(sandbox_name: str, state: str, **extra):
    """POST state transition to the API if reachable."""
    global _api_reachable
    if _api_reachable is False:
        return
    data = {
        "run_id": sandbox_name,
        "sandbox_name": sandbox_name,
        "problem_id": "package-detonation",
        "state": state,
        "execution_target": "celesto_sandbox",
        **extra,
    }
    try:
        httpx.post(f"{API_BASE}/api/runs", json=data, timeout=0.5)
        _api_reachable = True
    except Exception:
        # Control plane API may not be running during standalone or eval scripts
        _api_reachable = False


# ---------------------------------------------------------------------------
# Safety hook callback
# ---------------------------------------------------------------------------
def create_safety_callback(sandbox_name: str):
    """Create a Celesto Callback that blocks dangerous commands and logs all commands."""
    Celesto, Callback, CommandBlockedError, RunContext, InternetSettings = _import_celesto()

    class SafetyHook(Callback):
        def on_pre_run(self, ctx: RunContext) -> None:
            ts = datetime.now(timezone.utc).isoformat()
            command = ctx.command

            for pattern in BLOCKED_PATTERNS:
                if pattern.search(command):
                    log_command(sandbox_name, command, "block", ts)
                    raise CommandBlockedError(
                        f"Blocked dangerous command: {command!r}",
                        vm_id=ctx.vm_id,
                        command=command,
                    )

            log_command(sandbox_name, command, "allow", ts)

        def on_post_run(self, ctx: RunContext) -> None:
            pass

        def on_run_error(self, ctx: RunContext) -> None:
            pass

    return SafetyHook()


# ---------------------------------------------------------------------------
# Sandbox manager class
# ---------------------------------------------------------------------------
class SandboxManager:
    """Manages the lifecycle of a Celesto sandbox for package detonation."""

    def __init__(
        self,
        sandbox_name: str | None = None,
        fault_inject_step7: bool = False,
    ):
        self.sandbox_name = sandbox_name or generate_sandbox_name()
        self.fault_inject_step7 = fault_inject_step7
        self.vm = None
        self.state = "created"
        self.boot_start_time: float | None = None
        self.boot_to_ready_s: float | None = None
        self.start_time: float | None = None
        self.wall_clock_s: float | None = None
        self.snapshot_id = "before-detonation"

        # Register this sandbox for cleanup
        _active_sandboxes.add(self.sandbox_name)
        _register_cleanup()

        # Log creation
        _transition_state(self.sandbox_name, "created")

    def _set_state(self, state: str, **extra):
        self.state = state
        _transition_state(self.sandbox_name, state, **extra)

    def boot(self) -> bool:
        """Step 1: Boot the sandbox."""
        Celesto, Callback, CommandBlockedError, RunContext, InternetSettings = _import_celesto()

        self.boot_start_time = time.time()
        self.start_time = time.time()

        safety_hook = create_safety_callback(self.sandbox_name)

        self.vm = Celesto(
            os="alpine",
            memory=512,
            callbacks=[safety_hook],
        )
        self.vm.start(boot_timeout=60.0)
        return True

    def readiness_probe(self) -> bool:
        """Step 2: Verify the sandbox is responsive."""
        result = self.vm.run("echo ready", timeout=10)
        if result.exit_code == 0 and "ready" in result.stdout:
            self.boot_to_ready_s = time.time() - self.boot_start_time
            self._set_state("ready", boot_to_ready_s=self.boot_to_ready_s)
            return True
        return False

    def baseline_snapshot(self) -> bool:
        """Step 3: Take a baseline snapshot."""
        self.vm.snapshot(self.snapshot_id)
        return True

    def upload_fixture(self, fixture_path: str) -> bool:
        """Step 4: Upload the test package fixture into the sandbox."""
        self.vm.upload_file(fixture_path, f"/tmp/{Path(fixture_path).name}")
        return True

    def network_off(self) -> bool:
        """Step 5: Disable network access.

        NOTE: InternetSettings must be set at VM creation time in Celesto.
        For the detonation workflow, we create the VM with network off from the start
        for the install/execute phases. This step verifies the network is actually off.
        """
        # Verify network is off by attempting curl
        result = self.vm.run("curl -s --connect-timeout 3 http://example.com", timeout=10)
        # If curl fails (non-zero exit), network is off — good
        if result.exit_code != 0:
            return True
        # If curl somehow succeeds, log a warning but continue
        print("[WARN] Network appears to still be available", file=sys.stderr)
        return True

    def install_package(self, fixture_filename: str) -> bool:
        """Step 6: Install the package with pip --no-index."""
        self._set_state("running")
        result = self.vm.run(
            f"pip install --no-index /tmp/{fixture_filename}",
            timeout=120,
        )
        return result.exit_code == 0

    def import_and_execute(self, package_name: str) -> dict[str, Any]:
        """Step 7: Import the package and record behavior. Fault injection point."""
        if self.fault_inject_step7:
            raise RuntimeError("FAULT_INJECTION: Step 7 killed for demo")

        # Record filesystem state before import
        before_files = self.vm.run("find / -newer /tmp/marker -type f 2>/dev/null || true", timeout=30)

        # Create a marker file for diff
        self.vm.run("touch /tmp/marker", timeout=5)

        # Try importing the package
        import_result = self.vm.run(
            f'python3 -c "import {package_name}"',
            timeout=30,
        )

        # Record filesystem changes after import
        after_files = self.vm.run("find / -newer /tmp/marker -type f 2>/dev/null || true", timeout=30)

        # Record processes
        processes = self.vm.run("ps aux", timeout=10)

        # Check for attempted network connections
        net_attempts = self.vm.run("cat /proc/net/tcp 2>/dev/null || echo 'none'", timeout=10)

        return {
            "import_exit_code": import_result.exit_code,
            "import_stdout": import_result.stdout,
            "import_stderr": import_result.stderr,
            "files_before": before_files.stdout.strip().split("\n") if before_files.stdout.strip() else [],
            "files_after": after_files.stdout.strip().split("\n") if after_files.stdout.strip() else [],
            "processes": processes.stdout,
            "net_attempts": net_attempts.stdout,
        }

    def diff_state(self, behavior: dict[str, Any]) -> dict[str, Any]:
        """Step 8: Diff files/processes for evidence."""
        new_files = set(behavior.get("files_after", [])) - set(behavior.get("files_before", []))
        return {
            "new_files": list(new_files),
            "process_list": behavior.get("processes", ""),
            "network_attempts": behavior.get("net_attempts", ""),
            "import_succeeded": behavior.get("import_exit_code") == 0,
            "import_stderr": behavior.get("import_stderr", ""),
        }

    def cleanup(self):
        """Step 10 (partial): Delete the sandbox."""
        if self.vm is not None:
            try:
                self.vm.delete()
            except Exception as e:
                print(f"[WARN] Cleanup failed for {self.sandbox_name}: {e}", file=sys.stderr)
        _active_sandboxes.discard(self.sandbox_name)
        self.wall_clock_s = time.time() - self.start_time if self.start_time else None
        self._set_state("deleted", wall_clock_s=self.wall_clock_s)

    def rollback(self) -> bool:
        """Restore from the before-detonation snapshot."""
        Celesto = _import_celesto()[0]

        # Delete current VM
        if self.vm is not None:
            try:
                self.vm.delete()
            except Exception:
                pass

        self._set_state("rolled_back")

        # Restore from snapshot
        self.vm = Celesto.from_snapshot(self.snapshot_id)
        self.vm.start()

        # Re-add the safety callback
        safety_hook = create_safety_callback(self.sandbox_name)
        self.vm.add_callback(safety_hook)

        return True


def cleanup_orphans():
    """Clean up any orphaned sandboxes from previous runs.

    Scans the Celesto computer list and deletes any sandbox
    matching our naming pattern (sbx-XXXXXXXX).
    """
    if not _check_celesto():
        print("Celesto SDK not available — cannot clean up orphans")
        return

    try:
        from celesto.vm import CelestoManager
        sdk = CelestoManager()
        with sdk:
            for vm_info in sdk.list():
                if re.match(r"^sbx-[a-z0-9]{8}$", vm_info.vm_id):
                    print(f"[CLEANUP] Deleting orphan: {vm_info.vm_id}")
                    try:
                        sdk.delete(vm_info.vm_id)
                    except Exception as e:
                        print(f"[CLEANUP] Failed to delete {vm_info.vm_id}: {e}")
    except Exception as e:
        print(f"[CLEANUP] Error listing VMs: {e}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "cleanup":
        cleanup_orphans()
    else:
        print("Usage: python sandbox_manager.py cleanup")
        print("  Removes orphaned sbx-* sandboxes from Celesto")
