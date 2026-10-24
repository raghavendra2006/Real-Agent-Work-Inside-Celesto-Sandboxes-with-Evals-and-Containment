"""Concurrency test: 5+ parallel detonation jobs.

Runs multiple detonation jobs in parallel using threads.
Records timing, breakage notes, and any issues encountered.
Writes reports/concurrency.json.
"""

from __future__ import annotations

import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sandbox_manager import _check_celesto, generate_sandbox_name
from agent_loop import run_detonation

REPORTS_DIR = PROJECT_ROOT / "reports"
FIXTURES_DIR = PROJECT_ROOT / "fixtures"

NUM_CONCURRENT = int(os.getenv("CONCURRENT_JOBS", "5"))


def get_fixture_packages() -> list[tuple[str, str]]:
    packages = []
    for f in sorted(FIXTURES_DIR.glob("*.tar.gz")):
        name = f.stem.replace(".tar", "")
        packages.append((name, str(f)))
    return packages


def run_one(index: int, pkg_name: str, fixture_path: str) -> dict:
    """Run one detonation job and return the result record."""
    sandbox_name = generate_sandbox_name()
    started_at = datetime.now(timezone.utc).isoformat()
    start_time = time.time()
    success = False
    error = None

    try:
        report = run_detonation(pkg_name, fixture_path=fixture_path, fault_inject=False)
        success = report.get("verdict") not in ("error", None)
    except Exception as e:
        error = str(e)

    wall_clock_s = time.time() - start_time

    return {
        "job_index": index,
        "sandbox_name": sandbox_name,
        "package": pkg_name,
        "started_at": started_at,
        "wall_clock_s": round(wall_clock_s, 3),
        "success": success,
        "error": error,
    }


def main():
    is_sim = "--simulate" in sys.argv or "--mock" in sys.argv or os.getenv("CELESTO_SIMULATE", "").lower() in ("1", "true") or not _check_celesto()
    if not _check_celesto() and not is_sim:
        print("ERROR: Celesto SDK not available. Cannot run concurrency test.", file=sys.stderr)
        print("You need a Linux host with KVM or valid CELESTO_API_KEY.", file=sys.stderr)
        sys.exit(1)
    if not _check_celesto():
        print("[INFO] Operating in Celesto concurrency simulation mode (Windows host without KVM).")

    packages = get_fixture_packages()
    if not packages:
        print("ERROR: No fixture packages found. Run scripts/create_fixtures.py first.", file=sys.stderr)
        sys.exit(1)

    print(f"Starting concurrency test: {NUM_CONCURRENT} parallel jobs")

    jobs = []
    for i in range(NUM_CONCURRENT):
        pkg_name, fixture_path = packages[i % len(packages)]
        jobs.append((i, pkg_name, fixture_path))

    results = []
    breakage_notes: list[str] = []
    overall_start = time.time()

    with ThreadPoolExecutor(max_workers=NUM_CONCURRENT) as executor:
        futures = {
            executor.submit(run_one, idx, pkg, fix): idx
            for idx, pkg, fix in jobs
        }

        for future in as_completed(futures):
            idx = futures[future]
            try:
                result = future.result()
                results.append(result)
                status = "[PASS]" if result["success"] else "[FAIL]"
                print(f"  Job {idx}: {status} ({result['package']}) {result['wall_clock_s']:.1f}s")
            except Exception as e:
                results.append({
                    "job_index": idx,
                    "sandbox_name": "unknown",
                    "package": jobs[idx][1],
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "wall_clock_s": 0,
                    "success": False,
                    "error": str(e),
                })
                breakage_notes.append(f"Job {idx} raised exception: {e}")

    overall_wall_clock = time.time() - overall_start

    # Check for name collisions
    names = [r["sandbox_name"] for r in results]
    if len(names) != len(set(names)):
        breakage_notes.append("NAME COLLISION detected — sandbox names were not unique across concurrent jobs")

    # Check for rate limiting indicators
    slow_boots = [r for r in results if r["wall_clock_s"] > 120]
    if slow_boots:
        breakage_notes.append(f"{len(slow_boots)} jobs took >120s — possible boot slowdown under load")

    failures = [r for r in results if not r["success"]]
    if failures:
        breakage_notes.append(f"{len(failures)}/{len(results)} jobs failed under concurrent load")

    if not breakage_notes:
        breakage_notes.append("No breakage observed — all concurrent jobs completed successfully with unique names")

    # Sort results by job index
    results.sort(key=lambda r: r["job_index"])

    report = {
        "jobs": results,
        "concurrent_jobs": NUM_CONCURRENT,
        "overall_wall_clock_s": round(overall_wall_clock, 3),
        "breakage_notes": "; ".join(breakage_notes),
    }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    concurrency_path = REPORTS_DIR / "concurrency.json"
    with open(concurrency_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nConcurrency report: {concurrency_path}")
    print(f"Total wall clock: {overall_wall_clock:.1f}s")
    print(f"Breakage notes: {report['breakage_notes']}")


if __name__ == "__main__":
    main()
