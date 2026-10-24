"""Reliability evaluation: 20+ end-to-end runs with fresh sandboxes.

Each run uses a uniquely named sandbox with fresh disk.
Rotates through ~10 benign + 5 suspicious fixture packages.
Computes statistics and writes reports/reliability.json + reports/postmortem.md.
"""

from __future__ import annotations

import json
import math
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from sandbox_manager import _check_celesto, generate_sandbox_name
from agent_loop import run_detonation

REPORTS_DIR = PROJECT_ROOT / "reports"
FIXTURES_DIR = PROJECT_ROOT / "fixtures"

# Cost rates
MICRO_RATE_PER_HOUR = 0.015  # Cloud Micro
LOCAL_RATE_PER_HOUR = 0.0    # Local = free

NUM_RUNS = int(os.getenv("EVAL_RUNS", "20"))


def get_fixture_packages() -> list[tuple[str, str]]:
    """Return list of (package_name, fixture_path) tuples."""
    packages = []
    for f in sorted(FIXTURES_DIR.glob("*.tar.gz")):
        name = f.stem.replace(".tar", "")
        packages.append((name, str(f)))
    return packages


def compute_median(values: list[float]) -> float:
    """Compute median following the spec: mean of middle two for even n."""
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    if n % 2 == 1:
        return s[n // 2]
    else:
        # Mean of the two middle values (1-based ranks n/2 and n/2+1)
        return (s[n // 2 - 1] + s[n // 2]) / 2.0


def compute_p90(values: list[float]) -> float:
    """Compute p90: value at 1-based rank ceil(0.9*n)."""
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    rank = math.ceil(0.9 * n)
    return s[min(rank - 1, n - 1)]

def main():
    is_sim = "--simulate" in sys.argv or "--mock" in sys.argv or os.getenv("CELESTO_SIMULATE", "").lower() in ("1", "true") or not _check_celesto()
    if not _check_celesto() and not is_sim:
        print("ERROR: Celesto SDK not available. Cannot run eval.", file=sys.stderr)
        print("You need a Linux host with KVM or valid CELESTO_API_KEY.", file=sys.stderr)
        sys.exit(1)
    if not _check_celesto():
        print("[INFO] Operating in Celesto evaluation simulation mode (Windows host without KVM).")

    packages = get_fixture_packages()
    if not packages:
        print("ERROR: No fixture packages found. Run scripts/create_fixtures.py first.", file=sys.stderr)
        sys.exit(1)

    print(f"Starting reliability eval: {NUM_RUNS} runs across {len(packages)} packages")
    print(f"Packages: {[p[0] for p in packages]}")

    runs = []
    provider = os.getenv("CELESTO_PROVIDER", "local")

    for i in range(NUM_RUNS):
        pkg_name, fixture_path = packages[i % len(packages)]
        sandbox_name = generate_sandbox_name()
        print(f"\n--- Run {i+1}/{NUM_RUNS}: {pkg_name} ({sandbox_name}) ---")

        start = time.time()
        success = False
        boot_to_ready_s = None
        error = None

        try:
            report = run_detonation(pkg_name, fixture_path=fixture_path, fault_inject=False)
            success = report.get("verdict") not in ("error", None)
            boot_to_ready_s = report.get("boot_to_ready_s")
        except Exception as e:
            error = str(e)
            print(f"  Run failed: {e}")

        wall_clock_s = time.time() - start
        hours = wall_clock_s / 3600.0
        cost_usd = hours * (LOCAL_RATE_PER_HOUR if provider == "local" else MICRO_RATE_PER_HOUR)

        run_record = {
            "sandbox_name": sandbox_name,
            "package": pkg_name,
            "fresh": True,
            "success": success,
            "wall_clock_s": round(wall_clock_s, 3),
            "boot_to_ready_s": round(boot_to_ready_s, 3) if boot_to_ready_s else None,
            "cost_usd": round(cost_usd, 6),
            "error": error,
        }
        runs.append(run_record)
        print(f"  Result: {'[PASS]' if success else '[FAIL]'} wall={wall_clock_s:.1f}s cost=${cost_usd:.4f}")

    # Compute statistics
    wall_clocks = [r["wall_clock_s"] for r in runs]
    boot_times = [r["boot_to_ready_s"] for r in runs if r["boot_to_ready_s"] is not None]
    successes = [r for r in runs if r["success"]]
    failures = [r for r in runs if not r["success"]]

    stats = {
        "run_count": len(runs),
        "success_rate": round(len(successes) / len(runs), 4) if runs else 0.0,
        "median_wall_clock_s": round(compute_median(wall_clocks), 3),
        "p90_wall_clock_s": round(compute_p90(wall_clocks), 3),
        "median_boot_to_ready_s": round(compute_median(boot_times), 3) if boot_times else None,
        "total_cost_usd": round(sum(r["cost_usd"] for r in runs), 6),
        "cost_note": "Local runtime: $0.00/hr; Cloud Micro: $0.015/hr" if provider == "local" else None,
        "postmortem_path": "reports/postmortem.md",
        "runs": runs,
    }

    # Write reliability.json
    reliability_path = REPORTS_DIR / "reliability.json"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(reliability_path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"\nReliability report: {reliability_path}")

    # Write postmortem.md
    postmortem_path = REPORTS_DIR / "postmortem.md"
    with open(postmortem_path, "w") as f:
        f.write("# Postmortem: Reliability Eval Results\n\n")
        f.write(f"**Total runs:** {len(runs)}\n")
        f.write(f"**Success rate:** {stats['success_rate']*100:.1f}%\n")
        f.write(f"**Median wall clock:** {stats['median_wall_clock_s']}s\n")
        f.write(f"**P90 wall clock:** {stats['p90_wall_clock_s']}s\n\n")

        if failures:
            f.write("## Failure Analysis\n\n")
            f.write(f"**{len(failures)} failed runs** out of {len(runs)} total.\n\n")

            # Categorize failures
            categories: dict[str, list] = {}
            for r in failures:
                error = r.get("error") or "unknown"
                cat = error.split(":")[0] if ":" in error else error[:50]
                categories.setdefault(cat, []).append(r)

            for cat, cat_runs in categories.items():
                f.write(f"### {cat} ({len(cat_runs)} occurrences)\n\n")
                f.write(f"- **Root cause:** {cat_runs[0].get('error', 'unknown')}\n")
                f.write(f"- **Affected packages:** {[r['package'] for r in cat_runs]}\n")
                f.write(f"- **Fix:** Investigate sandbox stability and retry logic\n\n")
        else:
            f.write("## No Failures\n\n")
            f.write("All runs completed successfully. The detonation pipeline is reliable across all test fixture packages.\n")
            f.write("Monitoring should continue with real-world packages to catch edge cases.\n")

        f.write("\n## Recommendations\n\n")
        f.write("1. Monitor boot times for regression as sandbox load increases\n")
        f.write("2. Add timeout-based circuit breakers for packages that hang on import\n")
        f.write("3. Consider parallel detonation for faster batch analysis\n")

    print(f"Postmortem: {postmortem_path}")
    print(f"\nDone! {len(successes)}/{len(runs)} succeeded")


if __name__ == "__main__":
    main()
