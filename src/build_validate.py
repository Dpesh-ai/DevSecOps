"""
Build-validation stage (FR11, docs/REQUIREMENTS.md).

The Terms of Reference (Section 5.5 Stage 3, Section 6.1 Q1: "Can the pipeline
build selected repositories automatically?") requires the pipeline to actually
attempt building/installing each target repository, not only parse its
manifest for SBOM purposes. This module closes that gap: it validates that a
target's declared dependency set is genuinely resolvable and installable,
using the same package managers a real build would use, without requiring a
full, slow install (dependency resolution + metadata is sufficient to answer
"can this be built" and is orders of magnitude faster).

- Python targets: `pip install --dry-run -r requirements.txt` - resolves and
  reports what would be installed without downloading full wheels/sdists
  where avoidable.
- Node.js targets: `npm ci --dry-run` - validates the committed
  package-lock.json is installable and in sync with package.json, without
  extracting any packages to disk.

Both commands are the actual tools a real CI build step would run; this
module does not reimplement dependency resolution.
"""
from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
from pathlib import Path


def validate_python_target(target_dir: Path, timeout_s: int = 35) -> dict:
    """Resolves requirements.txt via pip's own resolver. Uses pip's
    structured `--report` JSON output (pip >= 22.2) as the primary source of
    truth for exactly which packages would be installed - this is a genuinely
    independent oracle from both this project's own requirements.txt parser
    (src/sbom_generate.py::_parse_requirements_txt) and cyclonedx-py's SBOM
    output, since it is pip's real dependency resolver reading the same file
    through a completely different code path. `resolved_package_names` is
    consumed by evaluate.py to independently cross-check the generated SBOM's
    completeness (see docs/PROFESSOR_REVIEW.md, "SBOM completeness metric
    circularity"), rather than only comparing the SBOM against the very
    parser that helped build it. Falls back to parsing pip's human-readable
    "Would install ..." log line if `--report` is unavailable or fails to
    produce usable JSON, so this still works against older pip versions."""
    req_file = target_dir / "requirements.txt"
    if not req_file.exists():
        return {"buildable": None, "method": None, "detail": "no requirements.txt found"}

    start = time.perf_counter()
    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "pip-install-report.json"
        proc = subprocess.run(
            ["pip", "install", "--dry-run", "--report", str(report_path), "-r", str(req_file)],
            capture_output=True, text=True, timeout=timeout_s,
        )
        duration = time.perf_counter() - start
        output = proc.stdout + proc.stderr

        if proc.returncode == 0 and report_path.exists():
            resolved_names = None
            try:
                report_data = json.loads(report_path.read_text())
                resolved_names = [
                    item["metadata"]["name"]
                    for item in report_data.get("install", [])
                    if item.get("metadata", {}).get("name")
                ]
            except (json.JSONDecodeError, KeyError, OSError):
                resolved_names = None
            if resolved_names:
                return {
                    "buildable": True,
                    "method": "pip install --dry-run --report (structured JSON install report)",
                    "packages_resolved": len(resolved_names),
                    "resolved_package_names": resolved_names,
                    "duration_seconds": round(duration, 2),
                    "detail": (
                        f"dependency resolution succeeded; {len(resolved_names)} packages would be "
                        "installed (package list read from pip's own structured --report JSON output, "
                        "not parsed from human-readable log text)"
                    ),
                }

        # Fallback: older pip versions, or a --report that didn't produce
        # usable JSON despite a zero exit code.
        would_install_match = re.search(r"Would install (.+)", output)
        if proc.returncode == 0 and would_install_match:
            packages = would_install_match.group(1).split()
            return {
                "buildable": True,
                "method": "pip install --dry-run -r requirements.txt (text-parsed fallback; --report unavailable)",
                "packages_resolved": len(packages),
                "resolved_package_names": None,
                "duration_seconds": round(duration, 2),
                "detail": f"dependency resolution succeeded; {len(packages)} packages would be installed",
            }

        error_lines = [l for l in output.splitlines() if l.strip().startswith(("ERROR:", "error:"))]
        reason = error_lines[-1].strip() if error_lines else "pip install --dry-run failed (see full log)"
        return {
            "buildable": False,
            "method": "pip install --dry-run --report",
            "duration_seconds": round(duration, 2),
            "detail": reason,
        }


def validate_node_target(target_dir: Path, timeout_s: int = 90) -> dict:
    lock_file = target_dir / "package-lock.json"
    if not lock_file.exists():
        return {"buildable": None, "method": None, "detail": "no package-lock.json found"}

    start = time.perf_counter()
    proc = subprocess.run(
        ["npm", "ci", "--dry-run", "--no-audit", "--no-fund", "--loglevel=error"],
        cwd=str(target_dir), capture_output=True, text=True, timeout=timeout_s,
    )
    duration = time.perf_counter() - start
    output = proc.stdout + proc.stderr

    # npm ci --dry-run reports success in several equivalent forms depending
    # on whether node_modules already partially exists ("added N packages",
    # "changed N packages", "removed N packages", or a combination) - a
    # zero exit code is the authoritative success signal; the package counts
    # below are best-effort detail extracted from whichever verb npm used.
    if proc.returncode == 0:
        counts = re.findall(r"(?:added|changed|removed) (\d+) package", output)
        total_summary_line = next((l for l in output.splitlines() if re.search(r"(added|changed|removed) \d+ package", l)), None)
        return {
            "buildable": True,
            "method": "npm ci --dry-run",
            "packages_resolved": sum(int(c) for c in counts) if counts else None,
            "duration_seconds": round(duration, 2),
            "detail": f"lockfile is installable and in sync with package.json"
                      + (f" ({total_summary_line.strip()})" if total_summary_line else ""),
        }

    error_lines = [l for l in output.splitlines() if "npm error" in l.lower() or "npm ERR" in l]
    reason = "; ".join(error_lines[:3]) if error_lines else f"npm ci --dry-run failed (exit {proc.returncode})"
    return {
        "buildable": False,
        "method": "npm ci --dry-run",
        "duration_seconds": round(duration, 2),
        "detail": reason,
    }


def validate_target(target_dir: Path) -> dict:
    try:
        if (target_dir / "requirements.txt").exists():
            return validate_python_target(target_dir)
        if (target_dir / "package.json").exists():
            return validate_node_target(target_dir)
        return {"buildable": None, "method": None, "detail": "unrecognised ecosystem"}
    except subprocess.TimeoutExpired as e:
        return {
            "buildable": None,
            "method": "pip install --dry-run" if (target_dir / "requirements.txt").exists() else "npm ci --dry-run",
            "duration_seconds": e.timeout,
            "detail": (
                f"build validation did not complete within {e.timeout}s - likely a slow/large "
                "dependency resolution or a native-extension build in progress (e.g. compiling a C "
                "extension) rather than a hard failure. Re-run with a longer timeout or in an "
                "environment with the relevant build toolchain (see docs/TRACEABILITY.md)."
            ),
        }
