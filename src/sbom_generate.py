"""
SBOM generation stage of the SBOM-first DevSecOps pipeline.

Responsibilities
----------------
1. Generate a CycloneDX 1.5 SBOM for a target repository.
   - Python ecosystem: shells out to the official ``cyclonedx-py`` tool
     (CycloneDX's reference Python SBOM generator) against requirements.txt.
   - Node.js ecosystem: parses ``package-lock.json`` (npm lockfile v2/v3)
     directly and emits a CycloneDX-conformant document. This mirrors what
     lockfile-based generators such as Syft / cyclonedx-npm do, and keeps the
     prototype self-contained (no dependency on a globally installed Node
     CLI tool, which is fragile in CI/sandboxed environments).
2. Compute an SBOM completeness/accuracy score by cross-checking the SBOM
   component list against the project's declared manifest (requirements.txt
   / package.json) and, where available, the full lockfile dependency tree.

This module answers RQ1 from the Terms of Reference:
    "To what extent are automatically generated SBOMs in various software
    ecosystems (Python, Node.js) accurate/complete?"
"""
from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

CYCLONEDX_SPEC_VERSION = "1.5"


@dataclass
class SBOMComponent:
    name: str
    version: str
    ecosystem: str  # "PyPI" or "npm"
    purl: str
    is_direct: bool
    depth: int  # 0 = direct dependency, 1 = transitive of a direct dep, etc.
    dependents: list[str] = field(default_factory=list)  # who requires this component


@dataclass
class SBOMResult:
    target_name: str
    ecosystem: str
    bom: dict
    components: list[SBOMComponent]
    completeness: dict


# --------------------------------------------------------------------------
# Python ecosystem (requirements.txt) via cyclonedx-py
# --------------------------------------------------------------------------

def _find_cyclonedx_py() -> str:
    """Locate the cyclonedx-py executable (handles PATH not being updated
    after a user-scheme pip install, which is common in CI containers)."""
    candidates = [
        "cyclonedx-py",
        str(Path.home() / ".local" / "bin" / "cyclonedx-py"),
        "/usr/local/bin/cyclonedx-py",
    ]
    for c in candidates:
        try:
            subprocess.run([c, "--version"], capture_output=True, check=True)
            return c
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    raise RuntimeError(
        "cyclonedx-py not found. Install with: pip install cyclonedx-bom"
    )


def generate_python_sbom(target_dir: Path, output_path: Path) -> SBOMResult:
    req_file = target_dir / "requirements.txt"
    if not req_file.exists():
        raise FileNotFoundError(f"No requirements.txt found in {target_dir}")

    tool = _find_cyclonedx_py()
    cmd = [tool, "requirements", "-o", str(output_path), str(req_file)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"cyclonedx-py failed: {proc.stderr}")

    bom = json.loads(output_path.read_text())

    # requirements.txt has no transitive resolution information, so every
    # component it lists is treated as "direct" (depth 0). This is itself an
    # accuracy finding worth reporting: pip requirements files alone cannot
    # produce a fully transitive SBOM without an installed environment or a
    # lock file (e.g. pip-compile / poetry.lock / Pipfile.lock).
    declared = _parse_requirements_txt(req_file)
    components = []
    for c in bom.get("components", []):
        name = c["name"]
        version = c.get("version", "")
        components.append(
            SBOMComponent(
                name=name,
                version=version,
                ecosystem="PyPI",
                purl=c.get("purl", f"pkg:pypi/{name}@{version}"),
                is_direct=name.lower() in declared,
                depth=0,
            )
        )

    completeness = _score_completeness(
        declared=declared,
        sbom_names={c.name.lower() for c in components},
        transitive_available=False,
    )

    return SBOMResult(
        target_name=target_dir.name,
        ecosystem="PyPI",
        bom=bom,
        components=components,
        completeness=completeness,
    )


def _parse_requirements_txt(path: Path) -> set[str]:
    """Extracts declared package names from a requirements.txt, tolerating
    the messier real-world syntax seen in production repos: inline `#`
    comments, extras (`celery[sqs]`), environment markers (`; python>=3.9`),
    and `-r other.txt` / `-e .` lines (skipped, not a package name)."""
    names = set()
    for raw_line in path.read_text().splitlines():
        stripped_for_vcs = raw_line.strip()
        if stripped_for_vcs.startswith(("git+", "hg+", "svn+", "bzr+")) and "#egg=" in stripped_for_vcs:
            # VCS requirement, e.g. git+https://.../repo.git@rev#egg=package-name
            names.add(stripped_for_vcs.split("#egg=", 1)[1].strip().lower())
            continue

        line = raw_line.split("#", 1)[0].strip()  # drop inline/trailing comments
        if not line or line.startswith(("-r ", "-e ", "--")):
            continue
        line = line.split(";", 1)[0].strip()  # drop environment markers
        if "[" in line:
            line = line.split("[", 1)[0]  # drop extras, e.g. celery[sqs] -> celery
        for sep in ("===", "==", ">=", "<=", "~=", ">", "<", "!="):
            if sep in line:
                line = line.split(sep)[0]
                break
        name = line.strip().lower()
        if name:
            names.add(name)
    return names


# --------------------------------------------------------------------------
# Node.js ecosystem (package-lock.json) - custom CycloneDX emitter
# --------------------------------------------------------------------------

def generate_node_sbom(target_dir: Path, output_path: Path) -> SBOMResult:
    lock_file = target_dir / "package-lock.json"
    pkg_file = target_dir / "package.json"
    if not lock_file.exists():
        raise FileNotFoundError(
            f"No package-lock.json found in {target_dir}. Run `npm install` "
            "first so the pipeline can resolve the full transitive tree."
        )

    lock = json.loads(lock_file.read_text())
    pkg = json.loads(pkg_file.read_text()) if pkg_file.exists() else {}
    declared_direct = set((pkg.get("dependencies", {}) or {}).keys()) | set(
        (pkg.get("devDependencies", {}) or {}).keys()
    )

    packages = lock.get("packages")
    if packages is None:
        raise ValueError("Unsupported lockfile format (expected lockfileVersion >= 2)")

    # Build a name -> node_modules path lookup and a dependency graph so we
    # can compute direct vs. transitive depth, matching what a real SBOM
    # tool derives from the resolved install tree.
    entries = {}  # path -> info
    for path, info in packages.items():
        if path == "":
            continue
        name = path.split("node_modules/")[-1]
        entries[path] = {"name": name, **info}

    name_to_paths: dict[str, list[str]] = {}
    for path, info in entries.items():
        name_to_paths.setdefault(info["name"], []).append(path)

    # BFS from root to compute depth + direct/transitive + "required by" edges
    depth_of: dict[str, int] = {}
    dependents: dict[str, set[str]] = {}
    root_deps = (packages.get("", {}) or {}).get("dependencies", {}) or {}

    frontier = []
    for dep_name in root_deps:
        for path in name_to_paths.get(dep_name, []):
            depth_of[path] = 0
            frontier.append(path)

    visited = set(frontier)
    while frontier:
        nxt = []
        for path in frontier:
            info = entries[path]
            for child_name in (info.get("dependencies", {}) or {}).keys():
                for child_path in name_to_paths.get(child_name, []):
                    dependents.setdefault(child_path, set()).add(info["name"])
                    if child_path not in visited:
                        depth_of[child_path] = depth_of[path] + 1
                        visited.add(child_path)
                        nxt.append(child_path)
        frontier = nxt

    components = []
    bom_components_json = []
    for path, info in entries.items():
        name = info["name"]
        version = info.get("version", "0.0.0")
        purl = f"pkg:npm/{name.replace('@', '%40') if name.startswith('@') else name}@{version}"
        depth = depth_of.get(path, -1)  # -1 = unreachable from declared deps (e.g. dev-only)
        is_direct = depth == 0
        components.append(
            SBOMComponent(
                name=name,
                version=version,
                ecosystem="npm",
                purl=purl,
                is_direct=is_direct,
                depth=depth if depth >= 0 else 0,
                dependents=sorted(dependents.get(path, set())),
            )
        )
        bom_components_json.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
                "scope": "required" if depth != -1 else "optional",
                "properties": [
                    {"name": "pipeline:depth", "value": str(max(depth, 0))},
                    {"name": "pipeline:direct", "value": str(is_direct).lower()},
                ],
            }
        )

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{_deterministic_uuid(target_dir.name)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": pkg.get("name", target_dir.name),
                "version": pkg.get("version", "0.0.0"),
            }
        },
        "components": bom_components_json,
    }
    output_path.write_text(json.dumps(bom, indent=2))

    completeness = _score_completeness(
        declared=set(n.lower() for n in declared_direct),
        sbom_names={c.name.lower() for c in components if c.is_direct},
        transitive_available=True,
        total_lockfile_entries=len(entries),
        total_sbom_entries=len(components),
    )

    return SBOMResult(
        target_name=target_dir.name,
        ecosystem="npm",
        bom=bom,
        components=components,
        completeness=completeness,
    )


def _deterministic_uuid(seed: str) -> str:
    import hashlib

    h = hashlib.sha1(seed.encode()).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _score_completeness(
    declared: set[str],
    sbom_names: set[str],
    transitive_available: bool,
    total_lockfile_entries: Optional[int] = None,
    total_sbom_entries: Optional[int] = None,
) -> dict:
    missing = declared - sbom_names
    extra = sbom_names - declared
    matched = declared & sbom_names
    precision = len(matched) / len(sbom_names) if sbom_names else 0.0
    recall = len(matched) / len(declared) if declared else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    result = {
        "declared_direct_dependencies": len(declared),
        "sbom_direct_components_matched": len(matched),
        "missing_from_sbom": sorted(missing),
        "unexpected_in_sbom": sorted(extra),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "transitive_dependencies_resolved": transitive_available,
    }
    if total_lockfile_entries is not None:
        result["total_lockfile_entries"] = total_lockfile_entries
        result["total_sbom_entries"] = total_sbom_entries
        result["transitive_capture_ratio"] = round(
            (total_sbom_entries / total_lockfile_entries) if total_lockfile_entries else 0.0, 4
        )
    return result


# --------------------------------------------------------------------------
# CLI entry point
# --------------------------------------------------------------------------

def generate_sbom_for_target(target_dir: Path, results_dir: Path) -> SBOMResult:
    results_dir.mkdir(parents=True, exist_ok=True)
    output_path = results_dir / f"sbom-{target_dir.name}.json"
    if (target_dir / "requirements.txt").exists():
        return generate_python_sbom(target_dir, output_path)
    if (target_dir / "package.json").exists():
        return generate_node_sbom(target_dir, output_path)
    raise ValueError(f"Unrecognised target ecosystem in {target_dir}")


if __name__ == "__main__":
    target = Path(sys.argv[1])
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("results")
    res = generate_sbom_for_target(target, out_dir)
    print(json.dumps({"target": res.target_name, "ecosystem": res.ecosystem,
                       "num_components": len(res.components),
                       "completeness": res.completeness}, indent=2))
