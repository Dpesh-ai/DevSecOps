"""
End-to-end orchestrator for the SBOM-first DevSecOps pipeline prototype.

Runs every stage described in the Terms of Reference (SBOM generation ->
vulnerability mapping -> KEV/EPSS enrichment -> risk scoring -> cryptographic
signing & tamper-detection experiments) against each configured target
repository, then computes the full set of evaluation metrics from ToR
Sections 5.8/6.1 and writes:

    results/report.json   - machine-readable, full detail
    results/REPORT.md      - human-readable summary for the dissertation

This is the script the GitHub Actions workflow calls, and the same script
a reviewer runs locally to reproduce the results end to end.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).parent))

from sbom_generate import generate_python_sbom, generate_node_sbom
from vuln_mapper import (
    map_python_vulnerabilities,
    map_node_vulnerabilities,
    cross_reference_kev,
    enrich_with_epss,
    enrich_with_nvd,
    compute_detection_coverage,
    records_to_json,
)
import os
from risk_scoring import (
    RiskWeights,
    score_vulnerabilities,
    evaluate_ranking_effectiveness,
    scored_to_json,
)
from sign_provenance import run_tamper_experiment
from build_validate import validate_target

REPO_ROOT = Path(__file__).parent.parent
TARGETS_DIR = REPO_ROOT / "targets"
RESULTS_DIR = REPO_ROOT / "results"
BUILD_VALIDATION_CACHE = RESULTS_DIR / "_build_validation_cache.json"


def _cross_check_python_sbom_against_pip(sbom_result, build_result: dict) -> Optional[dict]:
    """Independent SBOM-completeness oracle for Python targets.

    The precision/recall reported by sbom_generate.py's `_score_completeness`
    compares the generated SBOM against this project's OWN
    `_parse_requirements_txt` parser - both derived from the same source
    file by two parsers that will agree almost by definition on well-formed
    input, so that metric measures parser agreement, not real-world SBOM
    accuracy (flagged in docs/PROFESSOR_REVIEW.md, "SBOM completeness metric
    circularity"). pip's own dependency resolver, invoked independently in
    the build-validation stage (src/build_validate.py), is a genuinely
    different code path - it does full, real resolution of the manifest,
    not a name-extraction parse - so cross-checking the SBOM's component set
    against pip's resolved package list is an actually independent check."""
    if sbom_result.ecosystem != "PyPI":
        return None
    resolved_names = build_result.get("resolved_package_names")
    if not resolved_names:
        return {
            "available": False,
            "reason": "pip --report structured install list not available for this run "
                      "(older pip, or build validation did not succeed)",
        }
    resolved_lower = {n.lower() for n in resolved_names}
    sbom_lower = {c.name.lower() for c in sbom_result.components}
    matched = sbom_lower & resolved_lower
    missing_from_sbom = sorted(resolved_lower - sbom_lower)
    return {
        "available": True,
        "pip_resolved_package_count": len(resolved_lower),
        "sbom_component_count": len(sbom_lower),
        "matched": len(matched),
        "recall_vs_independent_pip_resolution": (
            round(len(matched) / len(resolved_lower), 4) if resolved_lower else None
        ),
        "present_in_pip_resolution_but_missing_from_sbom": missing_from_sbom,
    }


def _cached_build_validation(target_dir: Path) -> dict:
    """Build validation (pip/npm dependency resolution) is the slowest single
    step in the pipeline for some targets (e.g. a target with a native-extension
    dependency that fails partway through a real compile attempt). It is also
    the least likely result to change between runs of the same target, so it
    is cached to its own small file, populated by `evaluate.py --build-validate-only
    <name>` calls, rather than being re-run inline every time the rest of the
    pipeline runs."""
    cache = json.loads(BUILD_VALIDATION_CACHE.read_text()) if BUILD_VALIDATION_CACHE.exists() else {}
    if target_dir.name in cache:
        return cache[target_dir.name]
    result = validate_target(target_dir)
    cache[target_dir.name] = result
    BUILD_VALIDATION_CACHE.write_text(json.dumps(cache, indent=2, default=str))
    return result


def run_target(target_dir: Path) -> dict:
    print(f"\n=== Processing target: {target_dir.name} ===")
    t0 = time.perf_counter()

    # Stage 0: build validation (FR11) - can this target's dependency set
    # actually be resolved/installed by the real package manager? -------
    build_result = _cached_build_validation(target_dir)
    print(f"  Build validation: buildable={build_result['buildable']} ({build_result.get('method')}) "
          f"- {build_result['detail']}")

    # Stage 1: SBOM generation -----------------------------------------
    if (target_dir / "requirements.txt").exists():
        sbom_result = generate_python_sbom(target_dir, RESULTS_DIR / f"sbom-{target_dir.name}.json")
    elif (target_dir / "package.json").exists():
        sbom_result = generate_node_sbom(target_dir, RESULTS_DIR / f"sbom-{target_dir.name}.json")
    else:
        raise ValueError(f"Unrecognised ecosystem for {target_dir}")
    sbom_duration = time.perf_counter() - t0
    print(f"  SBOM: {len(sbom_result.components)} components "
          f"(ecosystem={sbom_result.ecosystem}, f1={sbom_result.completeness['f1_score']})")

    # Stage 2: vulnerability mapping ------------------------------------
    t1 = time.perf_counter()
    python_vuln_source = None
    if sbom_result.ecosystem == "PyPI":
        records, python_vuln_source = map_python_vulnerabilities(sbom_result.components)
    else:
        comps_by_name = {c.name: c for c in sbom_result.components}
        records = map_node_vulnerabilities(target_dir, comps_by_name)
    vuln_duration = time.perf_counter() - t1
    print(f"  Vulnerabilities found: {len(records)}" +
          (f" (source: {python_vuln_source})" if python_vuln_source else ""))

    # Stage 2b: independent SBOM-completeness cross-check (Python only) - see
    # docs/PROFESSOR_REVIEW.md, "SBOM completeness metric circularity".
    sbom_independent_cross_check = _cross_check_python_sbom_against_pip(sbom_result, build_result)

    # Stage 3: KEV cross-reference + EPSS enrichment ---------------------
    kev_source = cross_reference_kev(records)
    epss_reachable = enrich_with_epss(records)
    print(f"  KEV source: {kev_source} | EPSS reachable: {epss_reachable}")

    # Stage 3b: NVD enrichment (optional, off by default - see vuln_mapper.py
    # module docstring for why: NVD's public API is rate-limited to 5
    # req/30s, which would make every run take minutes if done unconditionally.
    # Set ENABLE_NVD_ENRICHMENT=1 to exercise it (e.g. on an unrestricted
    # network with time to spare, or with an NVD API key configured).
    nvd_summary = {"attempted": 0, "enriched": 0, "reachable": None}
    if os.environ.get("ENABLE_NVD_ENRICHMENT") == "1":
        nvd_summary = enrich_with_nvd(records)
        print(f"  NVD enrichment: attempted={nvd_summary['attempted']} enriched={nvd_summary['enriched']}")

    coverage = compute_detection_coverage(sbom_result.components, records)

    # Stage 4: risk scoring -----------------------------------------------
    # Build "how many components depend on X" by inverting SBOMComponent.dependents
    dependents_lookup: dict[str, int] = {}
    for c in sbom_result.components:
        dependents_lookup.setdefault(c.name, 0)
    for c in sbom_result.components:
        for dependent_name in c.dependents:
            dependents_lookup[c.name] = dependents_lookup.get(c.name, 0) + 1

    scored = score_vulnerabilities(records, dependents_lookup, RiskWeights())
    ranking_eval = evaluate_ranking_effectiveness(scored)

    # Stage 5: cryptographic signing + tamper-detection experiment --------
    sbom_path = RESULTS_DIR / f"sbom-{target_dir.name}.json"
    tamper_report = run_tamper_experiment(
        sbom_path,
        {"repository": f"local/{target_dir.name}", "ref": "main"},
        n_runs=20,
    )

    total_duration = time.perf_counter() - t0

    return {
        "target": target_dir.name,
        "ecosystem": sbom_result.ecosystem,
        "build_validation": build_result,
        "sbom_completeness": sbom_result.completeness,
        "sbom_independent_cross_check": sbom_independent_cross_check,
        "vulnerability_coverage": coverage,
        "python_vuln_source": python_vuln_source,
        "kev_source": kev_source,
        "epss_reachable": epss_reachable,
        "nvd_enrichment": nvd_summary,
        "risk_ranking_effectiveness": ranking_eval,
        "signing_and_tamper_detection": tamper_report,
        "timings_seconds": {
            "sbom_generation": round(sbom_duration, 3),
            "vulnerability_mapping": round(vuln_duration, 3),
            "total": round(total_duration, 3),
        },
        "top_10_risk_ranked_vulnerabilities": scored_to_json(scored[:10]),
        "_all_scored_vulnerabilities": scored_to_json(scored),
        "_all_sbom_components": len(sbom_result.components),
        # Raw vulnerability records (source, summary, fixed_in, aliases) are kept
        # alongside the scored/ranked view above - the ScoredVulnerability dataclass
        # drops these fields, but they're useful supporting evidence (e.g. for a
        # dissertation appendix) and cost nothing extra to compute, since records
        # were already produced by Stage 2.
        "_all_vulnerability_records": records_to_json(records),
    }


PARTIAL_RESULTS_PATH = RESULTS_DIR / "_partial_results.json"


def _load_partial() -> dict:
    if PARTIAL_RESULTS_PATH.exists():
        return json.loads(PARTIAL_RESULTS_PATH.read_text())
    return {}


def _save_partial(partial: dict) -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    PARTIAL_RESULTS_PATH.write_text(json.dumps(partial, indent=2, default=str))


def main(only_target: str | None = None, finalize_only: bool = False):
    RESULTS_DIR.mkdir(exist_ok=True)
    targets = sorted(p for p in TARGETS_DIR.iterdir() if p.is_dir())

    if not finalize_only:
        partial = _load_partial()
        run_list = [t for t in targets if t.name == only_target] if only_target else targets
        for t in run_list:
            partial[t.name] = run_target(t)
            _save_partial(partial)
    else:
        partial = _load_partial()

    missing = [t.name for t in targets if t.name not in partial]
    if missing:
        print(f"\nNot finalising yet - still missing results for: {missing}")
        print("Run again with --target <name> for each missing target, then --finalize.")
        return

    all_results = [partial[t.name] for t in targets]

    report = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "targets_evaluated": len(all_results),
        "results": all_results,
    }
    (RESULTS_DIR / "report.json").write_text(json.dumps(report, indent=2, default=str))
    write_markdown_summary(report)
    print(f"\nWrote {RESULTS_DIR / 'report.json'} and {RESULTS_DIR / 'REPORT.md'}")

    try:
        import compare_methods
        compare_methods.main()
    except Exception as e:  # noqa: BLE001 - comparison report is a bonus, not fatal
        print(f"WARNING: could not generate results/COMPARISON.md: {e}")

    try:
        import research_evaluation
        research_evaluation.main()
    except Exception as e:  # noqa: BLE001 - statistical report is a bonus, not fatal
        print(f"WARNING: could not generate results/RESEARCH_EVALUATION.md: {e}")


def write_markdown_summary(report: dict) -> None:
    lines = ["# SBOM-first DevSecOps Pipeline - Evaluation Report", ""]
    lines.append(f"Generated: {report['generated_at']}  ")
    lines.append(f"Targets evaluated: {report['targets_evaluated']}")
    lines.append("")

    for r in report["results"]:
        lines.append(f"## Target: `{r['target']}` ({r['ecosystem']})")
        lines.append("")

        bv = r.get("build_validation", {})
        lines.append("**Build validation (FR11 - can this repository actually be built?)**")
        lines.append(f"- Buildable: {bv.get('buildable')} (method: `{bv.get('method')}`)")
        lines.append(f"- {bv.get('detail')}")
        lines.append("")
        c = r["sbom_completeness"]
        lines.append("**SBOM completeness/accuracy (RQ1)**")
        lines.append(f"- Precision: {c['precision']}, Recall: {c['recall']}, F1: {c['f1_score']} "
                      "(vs. this project's own manifest parser - see independent cross-check below)")
        if "transitive_capture_ratio" in c:
            lines.append(f"- Transitive dependency capture ratio: {c['transitive_capture_ratio']}")
        cross = r.get("sbom_independent_cross_check")
        if cross:
            if cross.get("available"):
                lines.append(
                    f"- **Independent cross-check vs. pip's own resolver**: "
                    f"{cross['matched']}/{cross['pip_resolved_package_count']} pip-resolved packages "
                    f"present in the SBOM (recall = {cross['recall_vs_independent_pip_resolution']})"
                )
                if cross["present_in_pip_resolution_but_missing_from_sbom"]:
                    lines.append(
                        f"  - Missing from SBOM but resolved by pip: "
                        f"{', '.join(cross['present_in_pip_resolution_but_missing_from_sbom'][:10])}"
                    )
            else:
                lines.append(f"- Independent cross-check vs. pip's own resolver: not available ({cross['reason']})")
        lines.append("")

        cov = r["vulnerability_coverage"]
        lines.append("**Vulnerability detection coverage**")
        lines.append(f"- Components scanned: {cov['total_components_scanned']}")
        lines.append(f"- Components with known vulnerabilities: {cov['components_with_known_vulnerabilities']} "
                      f"({cov['component_vulnerability_rate']*100:.1f}%)")
        lines.append(f"- Unique vulnerabilities found: {cov['unique_vulnerabilities_found']}")
        lines.append(f"- By severity: {cov['vulnerabilities_by_severity']}")
        lines.append(f"- In CISA KEV: {cov['vulnerabilities_in_kev']} (source: {r['kev_source']})")
        if r.get("python_vuln_source"):
            lines.append(f"- Python vulnerability data source actually used this run: {r['python_vuln_source']}")
        lines.append("")

        rank = r["risk_ranking_effectiveness"]
        lines.append("**Risk scoring vs. CVSS-only baseline (RQ3)**")
        lines.append(f"- Spearman rank correlation: {rank['spearman_rank_correlation_risk_vs_cvss']}")
        lines.append(f"- Top-10 overlap ratio: {rank['top_10_overlap']['overlap_ratio']}")
        lines.append(f"- KEV-listed vulnerabilities: {rank['kev_listed_vulnerabilities']}")
        lines.append("")

        sign = r["signing_and_tamper_detection"]
        lines.append("**Cryptographic signing / provenance (RQ2)**")
        lines.append(f"- Tamper detection rate: {sign['tamper_detection_rate']*100:.1f}% over {sign['runs']} runs")
        lines.append(f"- Avg sign time: {sign['avg_sign_time_ms']} ms")
        lines.append(f"- Avg verify time: {sign['avg_verify_time_ms_untampered']} ms")
        lines.append(f"- Total signing overhead per artifact: {sign['total_signing_overhead_ms_per_artifact']} ms")
        lines.append("")

        lines.append("**Top 5 risk-ranked vulnerabilities**")
        lines.append("")
        lines.append("| Rank | Component | Vuln ID | Severity | Risk Score | CVSS-only Score | CVSS Rank |")
        lines.append("|---|---|---|---|---|---|---|")
        for v in r["top_10_risk_ranked_vulnerabilities"][:5]:
            lines.append(
                f"| {v['risk_rank']} | {v['component']}@{v['version']} | {v['vuln_id']} | "
                f"{v['severity']} | {v['risk_score']} | {v['cvss_only_score']} | {v['cvss_rank']} |"
            )
        lines.append("")

    (RESULTS_DIR / "REPORT.md").write_text("\n".join(lines))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", help="Run only this single target (results are cached and merged incrementally)")
    parser.add_argument("--finalize", action="store_true",
                         help="Skip running targets; just combine already-cached partial results into the final report")
    parser.add_argument("--build-validate-only", metavar="TARGET_NAME",
                         help="Only populate the build-validation cache for this target, then exit")
    args = parser.parse_args()

    if args.build_validate_only:
        target_path = TARGETS_DIR / args.build_validate_only
        result = _cached_build_validation(target_path)
        print(json.dumps(result, indent=2))
    else:
        main(only_target=args.target, finalize_only=args.finalize)
