"""
Tests for src/compare_methods.py and src/research_evaluation.py - the
report-generation and statistical-orchestration layers.

These previously had zero direct test coverage (flagged during a
professor-style self-audit, see docs/PROFESSOR_REVIEW.md, "no test coverage
for prose-generation code"), which is exactly where a real defect went
undetected: compare_methods.py's "Interpretation for RQ3" section contained
a hardcoded, stale illustrative prose example (a specific component/target/
rank claim) that no longer matched the actual computed data. These tests
exist specifically to make that class of bug structurally harder to
reintroduce, and to give the statistical-orchestration layer basic
regression coverage.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import compare_methods
import research_evaluation


def _make_scored(component, vuln_id, severity, cvss_rank, risk_rank, is_direct, dependents_count,
                  cvss_score=7.0, risk_score=70.0, in_kev=False, epss_score=None):
    return {
        "component": component, "version": "1.0.0", "ecosystem": "npm", "vuln_id": vuln_id,
        "primary_cve": f"CVE-2024-{abs(hash(vuln_id)) % 9999:04d}", "severity": severity,
        "cvss_score": cvss_score, "in_kev": in_kev, "epss_score": epss_score,
        "is_direct_dependency": is_direct, "dependents_count": dependents_count,
        "cvss_only_score": cvss_score, "risk_score": risk_score,
        "risk_rank": risk_rank, "cvss_rank": cvss_rank,
    }


def _make_target_result(name, ecosystem, scored):
    return {
        "target": name, "ecosystem": ecosystem,
        "_all_scored_vulnerabilities": scored,
        "risk_ranking_effectiveness": {
            "spearman_rank_correlation_risk_vs_cvss": 0.9,
            "top_10_overlap": {"overlap_ratio": 0.8},
        },
        "vulnerability_coverage": {"vulnerabilities_in_kev": sum(1 for s in scored if s["in_kev"])},
        "signing_and_tamper_detection": {"tamper_detection_rate": 1.0, "runs": 20},
    }


def test_summarise_target_computes_promoted_and_demoted_from_actual_data():
    # cvss_rank and risk_rank must each be a dense permutation of 1..n across
    # all items (as they always are in real report.json output, since
    # risk_scoring.score_vulnerabilities ranks the full set both ways) -
    # otherwise rank_biased_overlap's positional bookkeeping breaks. n=8 here.
    scored = [
        _make_scored("pkg-promoted", "GHSA-1", "HIGH", cvss_rank=8, risk_rank=1, is_direct=False, dependents_count=12),
        _make_scored("pkg-demoted", "GHSA-2", "LOW", cvss_rank=1, risk_rank=8, is_direct=False, dependents_count=0),
        *[_make_scored(f"pkg{i}", f"GHSA-{i}", "MEDIUM", cvss_rank=i, risk_rank=i, is_direct=True, dependents_count=0)
          for i in range(2, 8)],
    ]
    result = _make_target_result("demo-target", "npm", scored)
    summary = compare_methods.summarise_target(result)

    assert summary["promoted_5plus_ranks"] == 1
    assert summary["demoted_5plus_ranks"] == 1
    top_mover = summary["biggest_movers"][0]
    assert top_mover["component"] == "pkg-promoted@1.0.0"
    assert top_mover["delta"] == 7  # cvss_rank(8) - risk_rank(1)


def test_write_comparison_md_example_reflects_actual_biggest_mover(tmp_path, monkeypatch):
    """Regression test for the specific bug found during the professor-style
    review: the 'Interpretation for RQ3' section used to contain a fixed,
    hardcoded prose example (a specific component/target/rank claim) that
    did not match the real generated tables. Asserts the generated
    markdown's example is actually consistent with the input data."""
    monkeypatch.setattr(compare_methods, "RESULTS_DIR", tmp_path)

    # 7 items total; cvss_rank and risk_rank must each be a dense permutation
    # of 1..7. real-mover takes cvss_rank=6/risk_rank=1; the other six items
    # take the remaining cvss ranks {1,2,3,4,5,7} and risk ranks {2,3,4,5,6,7}
    # (order between the two doesn't matter for this test).
    other_cvss_ranks = [1, 2, 3, 4, 5, 7]
    other_risk_ranks = [2, 3, 4, 5, 6, 7]
    scored = [
        _make_scored("real-mover", "GHSA-9", "HIGH", cvss_rank=6, risk_rank=1, is_direct=False, dependents_count=20),
        *[
            _make_scored(f"pkg{i}", f"GHSA-{i}", "MEDIUM", cvss_rank=other_cvss_ranks[i], risk_rank=other_risk_ranks[i],
                         is_direct=True, dependents_count=0)
            for i in range(6)
        ],
    ]
    report = {"results": [_make_target_result("only-real-world-target", "npm", scored)]}
    summaries = [compare_methods.summarise_target(r) for r in report["results"]]

    compare_methods.write_comparison_md(report, summaries, "only-real-world-target")
    text = (tmp_path / "COMPARISON.md").read_text()

    # The example must cite the actual mover from the actual target, with
    # the actual ranks - not a hardcoded, potentially stale claim.
    assert "real-mover" in text
    assert "only-real-world-target" in text
    assert "CVSS-rank 6 to risk-rank 1" in text
    # Must not contain the specific historical hardcoded example that
    # triggered this test's existence in the first place.
    assert "lodash" not in text


def test_research_evaluation_analyse_target_includes_new_statistics():
    scored = [
        _make_scored(f"pkg{i}", f"GHSA-{i}", "HIGH", cvss_rank=i, risk_rank=((i % 10) + 1),
                     is_direct=True, dependents_count=0)
        for i in range(1, 11)
    ]
    result = _make_target_result("stats-target", "npm", scored)
    analysis = research_evaluation.analyse_target(result)

    assert "rbo" in analysis and analysis["rbo"]["rbo"] is not None
    assert "wilcoxon_rank_shift" in analysis
    assert "weight_sensitivity" in analysis
    assert analysis["weight_sensitivity"]["mean_spearman_vs_chosen_weights"] is not None
