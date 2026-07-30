"""
Unit tests for the statistical rigor layer (src/research_stats.py). These
exist independently of tests/test_pipeline.py because they test pure
statistical logic against hand-computable expected values, not the SBOM/
vulnerability-mapping pipeline itself.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

import research_stats as rs


def _fake_scored(n, cvss_ranks=None, risk_ranks=None, cvss_scores=None, risk_scores=None):
    """Builds minimal scored-vulnerability dicts, as they'd appear flattened
    inside results/report.json, for testing statistics in isolation."""
    cvss_ranks = cvss_ranks or list(range(1, n + 1))
    risk_ranks = risk_ranks or list(range(1, n + 1))
    cvss_scores = cvss_scores or [10 - r for r in cvss_ranks]
    risk_scores = risk_scores or [100 - r for r in risk_ranks]
    return [
        {
            "component": f"pkg{i}", "version": "1.0.0", "vuln_id": f"V{i}",
            "severity": "HIGH", "cvss_score": cvss_scores[i], "in_kev": False,
            "epss_score": None, "is_direct_dependency": True, "dependents_count": 0,
            "cvss_only_score": cvss_scores[i], "risk_score": risk_scores[i],
            "risk_rank": risk_ranks[i], "cvss_rank": cvss_ranks[i], "primary_cve": f"CVE-2024-{i:04d}",
        }
        for i in range(n)
    ]


def test_kendall_tau_perfect_agreement():
    scored = _fake_scored(10)  # identical ranks both ways
    result = rs.kendall_tau(scored)
    assert result["tau"] == 1.0


def test_kendall_tau_perfect_disagreement():
    n = 10
    scored = _fake_scored(n, cvss_ranks=list(range(1, n + 1)), risk_ranks=list(range(n, 0, -1)))
    result = rs.kendall_tau(scored)
    assert result["tau"] == -1.0


def test_wilcoxon_detects_systematic_difference():
    # risk_score always exactly 20 points higher than cvss_only*10 -> should be
    # a clear, statistically significant systematic difference.
    n = 20
    scored = _fake_scored(n, cvss_scores=[5.0] * n, risk_scores=[70.0] * n)
    result = rs.wilcoxon_score_difference(scored)
    assert result["significant_at_0.05"] is True
    assert result["mean_score_difference"] > 0


def test_wilcoxon_too_small_sample_returns_note():
    scored = _fake_scored(3)
    result = rs.wilcoxon_score_difference(scored)
    assert result["p_value"] is None
    assert "note" in result


def test_wilson_ci_100_percent_over_few_trials_is_wide():
    """100% detection over only 5 trials should NOT be reported as a tight
    interval - Wilson's interval correctly reflects that uncertainty."""
    ci_small = rs.wilson_confidence_interval(successes=5, n=5)
    ci_large = rs.wilson_confidence_interval(successes=200, n=200)
    assert ci_small["lower"] < ci_large["lower"]  # more trials -> tighter, higher lower bound


def test_random_ranking_floor_is_near_zero():
    result = rs.random_ranking_floor(n=50, n_trials=300)
    assert abs(result["mean_spearman"]) < 0.15  # should hover around 0, not near +/-1


def test_ablation_full_model_always_agrees_with_itself():
    scored = _fake_scored(15, cvss_ranks=list(range(1, 16)), risk_ranks=[15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1])
    result = rs.ablation_study(scored)
    full_key = "full_model (0.40 sev / 0.25 epss / 0.20 kev / 0.15 importance)"
    assert result["variants"][full_key]["spearman_vs_full_model"] == 1.0


# --------------------------------------------------------------------------
# Rank-Biased Overlap (top-weighted ranking agreement)
# --------------------------------------------------------------------------

def test_rbo_identical_rankings_is_one():
    result = rs.rank_biased_overlap(list(range(1, 21)), list(range(1, 21)))
    assert result["rbo"] == 1.0


def test_rbo_lower_when_top_ranks_disagree_more_than_bottom():
    n = 20
    identical = list(range(1, n + 1))
    # Swap positions 1 and 2 only (top of the list) vs. swap positions 19
    # and 20 only (bottom of the list) - both are a single transposition, so
    # Spearman/Kendall treat them almost identically, but RBO (top-weighted)
    # should treat the top swap as a bigger disagreement.
    top_swap = identical.copy()
    top_swap[0], top_swap[1] = top_swap[1], top_swap[0]
    bottom_swap = identical.copy()
    bottom_swap[-1], bottom_swap[-2] = bottom_swap[-2], bottom_swap[-1]

    rbo_top_swap = rs.rank_biased_overlap(identical, top_swap)["rbo"]
    rbo_bottom_swap = rs.rank_biased_overlap(identical, bottom_swap)["rbo"]
    assert rbo_top_swap < rbo_bottom_swap


def test_rbo_from_report_wrapper_matches_direct_call():
    scored = _fake_scored(10)
    direct = rs.rank_biased_overlap(
        [d["risk_rank"] for d in scored], [d["cvss_rank"] for d in scored]
    )
    via_wrapper = rs.rank_biased_overlap_from_report(scored)
    assert direct == via_wrapper


# --------------------------------------------------------------------------
# Wilcoxon rank-shift test (primary RQ3 significance test)
# --------------------------------------------------------------------------

def test_wilcoxon_rank_shift_detects_systematic_reordering():
    n = 20
    # Every item shifts up by exactly 3 ranks under the new method - a clear,
    # systematic, non-zero reordering that should be detected regardless of
    # the two scoring formulas' different weight budgets (the scale artefact
    # that affects wilcoxon_score_difference does not apply here, since this
    # test operates purely on rank integers).
    cvss_ranks = list(range(1, n + 1))
    risk_ranks = [max(1, r - 3) for r in cvss_ranks]
    scored = _fake_scored(n, cvss_ranks=cvss_ranks, risk_ranks=risk_ranks)
    result = rs.wilcoxon_rank_shift(scored)
    assert result["p_value"] is not None
    assert result["mean_rank_shift"] != 0


def test_wilcoxon_rank_shift_no_shift_is_not_significant():
    scored = _fake_scored(10)  # identical ranks -> zero shift everywhere
    result = rs.wilcoxon_rank_shift(scored)
    assert result["p_value"] == 1.0
    assert "note" in result


def test_wilcoxon_rank_shift_always_includes_structural_caveat():
    """The signed rank-shift test is a diagnostic, not primary evidence (see
    docs/RESEARCH_EVALUATION.md) - every code path must carry the caveat
    explaining why, so it can never be silently cited without it."""
    for n in (3, 10):
        scored = _fake_scored(n)
        result = rs.wilcoxon_rank_shift(scored)
        assert "caveat" in result and "sum to exactly zero" in result["caveat"].lower()


# --------------------------------------------------------------------------
# Reordering magnitude (the actual primary evidence for RQ3, not subject to
# the zero-sum-by-construction constraint that limits the signed Wilcoxon
# rank-shift test's power)
# --------------------------------------------------------------------------

def test_reordering_magnitude_summary_detects_large_shifts():
    n = 10
    cvss_ranks = list(range(1, n + 1))
    risk_ranks = list(range(n, 0, -1))  # fully reversed -> maximum possible reordering
    scored = _fake_scored(n, cvss_ranks=cvss_ranks, risk_ranks=risk_ranks)
    result = rs.reordering_magnitude_summary(scored)
    assert result["mean_absolute_rank_shift"] > 0
    assert result["fraction_moved_5plus_ranks"] > 0


def test_reordering_magnitude_summary_zero_when_identical():
    scored = _fake_scored(10)
    result = rs.reordering_magnitude_summary(scored)
    assert result["mean_absolute_rank_shift"] == 0
    assert result["fraction_moved_5plus_ranks"] == 0


def test_reordering_magnitude_null_gives_a_reference_point():
    result = rs.reordering_magnitude_null(n=20, n_trials=200)
    # For two independent random permutations of n items, mean |shift| should
    # be a substantial fraction of n (order n/3), not near zero.
    assert result["mean_absolute_rank_shift_under_random_pairing"] > 3.0


# --------------------------------------------------------------------------
# Monte Carlo weight-sensitivity analysis
# --------------------------------------------------------------------------

def test_weight_sensitivity_analysis_returns_bounded_correlations():
    scored = _fake_scored(15, cvss_ranks=list(range(1, 16)), risk_ranks=list(range(1, 16)))
    result = rs.weight_sensitivity_analysis(scored, n_samples=50)
    assert -1.0 <= result["mean_spearman_vs_chosen_weights"] <= 1.0
    assert result["min_spearman_vs_chosen_weights"] <= result["mean_spearman_vs_chosen_weights"]
    assert 0.0 <= result["mean_top_k_overlap_vs_chosen_weights"] <= 1.0


def test_weight_sensitivity_analysis_too_few_vulnerabilities():
    scored = _fake_scored(2)
    result = rs.weight_sensitivity_analysis(scored)
    assert "note" in result


# --------------------------------------------------------------------------
# Bonferroni correction
# --------------------------------------------------------------------------

def test_bonferroni_correction_divides_alpha_by_n_tests():
    result = rs.bonferroni_correction([0.001, 0.002, 0.5, None], family_wise_alpha=0.05)
    assert result["n_tests"] == 3  # None excluded
    assert result["bonferroni_corrected_alpha"] == pytest.approx(0.05 / 3, abs=1e-5)
    assert result["n_significant_after_correction"] == 2  # 0.001 and 0.002 clear 0.0167, 0.5 does not


def test_bonferroni_correction_no_valid_p_values():
    result = rs.bonferroni_correction([None, None])
    assert result["n_tests"] == 0
    assert result["bonferroni_corrected_alpha"] is None
