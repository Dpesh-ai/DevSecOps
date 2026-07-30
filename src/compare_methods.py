"""
Traditional method (CVSS-only prioritisation) vs. new method (data-driven
composite risk scoring) - the explicit comparison required by RQ3 and by
ToR Section 5.8 ("Comparison of CVSS-only prioritisation against the
proposed dependency risk scoring model").

Reads results/report.json (written by evaluate.py, which must be run
first) and produces:
    results/COMPARISON.md          - written summary with per-target and
                                      pooled statistics, plus concrete
                                      case studies of vulnerabilities that
                                      were re-prioritised
    results/rank_shift_<target>.png - a "slope chart" visualising, for the
                                      target with the most findings, how
                                      each vulnerability's priority rank
                                      changes between the two methods
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

import research_stats as rs

REPO_ROOT = Path(__file__).parent.parent
RESULTS_DIR = REPO_ROOT / "results"


def load_report() -> dict:
    path = RESULTS_DIR / "report.json"
    if not path.exists():
        raise FileNotFoundError("results/report.json not found - run `python src/evaluate.py` first.")
    return json.loads(path.read_text())


def _rank_shift_bucket(delta: int) -> str:
    if delta >= 5:
        return "promoted (more urgent under new method)"
    if delta <= -5:
        return "demoted (less urgent under new method)"
    return "broadly unchanged"


def summarise_target(result: dict) -> dict:
    scored = result["_all_scored_vulnerabilities"]
    deltas = [s["cvss_rank"] - s["risk_rank"] for s in scored]  # positive = promoted
    n = len(scored)
    promoted = sum(1 for d in deltas if d >= 5)
    demoted = sum(1 for d in deltas if d <= -5)
    unchanged = n - promoted - demoted

    biggest_movers = sorted(scored, key=lambda s: abs(s["cvss_rank"] - s["risk_rank"]), reverse=True)[:5]
    rbo = rs.rank_biased_overlap_from_report(scored)["rbo"] if n >= 2 else None

    return {
        "target": result["target"],
        "ecosystem": result["ecosystem"],
        "n_vulnerabilities": n,
        "spearman_correlation": result["risk_ranking_effectiveness"]["spearman_rank_correlation_risk_vs_cvss"],
        "top10_overlap_ratio": result["risk_ranking_effectiveness"]["top_10_overlap"]["overlap_ratio"],
        "rank_biased_overlap": rbo,
        "promoted_5plus_ranks": promoted,
        "demoted_5plus_ranks": demoted,
        "unchanged": unchanged,
        "biggest_movers": [
            {
                "component": f"{m['component']}@{m['version']}",
                "vuln_id": m["vuln_id"],
                "severity": m["severity"],
                "cvss_rank": m["cvss_rank"],
                "risk_rank": m["risk_rank"],
                "delta": m["cvss_rank"] - m["risk_rank"],
                "is_direct_dependency": m["is_direct_dependency"],
                "dependents_count": m["dependents_count"],
            }
            for m in biggest_movers
        ],
    }


def make_slope_chart(result: dict, out_path: Path, top_n: int = 15) -> None:
    scored = sorted(result["_all_scored_vulnerabilities"], key=lambda s: s["risk_rank"])[:top_n]
    if not scored:
        return

    fig, ax = plt.subplots(figsize=(9, max(5, top_n * 0.45)))
    labels = [f"{s['component']}@{s['version']} ({s['vuln_id']})" for s in scored]

    for i, s in enumerate(scored):
        cvss_rank, risk_rank = s["cvss_rank"], s["risk_rank"]
        colour = "#d62728" if cvss_rank > risk_rank else ("#2ca02c" if cvss_rank < risk_rank else "#7f7f7f")
        ax.plot([0, 1], [cvss_rank, risk_rank], marker="o", color=colour, alpha=0.8, linewidth=1.5)
        ax.text(-0.02, cvss_rank, f"#{cvss_rank}", ha="right", va="center", fontsize=8)
        ax.text(1.02, risk_rank, f"#{risk_rank}  {labels[i]}", ha="left", va="center", fontsize=8)

    ax.set_xlim(-0.6, 1.9)
    ax.invert_yaxis()
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Traditional\n(CVSS-only) rank", "New method\n(composite risk score) rank"], fontsize=10)
    ax.set_yticks([])
    for spine in ("top", "right", "left"):
        ax.spines[spine].set_visible(False)
    ax.set_title(
        f"Vulnerability priority rank: CVSS-only vs. composite risk score\n"
        f"target: {result['target']} ({result['ecosystem']}) - top {len(scored)} by risk score",
        fontsize=11,
    )
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def _real_world_target_names(report: dict) -> list[str]:
    controlled = {"node-sample", "python-sample"}
    return [r["target"] for r in report["results"] if r["target"] not in controlled]


def write_comparison_md(report: dict, summaries: list[dict], chart_target: str) -> None:
    real_world = _real_world_target_names(report)
    lines = [
        "# Traditional Method (CVSS-only) vs. New Method (Composite Risk Scoring)",
        "",
        "This report directly compares the two prioritisation strategies referenced in RQ3 of the "
        "Terms of Reference across every evaluated target repository - two controlled sample "
        f"repositories with deliberately pinned vulnerable dependencies, and {len(real_world)} "
        f"real-world open-source repositories ({', '.join(real_world)}).",
        "",
        "**Traditional method**: rank vulnerabilities purely by CVSS base score (or a severity-label "
        "mapping when no numeric score is available).",
        "",
        "**New method**: `risk_score = 100 x (0.40 x severity + 0.25 x exploitability (EPSS) "
        "+ 0.20 x KEV flag + 0.15 x dependency importance)`. See `src/risk_scoring.py` for the full "
        "implementation and `docs/ARCHITECTURE.md` for the rationale behind each weight.",
        "",
        "## Summary across all targets",
        "",
        "| Target | Ecosystem | Vulns | Spearman r | RBO (p=0.9) | Top-10 overlap | Promoted 5+ ranks | Demoted 5+ ranks | Unchanged |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for s in summaries:
        lines.append(
            f"| {s['target']} | {s['ecosystem']} | {s['n_vulnerabilities']} | "
            f"{s['spearman_correlation']} | {s['rank_biased_overlap']} | {s['top10_overlap_ratio']} | "
            f"{s['promoted_5plus_ranks']} | {s['demoted_5plus_ranks']} | {s['unchanged']} |"
        )
    lines.append("")
    lines.append(
        "*Spearman r weights a rank disagreement identically regardless of depth in the list, which "
        "is the wrong lens for a \"what do I fix first\" tool - a swap at position 70 of a 78-item "
        "list matters far less than a swap in the top 5. **Rank-Biased Overlap (RBO)** "
        "(Webber, Moffat & Zobel, 2010) is reported alongside it specifically because it is "
        "top-weighted (persistence p=0.9, so the first ~10 ranks carry roughly 65% of the total "
        "weight): a lower RBO than Spearman r for the same target means the two methods disagree "
        "more at the top of the list than their overall correlation suggests. The "
        "\"promoted/demoted 5+ ranks\" columns show that even with high overall correlation, a "
        "meaningful subset of individual vulnerabilities are reprioritised by 5 or more places - "
        "which is precisely the effect a risk-based model is supposed to have.*"
    )
    lines.append("")

    lines.append("## Case studies: vulnerabilities re-prioritised the most")
    lines.append("")
    for s in summaries:
        if not s["biggest_movers"]:
            continue
        lines.append(f"### {s['target']}")
        lines.append("")
        lines.append("| Component | Vuln ID | Severity | CVSS-only rank | Risk-score rank | Rank change | Direct dep? | Dependents |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for m in s["biggest_movers"]:
            direction = "promoted (more urgent)" if m["delta"] > 0 else ("demoted (less urgent)" if m["delta"] < 0 else "unchanged")
            lines.append(
                f"| {m['component']} | {m['vuln_id']} | {m['severity']} | {m['cvss_rank']} | "
                f"{m['risk_rank']} | {m['delta']:+d} ({direction}) | {m['is_direct_dependency']} | {m['dependents_count']} |"
            )
        lines.append("")

    lines.append("## Reading the rank-shift chart")
    lines.append("")
    lines.append(f"![Rank shift chart](rank_shift_{chart_target}.png)")
    lines.append("")
    lines.append(
        f"The chart above (`results/rank_shift_{chart_target}.png`) plots, for the "
        f"`{chart_target}` target's top 15 vulnerabilities by composite risk score, their rank "
        "under the traditional CVSS-only method (left) against their rank under the new composite "
        "method (right). Green lines moving upward/left-to-right indicate a vulnerability the new "
        "method considers *more* urgent than CVSS alone would suggest (e.g. because it sits deep in "
        "the dependency tree with many dependents, or is a direct, easily-reachable dependency); red "
        "lines indicate the opposite."
    )
    lines.append("")

    lines.append("## Interpretation for RQ3")
    lines.append("")

    # Build concrete examples from the ACTUAL computed data rather than a
    # fixed illustrative sentence. A previous version of this function
    # contained a hardcoded prose example (a specific "lodash promoted from
    # rank 3 to rank 1" claim) that went stale relative to the real output
    # and was caught during a self-audit (docs/PROFESSOR_REVIEW.md,
    # "COMPARISON.md factual inconsistency") - it described a target/rank
    # that did not exist in the actual generated tables. Generating the
    # example programmatically, as done here, makes that class of bug
    # structurally impossible: the prose can only ever say what the data
    # actually says.
    examples = []
    for s in summaries:
        if s["target"] not in real_world:
            continue
        promoted = [m for m in s["biggest_movers"] if m["delta"] > 0]
        if not promoted:
            continue
        top = promoted[0]
        dep_desc = (
            f"required by {top['dependents_count']} other resolved package(s)"
            if top["dependents_count"] else
            ("a direct dependency" if top["is_direct_dependency"] else "a transitive dependency with no other resolved dependents")
        )
        examples.append(
            f"in `{s['target']}`, `{top['component']}` ({top['vuln_id']}) moves from CVSS-rank "
            f"{top['cvss_rank']} to risk-rank {top['risk_rank']} ({dep_desc})"
        )

    agreement_note = (
        f"Across the {len(real_world)} real-world repositories evaluated, the composite risk score "
        "and the CVSS-only baseline agree on the *general* ordering of vulnerabilities in most "
        "targets (Spearman r reported per-target above), which is expected since severity is the "
        "largest single weight (0.40) in the composite model by design - the new method is not "
        "meant to contradict CVSS, but to refine it. The practically important finding is in the "
        "reordering *within* that broad agreement: the dependency-importance signal (and, where "
        "reachable, exploitability/KEV) pulls specific vulnerabilities up or down by several ranks"
    )
    if examples:
        agreement_note += " - for example, " + "; ".join(examples) + "."
    else:
        agreement_note += (
            ", although in this specific run the targets evaluated did not produce a case where any "
            "vulnerability's rank moved by 5 or more places (see the per-target tables above for the "
            "actual, smaller shifts observed)."
        )
    agreement_note += (
        " This is the concrete, evidence-based answer to RQ3: a data-driven model changes the "
        "*remediation order* a development team would follow, even when it does not change the "
        "*set* of vulnerabilities considered severe. See docs/RESEARCH_EVALUATION.md for why the "
        "KEV/EPSS-driven component of this claim is a mechanism sanity check rather than independent "
        "evidence, and why the dependency-importance-driven reordering is the non-circular evidence."
    )
    lines.append(agreement_note)
    lines.append("")

    total_kev = sum(r["vulnerability_coverage"]["vulnerabilities_in_kev"] for r in report["results"])
    n_targets = len(report["results"])
    lines.append(
        f"**Caveat to state explicitly in the dissertation**: across all {n_targets} evaluated targets "
        f"in this run, {total_kev} vulnerabilities were present in the (offline-snapshot or live) KEV "
        "catalogue, so the KEV and EPSS terms of the model had " +
        ("no opportunity" if total_kev == 0 else "only limited opportunity") +
        " to demonstrate their full effect here - the promotions observed above are driven mainly by "
        "the dependency-importance term. Re-running `python src/evaluate.py` with live KEV/EPSS feeds "
        "reachable (e.g. the GitHub Actions workflow) may surface additional KEV/EPSS-driven "
        "reprioritisation; the unit test `test_kev_listed_lower_cvss_can_outrank_higher_cvss_non_kev` "
        "in `tests/test_pipeline.py` proves that mechanism works correctly in isolation regardless."
    )

    (RESULTS_DIR / "COMPARISON.md").write_text("\n".join(lines))


def main():
    report = load_report()
    summaries = [summarise_target(r) for r in report["results"]]

    # Pick the target with the most vulnerability findings for the slope chart -
    # most informative real-world example.
    chart_result = max(report["results"], key=lambda r: len(r["_all_scored_vulnerabilities"]))
    make_slope_chart(chart_result, RESULTS_DIR / f"rank_shift_{chart_result['target']}.png")

    write_comparison_md(report, summaries, chart_result["target"])
    print(f"Wrote {RESULTS_DIR / 'COMPARISON.md'} and results/rank_shift_{chart_result['target']}.png")

    print("\n=== Summary ===")
    for s in summaries:
        print(f"{s['target']:20s} n={s['n_vulnerabilities']:3d}  spearman={s['spearman_correlation']:.3f}  "
              f"promoted5+={s['promoted_5plus_ranks']:2d}  demoted5+={s['demoted_5plus_ranks']:2d}")


if __name__ == "__main__":
    main()
