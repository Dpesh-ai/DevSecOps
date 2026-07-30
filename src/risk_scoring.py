"""
Dependency risk scoring stage of the SBOM-first DevSecOps pipeline.

Implements the data-driven risk scoring model described in the Terms of
Reference (Stage 7): a composite score built from severity, exploitability,
KEV membership and dependency-relationship/package-importance signals - and
compares its ranking of vulnerabilities against a traditional CVSS-only
baseline. This directly answers RQ3:

    "Are data-driven dependency risk scoring models more effective compared
    to traditional severity-based models like CVSS scores in prioritising
    vulnerabilities?"

Model
-----
risk_score = 100 * clamp(
      W_SEVERITY   * severity_norm
    + W_EXPLOIT    * exploitability
    + W_KEV        * kev_flag
    + W_IMPORTANCE * importance
)

  severity_norm  : CVSS base score / 10, falling back to a severity-label
                   mapping when no numeric CVSS score is available.
  exploitability : EPSS probability (0-1) when reachable; otherwise a
                   documented severity-derived proxy (see NOTE below).
  kev_flag       : 1.0 if the CVE is in CISA's KEV catalogue, else 0.0.
  importance     : blast-radius / exposure signal - combines whether the
                   vulnerable package is a direct dependency with how many
                   other packages in the tree depend on it (reverse-degree
                   centrality), normalised to [0, 1].

Weights are configurable (see RiskWeights) so the sensitivity of the model
to each factor can be examined experimentally, as required by the
evaluation plan (Section 5.8 of the ToR).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, asdict
from typing import Optional

from vuln_mapper import VulnRecord

SEVERITY_NORM = {
    "CRITICAL": 0.95,
    "HIGH": 0.75,
    "MODERATE": 0.55,
    "MEDIUM": 0.55,
    "LOW": 0.30,
    "UNKNOWN": 0.45,
}


@dataclass
class RiskWeights:
    severity: float = 0.40
    exploitability: float = 0.25
    kev: float = 0.20
    importance: float = 0.15

    def validate(self):
        total = self.severity + self.exploitability + self.kev + self.importance
        if not math.isclose(total, 1.0, abs_tol=1e-6):
            raise ValueError(f"RiskWeights must sum to 1.0, got {total}")


@dataclass
class ScoredVulnerability:
    component: str
    version: str
    ecosystem: str
    vuln_id: str
    primary_cve: Optional[str]
    severity: str
    cvss_score: Optional[float]
    in_kev: bool
    epss_score: Optional[float]
    is_direct_dependency: bool
    dependents_count: int
    cvss_only_score: float
    risk_score: float
    risk_rank: int = 0
    cvss_rank: int = 0


def _severity_norm(rec: VulnRecord) -> float:
    if rec.cvss_score is not None:
        return max(0.0, min(rec.cvss_score / 10.0, 1.0))
    return SEVERITY_NORM.get(rec.severity.upper(), 0.45)


def _exploitability(rec: VulnRecord) -> float:
    if rec.epss_score is not None:
        return max(0.0, min(rec.epss_score, 1.0))
    # NOTE: EPSS (FIRST.org) is queried live where the network allows it.
    # When unreachable, exploitability falls back to a severity-derived
    # proxy. This is a documented approximation, not a claim that severity
    # equals exploitability - it exists so the model degrades gracefully
    # rather than silently zeroing out an entire scoring dimension.
    return {"CRITICAL": 0.5, "HIGH": 0.3, "MODERATE": 0.15, "MEDIUM": 0.15,
            "LOW": 0.05, "UNKNOWN": 0.1}.get(rec.severity.upper(), 0.1)


def _importance(rec: VulnRecord, dependents_count: int, max_dependents: int) -> float:
    direct_component = 0.5 if rec.is_direct_dependency else 0.0
    if max_dependents > 0:
        centrality = 0.5 * (dependents_count / max_dependents)
    else:
        centrality = 0.0
    return min(direct_component + centrality, 1.0)


def score_vulnerabilities(
    records: list[VulnRecord],
    dependents_lookup: dict[str, int],
    weights: RiskWeights = RiskWeights(),
) -> list[ScoredVulnerability]:
    weights.validate()
    max_dependents = max(dependents_lookup.values(), default=0)

    scored = []
    for r in records:
        sev = _severity_norm(r)
        expl = _exploitability(r)
        kev = 1.0 if r.in_kev else 0.0
        dep_count = dependents_lookup.get(r.component, 0)
        imp = _importance(r, dep_count, max_dependents)

        composite = (
            weights.severity * sev
            + weights.exploitability * expl
            + weights.kev * kev
            + weights.importance * imp
        )
        cvss_only = sev * 10.0  # baseline model: CVSS (or mapped severity) alone, 0-10 scale

        scored.append(
            ScoredVulnerability(
                component=r.component,
                version=r.version,
                ecosystem=r.ecosystem,
                vuln_id=r.vuln_id,
                primary_cve=r.primary_cve(),
                severity=r.severity,
                cvss_score=r.cvss_score,
                in_kev=r.in_kev,
                epss_score=r.epss_score,
                is_direct_dependency=r.is_direct_dependency,
                dependents_count=dep_count,
                cvss_only_score=round(cvss_only, 4),
                risk_score=round(composite * 100, 4),
            )
        )

    # Rank both ways (rank 1 = highest priority)
    for rank, sv in enumerate(sorted(scored, key=lambda s: s.risk_score, reverse=True), start=1):
        sv.risk_rank = rank
    for rank, sv in enumerate(sorted(scored, key=lambda s: s.cvss_only_score, reverse=True), start=1):
        sv.cvss_rank = rank

    return sorted(scored, key=lambda s: s.risk_rank)


# --------------------------------------------------------------------------
# Ranking-effectiveness evaluation (RQ3)
# --------------------------------------------------------------------------

def spearman_rank_correlation(scored: list[ScoredVulnerability]) -> float:
    n = len(scored)
    if n < 2:
        return 1.0
    d2_sum = sum((s.risk_rank - s.cvss_rank) ** 2 for s in scored)
    return round(1 - (6 * d2_sum) / (n * (n**2 - 1)), 4)


def top_n_overlap(scored: list[ScoredVulnerability], n: int = 10) -> dict:
    n = min(n, len(scored))
    risk_top = {s.vuln_id + s.component for s in scored if s.risk_rank <= n}
    cvss_top = {s.vuln_id + s.component for s in scored if s.cvss_rank <= n}
    overlap = risk_top & cvss_top
    return {
        "n": n,
        "overlap_count": len(overlap),
        "overlap_ratio": round(len(overlap) / n, 4) if n else 0.0,
        "risk_only_top_n": [
            f"{s.component}@{s.version} ({s.vuln_id})"
            for s in scored if s.risk_rank <= n and (s.vuln_id + s.component) not in cvss_top
        ],
        "cvss_only_top_n_missed_by_risk_model": [
            f"{s.component}@{s.version} ({s.vuln_id})"
            for s in scored if s.cvss_rank <= n and (s.vuln_id + s.component) not in risk_top
        ],
    }


def evaluate_ranking_effectiveness(scored: list[ScoredVulnerability]) -> dict:
    """NOTE ON WHAT THIS DOES AND DOES NOT PROVE (read before citing this in
    the dissertation): `avg_rank_improvement_for_kev_items` and
    `..._for_high_epss_items` check whether items that are KEV-listed / have
    a high EPSS score move up in rank once the composite score is applied.
    KEV membership and EPSS are themselves weighted inputs to the composite
    score (weights.kev=0.20, weights.exploitability=0.25), so a positive
    number here is a MECHANISM SANITY CHECK - it confirms the scoring
    arithmetic does what it was designed to do - not independent evidence
    that doing so produces a *better* real-world prioritisation decision.
    Treating this as "evidence for RQ3" would be circular reasoning: it
    would mean testing whether the model rewards KEV membership by checking
    whether KEV-membership-weighted scores reward KEV membership. This
    exact issue was flagged in a self-audit (docs/PROFESSOR_REVIEW.md,
    "RQ3 evidence chain circularity") and is deliberately spelled out here
    rather than glossed over. The dependency-importance signal is NOT a
    CVSS/KEV/EPSS input, so reordering driven by it (analysed in
    results/COMPARISON.md and results/RESEARCH_EVALUATION.md) is the
    non-circular evidence this project can actually offer for RQ3."""
    kev_items = [s for s in scored if s.in_kev]
    high_epss_items = [s for s in scored if (s.epss_score or 0) >= 0.1]

    def _avg_rank_improvement(items):
        if not items:
            return None
        deltas = [s.cvss_rank - s.risk_rank for s in items]  # positive = moved up (more urgent)
        return round(sum(deltas) / len(deltas), 2)

    return {
        "spearman_rank_correlation_risk_vs_cvss": spearman_rank_correlation(scored),
        "top_10_overlap": top_n_overlap(scored, 10),
        "kev_listed_vulnerabilities": len(kev_items),
        "avg_rank_improvement_for_kev_items": _avg_rank_improvement(kev_items),
        "high_epss_vulnerabilities_(epss>=0.10)": len(high_epss_items),
        "avg_rank_improvement_for_high_epss_items": _avg_rank_improvement(high_epss_items),
        "interpretation": (
            "MECHANISM SANITY CHECK, NOT INDEPENDENT EVIDENCE: a positive "
            "'avg_rank_improvement' here only confirms that the composite "
            "score's own KEV/EPSS weight terms behave as designed (KEV "
            "membership is 20% of the score's weight, EPSS is 25%), which is "
            "a tautology, not a validation of RQ3. See this function's "
            "docstring and docs/RESEARCH_EVALUATION.md's 'Threats to "
            "validity' section for the actual, non-circular evidence this "
            "project offers (the dependency-importance-driven reordering, "
            "which is independent of CVSS/KEV/EPSS)."
        ),
    }


def scored_to_json(scored: list[ScoredVulnerability]) -> list[dict]:
    return [asdict(s) for s in scored]
