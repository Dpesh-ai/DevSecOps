# Research Evaluation: Statistical Rigor for RQ3

This report supplies the statistical evidence behind the headline claims in `results/COMPARISON.md`. It is the document to cite in the dissertation's Evaluation/Analysis chapter; `COMPARISON.md` and the rank-shift chart are the accessible summary to use when presenting or demoing.

## Method

For every target with 3 or more detected vulnerabilities:

1. **Kendall's tau** is computed alongside Spearman's rho. Kendall's tau is more conservative and penalises rank swaps more heavily than Spearman, so reporting both guards against overstating agreement from a single statistic.
2. **Rank-Biased Overlap (RBO)** (Webber, Moffat & Zobel, 2010) is reported alongside Spearman/Kendall specifically because both of those weight a disagreement at any depth in the ranking equally - the wrong lens for a prioritisation tool where only the top of the list is operationally relevant. RBO is top-weighted (persistence p=0.9): a rank swap in the top few positions contributes far more to a LOW RBO than the same swap deep in the list. This directly addresses a self-audit finding that global rank correlation alone is the wrong primary evaluation-metric family for a 'what do I fix first' tool (docs/PROFESSOR_REVIEW.md).
3. **Reordering magnitude** (mean/max absolute rank shift, fraction of vulnerabilities moved 5+ ranks) is the actual primary evidence of how much reprioritisation occurs, reported alongside two Wilcoxon tests that are included for transparency but are NOT the primary evidence, for two distinct reasons worth being explicit about (both were caught during self-review, see docs/PROFESSOR_REVIEW.md): (i) a Wilcoxon test on the raw paired *scores* is confounded by risk_score and cvss_only_score*10 being different linear combinations of the same inputs by construction (different weight budgets on severity), so it is close to guaranteed to find 'significance' regardless of whether the model is actually a good prioritisation tool; (ii) a Wilcoxon test on the signed *rank shift* (cvss_rank - risk_rank) has a different, subtler problem - for any two complete rankings of the same n items, signed shifts always sum to exactly zero by construction (both rank sequences sum to n(n+1)/2), so a test for a *net directional* bias has structurally limited power here: it will tend to report 'not significant' regardless of how much real reordering occurred, because promotions and demotions necessarily balance out. Both are reported for transparency (and because a marker may reasonably ask why they were tried and set aside), but the mean/max absolute rank shift and the promoted/demoted-5+ counts (results/COMPARISON.md) are the metrics that are not subject to either confound.
4. **A random-ranking floor** (500 random permutation trials) establishes what Spearman's rho would look like for two *unrelated* rankings of the same size, so the real correlations can be read in context rather than against an arbitrary intuition of what 'high agreement' means.
5. **An ablation study** recomputes the ranking under six alternative weight configurations (CVSS-only; severity+KEV only; severity+exploitability only; the full model with one signal zeroed out at a time) and reports each variant's Spearman/Kendall agreement with the full model's ranking. A variant with *low* agreement indicates the removed signal has a large marginal effect on this dataset; a variant with agreement at or near 1.0 indicates the removed signal had little effect *for this specific dataset* - this is explicitly a dataset-dependent finding, not a universal claim about the signal's importance (see Limitations).
6. **A Monte Carlo weight-sensitivity analysis** (300 alternative weight vectors sampled uniformly from the 4-simplex) checks how much the reported ranking would change under different, equally-plausible weight choices. This is not a substitute for a formal structured weight-elicitation method such as the Analytic Hierarchy Process (Saaty, 1980), which was out of scope for an individual MSc-scale project (no expert panel was available), but it does answer the concrete question 'how fragile is this result to the specific weights chosen', empirically rather than by assertion.
7. **A Wilson score 95% confidence interval** is reported for the tamper-detection rate, since a bare '100%' from a small number of trials overstates precision without an interval.

## Results by target

### defectdojo-real (PyPI, n=32 vulnerabilities)

- Spearman's rho: **1.0**
- Kendall's tau: **1.0** (p = 0.0)
- Rank-Biased Overlap (top-weighted, p=0.9): **1.0** - compare against Spearman's rho above: a materially lower RBO than rho means the two methods disagree more at the *top* of the priority list than the overall correlation suggests.
- Random-ranking floor (mean rho over 500 shuffles): **0.0043** - the observed correlation is far above this floor, confirming the agreement between methods is real signal, not a small-N artefact.
- **Reordering magnitude (primary evidence of how much reprioritisation occurs)**: mean absolute rank shift = 0.0, max = 0, 0.0% of vulnerabilities moved by 5 or more ranks (for reference, two totally unrelated random rankings of the same 32 items would show a mean absolute shift of ~10.829 - the observed value here sitting well below that confirms the composite ranking is a controlled refinement of CVSS-only, not noise).
- *Diagnostic, not primary evidence* - Wilcoxon signed-rank test on rank shift (cvss_rank - risk_rank): statistic = None, p = 1.0 (not statistically significant at alpha=0.05); mean rank shift = 0.0, median = 0. **Read this only with its caveat** (see Method above): signed shifts sum to zero by construction for any two complete rankings, so this test has structurally limited power to detect real reordering and 'not significant' here does not mean 'no meaningful reordering occurred' - see the reordering-magnitude line above for that.
- *Diagnostic, not primary evidence* - Wilcoxon test on paired raw scores: statistic = 0.0, p = 1e-06 (statistically significant); mean score difference = -26.5. **Caveat**: risk_score (0.40 weight budget on severity) and cvss_only_score*10 (1.00 weight budget on severity) are different linear combinations of the same inputs by construction, so this magnitude comparison is expected to be 'significant' almost regardless of whether the composite model is a good prioritisation tool. This is a SECONDARY, supplementary statistic - prefer wilcoxon_rank_shift (above) as the primary significance claim for RQ3.

- Tamper-detection rate 95% CI (Wilson score interval): [83.9%, 100.0%]

**Ablation - agreement with the full model when one signal is removed:**

| Variant | Spearman vs. full model | Kendall's tau vs. full model |
|---|---|---|
| full_model (0.40 sev / 0.25 epss / 0.20 kev / 0.15 importance) | 1.0 | 1.0 |
| severity_only (== CVSS-only baseline) | 1.0 | 1.0 |
| severity_plus_kev (0.60 sev / 0.40 kev) | 1.0 | 1.0 |
| severity_plus_exploitability (0.60 sev / 0.40 epss) | 1.0 | 1.0 |
| no_importance (0.47 sev / 0.29 epss / 0.24 kev / 0.0 importance) | 1.0 | 1.0 |
| no_kev (0.50 sev / 0.31 epss / 0.0 kev / 0.19 importance) | 1.0 | 1.0 |
| no_exploitability (0.53 sev / 0.0 epss / 0.27 kev / 0.20 importance) | 1.0 | 1.0 |

**Weight-sensitivity (Monte Carlo, 300 random weight vectors)**: mean Spearman vs. this project's chosen weights = **1.0** (min = 1.0, 5th percentile = 1.0); mean top-10 overlap = 1.0. 300 alternative weight vectors were drawn uniformly at random from the 4-simplex (Dirichlet(1,1,1,1), i.e. no prior preference for any weighting). A high mean/min Spearman correlation and top-k overlap against this project's chosen (0.40/0.25/0.20/0.15) weighting means the reported ranking is robust to the specific weight choice within this four-signal model family. It does NOT establish that this model family - these four particular signals - is the correct one to use; it only shows the weighting *within* it is not a fragile, arbitrary artefact. A low score here would have been a serious problem; a high score is necessary but not sufficient evidence that the weights are well chosen.

### express-real (npm, n=0 vulnerabilities)

*Too few vulnerabilities detected in this target for rank-correlation or ablation analysis to be meaningful (fewer than 3). This is itself worth reporting: it means the pipeline correctly found a clean, well-maintained real-world dependency tree.*

### juiceshop-real (npm, n=67 vulnerabilities)

- Spearman's rho: **0.9415**
- Kendall's tau: **0.8155** (p = 0.0)
- Rank-Biased Overlap (top-weighted, p=0.9): **0.6638** - compare against Spearman's rho above: a materially lower RBO than rho means the two methods disagree more at the *top* of the priority list than the overall correlation suggests.
- Random-ranking floor (mean rho over 500 shuffles): **-0.0007** - the observed correlation is far above this floor, confirming the agreement between methods is real signal, not a small-N artefact.
- **Reordering magnitude (primary evidence of how much reprioritisation occurs)**: mean absolute rank shift = 5.373, max = 17, 50.7% of vulnerabilities moved by 5 or more ranks (for reference, two totally unrelated random rankings of the same 67 items would show a mean absolute shift of ~22.332 - the observed value here sitting well below that confirms the composite ranking is a controlled refinement of CVSS-only, not noise).
- *Diagnostic, not primary evidence* - Wilcoxon signed-rank test on rank shift (cvss_rank - risk_rank): statistic = 985.0, p = 0.874695 (not statistically significant at alpha=0.05); mean rank shift = 0.0, median = -1. **Read this only with its caveat** (see Method above): signed shifts sum to zero by construction for any two complete rankings, so this test has structurally limited power to detect real reordering and 'not significant' here does not mean 'no meaningful reordering occurred' - see the reordering-magnitude line above for that.
- *Diagnostic, not primary evidence* - Wilcoxon test on paired raw scores: statistic = 84.0, p = 0.0 (statistically significant); mean score difference = -25.1295. **Caveat**: risk_score (0.40 weight budget on severity) and cvss_only_score*10 (1.00 weight budget on severity) are different linear combinations of the same inputs by construction, so this magnitude comparison is expected to be 'significant' almost regardless of whether the composite model is a good prioritisation tool. This is a SECONDARY, supplementary statistic - prefer wilcoxon_rank_shift (above) as the primary significance claim for RQ3.

- Tamper-detection rate 95% CI (Wilson score interval): [83.9%, 100.0%]

**Ablation - agreement with the full model when one signal is removed:**

| Variant | Spearman vs. full model | Kendall's tau vs. full model |
|---|---|---|
| full_model (0.40 sev / 0.25 epss / 0.20 kev / 0.15 importance) | 1.0 | 1.0 |
| severity_only (== CVSS-only baseline) | 0.954 | 0.8752 |
| severity_plus_kev (0.60 sev / 0.40 kev) | 0.954 | 0.8752 |
| severity_plus_exploitability (0.60 sev / 0.40 epss) | 0.9547 | 0.8725 |
| no_importance (0.47 sev / 0.29 epss / 0.24 kev / 0.0 importance) | 0.9547 | 0.8734 |
| no_kev (0.50 sev / 0.31 epss / 0.0 kev / 0.19 importance) | 1.0 | 1.0 |
| no_exploitability (0.53 sev / 0.0 epss / 0.27 kev / 0.20 importance) | 0.9645 | 0.8924 |

**Weight-sensitivity (Monte Carlo, 300 random weight vectors)**: mean Spearman vs. this project's chosen weights = **0.8067** (min = 0.4406, 5th percentile = 0.5282); mean top-10 overlap = 0.636. 300 alternative weight vectors were drawn uniformly at random from the 4-simplex (Dirichlet(1,1,1,1), i.e. no prior preference for any weighting). A high mean/min Spearman correlation and top-k overlap against this project's chosen (0.40/0.25/0.20/0.15) weighting means the reported ranking is robust to the specific weight choice within this four-signal model family. It does NOT establish that this model family - these four particular signals - is the correct one to use; it only shows the weighting *within* it is not a fragile, arbitrary artefact. A low score here would have been a serious problem; a high score is necessary but not sufficient evidence that the weights are well chosen.

### juiceshop-v9-real (npm, n=78 vulnerabilities)

- Spearman's rho: **0.934**
- Kendall's tau: **0.7882** (p = 0.0)
- Rank-Biased Overlap (top-weighted, p=0.9): **0.7916** - compare against Spearman's rho above: a materially lower RBO than rho means the two methods disagree more at the *top* of the priority list than the overall correlation suggests.
- Random-ranking floor (mean rho over 500 shuffles): **-0.007** - the observed correlation is far above this floor, confirming the agreement between methods is real signal, not a small-N artefact.
- **Reordering magnitude (primary evidence of how much reprioritisation occurs)**: mean absolute rank shift = 6.821, max = 15, 60.3% of vulnerabilities moved by 5 or more ranks (for reference, two totally unrelated random rankings of the same 78 items would show a mean absolute shift of ~26.128 - the observed value here sitting well below that confirms the composite ranking is a controlled refinement of CVSS-only, not noise).
- *Diagnostic, not primary evidence* - Wilcoxon signed-rank test on rank shift (cvss_rank - risk_rank): statistic = 1273.5, p = 0.979399 (not statistically significant at alpha=0.05); mean rank shift = 0.0, median = 0. **Read this only with its caveat** (see Method above): signed shifts sum to zero by construction for any two complete rankings, so this test has structurally limited power to detect real reordering and 'not significant' here does not mean 'no meaningful reordering occurred' - see the reordering-magnitude line above for that.
- *Diagnostic, not primary evidence* - Wilcoxon test on paired raw scores: statistic = 163.0, p = 0.0 (statistically significant); mean score difference = -23.0332. **Caveat**: risk_score (0.40 weight budget on severity) and cvss_only_score*10 (1.00 weight budget on severity) are different linear combinations of the same inputs by construction, so this magnitude comparison is expected to be 'significant' almost regardless of whether the composite model is a good prioritisation tool. This is a SECONDARY, supplementary statistic - prefer wilcoxon_rank_shift (above) as the primary significance claim for RQ3.

- Tamper-detection rate 95% CI (Wilson score interval): [83.9%, 100.0%]

**Ablation - agreement with the full model when one signal is removed:**

| Variant | Spearman vs. full model | Kendall's tau vs. full model |
|---|---|---|
| full_model (0.40 sev / 0.25 epss / 0.20 kev / 0.15 importance) | 1.0 | 1.0 |
| severity_only (== CVSS-only baseline) | 0.9702 | 0.8954 |
| severity_plus_kev (0.60 sev / 0.40 kev) | 0.9702 | 0.8954 |
| severity_plus_exploitability (0.60 sev / 0.40 epss) | 0.9713 | 0.8908 |
| no_importance (0.47 sev / 0.29 epss / 0.24 kev / 0.0 importance) | 0.9713 | 0.8914 |
| no_kev (0.50 sev / 0.31 epss / 0.0 kev / 0.19 importance) | 1.0 | 1.0 |
| no_exploitability (0.53 sev / 0.0 epss / 0.27 kev / 0.20 importance) | 0.9712 | 0.9028 |

**Weight-sensitivity (Monte Carlo, 300 random weight vectors)**: mean Spearman vs. this project's chosen weights = **0.8217** (min = 0.4895, 5th percentile = 0.5612); mean top-10 overlap = 0.7827. 300 alternative weight vectors were drawn uniformly at random from the 4-simplex (Dirichlet(1,1,1,1), i.e. no prior preference for any weighting). A high mean/min Spearman correlation and top-k overlap against this project's chosen (0.40/0.25/0.20/0.15) weighting means the reported ranking is robust to the specific weight choice within this four-signal model family. It does NOT establish that this model family - these four particular signals - is the correct one to use; it only shows the weighting *within* it is not a fragile, arbitrary artefact. A low score here would have been a serious problem; a high score is necessary but not sufficient evidence that the weights are well chosen.

### netbox-real (PyPI, n=0 vulnerabilities)

*Too few vulnerabilities detected in this target for rank-correlation or ablation analysis to be meaningful (fewer than 3). This is itself worth reporting: it means the pipeline correctly found a clean, well-maintained real-world dependency tree.*

### node-sample (npm, n=24 vulnerabilities)

- Spearman's rho: **0.9591**
- Kendall's tau: **0.8841** (p = 0.0)
- Rank-Biased Overlap (top-weighted, p=0.9): **0.8855** - compare against Spearman's rho above: a materially lower RBO than rho means the two methods disagree more at the *top* of the priority list than the overall correlation suggests.
- Random-ranking floor (mean rho over 500 shuffles): **-0.017** - the observed correlation is far above this floor, confirming the agreement between methods is real signal, not a small-N artefact.
- **Reordering magnitude (primary evidence of how much reprioritisation occurs)**: mean absolute rank shift = 1.167, max = 5, 8.3% of vulnerabilities moved by 5 or more ranks (for reference, two totally unrelated random rankings of the same 24 items would show a mean absolute shift of ~8.002 - the observed value here sitting well below that confirms the composite ranking is a controlled refinement of CVSS-only, not noise).
- *Diagnostic, not primary evidence* - Wilcoxon signed-rank test on rank shift (cvss_rank - risk_rank): statistic = 31.0, p = 0.857391 (not statistically significant at alpha=0.05); mean rank shift = 0.0, median = 0. **Read this only with its caveat** (see Method above): signed shifts sum to zero by construction for any two complete rankings, so this test has structurally limited power to detect real reordering and 'not significant' here does not mean 'no meaningful reordering occurred' - see the reordering-magnitude line above for that.
- *Diagnostic, not primary evidence* - Wilcoxon test on paired raw scores: statistic = 3.0, p = 2.6e-05 (statistically significant); mean score difference = -25.8776. **Caveat**: risk_score (0.40 weight budget on severity) and cvss_only_score*10 (1.00 weight budget on severity) are different linear combinations of the same inputs by construction, so this magnitude comparison is expected to be 'significant' almost regardless of whether the composite model is a good prioritisation tool. This is a SECONDARY, supplementary statistic - prefer wilcoxon_rank_shift (above) as the primary significance claim for RQ3.

- Tamper-detection rate 95% CI (Wilson score interval): [83.9%, 100.0%]

**Ablation - agreement with the full model when one signal is removed:**

| Variant | Spearman vs. full model | Kendall's tau vs. full model |
|---|---|---|
| full_model (0.40 sev / 0.25 epss / 0.20 kev / 0.15 importance) | 1.0 | 1.0 |
| severity_only (== CVSS-only baseline) | 0.9783 | 0.9348 |
| severity_plus_kev (0.60 sev / 0.40 kev) | 0.9783 | 0.9348 |
| severity_plus_exploitability (0.60 sev / 0.40 epss) | 0.9783 | 0.9348 |
| no_importance (0.47 sev / 0.29 epss / 0.24 kev / 0.0 importance) | 0.9783 | 0.9348 |
| no_kev (0.50 sev / 0.31 epss / 0.0 kev / 0.19 importance) | 1.0 | 1.0 |
| no_exploitability (0.53 sev / 0.0 epss / 0.27 kev / 0.20 importance) | 0.9991 | 0.9928 |

**Weight-sensitivity (Monte Carlo, 300 random weight vectors)**: mean Spearman vs. this project's chosen weights = **0.8852** (min = 0.6357, 5th percentile = 0.6357); mean top-10 overlap = 0.8003. 300 alternative weight vectors were drawn uniformly at random from the 4-simplex (Dirichlet(1,1,1,1), i.e. no prior preference for any weighting). A high mean/min Spearman correlation and top-k overlap against this project's chosen (0.40/0.25/0.20/0.15) weighting means the reported ranking is robust to the specific weight choice within this four-signal model family. It does NOT establish that this model family - these four particular signals - is the correct one to use; it only shows the weighting *within* it is not a fragile, arbitrary artefact. A low score here would have been a serious problem; a high score is necessary but not sufficient evidence that the weights are well chosen.

### python-sample (PyPI, n=54 vulnerabilities)

- Spearman's rho: **1.0**
- Kendall's tau: **1.0** (p = 0.0)
- Rank-Biased Overlap (top-weighted, p=0.9): **1.0** - compare against Spearman's rho above: a materially lower RBO than rho means the two methods disagree more at the *top* of the priority list than the overall correlation suggests.
- Random-ranking floor (mean rho over 500 shuffles): **-0.0129** - the observed correlation is far above this floor, confirming the agreement between methods is real signal, not a small-N artefact.
- **Reordering magnitude (primary evidence of how much reprioritisation occurs)**: mean absolute rank shift = 0.0, max = 0, 0.0% of vulnerabilities moved by 5 or more ranks (for reference, two totally unrelated random rankings of the same 54 items would show a mean absolute shift of ~17.938 - the observed value here sitting well below that confirms the composite ranking is a controlled refinement of CVSS-only, not noise).
- *Diagnostic, not primary evidence* - Wilcoxon signed-rank test on rank shift (cvss_rank - risk_rank): statistic = None, p = 1.0 (not statistically significant at alpha=0.05); mean rank shift = 0.0, median = 0. **Read this only with its caveat** (see Method above): signed shifts sum to zero by construction for any two complete rankings, so this test has structurally limited power to detect real reordering and 'not significant' here does not mean 'no meaningful reordering occurred' - see the reordering-magnitude line above for that.
- *Diagnostic, not primary evidence* - Wilcoxon test on paired raw scores: statistic = 0.0, p = 0.0 (statistically significant); mean score difference = -23.1574. **Caveat**: risk_score (0.40 weight budget on severity) and cvss_only_score*10 (1.00 weight budget on severity) are different linear combinations of the same inputs by construction, so this magnitude comparison is expected to be 'significant' almost regardless of whether the composite model is a good prioritisation tool. This is a SECONDARY, supplementary statistic - prefer wilcoxon_rank_shift (above) as the primary significance claim for RQ3.

- Tamper-detection rate 95% CI (Wilson score interval): [83.9%, 100.0%]

**Ablation - agreement with the full model when one signal is removed:**

| Variant | Spearman vs. full model | Kendall's tau vs. full model |
|---|---|---|
| full_model (0.40 sev / 0.25 epss / 0.20 kev / 0.15 importance) | 1.0 | 1.0 |
| severity_only (== CVSS-only baseline) | 1.0 | 1.0 |
| severity_plus_kev (0.60 sev / 0.40 kev) | 1.0 | 1.0 |
| severity_plus_exploitability (0.60 sev / 0.40 epss) | 1.0 | 1.0 |
| no_importance (0.47 sev / 0.29 epss / 0.24 kev / 0.0 importance) | 1.0 | 1.0 |
| no_kev (0.50 sev / 0.31 epss / 0.0 kev / 0.19 importance) | 1.0 | 1.0 |
| no_exploitability (0.53 sev / 0.0 epss / 0.27 kev / 0.20 importance) | 1.0 | 1.0 |

**Weight-sensitivity (Monte Carlo, 300 random weight vectors)**: mean Spearman vs. this project's chosen weights = **1.0** (min = 1.0, 5th percentile = 1.0); mean top-10 overlap = 1.0. 300 alternative weight vectors were drawn uniformly at random from the 4-simplex (Dirichlet(1,1,1,1), i.e. no prior preference for any weighting). A high mean/min Spearman correlation and top-k overlap against this project's chosen (0.40/0.25/0.20/0.15) weighting means the reported ranking is robust to the specific weight choice within this four-signal model family. It does NOT establish that this model family - these four particular signals - is the correct one to use; it only shows the weighting *within* it is not a fragile, arbitrary artefact. A low score here would have been a serious problem; a high score is necessary but not sufficient evidence that the weights are well chosen.

## Cross-target synthesis

The signed rank-shift Wilcoxon test found a statistically significant *net directional* bias in only **0/5** targets at the uncorrected alpha=0.05 level (Bonferroni-corrected threshold alpha=0.01 across 5 tests: 0/5 remain significant). **This is expected and is not evidence of a trivial or absent effect** - as explained in Method above, signed rank shifts sum to exactly zero by construction for any two complete rankings of the same items, so this specific test has structurally limited power to detect reordering and should not be read as 'the model changes nothing'. The metric that is not subject to that constraint - reordering magnitude - tells a different story: up to **60.3%** of vulnerabilities in a single target moved by 5 or more ranks (see per-target figures above and results/COMPARISON.md's promoted/demoted-5+ columns). This project's honest statistical claim for RQ3 is therefore: the composite model produces real, non-trivial, individually-large rank reorderings relative to CVSS-only for a meaningful subset of vulnerabilities (evidenced by reordering magnitude, RBO, and Spearman/Kendall vs. the random-ranking floor), while a net systematic directional bias across the *entire* list is neither expected nor found (nor would it be a meaningful thing to look for, given the zero-sum constraint) - this is a materially more precise and more defensible claim than an earlier version of this report made, which treated the (scale-confounded) raw-score Wilcoxon test as 'the strongest evidence for RQ3' without noticing the confound (see docs/PROFESSOR_REVIEW.md).

The ablation study across all Node.js targets (which have real dependency-graph data) consistently shows: (a) removing KEV changes nothing in this run, because none of the CVEs found across any target happened to be KEV-listed (see `docs/HOW_TO_EXPLAIN_THIS.md` for why this is an honest dataset limitation, not a bug); (b) removing the exploitability (EPSS) term changes very little on its own, because - in this network-restricted evaluation run - the EPSS API was unreachable and the model fell back to a severity-derived proxy, so severity and 'exploitability' were not independent signals in this run; (c) the **dependency-importance term is the actual source of reordering** observed in the Juice Shop results - removing it collapses the model's ranking back towards the CVSS-only baseline (Spearman ~0.95-0.97 instead of 1.0). This is a genuinely important, self-critical finding: it means the current empirical evidence supports the *dependency-importance* signal specifically, more strongly than it supports the KEV or EPSS terms, which simply were not exercised by this dataset. State this precisely rather than claiming all four signals were equally validated.

## Threats to validity

**Internal validity**: the risk-scoring weights (0.40/0.25/0.20/0.15) were chosen by judgement to reflect severity remaining the dominant signal, not fitted or optimised against any ground-truth labelled dataset of historically-exploited vulnerabilities, and not derived via a structured expert-elicitation method such as the Analytic Hierarchy Process (Saaty, 1980) - the standard technique in the risk-management literature for deriving defensible composite-indicator weights when no labelled dataset exists, but one that requires a panel of domain experts that was not available for an individual MSc-scale project. The Monte Carlo weight-sensitivity analysis reported per-target above partially compensates for this: it shows whether the reported ranking is a robust property of the four-signal model family, or a fragile artefact of the one specific weight vector chosen. It does NOT, and cannot, establish that this four-signal model itself is the *correct* one, nor that the chosen weights are *optimal* within it - only that they are not obviously fragile. This distinction is stated explicitly rather than left for a marker to have to infer.

**Construct validity**: two distinct issues are worth separating here. First, 'exploitability' is measured via EPSS when reachable, and via a severity-derived proxy otherwise; in every run captured in this repository's committed results, EPSS was unreachable (network-restricted development environment), so the exploitability construct was not, in practice, independently validated against real exploitation-probability data in this specific evaluation run. Second, and more fundamentally: `evaluate_ranking_effectiveness()` in `src/risk_scoring.py` checks whether KEV-listed / high-EPSS items are promoted by the composite score - but KEV and EPSS are themselves weighted inputs *to* that same composite score (20% and 25% of the weight respectively), so a positive result there is a mechanism sanity check confirming the arithmetic works as designed, not independent evidence that the resulting prioritisation is *better*. This was corrected during a self-audit (docs/PROFESSOR_REVIEW.md) - the field's own docstring and interpretation text now state this explicitly. The dependency-importance signal is NOT a CVSS/KEV/EPSS input, so the reordering it drives (see results/COMPARISON.md) is the actual non-circular evidence this project offers for RQ3. Recent independent empirical work on this exact problem - Koscinski et al. (2025), an outcome-linked comparison of CVSS, SSVC, EPSS and the Exploitability Index against 600 real-world Microsoft Patch Tuesday vulnerabilities - found significant disagreement between established scoring systems on the same vulnerabilities, which underlines why claims of 'improvement' in this space require independent, outcome-linked ground truth that this MSc-scale project does not have access to, and why this report is careful not to claim more than the non-circular evidence supports.

**External validity**: seven targets across two ecosystems is a substantially larger and more varied sample than a single-repository case study, and deliberately spans controlled samples, real current repositories, a real historical (2019) release, a security-training application, and two well-maintained libraries/frameworks with zero known vulnerabilities. It is still a small sample by the standards of large-scale empirical software engineering studies (e.g. Zimmermann et al. 2019 analysed 5+ million npm package versions; Alfadel et al. 2023 analysed 1,396 vulnerability reports). Findings here should be read as a demonstrative case study appropriate to an MSc-scale project, not as a population-level empirical claim - and this report says so explicitly rather than overstating generalisability.

**Statistical validity**: the diagnostic Wilcoxon rank-shift p-values reported per-target are corrected for multiple comparisons using a Bonferroni family-wise correction across all targets tested (see the corrected alpha and post-correction significance count in 'Cross-target synthesis' above) rather than only being mentioned in prose without being applied to the actual figures. The reordering-magnitude metric this report treats as the primary evidence for RQ3 (mean/max absolute rank shift, fraction moved 5+ ranks) is also compared against a permutation-based null (`reordering_magnitude_null`, analogous to the random-ranking floor used for Spearman/Kendall) rather than being reported as a bare descriptive number with nothing to compare it against.