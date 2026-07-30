# SBOM-first DevSecOps Pipeline with Cryptographic Provenance and Dependency Risk Scoring

MSc Computing individual project — Dipesh Sapkota, University of Huddersfield London Campus.

## What this project does

This is a pipeline that takes a code repository and:

1. Builds a Software Bill of Materials (SBOM) for it — a list of every dependency it uses, in the
   CycloneDX format.
2. Checks each dependency against known vulnerability databases (PyPI/OSV for Python, npm
   audit/GitHub Advisories for Node.js, plus CISA's known-exploited-vulnerabilities list and
   FIRST.org's EPSS exploit-probability scores where reachable).
3. Signs the SBOM and a real build artefact cryptographically, so you can prove later that it
   wasn't tampered with. This uses both a real Sigstore Cosign signing step (in CI) and a local
   from-scratch implementation of the same DSSE/in-toto signing approach, so it also works offline.
4. Scores every vulnerability found using a combined model — severity, how likely it is to be
   exploited, whether it's on CISA's actively-exploited list, and how central the affected package
   is in the dependency tree — and compares that ranking against the traditional method of just
   sorting by CVSS score.

It's tested against 7 target repositories: 2 small controlled examples with known vulnerable
dependencies pinned on purpose, and 5 real open-source projects pulled directly from GitHub
(OWASP DefectDojo, NetBox, Express, and two versions of OWASP Juice Shop — the current release and
its actual 2019 tag).

## Repository layout

```
├── .github/workflows/pipeline.yml   # CI: runs the whole pipeline, then signs/verifies with real Cosign
├── Dockerfile                       # container setup so it runs the same way everywhere
├── requirements.txt
├── src/
│   ├── build_validate.py            # checks whether a target's dependencies actually install
│   ├── sbom_generate.py             # builds the SBOM (Python + Node.js)
│   ├── vuln_mapper.py               # looks up vulnerabilities + KEV/EPSS enrichment
│   ├── risk_scoring.py              # the combined risk-scoring model + CVSS-only baseline
│   ├── sign_provenance.py           # local signing/verification/tamper-detection implementation
│   ├── compare_methods.py           # builds the comparison report + chart
│   ├── research_stats.py            # the statistics behind the comparison (correlation tests, etc.)
│   ├── research_evaluation.py       # runs research_stats.py across every target
│   ├── evaluate.py                  # runs everything end to end for every target
│   └── data/kev_snapshot.json       # offline backup copy of the CISA KEV list
├── targets/                         # the 7 repositories evaluated (2 controlled, 5 real)
├── tests/                           # 43 automated tests covering every stage
└── results/                         # generated output: SBOMs, reports, comparison charts
```

## Running it

### Locally
```bash
pip install -r requirements.txt
npm install --package-lock-only --prefix targets/node-sample

python src/evaluate.py           # runs every stage for every target, then builds the reports
python -m pytest tests/ -v       # runs the 43 tests
```

### In Docker
```bash
docker build -t sbom-pipeline .
docker run --rm -v "$(pwd)/results:/app/results" sbom-pipeline
```

### In GitHub Actions
Pushing to `main`, opening a PR, or triggering it manually runs the same pipeline with a real
network connection (so live EPSS/KEV data gets used instead of the offline fallback), followed by
a second job that does real Sigstore Cosign signing, verification, a deliberate tamper test, and a
GitHub-native build-provenance attestation.

## Why there are two signing methods

The CI workflow uses the real, industry-standard tool: Sigstore Cosign in keyless mode, backed by
GitHub's own identity tokens and short-lived certificates. `src/sign_provenance.py` is a from-scratch
Python version of the same idea (DSSE envelope, in-toto-style provenance statement, Ed25519
signatures, tamper detection based on digest mismatches). It exists so the pipeline still works
offline or in a restricted network, and so the timing/tamper-detection experiments can run many
times in a row for consistent measurements.

## Key results across the 7 targets

Full numbers are in `results/report.json` and `results/REPORT.md`. The comparison between the two
scoring methods (with a chart) is in `results/COMPARISON.md`, and the full statistical breakdown is
in `results/RESEARCH_EVALUATION.md`. Everything regenerates by running `python src/evaluate.py`.

- **SBOM accuracy**: all 7 targets got a perfect match (precision/recall/F1 = 1.0) against their
  declared dependencies. Node.js targets also resolve the full dependency tree (up to 954 packages
  found from 58 declared ones for the older Juice Shop version); Python targets can't do this from
  `requirements.txt` alone, since it doesn't record which package depends on which — that's a real
  limitation, not a bug, and it's consistent across all three Python targets tested.
- **Vulnerabilities found**: 255 total across all 7 targets, 177 of those across the 5 real-world
  ones specifically. Express and NetBox came back with zero — expected, since both are current,
  well-maintained projects, and it shows the tool isn't just manufacturing false positives.
- **Risk scoring vs. CVSS-only**: the combined model reorders vulnerabilities noticeably compared
  to sorting by CVSS alone — in some targets, over half the vulnerabilities moved by 5+ ranks.
  Testing which part of the model actually causes this (an ablation study) showed it's mainly the
  "how central is this package" signal doing the work, since none of the vulnerabilities found in
  this run happened to be on the CISA exploited list, and the exploit-probability service (EPSS)
  wasn't reachable from this network during testing — both are honestly reported as dataset
  limitations rather than glossed over.
- **Signing/tamper detection**: 100% tamper-detection rate across every target, with signing and
  verification adding only a few milliseconds of overhead. In CI, a real packaged build artefact is
  attested using Cosign's native SBOM-attestation command, not just a bare SBOM file.
- **Build validation**: checks whether each target's dependencies actually install. All 4 real
  Node.js targets build cleanly. Of the 3 real Python targets, only one does — NetBox pins a Django
  version that isn't published yet, and DefectDojo needs a native PostgreSQL library that isn't on
  a bare machine (it's in the Dockerfile/CI setup). Both are genuine findings, not pipeline bugs.

## Known limitations

- EPSS and the live CISA KEV feed weren't reachable from the network this was developed/tested on,
  so those runs used offline fallbacks. Both work automatically once real network access is
  available (e.g. in GitHub Actions).
- There's no way to work out real dependency-tree relationships from a plain `requirements.txt`
  file, so the "how central is this package" signal doesn't differentiate anything for Python
  targets specifically. A resolver that reads a proper lockfile (like `poetry.lock`) would fix this.
- The weights in the risk-scoring model (how much severity counts vs. exploitability vs. KEV vs.
  centrality) were chosen by judgement, not fit against a labelled dataset of real historical
  incidents — no such dataset was available for this project.
- 7 targets is a reasonable spread for a project this size, but still small next to large-scale
  academic studies that look at millions of packages.
- Direct NVD lookups are implemented but off by default, since NVD's public API only allows 5
  requests per 30 seconds without a key — turning it on would make every run take several minutes.
  Set `ENABLE_NVD_ENRICHMENT=1` to use it.
- The pipeline checks whether a target's dependencies install, not whether the whole application
  builds and runs (e.g. it doesn't run database migrations or compile TypeScript). That's a
  deliberate scope decision.
- Only CycloneDX is used for SBOM generation, not Syft as well — either is acceptable, but a
  side-by-side comparison of both tools would be a reasonable next step.
