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


