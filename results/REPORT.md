# SBOM-first DevSecOps Pipeline - Evaluation Report

Generated: 2026-07-30 01:34:17 UTC  
Targets evaluated: 7

## Target: `defectdojo-real` (PyPI)

**Build validation (FR11 - can this repository actually be built?)**
- Buildable: False (method: `pip install --dry-run --report`)
- error: metadata-generation-failed

**SBOM completeness/accuracy (RQ1)**
- Precision: 1.0, Recall: 1.0, F1: 1.0 (vs. this project's own manifest parser - see independent cross-check below)
- Independent cross-check vs. pip's own resolver: not available (pip --report structured install list not available for this run (older pip, or build validation did not succeed))

**Vulnerability detection coverage**
- Components scanned: 66
- Components with known vulnerabilities: 4 (6.1%)
- Unique vulnerabilities found: 32
- By severity: {'MEDIUM': 16, 'HIGH': 2, 'CRITICAL': 14}
- In CISA KEV: 0 (source: offline-snapshot:2026-01-15)
- Python vulnerability data source actually used this run: pypi-json-api (OSV-derived) + keyword-severity heuristic fallback (OSV.dev unreachable this run)

**Risk scoring vs. CVSS-only baseline (RQ3)**
- Spearman rank correlation: 1.0
- Top-10 overlap ratio: 1.0
- KEV-listed vulnerabilities: 0

**Cryptographic signing / provenance (RQ2)**
- Tamper detection rate: 100.0% over 20 runs
- Avg sign time: 0.1078 ms
- Avg verify time: 2.7718 ms
- Total signing overhead per artifact: 2.8796 ms

**Top 5 risk-ranked vulnerabilities**

| Rank | Component | Vuln ID | Severity | Risk Score | CVSS-only Score | CVSS Rank |
|---|---|---|---|---|---|---|
| 1 | Pillow@12.2.0 | GHSA-62p4-gmf7-7g93 | CRITICAL | 56.0 | 9.0 | 1 |
| 2 | Pillow@12.2.0 | GHSA-5x94-69rx-g8h2 | CRITICAL | 56.0 | 9.0 | 2 |
| 3 | Pillow@12.2.0 | GHSA-8v84-f9pq-wr9x | CRITICAL | 56.0 | 9.0 | 3 |
| 4 | Pillow@12.2.0 | GHSA-phj9-mv4w-65pm | CRITICAL | 56.0 | 9.0 | 4 |
| 5 | Pillow@12.2.0 | GHSA-45hq-cxwh-f6vc | CRITICAL | 56.0 | 9.0 | 5 |

## Target: `express-real` (npm)

**Build validation (FR11 - can this repository actually be built?)**
- Buildable: True (method: `npm ci --dry-run`)
- lockfile is installable and in sync with package.json (added 64 packages in 368ms)

**SBOM completeness/accuracy (RQ1)**
- Precision: 1.0, Recall: 1.0, F1: 1.0 (vs. this project's own manifest parser - see independent cross-check below)
- Transitive dependency capture ratio: 1.0

**Vulnerability detection coverage**
- Components scanned: 64
- Components with known vulnerabilities: 0 (0.0%)
- Unique vulnerabilities found: 0
- By severity: {}
- In CISA KEV: 0 (source: offline-snapshot:2026-01-15)

**Risk scoring vs. CVSS-only baseline (RQ3)**
- Spearman rank correlation: 1.0
- Top-10 overlap ratio: 0.0
- KEV-listed vulnerabilities: 0

**Cryptographic signing / provenance (RQ2)**
- Tamper detection rate: 100.0% over 20 runs
- Avg sign time: 0.1112 ms
- Avg verify time: 3.4204 ms
- Total signing overhead per artifact: 3.5316 ms

**Top 5 risk-ranked vulnerabilities**

| Rank | Component | Vuln ID | Severity | Risk Score | CVSS-only Score | CVSS Rank |
|---|---|---|---|---|---|---|

## Target: `juiceshop-real` (npm)

**Build validation (FR11 - can this repository actually be built?)**
- Buildable: True (method: `npm ci --dry-run`)
- lockfile is installable and in sync with package.json (added 832 packages in 781ms)

**SBOM completeness/accuracy (RQ1)**
- Precision: 1.0, Recall: 1.0, F1: 1.0 (vs. this project's own manifest parser - see independent cross-check below)
- Transitive dependency capture ratio: 1.0

**Vulnerability detection coverage**
- Components scanned: 745
- Components with known vulnerabilities: 26 (3.5%)
- Unique vulnerabilities found: 67
- By severity: {'LOW': 4, 'MODERATE': 28, 'HIGH': 29, 'CRITICAL': 6}
- In CISA KEV: 0 (source: offline-snapshot:2026-01-15)

**Risk scoring vs. CVSS-only baseline (RQ3)**
- Spearman rank correlation: 0.9415
- Top-10 overlap ratio: 0.7
- KEV-listed vulnerabilities: 0

**Cryptographic signing / provenance (RQ2)**
- Tamper detection rate: 100.0% over 20 runs
- Avg sign time: 0.1057 ms
- Avg verify time: 4.5061 ms
- Total signing overhead per artifact: 4.6118 ms

**Top 5 risk-ranked vulnerabilities**

| Rank | Component | Vuln ID | Severity | Risk Score | CVSS-only Score | CVSS Rank |
|---|---|---|---|---|---|---|
| 1 | lodash@2.4.2 | GHSA-jf85-cpcp-j695 | CRITICAL | 50.2393 | 9.1 | 3 |
| 2 | crypto-js@3.3.0 | GHSA-xwcq-pm8m-c4vf | CRITICAL | 48.967 | 9.1 | 1 |
| 3 | decompress@4.2.1 | GHSA-mp2f-45pm-3cg9 | CRITICAL | 48.967 | 9.1 | 2 |
| 4 | jsonwebtoken@0.4.0 | GHSA-8cf7-32gw-wr33 | HIGH | 47.5339 | 8.1 | 7 |
| 5 | express-jwt@0.1.3 | GHSA-6g6m-m6h5-w9gf | HIGH | 45.8 | 7.7 | 8 |

## Target: `juiceshop-v9-real` (npm)

**Build validation (FR11 - can this repository actually be built?)**
- Buildable: True (method: `npm ci --dry-run`)
- lockfile is installable and in sync with package.json (added 954 packages in 875ms)

**SBOM completeness/accuracy (RQ1)**
- Precision: 1.0, Recall: 1.0, F1: 1.0 (vs. this project's own manifest parser - see independent cross-check below)
- Transitive dependency capture ratio: 1.0

**Vulnerability detection coverage**
- Components scanned: 880
- Components with known vulnerabilities: 34 (3.9%)
- Unique vulnerabilities found: 77
- By severity: {'MODERATE': 31, 'HIGH': 33, 'LOW': 2, 'CRITICAL': 12}
- In CISA KEV: 0 (source: offline-snapshot:2026-01-15)

**Risk scoring vs. CVSS-only baseline (RQ3)**
- Spearman rank correlation: 0.934
- Top-10 overlap ratio: 0.7
- KEV-listed vulnerabilities: 0

**Cryptographic signing / provenance (RQ2)**
- Tamper detection rate: 100.0% over 20 runs
- Avg sign time: 0.1081 ms
- Avg verify time: 4.6371 ms
- Total signing overhead per artifact: 4.7452000000000005 ms

**Top 5 risk-ranked vulnerabilities**

| Rank | Component | Vuln ID | Severity | Risk Score | CVSS-only Score | CVSS Rank |
|---|---|---|---|---|---|---|
| 1 | sequelize@5.22.5 | GHSA-wrh9-cjv3-2hpw | CRITICAL | 60.0 | 10.0 | 1 |
| 2 | sequelize@5.22.5 | GHSA-f598-mfpv-gmfx | CRITICAL | 60.0 | 10.0 | 2 |
| 3 | sequelize@5.22.5 | GHSA-vqfx-gj96-3w95 | CRITICAL | 59.6 | 9.9 | 3 |
| 4 | libxmljs2@0.21.7 | GHSA-78h3-pg4x-j8cv | CRITICAL | 52.4 | 8.1 | 11 |
| 5 | libxmljs2@0.21.7 | GHSA-mjr4-7xg5-pfvh | CRITICAL | 52.4 | 8.1 | 12 |

## Target: `netbox-real` (PyPI)

**Build validation (FR11 - can this repository actually be built?)**
- Buildable: False (method: `pip install --dry-run --report`)
- ERROR: No matching distribution found for Django==6.0.7

**SBOM completeness/accuracy (RQ1)**
- Precision: 1.0, Recall: 1.0, F1: 1.0 (vs. this project's own manifest parser - see independent cross-check below)
- Independent cross-check vs. pip's own resolver: not available (pip --report structured install list not available for this run (older pip, or build validation did not succeed))

**Vulnerability detection coverage**
- Components scanned: 46
- Components with known vulnerabilities: 0 (0.0%)
- Unique vulnerabilities found: 0
- By severity: {}
- In CISA KEV: 0 (source: offline-snapshot:2026-01-15)
- Python vulnerability data source actually used this run: pypi-json-api (OSV-derived) + keyword-severity heuristic fallback (OSV.dev unreachable this run)

**Risk scoring vs. CVSS-only baseline (RQ3)**
- Spearman rank correlation: 1.0
- Top-10 overlap ratio: 0.0
- KEV-listed vulnerabilities: 0

**Cryptographic signing / provenance (RQ2)**
- Tamper detection rate: 100.0% over 20 runs
- Avg sign time: 0.1037 ms
- Avg verify time: 3.1001 ms
- Total signing overhead per artifact: 3.2037999999999998 ms

**Top 5 risk-ranked vulnerabilities**

| Rank | Component | Vuln ID | Severity | Risk Score | CVSS-only Score | CVSS Rank |
|---|---|---|---|---|---|---|

## Target: `node-sample` (npm)

**Build validation (FR11 - can this repository actually be built?)**
- Buildable: True (method: `npm ci --dry-run`)
- lockfile is installable and in sync with package.json (removed 180 packages, and changed 1 package in 4s)

**SBOM completeness/accuracy (RQ1)**
- Precision: 1.0, Recall: 1.0, F1: 1.0 (vs. this project's own manifest parser - see independent cross-check below)
- Transitive dependency capture ratio: 1.0

**Vulnerability detection coverage**
- Components scanned: 53
- Components with known vulnerabilities: 9 (17.0%)
- Unique vulnerabilities found: 24
- By severity: {'HIGH': 9, 'LOW': 5, 'MODERATE': 8, 'CRITICAL': 2}
- In CISA KEV: 0 (source: offline-snapshot:2026-01-15)

**Risk scoring vs. CVSS-only baseline (RQ3)**
- Spearman rank correlation: 0.9591
- Top-10 overlap ratio: 1.0
- KEV-listed vulnerabilities: 0

**Cryptographic signing / provenance (RQ2)**
- Tamper detection rate: 100.0% over 20 runs
- Avg sign time: 0.1069 ms
- Avg verify time: 2.9591 ms
- Total signing overhead per artifact: 3.066 ms

**Top 5 risk-ranked vulnerabilities**

| Rank | Component | Vuln ID | Severity | Risk Score | CVSS-only Score | CVSS Rank |
|---|---|---|---|---|---|---|
| 1 | minimist@0.0.8 | GHSA-xvch-5gv4-984h | CRITICAL | 59.2 | 9.8 | 1 |
| 2 | lodash@4.17.4 | GHSA-jf85-cpcp-j695 | CRITICAL | 56.4 | 9.1 | 2 |
| 3 | lodash@4.17.4 | GHSA-r5fr-rjxr-66jc | HIGH | 47.4 | 8.1 | 3 |
| 4 | lodash@4.17.4 | GHSA-p6mc-m468-83gw | HIGH | 44.6 | 7.4 | 9 |
| 5 | lodash@4.17.4 | GHSA-35jh-r3h4-6jhm | HIGH | 43.8 | 7.2 | 10 |

## Target: `python-sample` (PyPI)

**Build validation (FR11 - can this repository actually be built?)**
- Buildable: True (method: `pip install --dry-run --report (structured JSON install report)`)
- dependency resolution succeeded; 8 packages would be installed (package list read from pip's own structured --report JSON output, not parsed from human-readable log text)

**SBOM completeness/accuracy (RQ1)**
- Precision: 1.0, Recall: 1.0, F1: 1.0 (vs. this project's own manifest parser - see independent cross-check below)
- **Independent cross-check vs. pip's own resolver**: 5/8 pip-resolved packages present in the SBOM (recall = 0.625)
  - Missing from SBOM but resolved by pip: itsdangerous, markupsafe, werkzeug

**Vulnerability detection coverage**
- Components scanned: 5
- Components with known vulnerabilities: 5 (100.0%)
- Unique vulnerabilities found: 54
- By severity: {'MEDIUM': 38, 'CRITICAL': 10, 'HIGH': 6}
- In CISA KEV: 0 (source: offline-snapshot:2026-01-15)
- Python vulnerability data source actually used this run: pypi-json-api (OSV-derived) + keyword-severity heuristic fallback (OSV.dev unreachable this run)

**Risk scoring vs. CVSS-only baseline (RQ3)**
- Spearman rank correlation: 1.0
- Top-10 overlap ratio: 1.0
- KEV-listed vulnerabilities: 0

**Cryptographic signing / provenance (RQ2)**
- Tamper detection rate: 100.0% over 20 runs
- Avg sign time: 0.102 ms
- Avg verify time: 3.3424 ms
- Total signing overhead per artifact: 3.4444 ms

**Top 5 risk-ranked vulnerabilities**

| Rank | Component | Vuln ID | Severity | Risk Score | CVSS-only Score | CVSS Rank |
|---|---|---|---|---|---|---|
| 1 | pyyaml@5.3 | PYSEC-2020-96 | CRITICAL | 56.0 | 9.0 | 1 |
| 2 | pyyaml@5.3 | PYSEC-2021-142 | CRITICAL | 56.0 | 9.0 | 2 |
| 3 | pyyaml@5.3 | GHSA-8q59-q68h-6hv4 | CRITICAL | 56.0 | 9.0 | 3 |
| 4 | pyyaml@5.3 | GHSA-6757-jp84-gxfx | CRITICAL | 56.0 | 9.0 | 4 |
| 5 | urllib3@1.24.1 | GHSA-gm62-xv2j-4w53 | CRITICAL | 56.0 | 9.0 | 5 |
