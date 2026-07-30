"""
Unit / integration tests for the SBOM-first DevSecOps pipeline prototype.

Run with:  pytest -v tests/
(run from the project root; conftest-free layout, sys.path is patched below)
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest

from sbom_generate import generate_python_sbom, generate_node_sbom
from vuln_mapper import VulnRecord
from risk_scoring import RiskWeights, score_vulnerabilities, spearman_rank_correlation
from sign_provenance import sign_artifact, verify_envelope, run_tamper_experiment
from build_validate import validate_python_target, validate_node_target
import vuln_mapper

ROOT = Path(__file__).parent.parent
TARGETS = ROOT / "targets"


# --------------------------------------------------------------------------
# SBOM generation / completeness
# --------------------------------------------------------------------------

def test_python_sbom_matches_requirements_txt():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "sbom.json"
        result = generate_python_sbom(TARGETS / "python-sample", out)
        names = {c.name.lower() for c in result.components}
        assert "flask" in names
        assert "pyyaml" in names
        assert result.completeness["precision"] == 1.0
        assert result.completeness["recall"] == 1.0


def test_node_sbom_resolves_transitive_tree():
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "sbom.json"
        result = generate_node_sbom(TARGETS / "node-sample", out)
        # express/lodash/minimist are direct; a real transitive tree has
        # far more entries than the 3 declared in package.json.
        assert len(result.components) > 3
        direct_names = {c.name for c in result.components if c.is_direct}
        assert direct_names == {"express", "lodash", "minimist"}
        assert out.exists()


def test_node_sbom_fails_clearly_without_lockfile():
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp)
        (target / "package.json").write_text('{"name": "x", "dependencies": {}}')
        with pytest.raises(FileNotFoundError):
            generate_node_sbom(target, Path(tmp) / "sbom.json")


# --------------------------------------------------------------------------
# Risk scoring model
# --------------------------------------------------------------------------

def _rec(component, severity, cvss, kev=False, direct=True, epss=None):
    return VulnRecord(
        component=component, version="1.0.0", ecosystem="npm",
        vuln_id=f"TEST-{component}", aliases=[f"CVE-2024-{hash(component) % 9999:04d}"],
        severity=severity, cvss_score=cvss, in_kev=kev,
        is_direct_dependency=direct, epss_score=epss,
    )


def test_kev_listed_lower_cvss_can_outrank_higher_cvss_non_kev():
    """Core hypothesis of RQ3: a KEV-listed, actively-exploited vulnerability
    with a *lower* CVSS score should be prioritised above a higher-CVSS
    vulnerability that is not known to be exploited, once KEV/EPSS signals
    are folded into the composite score."""
    records = [
        _rec("pkg-high-cvss-no-signal", "HIGH", 8.5, kev=False, epss=0.01),
        _rec("pkg-kev-exploited", "MEDIUM", 6.0, kev=True, epss=0.9),
    ]
    scored = score_vulnerabilities(records, dependents_lookup={}, weights=RiskWeights())
    by_component = {s.component: s for s in scored}

    # CVSS-only baseline keeps the higher-CVSS one on top...
    assert by_component["pkg-high-cvss-no-signal"].cvss_rank == 1
    # ...but the composite risk model promotes the actively exploited one.
    assert by_component["pkg-kev-exploited"].risk_rank == 1
    assert by_component["pkg-kev-exploited"].risk_rank < by_component["pkg-high-cvss-no-signal"].risk_rank


def test_spearman_correlation_perfect_agreement_is_one():
    records = [_rec(f"pkg{i}", "HIGH", 9.0 - i, kev=False) for i in range(5)]
    scored = score_vulnerabilities(records, dependents_lookup={}, weights=RiskWeights(
        severity=1.0, exploitability=0.0, kev=0.0, importance=0.0
    ))
    # weights collapse the model to pure-CVSS -> rankings must be identical
    assert spearman_rank_correlation(scored) == 1.0


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        RiskWeights(severity=0.5, exploitability=0.5, kev=0.5, importance=0.5).validate()


# --------------------------------------------------------------------------
# Cryptographic signing / tamper detection
# --------------------------------------------------------------------------

def test_sign_and_verify_untampered_artifact_passes():
    with tempfile.TemporaryDirectory() as tmp:
        artifact = Path(tmp) / "artifact.json"
        artifact.write_text('{"hello": "world"}')
        result, _priv = sign_artifact(artifact, {"repository": "test/repo", "ref": "main"})
        verification = verify_envelope(result.envelope, result.public_key_pem, artifact)
        assert verification.valid


def test_tampered_artifact_fails_verification():
    with tempfile.TemporaryDirectory() as tmp:
        artifact = Path(tmp) / "artifact.json"
        artifact.write_text('{"hello": "world"}')
        result, _priv = sign_artifact(artifact, {"repository": "test/repo", "ref": "main"})

        tampered = Path(tmp) / "artifact_tampered.json"
        tampered.write_text('{"hello": "WORLD! injected payload"}')

        verification = verify_envelope(result.envelope, result.public_key_pem, tampered)
        assert not verification.valid


def test_enrich_with_nvd_parses_real_shaped_response(monkeypatch):
    """NVD's live API is unreachable from this development sandbox (see
    README 'Known limitations'), so this test verifies the parsing/enrichment
    logic against a fixture shaped exactly like a real NVD API 2.0 response
    (field names and nesting taken from NVD's published schema), rather than
    skipping NVD coverage entirely."""
    fake_nvd_response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-30861",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 7.5,
                                    "baseSeverity": "HIGH",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                },
                            }
                        ]
                    },
                }
            }
        ]
    }
    monkeypatch.setattr(vuln_mapper, "_http_get_json", lambda url, timeout=8: fake_nvd_response)
    monkeypatch.setattr(vuln_mapper.time, "sleep", lambda s: None)  # skip real rate-limit delay in tests

    record = VulnRecord(
        component="flask", version="1.0", ecosystem="PyPI", vuln_id="GHSA-m2qf-hxjv-5gpq",
        aliases=["CVE-2023-30861"], severity="MEDIUM", cvss_score=None,
    )
    summary = vuln_mapper.enrich_with_nvd([record], max_lookups=5)

    assert summary["enriched"] == 1
    assert record.cvss_score == 7.5
    assert record.severity == "HIGH"
    assert record.cvss_vector.startswith("CVSS:3.1")


def test_enrich_with_nvd_skips_records_that_already_have_cvss():
    record = VulnRecord(
        component="lodash", version="4.17.4", ecosystem="npm", vuln_id="GHSA-x",
        aliases=["CVE-2020-8203"], severity="HIGH", cvss_score=7.4,  # already has a real score from npm audit
    )
    summary = vuln_mapper.enrich_with_nvd([record])
    assert summary["attempted"] == 0  # nothing needed enrichment, so no NVD calls were made at all


def test_build_validation_detects_resolvable_python_deps():
    result = validate_python_target(TARGETS / "python-sample")
    assert result["buildable"] is True
    assert result["packages_resolved"] >= 5


def test_build_validation_detects_unresolvable_python_deps():
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp)
        # A version of a real package that has never existed and never will.
        (target / "requirements.txt").write_text("flask==999.999.999\n")
        result = validate_python_target(target)
        assert result["buildable"] is False


def test_build_validation_detects_resolvable_node_deps():
    result = validate_node_target(TARGETS / "node-sample")
    assert result["buildable"] is True


def test_build_validation_python_reports_structured_resolved_names():
    """The independent SBOM cross-check (evaluate.py::_cross_check_python_sbom_against_pip)
    depends on build_validate.py returning real package NAMES, not just a
    count, from pip's structured --report output - this was added after a
    self-audit found the SBOM completeness metric was circular (compared
    against this project's own requirements.txt parser). Confirm the
    structured path is actually what's exercised for a normal target."""
    result = validate_python_target(TARGETS / "python-sample")
    assert result["buildable"] is True
    assert result["resolved_package_names"] is not None
    names_lower = {n.lower() for n in result["resolved_package_names"]}
    assert "flask" in names_lower
    assert "requests" in names_lower


# --------------------------------------------------------------------------
# CVSS v3.1 base-score calculation (real formula, not a heuristic)
# --------------------------------------------------------------------------

def test_cvss3_base_score_matches_known_vectors():
    """Verified against FIRST.org's own worked examples for CVSS v3.1: a
    fully-critical vector (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) scores 9.8,
    and a network DoS-only vector (C:N/I:N/A:H, otherwise identical) scores
    7.5 - both are widely-cited reference values for these exact vectors."""
    critical = vuln_mapper.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert critical == 9.8

    dos_only = vuln_mapper.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")
    assert dos_only == 7.5


def test_cvss3_base_score_handles_malformed_vector():
    assert vuln_mapper.cvss3_base_score(None) is None
    assert vuln_mapper.cvss3_base_score("not-a-real-vector") is None


def test_cvss3_severity_band_matches_official_ranges():
    assert vuln_mapper.cvss3_severity_band(9.8) == "CRITICAL"
    assert vuln_mapper.cvss3_severity_band(7.5) == "HIGH"
    assert vuln_mapper.cvss3_severity_band(5.0) == "MEDIUM"
    assert vuln_mapper.cvss3_severity_band(2.0) == "LOW"
    assert vuln_mapper.cvss3_severity_band(0.0) == "NONE"
    assert vuln_mapper.cvss3_severity_band(None) == "UNKNOWN"


# --------------------------------------------------------------------------
# Python vulnerability mapping: OSV-first, heuristic-fallback (addresses a
# self-audit finding that the OSV path was previously dead code - see
# docs/PROFESSOR_REVIEW.md, "Python severity data")
# --------------------------------------------------------------------------

class _FakeComponent:
    def __init__(self, name, version):
        self.name = name
        self.version = version
        self.is_direct = True
        self.depth = 0


def test_map_python_vulnerabilities_uses_osv_when_reachable(monkeypatch):
    fake_records = [
        VulnRecord(component="flask", version="1.0", ecosystem="PyPI", vuln_id="OSV-TEST-1",
                   source="osv.dev (real CVSS v3.1 vector, base score computed locally)")
    ]
    monkeypatch.setattr(vuln_mapper, "map_python_vulnerabilities_osv", lambda components: fake_records)
    records, source = vuln_mapper.map_python_vulnerabilities([_FakeComponent("flask", "1.0")])
    assert records is fake_records
    assert "osv.dev" in source


def test_map_python_vulnerabilities_falls_back_when_osv_unreachable(monkeypatch):
    monkeypatch.setattr(vuln_mapper, "map_python_vulnerabilities_osv", lambda components: None)
    monkeypatch.setattr(vuln_mapper, "_http_get_json", lambda url, timeout=8: None)  # PyPI also unreachable
    records, source = vuln_mapper.map_python_vulnerabilities([_FakeComponent("flask", "1.0")])
    assert records == []  # PyPI unreachable too, so no records, but the call path itself must not crash
    assert "fallback" in source.lower()


def test_tamper_experiment_reports_full_detection_rate():
    with tempfile.TemporaryDirectory() as tmp:
        artifact = Path(tmp) / "sbom.json"
        artifact.write_text('{"bomFormat": "CycloneDX", "components": []}')
        report = run_tamper_experiment(artifact, {"repository": "test/repo"}, n_runs=10)
        assert report["tamper_detection_rate"] == 1.0
        assert report["baseline_verification_passed"] is True
        assert report["avg_sign_time_ms"] < 50  # sanity bound, not a hard perf requirement
