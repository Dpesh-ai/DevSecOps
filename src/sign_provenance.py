"""
Cryptographic signing & provenance stage of the SBOM-first DevSecOps pipeline.

This module answers RQ2 from the Terms of Reference:
    "Can cryptographic provenance techniques improve build artefact
    integrity and traceability without introducing significant performance
    cost?"

Design note - why a self-contained Ed25519/DSSE implementation instead of
shelling out to the real `cosign` binary
------------------------------------------------------------------------
The production pipeline (see .github/workflows/pipeline.yml) uses Sigstore
Cosign in **keyless** mode: `cosign sign-blob --yes`, which obtains a
short-lived certificate from Fulcio via GitHub Actions' OIDC token and
records the signature in the public Rekor transparency log. That is the
real, industry-standard mechanism this project evaluates.

For local development, unit testing and offline reproducibility (a
GitHub Actions runner or a reviewer's machine without network access to
Fulcio/Rekor), this module implements the same *conceptual* workflow -
DSSE (Dead Simple Signing Envelope) attestations over an in-toto-style
provenance predicate, signed with Ed25519 - using only Python's
`cryptography` library. The envelope format, the fields captured, and the
tamper-detection property being tested are the same as cosign's; only the
transparency-log and Fulcio-certificate steps are out of scope for the
offline path. This lets the experiments in evaluate.py run deterministically
in CI without depending on external OIDC infrastructure being reachable.
"""
from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


@dataclass
class SigningResult:
    envelope: dict
    public_key_pem: str
    sign_duration_ms: float


@dataclass
class VerificationResult:
    valid: bool
    reason: str
    verify_duration_ms: float


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def build_provenance_statement(artifact_path: Path, build_metadata: dict) -> dict:
    """Builds an in-toto v1 Statement whose predicate follows the SLSA
    Provenance shape (builder id, invocation, materials). This is the
    payload that gets wrapped in a DSSE envelope and signed - conceptually
    identical to what `cosign attest`/GitHub's `attest-build-provenance`
    action produces."""
    digest_hex = _sha256_file(artifact_path)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": artifact_path.name,
                "digest": {"sha256": digest_hex},
            }
        ],
        "predicateType": PROVENANCE_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/actions/runs",
                "externalParameters": {
                    "repository": build_metadata.get("repository", "unknown"),
                    "ref": build_metadata.get("ref", "unknown"),
                },
            },
            "runDetails": {
                "builder": {"id": build_metadata.get("builder_id", "local-prototype-builder")},
                "metadata": {
                    "invocationId": build_metadata.get("invocation_id", "local-run"),
                    "startedOn": datetime.now(timezone.utc).isoformat(),
                },
            },
        },
    }


def _canonical_json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_artifact(artifact_path: Path, build_metadata: dict) -> tuple[SigningResult, Ed25519PrivateKey]:
    priv, pub = generate_keypair()
    statement = build_provenance_statement(artifact_path, build_metadata)
    payload_bytes = _canonical_json_bytes(statement)

    # DSSE pre-authentication encoding: PAE(type, body)
    pae = _pae(DSSE_PAYLOAD_TYPE, payload_bytes)

    start = time.perf_counter()
    signature = priv.sign(pae)
    duration_ms = (time.perf_counter() - start) * 1000

    envelope = {
        "payload": base64.b64encode(payload_bytes).decode(),
        "payloadType": DSSE_PAYLOAD_TYPE,
        "signatures": [
            {
                "keyid": _keyid(pub),
                "sig": base64.b64encode(signature).decode(),
            }
        ],
    }
    return SigningResult(
        envelope=envelope,
        public_key_pem=pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
        sign_duration_ms=round(duration_ms, 4),
    ), priv


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding, per the DSSE spec used by
    Sigstore/in-toto: PAE(type, body) =
        "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body
    """
    parts = [
        b"DSSEv1",
        str(len(payload_type)).encode(),
        payload_type.encode(),
        str(len(payload)).encode(),
        payload,
    ]
    return b" ".join(parts)


def _keyid(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def verify_envelope(envelope: dict, public_key_pem: str, expected_artifact_path: Path) -> VerificationResult:
    start = time.perf_counter()
    try:
        pub = serialization.load_pem_public_key(public_key_pem.encode())
        payload_bytes = base64.b64decode(envelope["payload"])
        pae = _pae(envelope["payloadType"], payload_bytes)
        sig = base64.b64decode(envelope["signatures"][0]["sig"])
        pub.verify(sig, pae)  # raises InvalidSignature on mismatch

        # Additionally re-check the digest inside the payload against the
        # artifact currently on disk - this is what actually catches
        # "the artifact was swapped/tampered after signing" tampering,
        # as opposed to "the signature bytes were corrupted".
        statement = json.loads(payload_bytes)
        expected_digest = statement["subject"][0]["digest"]["sha256"]
        actual_digest = _sha256_file(expected_artifact_path)
        if expected_digest != actual_digest:
            duration_ms = (time.perf_counter() - start) * 1000
            return VerificationResult(
                valid=False,
                reason=(
                    f"Signature is cryptographically valid but the artifact digest "
                    f"does not match what was signed (expected {expected_digest[:12]}…, "
                    f"got {actual_digest[:12]}…). The artifact was modified after signing."
                ),
                verify_duration_ms=round(duration_ms, 4),
            )
        duration_ms = (time.perf_counter() - start) * 1000
        return VerificationResult(valid=True, reason="signature and digest verified", verify_duration_ms=round(duration_ms, 4))
    except InvalidSignature:
        duration_ms = (time.perf_counter() - start) * 1000
        return VerificationResult(valid=False, reason="invalid signature", verify_duration_ms=round(duration_ms, 4))
    except Exception as e:  # noqa: BLE001 - surfaced to the caller/report deliberately
        duration_ms = (time.perf_counter() - start) * 1000
        return VerificationResult(valid=False, reason=f"verification error: {e}", verify_duration_ms=round(duration_ms, 4))


# --------------------------------------------------------------------------
# Controlled tamper-detection experiment (ToR Stage 6 / Section 5.6)
# --------------------------------------------------------------------------

def run_tamper_experiment(artifact_path: Path, build_metadata: dict, n_runs: int = 20) -> dict:
    """Signs the artifact, verifies the untampered case, then flips a single
    byte in a *copy* of the artifact and verifies again, repeated n_runs
    times to obtain stable overhead timings. Returns a full experiment
    report used by evaluate.py."""
    sign_times, verify_ok_times, verify_tampered_times = [], [], []
    baseline_ok = None
    tamper_detected_count = 0

    for i in range(n_runs):
        result, _priv = sign_artifact(artifact_path, build_metadata)  # ephemeral per-run keypair, unused here
        sign_times.append(result.sign_duration_ms)

        ok = verify_envelope(result.envelope, result.public_key_pem, artifact_path)
        verify_ok_times.append(ok.verify_duration_ms)
        if baseline_ok is None:
            baseline_ok = ok.valid

        data = bytearray(artifact_path.read_bytes())
        data[0] = data[0] ^ 0xFF  # flip bits in the first byte
        with tempfile.TemporaryDirectory() as tmpdir:
            tampered_copy = Path(tmpdir) / (artifact_path.name + ".tampered")
            tampered_copy.write_bytes(bytes(data))
            tampered_check = verify_envelope(result.envelope, result.public_key_pem, tampered_copy)
        verify_tampered_times.append(tampered_check.verify_duration_ms)
        if not tampered_check.valid:
            tamper_detected_count += 1

    def _avg(xs):
        return round(sum(xs) / len(xs), 4) if xs else 0.0

    return {
        "runs": n_runs,
        "baseline_verification_passed": baseline_ok,
        "tamper_detection_rate": round(tamper_detected_count / n_runs, 4),
        "avg_sign_time_ms": _avg(sign_times),
        "avg_verify_time_ms_untampered": _avg(verify_ok_times),
        "avg_verify_time_ms_tampered": _avg(verify_tampered_times),
        "total_signing_overhead_ms_per_artifact": _avg(sign_times) + _avg(verify_ok_times),
    }
