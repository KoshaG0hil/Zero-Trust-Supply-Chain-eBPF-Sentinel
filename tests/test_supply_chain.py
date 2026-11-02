"""
Unit Tests for Zero-Trust Supply Chain eBPF Sentinel
"""

import pytest
from core.ebpf_monitor import EbpfBuildMonitor, BuildSandboxPolicy
from core.slsa_provenance import SlsaProvenanceEngine
from core.sigstore_verifier import SigstoreCosignGate


def test_ebpf_legitimate_build():
    monitor = EbpfBuildMonitor()
    ev1 = monitor.trace_syscall("openat", 100, "python3", "setup.py")
    ev2 = monitor.trace_syscall("connect", 100, "pip", "pypi.org:443")

    assert ev1.is_authorized is True
    assert ev2.is_authorized is True
    assert monitor.get_audit_summary()["is_build_compromised"] is False


def test_ebpf_catch_c2_network_beacon():
    monitor = EbpfBuildMonitor()
    bad_event = monitor.trace_syscall("connect", 200, "curl", "attacker-c2.evil.com:8080")

    assert bad_event.is_authorized is False
    assert "Unauthorized Outbound Network Connection" in bad_event.policy_violation_reason
    assert monitor.get_audit_summary()["is_build_compromised"] is True


def test_ebpf_catch_credential_theft():
    monitor = EbpfBuildMonitor()
    bad_event = monitor.trace_syscall("openat", 201, "python", "/root/.aws/credentials")

    assert bad_event.is_authorized is False
    assert "Sensitive Host Path Access Attempt" in bad_event.policy_violation_reason


def test_slsa_provenance_schema():
    prov = SlsaProvenanceEngine.generate_provenance(
        artifact_name="app:v1",
        artifact_digest="sha256:abc123",
        builder_id="builder-1",
        repo_uri="https://github.com/test/repo",
        commit_sha="commit-123",
        hermetic_build=True,
        ebpf_verified=True,
        dependencies=[]
    )

    assert prov["_type"] == "https://in-toto.io/Statement/v1"
    assert prov["predicateType"] == "https://slsa.dev/provenance/v1"
    assert prov["predicate"]["buildDefinition"]["systemParameters"]["ebpfKernelTraceVerified"] is True


def test_sigstore_admission_gate():
    payload = {"test": "data"}
    sig = SigstoreCosignGate.simulate_keyless_sign(payload, "https://token.actions.githubusercontent.com", "KoshaG0hil/repo")

    # Clean build -> admitted
    clean_audit = {"is_build_compromised": False, "policy_violations_count": 0}
    admitted, msg = SigstoreCosignGate.evaluate_admission_policy(sig, "https://token.actions.githubusercontent.com", "KoshaG0hil", clean_audit)
    assert admitted is True

    # Compromised build -> denied
    dirty_audit = {"is_build_compromised": True, "policy_violations_count": 3}
    denied, msg2 = SigstoreCosignGate.evaluate_admission_policy(sig, "https://token.actions.githubusercontent.com", "KoshaG0hil", dirty_audit)
    assert denied is False
    assert "compromised" in msg2
