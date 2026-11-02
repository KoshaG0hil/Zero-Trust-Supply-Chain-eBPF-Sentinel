"""
eBPF Kernel Build Sandbox Monitor
Simulates kernel tracepoint interception (kprobe/sys_enter_connect, sys_enter_execve, sys_enter_openat)
to enforce zero-trust runtime boundaries during CI/CD package compilation and installation.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel
import time


class SyscallEvent(BaseModel):
    timestamp: float
    syscall: str  # connect, execve, openat
    pid: int
    process_name: str
    target: str  # IP/Host, File path, or Binary executed
    is_authorized: bool
    policy_violation_reason: Optional[str] = None


class BuildSandboxPolicy(BaseModel):
    allowed_domains: List[str] = ["registry.npmjs.org", "pypi.org", "files.pythonhosted.org"]
    blocked_files: List[str] = ["/etc/shadow", "/root/.aws/credentials", "/var/run/docker.sock", ".env"]
    allow_network: bool = True
    allow_subshells: bool = False


class EbpfBuildMonitor:
    """eBPF kernel probe monitor enforcing build sandbox integrity."""

    def __init__(self, policy: Optional[BuildSandboxPolicy] = None):
        self.policy = policy or BuildSandboxPolicy()
        self.captured_events: List[SyscallEvent] = []
        self.violations: List[SyscallEvent] = []

    def trace_syscall(self, syscall: str, pid: int, process_name: str, target: str) -> SyscallEvent:
        """Evaluates simulated kernel tracepoint against strict build security policy."""
        is_authorized = True
        violation_reason = None

        if syscall == "connect":
            if not self.policy.allow_network:
                is_authorized = False
                violation_reason = "Egress Network Prohibited in Hermetic Build Sandbox"
            elif not any(domain in target for domain in self.policy.allowed_domains):
                is_authorized = False
                violation_reason = f"Unauthorized Outbound Network Connection to {target}"

        elif syscall == "openat":
            if any(blocked in target for blocked in self.policy.blocked_files):
                is_authorized = False
                violation_reason = f"Sensitive Host Path Access Attempt: {target}"

        elif syscall == "execve":
            if not self.policy.allow_subshells and any(sh in target for sh in ["/bin/sh", "/bin/bash", "curl", "wget", "nc"]):
                is_authorized = False
                violation_reason = f"Suspicious Child Process Spawned During Build: {target}"

        event = SyscallEvent(
            timestamp=time.time(),
            syscall=syscall,
            pid=pid,
            process_name=process_name,
            target=target,
            is_authorized=is_authorized,
            policy_violation_reason=violation_reason
        )

        self.captured_events.append(event)
        if not is_authorized:
            self.violations.append(event)

        return event

    def get_audit_summary(self) -> Dict[str, Any]:
        return {
            "total_syscalls_monitored": len(self.captured_events),
            "policy_violations_count": len(self.violations),
            "is_build_compromised": len(self.violations) > 0,
            "violations": [v.model_dump() for v in self.violations]
        }
