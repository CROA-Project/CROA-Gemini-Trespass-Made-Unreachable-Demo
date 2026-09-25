"""Trusted fixtures for contract-boundary tests.

Demo role: construct controllable C7 and C6 dependencies for negative tests.
Gemini action it addresses: #1–3, verifying that rejected contracts have no effects.
Must never import: live services; test code may construct trusted infrastructure.
"""

from dataclasses import dataclass
from pathlib import Path

import pytest

from croa.c5_evidence import EvidenceLog
from croa.c6_firewall import ExecutionFirewall
from croa.c7_compiler import ContractCompiler, Signer
from croa.contracts import ECC, Request
from models import CREDENTIAL_ID, CTF_TARGET, Parameters
from world.hosts import World


@dataclass
class Clock:
    """A controllable clock shared by contract compilation and redemption."""

    now: float = 1000

    def __call__(self) -> float:
        """Return the test's current timestamp.

        Returns:
            Seconds since the test's epoch.
        """
        return self.now


@dataclass
class FirewallCase:
    """A fresh signed login with a fixed clock and inspectable World effects."""

    signer: Signer
    compiler: ContractCompiler
    firewall: ExecutionFirewall
    world: World
    evidence: EvidenceLog
    parameters: Parameters
    ecc: ECC
    clock: Clock


@pytest.fixture
def boundary(tmp_path: Path) -> FirewallCase:
    """Give each test an isolated C6 nonce set, World, and evidence file."""
    signer = Signer(b"test-only-hmac-key")
    world = World()
    evidence = EvidenceLog(tmp_path / "evidence.jsonl")
    clock = Clock()
    compiler = ContractCompiler(signer, clock=clock)
    firewall = ExecutionFirewall(signer, world, evidence, clock=clock)
    parameters = Parameters(credential_id=CREDENTIAL_ID)
    ecc = compiler.compile_ecc(Request("login", CTF_TARGET, parameters))
    return FirewallCase(
        signer, compiler, firewall, world, evidence, parameters, ecc, clock
    )
