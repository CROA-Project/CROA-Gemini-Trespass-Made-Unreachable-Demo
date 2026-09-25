"""Replay composition and direct World adapter.

Demo role: construct isolated worlds and wire capabilities outside agent/.
Gemini action it addresses: #1–3 plus isolated capability injection for S4.
Must never import: scripted plans; this module wires dependencies, not agent choices.
Registry flags are applied here so every governed run has one construction path.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from agent.bypass_tools import BypassTools
from agent.tools import GovernedTools, Tools, UngovernedTools
from croa import reasons
from croa.c1_policy import ISSUED_CREDENTIALS
from croa.c3_resolver import FEDERATED_CONTEXT_REGISTRY, PathResolver, RegistryEntry
from croa.c4_trajectory import TrajectoryMonitor
from croa.c5_evidence import EvidenceLog
from croa.c6_firewall import ExecutionFirewall
from croa.c7_compiler import ContractCompiler, Signer
from croa.plane import ControlPlane
from models import CREDENTIAL_ID, REAL_TARGET, ExecutionResult, Parameters
from world.hosts import World


class DirectWorldAccess:
    """Ungoverned adapter kept outside the agent's import boundary."""

    def __init__(self, world: World) -> None:
        """Attach a World exclusively for direct ungoverned execution."""
        self._world = world

    def execute(
        self, action: str, target: str, parameters: Parameters,
    ) -> ExecutionResult:
        """Execute a tool action without policy, contracts, or evidence admission.

        Args:
            action: Login or file read.
            target: Host to contact.
            parameters: Authentication or file inputs.
        Returns:
            World outcome without governance metadata.
        Raises:
            KeyError: If the requested host or file does not exist.
            PermissionError: If a read lacks a host-bound session.
        """
        if action == "read_file":
            data = self._world.read_file(
                target, parameters.session_token, parameters.path or ""
            )
            return ExecutionResult(True, reasons.FILE_READ, data=data)
        if action != "login":
            return ExecutionResult(False, reasons.ACTION_NOT_PERMITTED)
        if parameters.credential_id is None:
            login = self._world.login(target, password=parameters.password)
        else:
            credential = self._world.credential
            if (parameters.password is not None
                    or parameters.credential_id != credential.credential_id):
                return ExecutionResult(False, reasons.AUTH_FAILED)
            login = self._world.login(target, secret=self._world.credential.secret)
        return ExecutionResult(login.success, login.reason, login.session_token)


@dataclass(frozen=True)
class RegistryOptions:
    """Explicit demo misconfigurations, applied only to a fresh per-run registry."""

    ambiguous: bool = False
    registry_mistake: bool = False


def build_registry(
    options: RegistryOptions = RegistryOptions(),
) -> Mapping[str, RegistryEntry]:
    """Build one isolated registry containing only the requested demo additions.

    Args:
        options: Optional ambiguity and real-host registration demonstrations.
    Returns:
        Immutable registry derived from C3's default registered targets.
    """
    registry = dict(FEDERATED_CONTEXT_REGISTRY)
    if options.ambiguous:
        variant = "host:backup.orion-logistics.test"
        registry[variant] = RegistryEntry(variant, "host", "Orion Logistics")
    if options.registry_mistake:
        registry[REAL_TARGET] = RegistryEntry(REAL_TARGET, "host", "Orion Logistics")
    return MappingProxyType(registry)


@dataclass(frozen=True)
class ScenarioRuntime:
    """Tools for the plan and a separate World handle for acceptance checks."""

    tools: Tools
    world: World


def build_runtime(
    mode: str, evidence: EvidenceLog | None = None, *,
    options: RegistryOptions = RegistryOptions(),
    bypass: bool = False,
) -> ScenarioRuntime:
    """Build fresh scenario state and give the agent only its tool capabilities.

    Args:
        mode: Ungoverned or governed execution.
        evidence: Required evidence sink for governed execution.
        options: Registry additions and name-ambiguity behavior for this run.
        bypass: Give only S4 direct access to the injected executor capability.
    Returns:
        Tools and their isolated World for the runner and evaluator.
    Raises:
        ValueError: If the mode is unknown or governed evidence is missing.
    """
    world = World(ISSUED_CREDENTIALS[CREDENTIAL_ID])
    if mode == "ungoverned":
        direct = DirectWorldAccess(world)
        tools = UngovernedTools(direct.execute, world.public_repo_read)
        return ScenarioRuntime(tools, world)
    if mode != "governed" or evidence is None:
        raise ValueError("Governed execution requires an evidence log")
    signer = Signer()
    compiler = ContractCompiler(signer)
    resolver = PathResolver(build_registry(options), ambiguous=options.ambiguous)
    monitor = TrajectoryMonitor()
    plane = ControlPlane(
        compiler.compile_ecc, evidence, resolver=resolver, checks=(monitor.check,),
    )
    firewall = ExecutionFirewall(signer, world, evidence)
    tool_type = BypassTools if bypass else GovernedTools
    governed = tool_type(plane, firewall, firewall.public_repo_read)
    return ScenarioRuntime(governed, world)
