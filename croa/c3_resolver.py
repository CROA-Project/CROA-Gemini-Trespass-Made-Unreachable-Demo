"""C3 Path Resolver.

CROA component: C3 — grounds a proposed target against the registry.
Gemini action it addresses: #1, resolving a fictional company name to a real host.
Fails closed: unregistered targets, incompatible types, and ambiguous names are
denied before any later control-plane check or contract compilation.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from croa.contracts import Request
from croa.reasons import DENY, PERMIT, TARGET_AMBIGUOUS, TARGET_NOT_REGISTERED
from models import CTF_TARGET, StageTrace


@dataclass(frozen=True)
class RegistryEntry:
    """A known target's identifier, resource type, and optional company name."""

    target: str
    kind: str
    company_name: str | None = None


@dataclass(frozen=True)
class Grounding:
    """C3's verdict and the single concrete target it grounded, if any."""

    verdict: str
    reason: str
    target: str | None = None


FEDERATED_CONTEXT_REGISTRY: Mapping[str, RegistryEntry] = MappingProxyType({
    CTF_TARGET: RegistryEntry(CTF_TARGET, "host", "Orion Logistics"),
    "endpoint:public_repo": RegistryEntry("endpoint:public_repo", "endpoint"),
})


def resolve_target(
    action: str, target: str, *,
    registry: Mapping[str, RegistryEntry] = FEDERATED_CONTEXT_REGISTRY,
) -> Grounding:
    """Ground only an exact registered target with the action's required type.

    Args:
        action: Proposed operation; host actions require a host entry.
        target: Exact identifier proposed by the agent.
        registry: Immutable registry for this run, including any demo flags.
    Returns:
        PERMIT for a compatible entry, otherwise TARGET_NOT_REGISTERED.
    """
    kinds = {"login": "host", "read_file": "host", "read_public_repo": "endpoint"}
    expected_kind = kinds.get(action)
    entry = registry.get(target)
    if entry is None:
        return Grounding(DENY, TARGET_NOT_REGISTERED)
    if entry.kind != expected_kind:
        return Grounding(DENY, TARGET_NOT_REGISTERED)
    return Grounding(PERMIT, PERMIT, target)


def resolve_by_name(
    name: str, *, registry: Mapping[str, RegistryEntry] = FEDERATED_CONTEXT_REGISTRY,
) -> Grounding:
    """Require a company name to identify exactly one registered host.

    Args:
        name: Company name used in the agent's resolution step.
        registry: Registry against which that name must be unambiguous.
    Returns:
        One grounded host, TARGET_AMBIGUOUS, or TARGET_NOT_REGISTERED.
    """
    matches = [entry for entry in registry.values()
               if entry.kind == "host" and entry.company_name == name]
    if len(matches) > 1:
        return Grounding(DENY, TARGET_AMBIGUOUS)
    if not matches:
        return Grounding(DENY, TARGET_NOT_REGISTERED)
    return resolve_target("login", matches[0].target, registry=registry)


class PathResolver:
    """C3's per-run registry and optional name-ambiguity demonstration."""

    def __init__(
        self, registry: Mapping[str, RegistryEntry] = FEDERATED_CONTEXT_REGISTRY,
        *, ambiguous: bool = False,
    ) -> None:
        """Snapshot the registry so callers cannot change it during a proposal."""
        self._registry = MappingProxyType(dict(registry))
        self._ambiguous = ambiguous

    def check(self, request: Request) -> StageTrace:
        """Check optional name ambiguity before grounding the actual proposed target.

        Args:
            request: Proposed target and any company name from agent reasoning.
        Returns:
            C3's PERMIT or DENY trace with its stable reason code.
        """
        if self._ambiguous and request.company_name is not None:
            name = resolve_by_name(request.company_name, registry=self._registry)
            if name.verdict == DENY:
                return StageTrace("C3", DENY, name.reason)
        grounded = resolve_target(
            request.action, request.target, registry=self._registry
        )
        return StageTrace("C3", grounded.verdict, grounded.reason)
