"""C3 registry and ambiguity checks.

Demo role: verify grounding without allowing any World effects.
Gemini action it addresses: #1, confusing a fictional company with a real host.
Must never import: world or signing/firewall implementations.
"""

import pytest

from croa.c3_resolver import (
    FEDERATED_CONTEXT_REGISTRY,
    PathResolver,
    RegistryEntry,
    resolve_by_name,
    resolve_target,
)
from croa.contracts import Request
from croa.reasons import DENY, PERMIT, TARGET_AMBIGUOUS, TARGET_NOT_REGISTERED
from models import CTF_TARGET, REAL_TARGET, Parameters
from runtime import RegistryOptions, build_registry


@pytest.mark.parametrize("action,target", [
    ("login", CTF_TARGET), ("read_file", CTF_TARGET),
    ("read_public_repo", "endpoint:public_repo"),
])
def test_registered(action: str, target: str) -> None:
    """Ground each compatible registered target to its exact identifier."""
    result = resolve_target(action, target)
    assert result.verdict == PERMIT and result.reason == PERMIT
    assert result.target == target
    assert set(FEDERATED_CONTEXT_REGISTRY) == {CTF_TARGET, "endpoint:public_repo"}


@pytest.mark.parametrize("target", [
    REAL_TARGET, "", "Orion Logistics", CTF_TARGET + "/",
])
def test_unregistered(target: str) -> None:
    """Reject unregistered and malformed identifiers instead of guessing a host."""
    result = resolve_target("login", target)
    assert result.verdict == DENY and result.reason == TARGET_NOT_REGISTERED
    assert result.target is None


@pytest.mark.parametrize("action,target", [
    ("login", "endpoint:public_repo"), ("read_file", "endpoint:public_repo"),
    ("read_public_repo", CTF_TARGET), ("unknown_action", CTF_TARGET),
])
def test_type_mismatch(action: str, target: str) -> None:
    """An entry registered for another resource type cannot ground the action."""
    result = resolve_target(action, target)
    assert result.verdict == DENY and result.reason == TARGET_NOT_REGISTERED


def test_inconsistent_entry_type() -> None:
    """A host-shaped ID with endpoint metadata cannot ground a host action."""
    registry = {CTF_TARGET: RegistryEntry(CTF_TARGET, "endpoint")}
    assert resolve_target("login", CTF_TARGET, registry=registry).verdict == DENY


def test_name_requires_one_registered_match() -> None:
    """Resolve a unique company but reject missing or ambiguous company names."""
    assert resolve_by_name("Orion Logistics").target == CTF_TARGET
    assert resolve_by_name("Unknown").reason == TARGET_NOT_REGISTERED
    registry = build_registry(RegistryOptions(ambiguous=True))
    result = resolve_by_name("Orion Logistics", registry=registry)
    assert result.verdict == DENY and result.reason == TARGET_AMBIGUOUS
    assert result.target is None


def test_registry_flags_are_isolated() -> None:
    """Flagged registries cannot mutate later runs or C3's default registry."""
    flagged = build_registry(RegistryOptions(ambiguous=True, registry_mistake=True))
    assert len(flagged) == 4 and REAL_TARGET in flagged
    assert resolve_target("login", REAL_TARGET, registry=flagged).verdict == PERMIT
    assert set(build_registry()) == {CTF_TARGET, "endpoint:public_repo"}
    with pytest.raises(TypeError):
        flagged[REAL_TARGET] = RegistryEntry(REAL_TARGET, "host")


def test_name_check_never_substitutes_a_registered_target() -> None:
    """A unique registered company match cannot authorize the wrong actual host."""
    resolver = PathResolver(ambiguous=True)
    request = Request(
        "login", REAL_TARGET, Parameters(), company_name="Orion Logistics"
    )
    assert resolver.check(request).reason == TARGET_NOT_REGISTERED


def test_resolver_snapshots_registry() -> None:
    """Later mutations to the input mapping cannot widen the resolver's authority."""
    registry = dict(FEDERATED_CONTEXT_REGISTRY)
    resolver = PathResolver(registry)
    registry[REAL_TARGET] = RegistryEntry(REAL_TARGET, "host")
    assert resolver.check(Request("login", REAL_TARGET, Parameters())).verdict == DENY
