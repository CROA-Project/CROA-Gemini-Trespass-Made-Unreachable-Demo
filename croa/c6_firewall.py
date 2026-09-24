"""C6 Execution Firewall.

CROA component: C6 — the governed execution boundary and secret injector.
Gemini action it addresses: #1–3, requiring an unchanged, single-use authorization.
Fails closed: presence, signature, identity, expiry, parameters, then replay are
checked before World execution; secrets are injected only after admission.
C1 policy is rechecked after replay validation using the same evaluator as C2.
"""

import time
from collections.abc import Callable
from dataclasses import replace

from croa import reasons
from croa.c1_policy import lookup_credential
from croa.c2_governor import evaluate
from croa.c5_evidence import EvidenceLog
from croa.c7_compiler import Signer
from croa.contracts import ECC, Request
from croa.serialization import parameters_hash
from models import ExecutionResult, Parameters, StageTrace
from world.hosts import World


class ExecutionFirewall:
    """Verify contracts and consume nonces before any governed target effect."""

    def __init__(
        self, signer: Signer, world: World, evidence: EvidenceLog, *,
        clock: Callable[[], float] = time.time, session_id: str = "demo-session",
        subject: str = "agent:gemini-replay",
    ) -> None:
        """Attach trusted execution dependencies and the expected caller identity."""
        self._signer, self._world, self._evidence = signer, world, evidence
        self._clock, self._session_id, self._subject = clock, session_id, subject
        self._nonces: set[str] = set()

    def execute(self, ecc: ECC | None, parameters: Parameters) -> ExecutionResult:
        """Verify, consume, and execute a contract, logging admission and outcome.

        Args:
            ecc: Presented contract, or None for a bypass attempt.
            parameters: Exact inputs the caller intends to execute.
        Returns:
            A named denial or the result of the admitted World operation.
        Raises:
            OSError: If required evidence cannot be stored.
            ValueError: If the evidence chain is already corrupt.
        """
        reason = self._rejection(ecc, parameters)
        if reason is not None:
            self._record("ECC_REJECTED", ecc, reason)
            trace = StageTrace("C6", reasons.DENY, reason)
            return ExecutionResult(False, reason, traces=[trace])
        assert ecc is not None
        self._record("ECC_ADMITTED", ecc, reasons.PERMIT)
        self._nonces.add(ecc.nonce)
        outcome = self._execute_world(ecc, parameters)
        self._record("WORLD_OUTCOME", ecc, outcome.reason)
        trace = StageTrace("C6", reasons.PERMIT, reasons.PERMIT, "exec")
        return replace(outcome, traces=[trace])

    def public_repo_read(self, repo_id: str) -> str:
        """Expose public source material outside the governed action set.

        Args:
            repo_id: Public repository used by the scripted reasoning step.
        Returns:
            Public configuration text, without any privileged host read.
        Raises:
            KeyError: If the repository does not exist.
        """
        return self._world.public_repo_read(repo_id)

    def _rejection(self, ecc: ECC | None, parameters: Parameters) -> str | None:
        """Return the first failed check in the prescribed C6 order."""
        if ecc is None:
            return reasons.MISSING_ECC
        if not isinstance(ecc, ECC):
            return reasons.INVALID_SIGNATURE
        try:
            valid = self._signer.verify(ecc.payload(), ecc.sig)
        except (TypeError, ValueError):
            valid = False
        identity_matches = (
            ecc.subject == self._subject and ecc.session_id == self._session_id
        )
        if not valid:
            return reasons.INVALID_SIGNATURE
        if not identity_matches:
            return reasons.SUBJECT_MISMATCH
        if self._clock() >= ecc.exp:
            return reasons.ECC_EXPIRED
        if parameters_hash(parameters) != ecc.parameters_hash:
            return reasons.PARAMETER_MISMATCH
        if ecc.nonce in self._nonces:
            return reasons.ECC_REPLAYED
        verdict = evaluate(Request(ecc.action, ecc.target, parameters))
        return verdict.reason if verdict.verdict == reasons.DENY else None

    def _execute_world(self, ecc: ECC, parameters: Parameters) -> ExecutionResult:
        """Dispatch admitted actions without ever giving the agent an issued secret."""
        if ecc.action not in ("login", "read_file"):
            return ExecutionResult(False, reasons.ACTION_NOT_PERMITTED)
        if ecc.target not in self._world.hosts:
            return ExecutionResult(False, reasons.TARGET_NOT_FOUND)
        if ecc.action == "login":
            return self._login(ecc.target, parameters)
        try:
            contents = self._world.read_file(
                ecc.target, parameters.session_token, parameters.path or ""
            )
        except PermissionError:
            return ExecutionResult(False, reasons.SESSION_REQUIRED)
        except KeyError:
            return ExecutionResult(False, reasons.FILE_NOT_FOUND)
        return ExecutionResult(True, reasons.FILE_READ, data=contents)

    def _login(self, target: str, parameters: Parameters) -> ExecutionResult:
        """Resolve an issued reference only inside the admitted execution boundary."""
        if parameters.credential_id is None:
            login = self._world.login(target, password=parameters.password)
        else:
            credential = lookup_credential(parameters.credential_id, target)
            if credential is None:
                return ExecutionResult(False, reasons.CREDENTIAL_NOT_ISSUED)
            login = self._world.login(target, secret=credential.secret)
        return ExecutionResult(login.success, login.reason, login.session_token)

    def _record(self, event: str, ecc: ECC | None, reason: str) -> None:
        """Record contract identity and outcome without logging injected secrets."""
        data = {
            "ecc_id": ecc.ecc_id if isinstance(ecc, ECC) else None, "reason": reason,
        }
        if event in ("ECC_ADMITTED", "ECC_REJECTED"):
            verdict = reasons.DENY if event == "ECC_REJECTED" else reasons.PERMIT
            data["verdict"] = verdict
        self._evidence.append({
            "component": "C6", "event": event, "data": data,
        })
