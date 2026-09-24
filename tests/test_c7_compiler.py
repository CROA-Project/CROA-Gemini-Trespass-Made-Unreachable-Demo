"""C7 wire-format and HMAC interoperability checks.

Demo role: verify the specified canonical bytes, fields, lifetime, and signature.
Gemini action it addresses: #1–3, binding authorization to exact execution inputs.
Must never import: live services; test code may inspect generated contracts.
"""

import hashlib
import hmac
import json
from dataclasses import asdict
from uuid import UUID

from croa.c7_compiler import ContractCompiler, Signer, canonical_json, parameters_hash
from croa.contracts import Request
from models import CREDENTIAL_ID, CTF_TARGET, Parameters


def test_canonical_parameter_bytes() -> None:
    """Match the canonical JSON specification independently of contract generation."""
    parameters = Parameters(path="/ctf/flag.txt", session_token="session-1")
    expected = b'{"path":"/ctf/flag.txt","session_token":"session-1"}'
    assert canonical_json(parameters.to_dict()).encode() == expected
    assert parameters_hash(parameters) == hashlib.sha256(expected).hexdigest()


def test_contract_fields_signature_and_unique_nonce() -> None:
    """Verify exact contract fields and HMAC against the standard-library primitive."""
    key = b"independent-verification-key"
    compiler = ContractCompiler(Signer(key), clock=lambda: 1000)
    request = Request("login", CTF_TARGET, Parameters(credential_id=CREDENTIAL_ID))
    ecc = compiler.compile_ecc(request)
    fields = asdict(ecc)
    signature = fields.pop("sig")
    assert set(fields) == {
        "ecc_id", "session_id", "subject", "action", "target", "parameters_hash",
        "invariant_set_version", "iat", "exp", "nonce",
    }
    encoded = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    assert signature == hmac.new(key, encoded, hashlib.sha256).hexdigest()
    assert ecc.iat == 1000 and ecc.exp == 1300
    assert ecc.invariant_set_version == "gemini-demo-policy-v1"
    assert UUID(ecc.nonce).version == UUID(ecc.ecc_id).version == 4
    second = compiler.compile_ecc(request)
    assert second.nonce != ecc.nonce and second.ecc_id != ecc.ecc_id
