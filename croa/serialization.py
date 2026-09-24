"""Canonical serialization for evidence and contracts.

CROA component: C5/C7/C6 — stable bytes for hashes and signatures.
Gemini action it addresses: #1–3, preventing execution inputs from changing unnoticed.
Fails closed: non-JSON inputs cannot be signed or hashed.
"""

import hashlib
import json

from models import Parameters


def canonical_json(value: object) -> str:
    """Serialize JSON data identically for signing and verification.

    Args:
        value: JSON-compatible data.
    Returns:
        Sorted JSON without insignificant whitespace.
    Raises:
        TypeError: If a value cannot be serialized as JSON.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def parameters_hash(parameters: Parameters) -> str:
    """Bind all supplied execution parameters to their canonical JSON digest.

    Args:
        parameters: Exact inputs intended for execution.
    Returns:
        SHA-256 hexadecimal digest of the parameter mapping.
    """
    return hashlib.sha256(canonical_json(parameters.to_dict()).encode()).hexdigest()
