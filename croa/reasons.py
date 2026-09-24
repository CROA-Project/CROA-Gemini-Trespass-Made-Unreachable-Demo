"""Stable outcome and denial vocabulary.

CROA component: shared reason codes for the control plane and target outcomes.
Gemini action it addresses: #1–3, making each execution decision explainable.
Fails closed: components return named denial codes instead of silent rejection.
"""

# Control plane and C6 emit PERMIT when their applicable checks pass.
PERMIT = "PERMIT"
# Control plane and C6 emit DENY when an execution request is rejected.
DENY = "DENY"
# C3 emits TARGET_NOT_REGISTERED for an absent target or incompatible action/type.
TARGET_NOT_REGISTERED = "TARGET_NOT_REGISTERED"
# C3 emits TARGET_AMBIGUOUS when multiple registered targets match a name.
TARGET_AMBIGUOUS = "TARGET_AMBIGUOUS"
# C2 (and C6's credential lookup) emits this for an unknown or wrongly-bound ID.
CREDENTIAL_NOT_ISSUED = "CREDENTIAL_NOT_ISSUED"
# C2 and C6 emit this when authentication does not match C1's permitted modes.
AUTH_MODE_NOT_PERMITTED = "AUTH_MODE_NOT_PERMITTED"
# C2 and C6 emit this for unmatched policy; C6 also rejects unsupported operations.
ACTION_NOT_PERMITTED = "ACTION_NOT_PERMITTED"
# C4 emits TRAJECTORY_LIMIT_EXCEEDED when an authentication limit would be exceeded.
TRAJECTORY_LIMIT_EXCEEDED = "TRAJECTORY_LIMIT_EXCEEDED"
# C6 emits MISSING_ECC when execution is attempted without a contract.
MISSING_ECC = "MISSING_ECC"
# C6 emits INVALID_SIGNATURE when the presented signature does not authenticate ECC.
INVALID_SIGNATURE = "INVALID_SIGNATURE"
# C6 emits SUBJECT_MISMATCH for a signed subject or session unlike its trusted caller.
SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
# C6 emits ECC_EXPIRED when the signed expiration time has been reached.
ECC_EXPIRED = "ECC_EXPIRED"
# C6 emits PARAMETER_MISMATCH when the proposed execution inputs differ from the ECC.
PARAMETER_MISMATCH = "PARAMETER_MISMATCH"
# C6 emits ECC_REPLAYED when the contract nonce has already been consumed.
ECC_REPLAYED = "ECC_REPLAYED"
# World emits AUTH_FAILED when authentication inputs do not match the target.
AUTH_FAILED = "AUTH_FAILED"
# World emits SESSION_GRANTED when target authentication succeeds.
SESSION_GRANTED = "SESSION_GRANTED"
# World emits SESSION_REQUIRED when a read lacks a session bound to that host.
SESSION_REQUIRED = "SESSION_REQUIRED"
# C6 and the ungoverned adapter emit FILE_READ after a successful target read.
FILE_READ = "FILE_READ"
# C6 emits TARGET_NOT_FOUND when a contracted target does not exist in the World.
TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
# C6 emits FILE_NOT_FOUND when the authenticated host lacks the requested file.
FILE_NOT_FOUND = "FILE_NOT_FOUND"
# C5 emits OK when every stored record belongs to the intact hash chain.
OK = "OK"
# C5 emits CHAIN_BROKEN at the first malformed or inconsistent stored record.
CHAIN_BROKEN = "CHAIN_BROKEN"
