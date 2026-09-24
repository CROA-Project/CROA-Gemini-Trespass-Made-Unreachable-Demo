"""C5 persisted evidence-chain checks.

Demo role: verify append, reopen, tamper detection, and broken-link reporting.
Gemini action it addresses: #1–3, preserving inspectable execution evidence.
Must never import: world or signing/firewall implementations.
"""

import json
from pathlib import Path

import pytest

from croa.c5_evidence import EvidenceLog
from croa.reasons import CHAIN_BROKEN, OK


def test_append_verify_and_reopen(tmp_path: Path) -> None:
    """Append without overwriting and verify the persisted predecessor links."""
    path = tmp_path / "evidence.jsonl"
    evidence = EvidenceLog(path)
    assert evidence.verify_chain().records == 0
    first = evidence.append({"component": "C7", "event": "ECC_ISSUED", "data": {}})
    original = path.read_bytes()
    evidence = EvidenceLog(path)
    second = evidence.append({"component": "C6", "event": "ECC_ADMITTED", "data": {}})
    assert path.read_bytes().startswith(original)
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert records[1]["prev_hash"] == first and records[1]["hash"] == second
    assert records[0]["seq"] == 1 and records[1]["seq"] == 2
    chain = evidence.verify_chain()
    assert chain.ok and chain.reason == OK and chain.records == 2


@pytest.mark.parametrize("tampering", ["data", "prev_hash", "seq", "malformed"])
def test_first_broken_link_reported(tmp_path: Path, tampering: str) -> None:
    """Report record two as the first altered link and refuse further appends."""
    evidence = EvidenceLog(tmp_path / "evidence.jsonl")
    for number in range(3):
        evidence.append({"component": "C5", "event": "test", "data": {"n": number}})
    lines = evidence.path.read_text().splitlines()
    record = json.loads(lines[1])
    if tampering == "malformed":
        lines[1] = "not JSON"
    else:
        record[tampering] = "altered"
        lines[1] = json.dumps(record)
    evidence.path.write_text("\n".join(lines) + "\n")
    chain = evidence.verify_chain()
    assert not chain.ok and chain.reason == CHAIN_BROKEN and chain.broken_link == 2
    before = evidence.path.read_bytes()
    with pytest.raises(ValueError, match=CHAIN_BROKEN):
        evidence.append({"component": "C5", "event": "test", "data": {}})
    assert evidence.path.read_bytes() == before
