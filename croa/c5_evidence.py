"""C5 Audit & Provenance Store.

CROA component: C5 — append-only JSONL with a SHA-256 predecessor chain.
Gemini action it addresses: #1–3, recording decisions and actual target outcomes.
Fails closed: malformed or altered records report the first broken link.
"""

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

from croa.reasons import CHAIN_BROKEN, OK
from croa.serialization import canonical_json

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class ChainResult:
    """Verification outcome identifying the first broken physical record."""

    ok: bool
    records: int
    broken_link: int | None = None
    reason: str = OK


class EvidenceLog:
    """A single-process, persistent evidence chain; verification reads disk."""

    def __init__(self, path: str | Path) -> None:
        """Attach an evidence path without truncating any existing records."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, event: dict[str, object]) -> str:
        """Append an event only when the stored predecessor chain is intact.

        Args:
            event: Component, event name, and JSON-compatible data mapping.
        Returns:
            The appended record's SHA-256 hash.
        Raises:
            ValueError: If the existing chain is broken.
            KeyError: If a required event field is absent.
            OSError: If evidence cannot be read or written to the file.
        """
        chain = self.verify_chain()
        if not chain.ok:
            raise ValueError(f"{CHAIN_BROKEN}: {chain.broken_link}")
        lines = self._lines()
        previous = json.loads(lines[-1])["hash"] if lines else GENESIS_HASH
        record = {
            "seq": len(lines) + 1, "ts": time.time(),
            "component": event["component"], "event": event["event"],
            "data": event["data"], "prev_hash": previous,
        }
        digest = hashlib.sha256(canonical_json(record).encode()).hexdigest()
        record["hash"] = digest
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(canonical_json(record) + "\n")
        return digest

    def verify_chain(self) -> ChainResult:
        """Verify stored hashes, predecessor links, and consecutive sequence numbers.

        Returns:
            OK with the record count, or the first broken one-based link.
        Raises:
            OSError: If the evidence file cannot be read.
        """
        lines = self._lines()
        previous = GENESIS_HASH
        for number, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
                digest = record.pop("hash")
                expected = hashlib.sha256(canonical_json(record).encode()).hexdigest()
                valid = (
                    record["seq"] == number and record["prev_hash"] == previous
                    and digest == expected
                    and set(record) == {"seq", "ts", "component", "event", "data",
                                        "prev_hash"}
                )
            except (ValueError, TypeError, KeyError, AttributeError):
                valid = False
            if not valid:
                return ChainResult(False, len(lines), number, CHAIN_BROKEN)
            previous = digest
        return ChainResult(True, len(lines))

    def _lines(self) -> list[str]:
        """Treat a not-yet-created log as an empty chain."""
        if not self.path.exists():
            return []
        return self.path.read_text(encoding="utf-8").splitlines()
