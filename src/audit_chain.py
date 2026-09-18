"""
audit_chain.py
----------------
Lightweight blockchain-inspired audit ledger.

Deliberately NOT a full consensus blockchain (no mining, no P2P,
no shards) -- that scope belongs to DRL-sharding frameworks like
ZT-BlocIoT, which is exactly the multi-week engineering effort this
6-day workshop paper does not attempt. Instead, this gives the
"Blockchain" relevance the BSS 2026 CFP asks for in a form that is
honest about its own scope: a hash-chained, tamper-evident log of
every zero-trust policy decision (with its SHAP justification),
so a device's access history cannot be silently altered after the
fact -- the same integrity property audits need from a blockchain,
without the scalability engineering of full sharding/consensus.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


@dataclass
class Block:
    index: int
    timestamp: float
    record: Dict[str, Any]
    prev_hash: str
    hash: str = field(default="")

    def compute_hash(self) -> str:
        payload = json.dumps(
            {"index": self.index, "timestamp": self.timestamp,
             "record": self.record, "prev_hash": self.prev_hash},
            sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()


class HashChain:
    GENESIS_PREV = "0" * 64

    def __init__(self):
        self.chain: List[Block] = []
        self._add_genesis()

    def _add_genesis(self):
        genesis = Block(index=0, timestamp=time.time(),
                         record={"genesis": True}, prev_hash=self.GENESIS_PREV)
        genesis.hash = genesis.compute_hash()
        self.chain.append(genesis)

    def add_record(self, record: Dict[str, Any]) -> Block:
        prev = self.chain[-1]
        block = Block(index=prev.index + 1, timestamp=time.time(),
                       record=record, prev_hash=prev.hash)
        block.hash = block.compute_hash()
        self.chain.append(block)
        return block

    def verify(self) -> bool:
        """Detect any tampering: recompute hashes and check links."""
        for i in range(1, len(self.chain)):
            cur, prev = self.chain[i], self.chain[i - 1]
            if cur.prev_hash != prev.hash:
                return False
            if cur.hash != cur.compute_hash():
                return False
        return True

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump([asdict(b) for b in self.chain], f, indent=2)


def _demo_tamper_detection():
    """Sanity check: mutating a past record must break verification."""
    chain = HashChain()
    for i in range(5):
        chain.add_record({"device_id": f"dev_{i}", "decision": "ALLOW"})
    assert chain.verify() is True

    # tamper with block 2's record after the fact
    chain.chain[2].record["decision"] = "ALLOW_HACKED"
    assert chain.verify() is False
    print("Tamper-detection sanity check passed: "
          "post-hoc edit of an audit record is detected.")


if __name__ == "__main__":
    _demo_tamper_detection()
