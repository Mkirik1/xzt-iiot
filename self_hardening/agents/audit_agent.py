"""
audit_agent.py (agents package)
------------------------------------
Wraps the hash-chained ledger as a named agent. Per the brief's Agent
Security section: AuditAgent CAN append the ledger, CANNOT modify
previous records -- enforced structurally here since HashChain only
exposes add_record() (append) and verify()/save() (read), no
update/delete method exists at all, so there is nothing for a caller
(malicious or buggy) to call even by mistake.
"""

import importlib.util
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from agents.base_agent import BaseAgent, AgentResult  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "audit_chain_reused", Path(__file__).parent.parent.parent / "src" / "audit_chain.py")
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
HashChain = _mod.HashChain


class AuditAgent(BaseAgent):
    agent_id = "audit_agent"
    name = "Audit Agent"

    def __init__(self):
        super().__init__()
        self.chain = HashChain()

    def append(self, record: dict):
        self.chain.add_record(record)

    def run(self) -> AgentResult:
        """Verify the ledger's integrity end-to-end."""
        self.status = "running"
        valid = self.chain.verify()
        return self._result(
            output={"valid": valid, "blocks": len(self.chain.chain)}, confidence=1.0,
            reasoning_summary=f"Verified {len(self.chain.chain)} hash-chained audit blocks: "
                               f"{'no tampering detected' if valid else 'INTEGRITY FAILURE'}.")
