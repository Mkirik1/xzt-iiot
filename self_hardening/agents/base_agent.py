"""
base_agent.py
----------------
Common interface for every agent in the system (brief Section 30):
agent_id, name, status, run(), with output/confidence/reasoning_summary/
timestamp attached to every result. Deterministic/rule-based by
design -- no external LLM dependency (brief: "The system must work
without an external LLM").
"""

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentResult:
    agent_id: str
    output: Any
    confidence: float           # 0..1, rule-based agents report 1.0 for
                                 # deterministic outcomes, <1.0 where the
                                 # agent is making a judgment call
    reasoning_summary: str
    timestamp: float = field(default_factory=time.time)


class BaseAgent:
    agent_id: str = "base_agent"
    name: str = "BaseAgent"

    def __init__(self):
        self.status = "idle"

    def run(self, *args, **kwargs) -> AgentResult:
        raise NotImplementedError

    def _result(self, output, confidence, reasoning_summary) -> AgentResult:
        self.status = "idle"
        return AgentResult(agent_id=self.agent_id, output=output,
                            confidence=confidence, reasoning_summary=reasoning_summary)
