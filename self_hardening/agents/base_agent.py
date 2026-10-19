"""
base_agent.py
----------------
Common interface for the eight components named *Agent (brief Section
30): agent_id, name, status, run(), with output/confidence/
reasoning_summary/timestamp attached to every result. Deterministic,
no external LLM dependency (brief: "The system must work without an
external LLM").

WHAT "AGENT" MEANS HERE (response to reviewer R5). We use the standard
definition of Russell & Norvig (Artificial Intelligence: A Modern
Approach): an agent perceives its environment and acts on it, and the
classes differ in how actions are chosen. A component is classified by
what it actually does in the loop, not by its class name:

  goal_based_agent     perceives the environment's current state, has
                       an explicit objective, chooses among alternative
                       actions by predicting which best achieves it, and
                       acts; its actions change what it perceives next
                       cycle.
  simple_reflex_agent  perceives and acts through fixed condition-action
                       rules, with no objective it optimises.
  service              does not choose among actions toward a goal: a
                       deterministic function, evaluator, logger or
                       scheduler that the loop calls.

Only two components are goal-based agents: BlueAgent (objective mode,
maximises J) and EvolutionaryRedAgent (maximises evasion against the
current policy). The class names are kept for continuity with the
brief and the code; the paper must use these classifications, not
"8 autonomous agents".
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


AGENT_KINDS = ("goal_based_agent", "simple_reflex_agent", "service")


class BaseAgent:
    agent_id: str = "base_agent"
    name: str = "BaseAgent"
    agent_kind: str = "service"   # one of AGENT_KINDS; subclasses must set it honestly

    def __init__(self):
        self.status = "idle"

    def run(self, *args, **kwargs) -> AgentResult:
        raise NotImplementedError

    def _result(self, output, confidence, reasoning_summary) -> AgentResult:
        self.status = "idle"
        return AgentResult(agent_id=self.agent_id, output=output,
                            confidence=confidence, reasoning_summary=reasoning_summary)
