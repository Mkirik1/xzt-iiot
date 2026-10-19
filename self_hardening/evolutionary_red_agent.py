"""
evolutionary_red_agent.py
-----------------------------
Upgrades the Red Agent from "sample random parameters within a fixed
range" to a real (1+lambda)-style evolutionary search: within each
attack category's declared threat-model bounds (the same ranges
red_agent.py already uses), search for the SPECIFIC parameter
combination that most successfully evades the current policy -- i.e.
a worst-case robustness search, not just average-case random sampling.

SAFETY: identical safety envelope to red_agent.py -- this only
searches over abstract numeric attribute values already declared in
GENE_BOUNDS below (all taken directly from red_agent.py's existing
perturbation ranges). It cannot produce a genome outside the declared
threat model; it cannot invent a new attack CATEGORY, only find the
hardest-to-catch point within an already-declared one. No network
access, no real exploit code, nothing outside this closed numeric
search space.

Why this addresses "does it find genuinely new things": each run's
population is seeded randomly and mutated independently, so the exact
bypass parameters found differ from the previous run -- the system is
not replaying a fixed script, it is re-deriving the worst case fresh
each time, the same way a real red team varies its approach.
"""

import random
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).parent))
from agents.base_agent import AgentResult, BaseAgent  # noqa: E402
from attributes import (AccessRequest, SubjectAttributes, DeviceAttributes,  # noqa: E402
                         NetworkAttributes, ContextAttributes)
from policy_engine import PolicyEngine  # noqa: E402
from red_agent import RESOURCE_ACTION_PAIRS  # noqa: E402

# Same bounds red_agent.py already uses per scenario (the DECLARED threat
# model) -- evolution searches only inside these boxes, it cannot escape
# the threat model that was explicitly authorized.
GENE_BOUNDS: Dict[str, Dict[str, Tuple[float, float]]] = {
    "stolen_credentials":          {"behavioral_trust": (0.2, 0.4), "anomaly_score": (0.5, 0.75)},
    "compromised_device":          {"device_integrity": (0.3, 0.55), "anomaly_score": (0.4, 0.65)},
    "behavioral_anomaly":          {"behavioral_trust": (0.1, 0.3), "anomaly_score": (0.55, 0.8)},
    "privilege_escalation_attempt": {"behavioral_trust": (0.15, 0.35), "anomaly_score": (0.6, 0.85)},
    "replay_simulation":           {"authentication_strength": (0.4, 0.6), "behavioral_trust": (0.3, 0.5),
                                     "anomaly_score": (0.35, 0.55)},
    "firmware_integrity_failure":  {"device_integrity": (0.05, 0.3)},
}

POP_SIZE = 12
N_GENERATIONS = 5
MUTATION_SIGMA = 0.04
FIXED_ROLE = "engineer"
FIXED_TARGET = ("PLC_CONTROLLER", "WRITE_SETPOINT", "engineering")


@dataclass
class Genome:
    scenario: str
    genes: Dict[str, float]
    fitness: float = 0.0  # = trust_score achieved; higher = closer to/through the ALLOW boundary


def _clip(v, lo, hi):
    return max(lo, min(hi, v))


def _random_genome(scenario: str, rng: random.Random) -> Genome:
    bounds = GENE_BOUNDS[scenario]
    return Genome(scenario=scenario, genes={k: rng.uniform(lo, hi) for k, (lo, hi) in bounds.items()})


def _mutate(parent: Genome, rng: random.Random) -> Genome:
    bounds = GENE_BOUNDS[parent.scenario]
    child_genes = {}
    for k, v in parent.genes.items():
        lo, hi = bounds[k]
        child_genes[k] = _clip(v + rng.gauss(0, MUTATION_SIGMA), lo, hi)
    return Genome(scenario=parent.scenario, genes=child_genes)


def _genome_to_request(genome: Genome, req_id: str) -> AccessRequest:
    g = genome.genes
    resource, action, zone = FIXED_TARGET
    return AccessRequest(
        request_id=req_id,
        subject=SubjectAttributes(user_id="evo_attacker", role=FIXED_ROLE,
                                   identity_confidence=g.get("identity_confidence", 0.9),
                                   authentication_strength=g.get("authentication_strength", 0.9)),
        device=DeviceAttributes(device_id="evo_device",
                                 device_integrity=g.get("device_integrity", 0.9), patch_level=0.9),
        network=NetworkAttributes(source_zone=zone, expected_zone=zone),
        context=ContextAttributes(behavioral_trust=g.get("behavioral_trust", 0.9),
                                   anomaly_score=g.get("anomaly_score", 0.05), access_hour=12),
        resource=resource, action=action, label=genome.scenario,
    )


def evolve_worst_case(policy_engine: PolicyEngine, seed: int = 1,
                       pop_size: int = POP_SIZE, n_generations: int = N_GENERATIONS
                       ) -> Tuple[List[AccessRequest], dict]:
    """Runs the evolutionary search for EVERY scenario category, returns
    the final (evolved, worst-case) population as AccessRequests, plus
    generation-by-generation best-fitness stats for transparency."""
    rng = random.Random(seed)
    all_requests: List[AccessRequest] = []
    history = {}

    for scenario in GENE_BOUNDS:
        population = [_random_genome(scenario, rng) for _ in range(pop_size)]
        gen_best = []

        for gen in range(n_generations):
            for genome in population:
                req = _genome_to_request(genome, f"evo_{scenario}_{gen}")
                decision = policy_engine.evaluate(req)
                # reward getting through (ALLOW) strongly; otherwise reward
                # getting closer to the threshold (higher trust_score)
                genome.fitness = decision.trust_score + (1.0 if decision.decision == "ALLOW" else 0.0)

            population.sort(key=lambda g: -g.fitness)
            gen_best.append(round(population[0].fitness, 4))

            survivors = population[:max(2, pop_size // 3)]
            children = [_mutate(rng.choice(survivors), rng) for _ in range(pop_size - len(survivors))]
            population = survivors + children

        history[scenario] = gen_best
        # keep the final generation's population as this cycle's test set
        # for this scenario (not just the single best -- a spread of
        # near-optimal variants, more realistic as a test suite)
        for i, genome in enumerate(population):
            all_requests.append(_genome_to_request(genome, f"evo_{scenario}_final_{i}"))

    return all_requests, history


class EvolutionaryRedAgent(BaseAgent):
    agent_id = "evolutionary_red_agent"
    name = "Evolutionary Red Agent"
    agent_kind = "goal_based_agent"   # queries the CURRENT policy and searches for the scenario parameters that maximise evasion

    def run(self, policy_engine: PolicyEngine, seed: int) -> AgentResult:
        self.status = "running"
        requests, history = evolve_worst_case(policy_engine, seed=seed)
        improved = {s: (h[-1] - h[0]) for s, h in history.items()}
        return self._result(
            output={"requests": requests, "generation_history": history},
            confidence=1.0,
            reasoning_summary=(f"Evolved worst-case attack variants across {len(history)} categories "
                                f"over {N_GENERATIONS} generations; fitness improvement per category: "
                                + ", ".join(f"{s}:+{v:.3f}" for s, v in improved.items())))
