# -*- encoding: utf-8 -*-
"""
Algorithm Registry - Verifiable Algorithm (GAID) Management.

Provides registration and execution of verifiable algorithms
with attestation support.

Usage:
    from keri_sec.algorithms import AlgorithmRegistry, Algorithm

    registry = AlgorithmRegistry()

    # Register an algorithm
    algo = registry.register(
        name="constraint-verification",
        version="1.0.0",
        implementation=verify_constraint,
        description="Verify a constraint against environment",
    )

    # Execute with attestation
    result = registry.execute(
        algorithm_said=algo.said,
        inputs={"name": "keri", "spec": ">=1.2.0"},
        issuer_hab=session_hab,
        tier=Tier.KEL_ANCHORED,
    )

Credit:
- KERI/ACDC: Samuel M. Smith
- Transit handler pattern: Cognitect
"""

from .registry import (
    Algorithm,
    AlgorithmRegistry,
    ExecutionResult,
    get_algorithm_registry,
    reset_algorithm_registry,
)
from .daid import (
    AlgorithmCategory,
    AlgorithmDAID,
    AlgorithmDAIDRegistry,
    AlgorithmStatus,
    AlgorithmVersion,
    DeprecationNotice,
    get_algorithm_daid_registry,
    reset_algorithm_daid_registry,
)

__all__ = [
    # Original registry
    "Algorithm",
    "AlgorithmRegistry",
    "ExecutionResult",
    "get_algorithm_registry",
    "reset_algorithm_registry",
    # DAID registry
    "AlgorithmCategory",
    "AlgorithmDAID",
    "AlgorithmDAIDRegistry",
    "AlgorithmStatus",
    "AlgorithmVersion",
    "DeprecationNotice",
    "get_algorithm_daid_registry",
    "reset_algorithm_daid_registry",
]
