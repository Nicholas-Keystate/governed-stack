# -*- encoding: utf-8 -*-
"""
Algorithm Registry - GAID Implementation.

Manages verifiable algorithms with SAID-based identity and
optional attestation on execution.
"""

import inspect
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from ..attestation import Tier, Attestation, create_attestation, compute_said

logger = logging.getLogger(__name__)


@dataclass
class Algorithm:
    """A registered verifiable algorithm."""
    name: str
    version: str
    said: str  # SAID of spec (name + version + implementation hash)
    implementation: Callable
    description: str = ""
    implementation_said: str = ""  # SAID of implementation source
    registered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "said": self.said,
            "description": self.description,
            "implementation_said": self.implementation_said,
            "registered_at": self.registered_at,
        }


@dataclass
class ExecutionResult:
    """Result of algorithm execution."""
    algorithm_said: str
    result: Any
    input_said: str
    output_said: str
    attestation: Optional[Attestation] = None
    executed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_attested(self) -> bool:
        return self.attestation is not None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm_said": self.algorithm_said,
            "result": self.result,
            "input_said": self.input_said,
            "output_said": self.output_said,
            "attestation": self.attestation.to_dict() if self.attestation else None,
            "executed_at": self.executed_at,
        }

    def storage_size(self) -> int:
        """Estimate storage size in bytes."""
        base = len(json.dumps({
            "algorithm_said": self.algorithm_said,
            "input_said": self.input_said,
            "output_said": self.output_said,
            "executed_at": self.executed_at,
        }))
        if self.attestation:
            base += self.attestation.storage_size()
        return base


class AlgorithmRegistry:
    """
    Registry of verifiable algorithms.

    Algorithms are identified by SAID computed from their specification
    (name, version, implementation source). Executions can be attested
    at different tiers.
    """

    def __init__(self):
        self._algorithms: Dict[str, Algorithm] = {}  # said -> Algorithm
        self._by_name: Dict[str, Algorithm] = {}     # name -> latest Algorithm
        self._lock = threading.Lock()
        self._executions: List[ExecutionResult] = []  # For storage measurement

    def register(
        self,
        name: str,
        version: str,
        implementation: Callable,
        description: str = "",
    ) -> Algorithm:
        """
        Register a verifiable algorithm.

        Args:
            name: Algorithm name
            version: Version string
            implementation: Callable that implements the algorithm
            description: Human-readable description

        Returns:
            Registered Algorithm with computed SAID
        """
        # Get implementation source for SAID
        try:
            impl_source = inspect.getsource(implementation)
        except (TypeError, OSError):
            impl_source = str(implementation)

        impl_said = compute_said(impl_source)

        # Compute algorithm SAID from spec
        spec = {
            "name": name,
            "version": version,
            "implementation_said": impl_said,
        }
        said = compute_said(spec)

        algorithm = Algorithm(
            name=name,
            version=version,
            said=said,
            implementation=implementation,
            description=description,
            implementation_said=impl_said,
        )

        with self._lock:
            self._algorithms[said] = algorithm
            self._by_name[name] = algorithm

        logger.info(f"Registered algorithm: {name} v{version} -> {said[:16]}...")
        return algorithm

    def get(self, said: str) -> Optional[Algorithm]:
        """Get algorithm by SAID."""
        with self._lock:
            # Try exact match
            if said in self._algorithms:
                return self._algorithms[said]
            # Try prefix match
            for full_said, algo in self._algorithms.items():
                if full_said.startswith(said):
                    return algo
        return None

    def get_by_name(self, name: str) -> Optional[Algorithm]:
        """Get latest algorithm by name."""
        with self._lock:
            return self._by_name.get(name)

    def execute(
        self,
        algorithm_said: str,
        inputs: Dict[str, Any],
        issuer_hab: Any = None,
        tier: Tier = Tier.SAID_ONLY,
        schema_said: Optional[str] = None,
        credential_service: Any = None,
    ) -> ExecutionResult:
        """
        Execute an algorithm with optional attestation.

        Args:
            algorithm_said: SAID (or prefix) of algorithm to execute
            inputs: Input arguments as dict
            issuer_hab: Issuer for attestation (required for Tier 1 & 2)
            tier: Attestation tier
            schema_said: Schema for TEL attestation
            credential_service: Service for TEL attestation

        Returns:
            ExecutionResult with result and optional attestation
        """
        algorithm = self.get(algorithm_said)
        if algorithm is None:
            raise ValueError(f"Algorithm not found: {algorithm_said}")

        # Compute input SAID
        input_said = compute_said(inputs)

        # Execute
        result = algorithm.implementation(**inputs)

        # Compute output SAID
        if isinstance(result, dict):
            output_said = compute_said(result)
        else:
            output_said = compute_said({"result": result})

        # Create attestation if not SAID_ONLY or if issuer provided
        attestation = None
        if tier != Tier.SAID_ONLY or issuer_hab is not None:
            attestation_content = {
                "algorithm_said": algorithm.said,
                "algorithm_name": algorithm.name,
                "algorithm_version": algorithm.version,
                "input_said": input_said,
                "output_said": output_said,
                "outcome": "success",
            }

            try:
                attestation = create_attestation(
                    tier=tier,
                    content=attestation_content,
                    issuer_hab=issuer_hab,
                    schema_said=schema_said,
                    credential_service=credential_service,
                )
            except Exception as e:
                logger.warning(f"Attestation failed: {e}")

        exec_result = ExecutionResult(
            algorithm_said=algorithm.said,
            result=result,
            input_said=input_said,
            output_said=output_said,
            attestation=attestation,
        )

        # Track for storage measurement
        with self._lock:
            self._executions.append(exec_result)

        return exec_result

    def list_algorithms(self) -> List[Algorithm]:
        """List all registered algorithms."""
        with self._lock:
            return list(self._algorithms.values())

    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics for executions."""
        with self._lock:
            total_size = sum(e.storage_size() for e in self._executions)
            by_tier = {t: 0 for t in Tier}
            for e in self._executions:
                if e.attestation:
                    by_tier[e.attestation.tier] += e.storage_size()
                else:
                    by_tier[Tier.SAID_ONLY] += e.storage_size()

            return {
                "execution_count": len(self._executions),
                "total_bytes": total_size,
                "by_tier": {t.name: v for t, v in by_tier.items()},
                "average_bytes": total_size // len(self._executions) if self._executions else 0,
            }

    def clear_executions(self):
        """Clear execution history (for testing)."""
        with self._lock:
            self._executions.clear()


# Module-level singleton
_registry: Optional[AlgorithmRegistry] = None
_registry_lock = threading.Lock()


def get_algorithm_registry() -> AlgorithmRegistry:
    """Get the algorithm registry singleton."""
    global _registry
    with _registry_lock:
        if _registry is None:
            _registry = AlgorithmRegistry()
        return _registry


def reset_algorithm_registry():
    """Reset the registry (for testing)."""
    global _registry
    with _registry_lock:
        _registry = None
