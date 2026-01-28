# -*- encoding: utf-8 -*-
"""
RuntimeResolver - Resolve GAID to expected dependencies.

Resolves a RuntimeGAID to its expected dependencies, supporting:
- Algorithm GAID resolution via AlgorithmDAIDRegistry
- Protocol GAID resolution (when protocol registry available)
- Version chain walking for superseded GAIDs

Usage:
    from keri_sec.runtime import RuntimeResolver, get_runtime_gaid_registry

    resolver = RuntimeResolver(
        runtime_registry=get_runtime_gaid_registry(),
        algorithm_registry=get_algorithm_daid_registry(),
    )

    # Resolve all dependencies for a runtime
    deps = resolver.resolve_dependencies("EGAID...")

    # Check if all dependencies are available
    result = resolver.check_availability("EGAID...")
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class ResolvedDependency:
    """A resolved dependency."""
    name: str
    gaid: str
    category: str  # "algorithm", "protocol", "runtime"
    version: str
    status: str  # "active", "deprecated", "superseded", "unknown"
    successor_gaid: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "gaid": self.gaid,
            "category": self.category,
            "version": self.version,
            "status": self.status,
            "successor_gaid": self.successor_gaid,
        }


@dataclass
class DependencyGraph:
    """Graph of resolved dependencies for a runtime."""
    runtime_gaid: str
    runtime_name: str
    dependencies: List[ResolvedDependency] = field(default_factory=list)
    unresolved: List[str] = field(default_factory=list)
    deprecated: List[str] = field(default_factory=list)
    resolved_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def all_resolved(self) -> bool:
        return len(self.unresolved) == 0

    @property
    def has_deprecated(self) -> bool:
        return len(self.deprecated) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "runtime_gaid": self.runtime_gaid,
            "runtime_name": self.runtime_name,
            "all_resolved": self.all_resolved,
            "has_deprecated": self.has_deprecated,
            "dependency_count": len(self.dependencies),
            "unresolved": self.unresolved,
            "deprecated": self.deprecated,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "resolved_at": self.resolved_at,
        }


@dataclass
class AvailabilityResult:
    """Result of dependency availability check."""
    available: bool
    missing: List[str] = field(default_factory=list)
    deprecated: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "available": self.available,
            "missing": self.missing,
            "deprecated": self.deprecated,
            "warnings": self.warnings,
        }


class RuntimeResolver:
    """
    Resolves RuntimeGAIDs to their expected dependencies.

    Connects RuntimeGAIDRegistry to AlgorithmDAIDRegistry (and future
    protocol registries) to build complete dependency graphs.
    """

    def __init__(
        self,
        runtime_registry=None,
        algorithm_registry=None,
        protocol_registry=None,  # Future: ProtocolGAIDRegistry
    ):
        """
        Initialize resolver with registries.

        Args:
            runtime_registry: RuntimeGAIDRegistry
            algorithm_registry: AlgorithmDAIDRegistry
            protocol_registry: Future protocol registry
        """
        self._runtime_registry = runtime_registry
        self._algorithm_registry = algorithm_registry
        self._protocol_registry = protocol_registry

    def resolve_dependencies(self, runtime_gaid: str) -> DependencyGraph:
        """
        Resolve all dependencies for a runtime GAID.

        Args:
            runtime_gaid: GAID of runtime to resolve

        Returns:
            DependencyGraph with all resolved dependencies
        """
        if self._runtime_registry is None:
            raise ValueError("Runtime registry not configured")

        runtime = self._runtime_registry.resolve(runtime_gaid)
        if runtime is None:
            return DependencyGraph(
                runtime_gaid=runtime_gaid,
                runtime_name="unknown",
                unresolved=[f"Runtime GAID not found: {runtime_gaid}"],
            )

        dependencies: List[ResolvedDependency] = []
        unresolved: List[str] = []
        deprecated: List[str] = []

        manifest = runtime.current_manifest
        if manifest is None:
            return DependencyGraph(
                runtime_gaid=runtime_gaid,
                runtime_name=runtime.name,
                unresolved=["Runtime has no manifest"],
            )

        # Resolve algorithm dependencies
        for algo_name, algo_gaid in manifest.algorithm_gaids.items():
            dep = self._resolve_algorithm(algo_name, algo_gaid)
            if dep:
                dependencies.append(dep)
                if dep.status in ("deprecated", "superseded"):
                    deprecated.append(f"{algo_name}:{algo_gaid[:16]}...")
            else:
                unresolved.append(f"algorithm:{algo_name}:{algo_gaid[:16]}...")

        # Resolve protocol dependencies
        for proto_name, proto_gaid in manifest.protocol_gaids.items():
            dep = self._resolve_protocol(proto_name, proto_gaid)
            if dep:
                dependencies.append(dep)
                if dep.status in ("deprecated", "superseded"):
                    deprecated.append(f"{proto_name}:{proto_gaid[:16]}...")
            else:
                # Protocols may not have registry yet - mark as unknown but not unresolved
                dependencies.append(ResolvedDependency(
                    name=proto_name,
                    gaid=proto_gaid,
                    category="protocol",
                    version="unknown",
                    status="unknown",
                ))

        return DependencyGraph(
            runtime_gaid=runtime_gaid,
            runtime_name=runtime.name,
            dependencies=dependencies,
            unresolved=unresolved,
            deprecated=deprecated,
        )

    def _resolve_algorithm(self, name: str, gaid: str) -> Optional[ResolvedDependency]:
        """Resolve an algorithm dependency."""
        if self._algorithm_registry is None:
            return None

        # Try to resolve by GAID first, then by name
        algo = self._algorithm_registry.resolve(gaid)
        if algo is None:
            algo = self._algorithm_registry.resolve(name)

        if algo is None:
            return None

        return ResolvedDependency(
            name=algo.name,
            gaid=algo.daid,
            category="algorithm",
            version=algo.current_version.version if algo.current_version else "unknown",
            status=algo.status.value,
            successor_gaid=algo.successor_daid,
        )

    def _resolve_protocol(self, name: str, gaid: str) -> Optional[ResolvedDependency]:
        """Resolve a protocol dependency."""
        if self._protocol_registry is None:
            return None

        # Future: implement protocol registry resolution
        return None

    def check_availability(self, runtime_gaid: str) -> AvailabilityResult:
        """
        Check if all dependencies for a runtime are available.

        Args:
            runtime_gaid: GAID of runtime to check

        Returns:
            AvailabilityResult indicating what's available/missing
        """
        graph = self.resolve_dependencies(runtime_gaid)

        missing = list(graph.unresolved)
        deprecated = list(graph.deprecated)
        warnings = []

        # Add warnings for deprecated dependencies
        for dep in graph.dependencies:
            if dep.status == "deprecated" and dep.successor_gaid:
                warnings.append(
                    f"{dep.category}:{dep.name} is deprecated, migrate to {dep.successor_gaid[:16]}..."
                )

        return AvailabilityResult(
            available=len(missing) == 0,
            missing=missing,
            deprecated=deprecated,
            warnings=warnings,
        )

    def get_supersession_chain(self, gaid: str, max_depth: int = 10) -> List[str]:
        """
        Walk the supersession chain for a GAID.

        Args:
            gaid: Starting GAID
            max_depth: Maximum chain depth to walk

        Returns:
            List of GAIDs in chain (oldest to newest)
        """
        chain = [gaid]
        current = gaid
        visited: Set[str] = {gaid}

        for _ in range(max_depth):
            # Try runtime registry
            if self._runtime_registry:
                runtime = self._runtime_registry.resolve(current)
                if runtime and runtime.deprecation and runtime.deprecation.successor_gaid:
                    successor = runtime.deprecation.successor_gaid
                    if successor not in visited:
                        chain.append(successor)
                        visited.add(successor)
                        current = successor
                        continue

            # Try algorithm registry
            if self._algorithm_registry:
                algo = self._algorithm_registry.resolve(current)
                if algo and algo.successor_daid:
                    successor = algo.successor_daid
                    if successor not in visited:
                        chain.append(successor)
                        visited.add(successor)
                        current = successor
                        continue

            # No more successors found
            break

        return chain

    def get_latest_in_chain(self, gaid: str) -> str:
        """
        Get the latest (non-deprecated) GAID in a supersession chain.

        Args:
            gaid: Starting GAID

        Returns:
            Latest GAID in chain
        """
        chain = self.get_supersession_chain(gaid)
        return chain[-1] if chain else gaid
