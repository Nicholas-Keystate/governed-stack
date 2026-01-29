# -*- encoding: utf-8 -*-
"""
BaseGAIDRegistry - Generic base class for GAID/DAID registries.

Provides the common infrastructure shared by all governed identifier registries:
- Thread-safe storage with primary (GAID→object) and name indexes
- Optional governance gate integration (fail-closed enforcement)
- Resolution by GAID, prefix, or name (extensible for custom indexes)
- Deprecation lifecycle

Subclasses implement register(), rotate(), and domain-specific methods.
The base class provides helpers (_enforce, _store, resolve, deprecate)
rather than template methods, keeping each registry's register/rotate
logic explicit and readable.

Usage:
    class MyRegistry(BaseGAIDRegistry[MyGAID]):
        def _apply_deprecation(self, obj, reason, successor, deadline):
            obj.status = MyStatus.DEPRECATED
            obj.deprecation = DeprecationNotice(reason=reason, ...)

        def register(self, name, **kwargs):
            self._enforce(Operation.REGISTER, issuer_hab=kwargs.get('issuer_hab'))
            # ... build object ...
            self._store(obj.gaid, name, obj)
            return obj
"""

import logging
import threading
from abc import ABC, abstractmethod
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    Generic,
    List,
    Optional,
    TypeVar,
)

from keri_governance.cardinal import Operation

if TYPE_CHECKING:
    from .governance.gate import GovernanceGate

logger = logging.getLogger(__name__)

T = TypeVar("T")


class BaseGAIDRegistry(ABC, Generic[T]):
    """
    Lean base class for GAID/DAID registries.

    Provides storage, locking, governance gate, resolution, and deprecation.
    Does NOT impose template methods for register/rotate — those stay in
    subclasses because inception data and version fields vary per registry.
    """

    def __init__(self, governance_gate: Optional["GovernanceGate"] = None):
        self._entities: Dict[str, T] = {}
        self._by_name: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._governance_gate = governance_gate

    # ------------------------------------------------------------------
    # Governance
    # ------------------------------------------------------------------

    def set_governance_gate(self, gate: "GovernanceGate") -> None:
        """Enable governance enforcement (two-phase lifecycle)."""
        self._governance_gate = gate

    def _enforce(self, operation: Operation, issuer_hab: Any = None) -> None:
        """Call governance gate if present. No-op otherwise."""
        if self._governance_gate is not None:
            self._governance_gate.enforce(operation, issuer_hab=issuer_hab)

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def _store(self, identifier: str, name: str, obj: T) -> None:
        """Store object in primary + name indexes (caller holds no lock)."""
        with self._lock:
            self._entities[identifier] = obj
            self._by_name[name] = identifier

    # ------------------------------------------------------------------
    # Resolution
    # ------------------------------------------------------------------

    def resolve(self, identifier: str) -> Optional[T]:
        """
        Resolve by GAID/DAID, prefix, or name.

        Resolution order:
        1. Exact GAID/DAID match
        2. GAID/DAID prefix match
        3. Name lookup
        4. Custom indexes (via _resolve_extra override)
        """
        with self._lock:
            # Exact match
            if identifier in self._entities:
                return self._entities[identifier]

            # Prefix match
            for gaid, obj in self._entities.items():
                if gaid.startswith(identifier):
                    return obj

            # Name lookup
            if identifier in self._by_name:
                gaid = self._by_name[identifier]
                return self._entities.get(gaid)

            # Custom indexes (subclass hook)
            return self._resolve_extra(identifier)

    def _resolve_extra(self, identifier: str) -> Optional[T]:
        """Override for custom index lookups (CESR codes, content SAIDs, etc).

        Called inside the lock. Default returns None.
        """
        return None

    # ------------------------------------------------------------------
    # Deprecation
    # ------------------------------------------------------------------

    def deprecate(
        self,
        identifier: str,
        reason: str,
        successor: Optional[str] = None,
        deadline: Optional[str] = None,
        issuer_hab: Any = None,
    ) -> None:
        """Deprecate an object with governance enforcement."""
        self._enforce(Operation.DEPRECATE, issuer_hab=issuer_hab)

        obj = self.resolve(identifier)
        if obj is None:
            raise ValueError(f"Not found: {identifier}")

        with self._lock:
            self._apply_deprecation(obj, reason, successor, deadline)

        logger.warning(
            f"Deprecated {self._entity_label}: "
            f"{getattr(obj, 'name', identifier)} - {reason}"
        )

    @abstractmethod
    def _apply_deprecation(
        self,
        obj: T,
        reason: str,
        successor: Optional[str],
        deadline: Optional[str],
    ) -> None:
        """Set status + deprecation notice on obj. Called under lock."""

    # ------------------------------------------------------------------
    # Listing
    # ------------------------------------------------------------------

    def list_all(self, include_deprecated: bool = True) -> List[T]:
        """List all objects, optionally excluding deprecated."""
        with self._lock:
            objects = list(self._entities.values())
        if not include_deprecated:
            objects = [o for o in objects if not getattr(o, "is_deprecated", False)]
        return objects

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def _entity_label(self) -> str:
        """Label for log messages (e.g. 'algorithm', 'schema')."""
        name = type(self).__name__
        for suffix in ("DAIDRegistry", "GAIDRegistry", "Registry"):
            if name.endswith(suffix):
                return name[: -len(suffix)].lower()
        return name.lower()
