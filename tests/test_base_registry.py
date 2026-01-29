# -*- encoding: utf-8 -*-
"""
Tests for BaseGAIDRegistry - the generic base class for GAID/DAID registries.

Uses a minimal concrete subclass (StubRegistry) to test the base class
mechanics in isolation: storage, locking, resolution, governance, deprecation.
"""

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from unittest.mock import MagicMock

import pytest

from keri_governance.cardinal import ArtifactType, CardinalCheckResult, CardinalRule, Operation
from keri_governance.primitives import StrengthLevel

from keri_sec.base_registry import BaseGAIDRegistry
from keri_sec.governance.gate import GovernanceGate, GovernanceViolation
from keri_sec.governance.cardinal_checker_bridge import GovernedCheckResult


# ---------------------------------------------------------------------------
# Stub types for testing
# ---------------------------------------------------------------------------


class StubStatus(Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"


@dataclass
class StubDeprecation:
    reason: str
    successor: Optional[str] = None
    deadline: Optional[str] = None


@dataclass
class StubVersion:
    version: str
    content_said: str = ""


@dataclass
class StubGAID:
    gaid: str
    name: str
    status: StubStatus = StubStatus.ACTIVE
    deprecation: Optional[StubDeprecation] = None
    versions: list = field(default_factory=list)
    current_version_index: int = 0
    extra_code: Optional[str] = None

    @property
    def current_version(self):
        return self.versions[self.current_version_index] if self.versions else None

    @property
    def is_deprecated(self):
        return self.status == StubStatus.DEPRECATED


# ---------------------------------------------------------------------------
# Concrete stub registry
# ---------------------------------------------------------------------------


class StubRegistry(BaseGAIDRegistry[StubGAID]):
    """Minimal concrete registry for testing BaseGAIDRegistry."""

    def __init__(self, governance_gate=None):
        super().__init__(governance_gate=governance_gate)
        self._by_code: dict = {}

    def register(self, name: str, gaid: str, extra_code: str = None, issuer_hab=None):
        self._enforce(Operation.REGISTER, issuer_hab=issuer_hab)
        obj = StubGAID(
            gaid=gaid,
            name=name,
            versions=[StubVersion(version="1.0.0")],
            extra_code=extra_code,
        )
        self._store(gaid, name, obj)
        if extra_code:
            with self._lock:
                self._by_code[extra_code] = gaid
        return obj

    def _resolve_extra(self, identifier):
        if identifier in self._by_code:
            gaid = self._by_code[identifier]
            return self._entities.get(gaid)
        return None

    def _apply_deprecation(self, obj, reason, successor, deadline):
        obj.status = StubStatus.DEPRECATED
        obj.deprecation = StubDeprecation(
            reason=reason, successor=successor, deadline=deadline,
        )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestStorage:
    """Test basic storage and retrieval."""

    def test_register_and_resolve_by_gaid(self):
        reg = StubRegistry()
        obj = reg.register("foo", "GAID_FOO")
        assert reg.resolve("GAID_FOO") is obj

    def test_resolve_by_name(self):
        reg = StubRegistry()
        reg.register("bar", "GAID_BAR")
        assert reg.resolve("bar").gaid == "GAID_BAR"

    def test_resolve_by_prefix(self):
        reg = StubRegistry()
        reg.register("baz", "GAID_BAZ_LONG")
        assert reg.resolve("GAID_BAZ").gaid == "GAID_BAZ_LONG"

    def test_resolve_not_found(self):
        reg = StubRegistry()
        assert reg.resolve("nonexistent") is None

    def test_resolve_extra_index(self):
        reg = StubRegistry()
        reg.register("alg", "GAID_ALG", extra_code="E")
        assert reg.resolve("E").gaid == "GAID_ALG"

    def test_list_all(self):
        reg = StubRegistry()
        reg.register("a", "GAID_A")
        reg.register("b", "GAID_B")
        assert len(reg.list_all()) == 2

    def test_list_all_exclude_deprecated(self):
        reg = StubRegistry()
        reg.register("a", "GAID_A")
        reg.register("b", "GAID_B")
        reg.deprecate("GAID_A", reason="old")
        all_items = reg.list_all(include_deprecated=True)
        active_items = reg.list_all(include_deprecated=False)
        assert len(all_items) == 2
        assert len(active_items) == 1
        assert active_items[0].name == "b"


class TestDeprecation:
    """Test deprecation lifecycle."""

    def test_deprecate_sets_status(self):
        reg = StubRegistry()
        reg.register("dep", "GAID_DEP")
        reg.deprecate("GAID_DEP", reason="obsolete")
        obj = reg.resolve("GAID_DEP")
        assert obj.is_deprecated
        assert obj.deprecation.reason == "obsolete"

    def test_deprecate_with_successor(self):
        reg = StubRegistry()
        reg.register("old", "GAID_OLD")
        reg.register("new", "GAID_NEW")
        reg.deprecate("GAID_OLD", reason="replaced", successor="GAID_NEW")
        obj = reg.resolve("GAID_OLD")
        assert obj.deprecation.successor == "GAID_NEW"

    def test_deprecate_not_found_raises(self):
        reg = StubRegistry()
        with pytest.raises(ValueError, match="Not found"):
            reg.deprecate("GAID_MISSING", reason="gone")


class TestGovernanceGate:
    """Test governance gate integration."""

    def _make_denying_gate(self):
        gate = MagicMock(spec=GovernanceGate)
        rule = CardinalRule(
            artifact_type=ArtifactType.ALG,
            operation=Operation.REGISTER,
            min_strength=StrengthLevel.TEL_ANCHORED,
        )
        gate.enforce.side_effect = GovernanceViolation(
            GovernedCheckResult(
                check_result=CardinalCheckResult(
                    allowed=False,
                    rule=rule,
                    actual_strength=StrengthLevel.SAID_ONLY,
                    message="denied",
                ),
                matrix_gaid="GAID_test",
                matrix_said="SAID_test",
                matrix_version="1.0.0",
            )
        )
        return gate

    def test_no_gate_allows_all(self):
        reg = StubRegistry()
        obj = reg.register("free", "GAID_FREE")
        assert obj is not None

    def test_gate_denies_register(self):
        gate = self._make_denying_gate()
        reg = StubRegistry(governance_gate=gate)
        with pytest.raises(GovernanceViolation):
            reg.register("denied", "GAID_DENIED")

    def test_gate_denies_deprecate(self):
        reg = StubRegistry()
        reg.register("x", "GAID_X")
        gate = self._make_denying_gate()
        reg.set_governance_gate(gate)
        with pytest.raises(GovernanceViolation):
            reg.deprecate("GAID_X", reason="test")

    def test_two_phase_lifecycle(self):
        """Genesis ungoverned, then gate enabled."""
        reg = StubRegistry()
        genesis = reg.register("genesis", "GAID_GENESIS")
        assert genesis is not None

        gate = self._make_denying_gate()
        reg.set_governance_gate(gate)

        with pytest.raises(GovernanceViolation):
            reg.register("post-gate", "GAID_POST")

        # Genesis still accessible
        assert reg.resolve("genesis") is not None


class TestThreadSafety:
    """Test that concurrent access is safe."""

    def test_concurrent_registers(self):
        reg = StubRegistry()
        errors = []

        def do_register(i):
            try:
                reg.register(f"item-{i}", f"GAID_{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=do_register, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(reg.list_all()) == 20


class TestEntityLabel:
    """Test the _entity_label property for logging."""

    def test_stub_registry_label(self):
        reg = StubRegistry()
        assert reg._entity_label == "stub"
