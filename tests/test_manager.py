# -*- encoding: utf-8 -*-
"""Tests for StackManager."""

import pytest
import tempfile
from pathlib import Path

from keri_sec import (
    StackManager,
    ConstraintType,
    KERI_PRODUCTION_STACK,
    reset_stack_manager,
)


@pytest.fixture
def temp_path(tmp_path):
    """Temporary path for stack storage."""
    return tmp_path / "stacks"


@pytest.fixture
def manager(temp_path):
    """Create a fresh StackManager."""
    reset_stack_manager()
    return StackManager(base_path=temp_path)


class TestStackDefinition:
    """Tests for stack definition."""

    def test_define_simple_stack(self, manager):
        """Define a simple stack."""
        stack = manager.define_stack(
            name="test-stack",
            controller_aid="BTEST_CONTROLLER_AID_1234567890",
            constraints={
                "python": ">=3.10",
                "requests": ">=2.28.0",
            },
        )

        assert stack is not None
        assert stack.name == "test-stack"
        assert stack.said.startswith("E")  # Blake3 SAID
        assert len(stack.constraints) == 2

    def test_constraint_types(self, manager):
        """Constraint types are correctly detected."""
        stack = manager.define_stack(
            name="typed-stack",
            controller_aid="BTEST_AID",
            constraints={
                "python": ">=3.12",
                "keri": ">=1.2.0",
                "system:libsodium": ">=1.0.18",
                "binary:kli": ">=1.0.0",
            },
        )

        assert stack.constraints["python"].constraint_type == ConstraintType.PYTHON
        assert stack.constraints["keri"].constraint_type == ConstraintType.PACKAGE
        assert stack.constraints["libsodium"].constraint_type == ConstraintType.SYSTEM
        assert stack.constraints["kli"].constraint_type == ConstraintType.BINARY

    def test_constraint_saids(self, manager):
        """Each constraint gets a SAID."""
        stack = manager.define_stack(
            name="said-stack",
            controller_aid="BTEST_AID",
            constraints={"python": ">=3.12", "hio": ">=0.6.0"},
        )

        assert stack.constraints["python"].said.startswith("E")
        assert stack.constraints["hio"].said.startswith("E")
        assert stack.constraints["python"].said != stack.constraints["hio"].said

    def test_stack_said_deterministic(self, manager):
        """Stack SAID is deterministic (same input = same SAID)."""
        constraints = {"python": ">=3.12", "hio": ">=0.6.0"}

        stack1 = manager.define_stack(
            name="det-stack",
            controller_aid="BTEST_AID",
            constraints=constraints,
        )
        stack2 = manager.define_stack(
            name="det-stack",
            controller_aid="BTEST_AID",
            constraints=constraints,
        )

        assert stack1.said == stack2.said

    def test_stack_said_order_independent(self, manager):
        """Stack SAID is independent of constraint order."""
        stack1 = manager.define_stack(
            name="order-stack",
            controller_aid="BTEST_AID",
            constraints={"a": ">=1.0", "b": ">=2.0", "c": ">=3.0"},
        )
        stack2 = manager.define_stack(
            name="order-stack",
            controller_aid="BTEST_AID",
            constraints={"c": ">=3.0", "a": ">=1.0", "b": ">=2.0"},
        )

        assert stack1.said == stack2.said


class TestComplianceCheck:
    """Tests for compliance checking."""

    def test_python_compliance(self, manager):
        """Check Python version compliance."""
        stack = manager.define_stack(
            name="py-check",
            controller_aid="BTEST_AID",
            constraints={"python": ">=3.10"},
        )

        result = manager.check_compliance(stack.said)

        assert result.checks["python"].compliant is True
        assert result.checks["python"].installed is not None

    def test_compliance_structure(self, manager):
        """Compliance result has correct structure."""
        stack = manager.define_stack(
            name="struct-check",
            controller_aid="BTEST_AID",
            constraints={"python": ">=3.10"},
        )

        result = manager.check_compliance(stack.said)

        assert hasattr(result, "compliant")
        assert hasattr(result, "stack_said")
        assert hasattr(result, "checks")
        assert hasattr(result, "missing")
        assert hasattr(result, "outdated")


class TestCodeGeneration:
    """Tests for code generation."""

    def test_generate_pyproject(self, manager):
        """Generate pyproject.toml."""
        stack = manager.define_stack(
            name="gen-stack",
            controller_aid="BTEST_AID",
            constraints={"python": ">=3.12", "keri": ">=1.2.0"},
        )

        toml = manager.generate_pyproject(stack.said)

        assert "requires-python" in toml
        assert ">=3.12" in toml
        assert "dependencies" in toml
        assert "keri" in toml
        assert "SAID:" in toml

    def test_generate_requirements(self, manager):
        """Generate requirements.txt."""
        stack = manager.define_stack(
            name="req-stack",
            controller_aid="BTEST_AID",
            constraints={"python": ">=3.12", "requests": ">=2.28.0"},
        )

        reqs = manager.generate_requirements(stack.said)

        assert "requests>=2.28.0" in reqs
        assert "SAID:" in reqs
        assert "python>=" not in reqs  # Python not in requirements.txt


class TestVersionComparison:
    """Tests for version comparison."""

    def test_gte(self, manager):
        """Test >= comparison."""
        assert manager._version_satisfies("3.12.0", ">=3.10") is True
        assert manager._version_satisfies("3.9.0", ">=3.10") is False

    def test_lte(self, manager):
        """Test <= comparison."""
        assert manager._version_satisfies("1.5.0", "<=2.0.0") is True
        assert manager._version_satisfies("2.1.0", "<=2.0.0") is False

    def test_exact(self, manager):
        """Test == comparison."""
        assert manager._version_satisfies("1.2.3", "==1.2.3") is True
        assert manager._version_satisfies("1.2.4", "==1.2.3") is False


class TestPersistence:
    """Tests for stack persistence."""

    def test_stacks_persist(self, temp_path):
        """Stacks persist across manager instances."""
        # Create stack with first manager
        manager1 = StackManager(base_path=temp_path)
        stack = manager1.define_stack(
            name="persist-stack",
            controller_aid="BTEST_AID",
            constraints={"python": ">=3.12"},
        )
        stack_said = stack.said

        # Create new manager, should load existing stacks
        manager2 = StackManager(base_path=temp_path)
        loaded = manager2.get_stack(stack_said)

        assert loaded is not None
        assert loaded.name == "persist-stack"
        assert loaded.said == stack_said


class TestPresetStacks:
    """Tests for preset stacks."""

    def test_keri_production_has_essentials(self):
        """KERI production stack has essential packages."""
        assert "python" in KERI_PRODUCTION_STACK
        assert "keri" in KERI_PRODUCTION_STACK
        assert "hio" in KERI_PRODUCTION_STACK

    def test_define_preset(self, manager):
        """Can define a stack from preset."""
        stack = manager.define_stack(
            name="preset-stack",
            controller_aid="BTEST_AID",
            constraints=KERI_PRODUCTION_STACK,
        )

        assert len(stack.constraints) == len(KERI_PRODUCTION_STACK)
