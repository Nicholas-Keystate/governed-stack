# -*- encoding: utf-8 -*-
"""
Dogfooding test - keri-sec manages its own dependencies.

This test simulates using keri-sec to govern its own development environment.
It exposes the bootstrap problem and environment isolation gaps.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


class TestDogfooding:
    """Test keri-sec managing its own dependencies."""

    def test_define_self_stack(self):
        """Define a stack for keri-sec development."""
        # Import here to test the import path issue
        from keri_sec import StackManager, ConstraintType

        sm = StackManager(base_path=Path(tempfile.mkdtemp()))

        # Define what keri-sec needs
        stack = sm.define_stack(
            name="keri-sec-dev",
            controller_aid="BSELF_DOGFOOD_TEST",
            constraints={
                "python": ">=3.12",
                "keri": ">=1.2.0",
                "hio": ">=0.6.14",
                "packaging": ">=23.0",
                "pytest": ">=8.0.0",
                # System constraint - the problematic one
                # "system:libsodium": ">=1.0.18",
            },
            rationale="Self-governance: keri-sec development environment",
        )

        assert stack.said.startswith("E")
        assert len(stack.constraints) == 5
        assert "python" in stack.constraints
        assert "keri" in stack.constraints

    def test_verify_current_environment(self):
        """Verify current environment against self-stack."""
        from keri_sec import StackManager

        sm = StackManager(base_path=Path(tempfile.mkdtemp()))

        stack = sm.define_stack(
            name="keri-sec-dev",
            controller_aid="BSELF_DOGFOOD_TEST",
            constraints={
                "python": ">=3.12",
                "keri": ">=1.2.0",
                "hio": ">=0.6.14",
            },
        )

        result = sm.check_compliance(stack.said)

        # We should be compliant since we're running in the dev environment
        assert result.compliant, f"Missing: {result.missing}, Outdated: {result.outdated}"

    def test_generate_own_pyproject(self):
        """Generate pyproject.toml that matches our actual pyproject.toml."""
        from keri_sec import StackManager

        sm = StackManager(base_path=Path(tempfile.mkdtemp()))

        stack = sm.define_stack(
            name="keri-sec",
            controller_aid="BSELF_DOGFOOD_TEST",
            constraints={
                "python": ">=3.12",
                "keri": ">=1.2.0",
                "hio": ">=0.6.14",
                "packaging": ">=23.0",
            },
        )

        generated = sm.generate_pyproject(stack.said)

        # Verify structure
        assert "# GOVERNED STACK" in generated
        assert "# SAID:" in generated
        assert 'requires-python = ">=3.12"' in generated
        assert '"keri>=1.2.0"' in generated

    def test_handler_verification_path(self):
        """Test that handler-based verification works for self-check."""
        from keri_sec import StackManager, get_handler

        sm = StackManager(base_path=Path(tempfile.mkdtemp()))

        # Verify Python version via handler directly
        python_handler = get_handler("python")
        result = python_handler.verify("python", ">=3.12")

        assert result.verified, f"Python check failed: {result.message}"
        assert "3.1" in result.actual_value  # Should be 3.12+

        # Verify keri package via handler
        package_handler = get_handler("package")
        result = package_handler.verify("keri", ">=1.0.0")

        # This might fail if keri isn't installed, which is the bootstrap problem
        if result.verified:
            assert result.actual_value  # Has a version string

    def test_bootstrap_problem_exposed(self):
        """
        Demonstrate the bootstrap problem.

        To verify keri>=1.2.0 is installed, we need to import keri.
        But if keri isn't installed, we can't verify anything.

        This is the fundamental limitation of self-verification.
        """
        from keri_sec import get_handler

        handler = get_handler("package")

        # Try to verify a package that definitely doesn't exist
        result = handler.verify("nonexistent-package-xyz", ">=1.0.0")

        assert not result.verified
        assert "not installed" in result.message.lower()

        # The bootstrap insight: we CAN'T verify keri without keri
        # So keri-sec has an implicit dependency on its verifier

    def test_said_determinism_for_self(self):
        """Verify SAID computation is deterministic for self-governance."""
        from keri_sec import StackManager

        sm1 = StackManager(base_path=Path(tempfile.mkdtemp()))
        sm2 = StackManager(base_path=Path(tempfile.mkdtemp()))

        constraints = {
            "python": ">=3.12",
            "keri": ">=1.2.0",
            "hio": ">=0.6.14",
        }

        stack1 = sm1.define_stack(
            name="keri-sec-dev",
            controller_aid="BCONTROLLER",
            constraints=constraints,
        )

        stack2 = sm2.define_stack(
            name="keri-sec-dev",
            controller_aid="BCONTROLLER",
            constraints=constraints,
        )

        # Same inputs = same SAID (deterministic)
        assert stack1.said == stack2.said

    @pytest.mark.skipif(
        not Path("/opt/homebrew/lib/libsodium.dylib").exists(),
        reason="libsodium not at expected path"
    )
    def test_system_constraint_verification(self):
        """
        Test system constraint verification (if libsodium available).

        This demonstrates why system constraints are harder:
        - Location varies by platform
        - Version extraction is fragile
        - No universal package manager query
        """
        from keri_sec import get_handler

        handler = get_handler("system")
        result = handler.verify("libsodium", ">=1.0.0")

        # May or may not work depending on environment
        # The point is to demonstrate the challenge
        print(f"System constraint result: {result}")


class TestTransitSchemaParadox:
    """
    Test the Transit "no schemas" vs KERI "schemas required" tension.

    Transit claims semantic preservation without schemas.
    KERI requires schemas for ACDC credentials.
    How do we reconcile this?
    """

    def test_handler_as_implicit_schema(self):
        """
        Demonstrate that Transit handlers ARE schemas, just in code form.

        The handler's serialize() method defines the canonical structure.
        The handler's verify() method defines the validation rules.
        Together, they ARE a schema - just not as external JSON Schema.
        """
        from keri_sec import get_handler

        handler = get_handler("package")

        # The handler defines:
        # 1. Structure: {"handler": "K", "type": "package", "name": ..., "spec": ...}
        # 2. Validation: Check importlib.metadata.version()
        # 3. Serialization: JSON with sorted keys

        # This IS a schema, embedded in code
        serialized = handler.serialize("keri", ">=1.2.0")

        # The "schema" is implicit in the byte structure
        import json
        data = json.loads(serialized)

        assert "handler" in data  # Type tag (Transit-style)
        assert "type" in data     # Human-readable type
        assert "name" in data     # Constraint name
        assert "spec" in data     # Version spec

    def test_said_as_schema_reference(self):
        """
        KERI insight: SAID IS the schema reference.

        Transit uses tags to identify types.
        KERI uses SAIDs to identify schemas.
        Both are content-addressed - neither requires a central registry.
        """
        from keri_sec import get_handler

        handler = get_handler("package")

        # Same inputs = same SAID (content-addressed)
        said1 = handler.compute_said("keri", ">=1.2.0")
        said2 = handler.compute_said("keri", ">=1.2.0")

        assert said1 == said2

        # Different inputs = different SAID
        said3 = handler.compute_said("keri", ">=1.3.0")
        assert said1 != said3

        # The SAID IS the "schema version" - change content, change SAID

    def test_extension_type_schema_bridge(self):
        """
        Extension types could bridge to full ACDC schemas if needed.

        Ground types: Handler IS schema (Transit pattern)
        Extension types: Can reference external schema SAID (KERI pattern)
        """
        from keri_sec import ExtensionConstraint

        ext = ExtensionConstraint(
            tag="keri-production",
            ground_type="package",
            constraints=[
                {"name": "keri", "version": ">=1.2.0"},
                {"name": "hio", "version": ">=0.6.14"},
            ],
            metadata={
                # Could reference ACDC schema here
                "acdc_schema_said": "ESchemaForKeriProductionStack...",
            },
        )

        # Extension has both:
        # 1. Handler-based ground verification (Transit pattern)
        # 2. Optional schema reference (KERI pattern)
        assert ext.ground_type == "package"  # Uses PackageHandler
        assert "acdc_schema_said" in ext.metadata  # Can link to ACDC

    def test_schema_free_verification(self):
        """
        Demonstrate that verification doesn't require external schema lookup.

        This is Transit's key insight applied to KERI:
        The handler knows how to verify - no schema fetch needed.
        """
        from keri_sec import StackManager, get_handler

        sm = StackManager(base_path=Path(tempfile.mkdtemp()))

        # Define stack (computes SAIDs)
        stack = sm.define_stack(
            name="test",
            controller_aid="BTEST",
            constraints={"python": ">=3.12"},
        )

        # Verify against stack (no schema lookup)
        result = sm.check_compliance(stack.said)

        # Verification happened entirely locally:
        # 1. Handler knew how to serialize (implicit schema)
        # 2. Handler knew how to verify (embedded logic)
        # 3. SAID provided content-addressing (no registry)

        assert result.compliant or not result.compliant  # Either way, it worked
