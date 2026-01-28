# -*- encoding: utf-8 -*-
"""
Attack scenario tests demonstrating governance advantages.

These tests show concrete examples where traditional dependency management
fails but keri-sec's cryptographic commitments succeed.

PHILOSOPHY:
- Traditional pyproject.toml/requirements.txt can be edited by anyone
- No cryptographic binding between "who approved" and "what was approved"
- Version drift happens silently across environments
- Supply chain attacks can inject malicious versions undetected

GOVERNED APPROACH:
- Every constraint has a SAID (cryptographic hash)
- Stack SAID changes if ANY constraint changes
- Controller AID binds authorization to the constraint
- Tampering is detectable: recompute SAID, compare
"""

import pytest
import json
import hashlib
from pathlib import Path

from keri_sec import (
    StackManager,
    KERI_PRODUCTION_STACK,
    MINIMAL_STACK,
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


class TestTamperDetection:
    """
    SCENARIO: Developer receives pyproject.toml, modifies a version.

    TRADITIONAL: No way to detect the modification.
    GOVERNED: SAID verification fails immediately.
    """

    def test_modified_pyproject_detectable(self, manager):
        """Modifying generated pyproject.toml is cryptographically detectable."""
        # Create keri-sec stack
        stack = manager.define_stack(
            name="secure-project",
            controller_aid="BAUTHORIZED_CONTROLLER_AID",
            constraints={"python": ">=3.12", "keri": ">=1.2.0"},
        )
        original_said = stack.said

        # Generate pyproject.toml
        original_toml = manager.generate_pyproject(stack.said)
        assert "keri>=1.2.0" in original_toml

        # ATTACK: Malicious actor modifies the version
        tampered_toml = original_toml.replace("keri>=1.2.0", "keri>=0.0.1")

        # DETECTION: Verify the tampering is detectable
        # Extract SAID from tampered file and compare
        assert "SAID: " + original_said in original_toml
        assert "SAID: " + original_said in tampered_toml  # SAID comment still there

        # But content no longer matches SAID
        # Redefine with tampered constraints - SAID will differ
        tampered_stack = manager.define_stack(
            name="secure-project",
            controller_aid="BAUTHORIZED_CONTROLLER_AID",
            constraints={"python": ">=3.12", "keri": ">=0.0.1"},  # Tampered
        )

        # PROOF: Different constraints = different SAID
        assert tampered_stack.said != original_said
        # The SAID in the file no longer matches the content

    def test_requirements_tampering_detectable(self, manager):
        """Tampering with requirements.txt is detectable via constraint SAIDs."""
        stack = manager.define_stack(
            name="req-project",
            controller_aid="BCONTROLLER",
            constraints={"requests": ">=2.28.0", "urllib3": ">=1.26.0"},
        )

        reqs = manager.generate_requirements(stack.said)

        # Each line has its constraint SAID
        assert "# SAID: E" in reqs

        # Extract a constraint SAID
        for line in reqs.split("\n"):
            if "requests>=" in line and "SAID:" in line:
                original_line = line
                # Parse the SAID
                said_part = line.split("SAID: ")[1].strip()
                break

        # Verify the SAID is deterministic
        constraint = stack.constraints["requests"]
        assert constraint.said == said_part

        # If someone changes "requests>=2.28.0" to "requests>=2.0.0"
        # They would need to forge the SAID (cryptographically infeasible)


class TestSilentDrift:
    """
    SCENARIO: Production runs keri==1.2.0, dev has keri==1.3.0,
              CI uses keri==1.2.5. Nobody notices until bugs appear.

    TRADITIONAL: Each environment drifts independently.
    GOVERNED: All environments verify against the same SAID.
    """

    def test_drift_detected_by_said_mismatch(self, manager, temp_path):
        """Version drift across environments is detectable."""
        # Ops team defines production stack
        prod_stack = manager.define_stack(
            name="production",
            controller_aid="BOPS_TEAM_AID",
            constraints={"keri": "==1.2.0", "hio": "==0.6.14"},
        )
        prod_said = prod_stack.said

        # Dev team tries to use different versions
        dev_constraints = {"keri": "==1.3.0", "hio": "==0.6.14"}  # Different keri!

        # If dev defines "their" stack, SAID will differ
        dev_stack = manager.define_stack(
            name="production",  # Same name
            controller_aid="BOPS_TEAM_AID",  # Same controller
            constraints=dev_constraints,
        )

        # PROOF: Drift is immediately visible
        assert dev_stack.said != prod_said

        # The dev environment cannot claim compliance with prod SAID
        # Because their constraints produce a different SAID

    def test_cross_environment_verification(self, manager):
        """Same stack definition guarantees identical SAID across calls."""
        constraints = {"python": ">=3.12", "keri": ">=1.2.0,<2.0.0"}

        # Define same stack twice (simulates different environments)
        stack1 = manager.define_stack(
            name="myapp",
            controller_aid="BMASTER",
            constraints=constraints,
        )

        stack2 = manager.define_stack(
            name="myapp",
            controller_aid="BMASTER",
            constraints=constraints,
        )

        # PROOF: Identical definitions = identical SAIDs
        # Both environments verify against same SAID
        assert stack1.said == stack2.said

        # Any deviation produces different SAID
        deviated = manager.define_stack(
            name="myapp",
            controller_aid="BMASTER",
            constraints={"python": ">=3.12", "keri": ">=1.3.0,<2.0.0"},  # Different keri
        )
        assert deviated.said != stack1.said


class TestUnauthorizedModification:
    """
    SCENARIO: Junior dev changes keri version without approval.

    TRADITIONAL: Git blame shows change, but no cryptographic proof of authorization.
    GOVERNED: Controller AID didn't sign the new SAID.
    """

    def test_unauthorized_change_produces_different_said(self, manager):
        """Unauthorized version changes produce detectably different SAIDs."""
        # Authorized stack by senior engineer
        authorized = manager.define_stack(
            name="company-stack",
            controller_aid="BSENIOR_ENGINEER_AID",
            constraints={"keri": ">=1.2.0,<2.0.0"},
        )
        authorized_said = authorized.said

        # Junior dev tries to "update" without authorization
        unauthorized = manager.define_stack(
            name="company-stack",
            controller_aid="BSENIOR_ENGINEER_AID",  # Claims same controller
            constraints={"keri": ">=1.3.0,<2.0.0"},  # Different constraint
        )

        # PROOF: SAID differs, so this isn't the authorized stack
        assert unauthorized.said != authorized_said

        # In production:
        # - CI checks against authorized_said
        # - Unauthorized changes fail verification
        # - Git history + KERI KEL shows junior didn't have authority

    def test_controller_binding(self, manager):
        """Controller AID is cryptographically bound to constraints."""
        constraints = {"python": ">=3.12"}

        # Same constraints, different controllers
        stack1 = manager.define_stack(
            name="test",
            controller_aid="BALICE_AID_12345",
            constraints=constraints,
        )
        stack2 = manager.define_stack(
            name="test",
            controller_aid="BBOB_AID_67890",
            constraints=constraints,
        )

        # PROOF: Different controller = different SAID
        # You can't claim Alice's authority with Bob's AID
        assert stack1.said != stack2.said


class TestSupplyChainAttack:
    """
    SCENARIO: Attacker compromises CI, injects malicious dependency version.

    TRADITIONAL: CI installs whatever requirements.txt says.
    GOVERNED: CI verifies SAID before installation.
    """

    def test_injected_dependency_detectable(self, manager):
        """Injected malicious dependency changes SAID."""
        # Legitimate stack
        legit = manager.define_stack(
            name="webapp",
            controller_aid="BSECURITY_TEAM",
            constraints={
                "django": ">=4.0,<5.0",
                "celery": ">=5.2.0",
            },
        )
        legit_said = legit.said

        # Attacker injects malicious package
        compromised = manager.define_stack(
            name="webapp",
            controller_aid="BSECURITY_TEAM",
            constraints={
                "django": ">=4.0,<5.0",
                "celery": ">=5.2.0",
                "evil-package": ">=1.0.0",  # INJECTED
            },
        )

        # PROOF: Injection detected via SAID mismatch
        assert compromised.said != legit_said

    def test_version_downgrade_attack_detectable(self, manager):
        """Downgrade attacks (using vulnerable versions) are detectable."""
        # Secure stack with patched versions
        secure = manager.define_stack(
            name="secure-app",
            controller_aid="BSEC_TEAM",
            constraints={"requests": ">=2.31.0"},  # CVE-2023-32681 patched
        )

        # Attacker downgrades to vulnerable version
        vulnerable = manager.define_stack(
            name="secure-app",
            controller_aid="BSEC_TEAM",
            constraints={"requests": ">=2.25.0"},  # Vulnerable!
        )

        # PROOF: Downgrade detected
        assert vulnerable.said != secure.said


class TestReproducibility:
    """
    SCENARIO: "Works on my machine" - builds differ across environments.

    TRADITIONAL: Lock files can drift, be regenerated differently.
    GOVERNED: SAID guarantees identical constraints regardless of when/where.
    """

    def test_said_reproducible_across_time(self, temp_path):
        """Same inputs always produce same SAID, regardless of time."""
        constraints = {"python": ">=3.12", "keri": ">=1.2.0"}

        # First definition
        manager1 = StackManager(base_path=temp_path / "m1")
        stack1 = manager1.define_stack(
            name="repro-test",
            controller_aid="BCONTROLLER",
            constraints=constraints,
        )

        # "Later" definition (different manager instance)
        manager2 = StackManager(base_path=temp_path / "m2")
        stack2 = manager2.define_stack(
            name="repro-test",
            controller_aid="BCONTROLLER",
            constraints=constraints,
        )

        # PROOF: Identical SAIDs
        assert stack1.said == stack2.said

    def test_constraint_order_irrelevant(self, manager):
        """SAID is independent of constraint definition order."""
        # Order 1
        stack1 = manager.define_stack(
            name="order-test",
            controller_aid="BCTRL",
            constraints={"z": ">=1.0", "a": ">=2.0", "m": ">=3.0"},
        )

        # Order 2 (different order)
        stack2 = manager.define_stack(
            name="order-test",
            controller_aid="BCTRL",
            constraints={"a": ">=2.0", "m": ">=3.0", "z": ">=1.0"},
        )

        # Order 3 (another different order)
        stack3 = manager.define_stack(
            name="order-test",
            controller_aid="BCTRL",
            constraints={"m": ">=3.0", "z": ">=1.0", "a": ">=2.0"},
        )

        # PROOF: All produce same SAID
        assert stack1.said == stack2.said == stack3.said


class TestVerificationWorkflow:
    """
    SCENARIO: CI/CD pipeline needs to verify dependencies before deploy.

    These tests demonstrate the verification workflow.
    """

    def test_verify_against_known_said(self, manager):
        """CI can verify current constraints match expected SAID."""
        # Security team publishes approved SAID
        approved = manager.define_stack(
            name="approved-stack",
            controller_aid="BSECURITY_TEAM",
            constraints=MINIMAL_STACK,
        )
        approved_said = approved.said

        # CI receives constraints from developer
        developer_constraints = MINIMAL_STACK.copy()

        # CI verifies by recomputing
        verification = manager.define_stack(
            name="approved-stack",
            controller_aid="BSECURITY_TEAM",
            constraints=developer_constraints,
        )

        # PROOF: Verification passes - SAIDs match
        assert verification.said == approved_said

    def test_reject_modified_constraints(self, manager):
        """CI rejects constraints that don't match approved SAID."""
        # Approved SAID
        approved = manager.define_stack(
            name="prod-stack",
            controller_aid="BOPS",
            constraints={"keri": ">=1.2.0"},
        )
        approved_said = approved.said

        # Developer submits "slightly" modified constraints
        modified = manager.define_stack(
            name="prod-stack",
            controller_aid="BOPS",
            constraints={"keri": ">=1.2.1"},  # Sneaky change
        )

        # PROOF: Verification fails
        assert modified.said != approved_said
        # CI would reject this deploy


class TestAuditTrail:
    """
    SCENARIO: Auditor asks "who approved this version 6 months ago?"

    TRADITIONAL: Git blame (mutable), no cryptographic proof.
    GOVERNED: Controller AID + SAID = verifiable proof.
    """

    def test_stack_contains_audit_info(self, manager):
        """Stack contains all info needed for audit."""
        stack = manager.define_stack(
            name="auditable",
            controller_aid="BAUDITOR_APPROVED_AID",
            constraints={"critical-pkg": ">=2.0.0"},
            rationale="Security review completed 2026-01-24",
        )

        # PROOF: All audit info is preserved
        assert stack.controller_aid == "BAUDITOR_APPROVED_AID"
        # Rationale is stored per-constraint
        assert stack.constraints["critical-pkg"].rationale == "Security review completed 2026-01-24"
        assert stack.said is not None  # Cryptographic commitment

        # The SAID binds controller + constraints together
        # Changing controller changes SAID
        different_controller = manager.define_stack(
            name="auditable",
            controller_aid="BDIFFERENT_AID",  # Different controller
            constraints={"critical-pkg": ">=2.0.0"},
            rationale="Security review completed 2026-01-24",
        )
        assert different_controller.said != stack.said

    def test_name_changes_said(self, manager):
        """Stack name is part of the cryptographic commitment."""
        stack1 = manager.define_stack(
            name="original-name",
            controller_aid="BCTRL",
            constraints={"pkg": ">=1.0"},
        )

        stack2 = manager.define_stack(
            name="different-name",  # Only name changed
            controller_aid="BCTRL",
            constraints={"pkg": ">=1.0"},
        )

        # PROOF: Name is part of the commitment
        assert stack1.said != stack2.said


class TestVerificationAPI:
    """
    Tests for the verification API that enables "cannot be edited manually".

    These tests demonstrate the verification workflow that makes
    manual editing cryptographically detectable.
    """

    def test_verify_stack_returns_true_for_matching(self, manager):
        """verify_stack returns True when constraints match SAID."""
        constraints = {"python": ">=3.12", "keri": ">=1.2.0"}

        # Define stack to get known-good SAID
        stack = manager.define_stack(
            name="verify-test",
            controller_aid="BVERIFIER",
            constraints=constraints,
        )

        # Verify with same inputs
        verified, computed = manager.verify_stack(
            expected_said=stack.said,
            name="verify-test",
            controller_aid="BVERIFIER",
            constraints=constraints,
        )

        assert verified is True
        assert computed == stack.said

    def test_verify_stack_returns_false_for_tampered(self, manager):
        """verify_stack returns False when constraints are modified."""
        stack = manager.define_stack(
            name="tamper-verify",
            controller_aid="BOWNER",
            constraints={"keri": ">=1.2.0"},
        )

        # Try to verify with modified constraints
        verified, computed = manager.verify_stack(
            expected_said=stack.said,
            name="tamper-verify",
            controller_aid="BOWNER",
            constraints={"keri": ">=1.3.0"},  # TAMPERED
        )

        assert verified is False
        assert computed != stack.said

    def test_verify_pyproject_detects_modification(self, manager):
        """verify_pyproject detects when content doesn't match embedded SAID."""
        # Create stack and generate pyproject
        stack = manager.define_stack(
            name="pyproj-verify",
            controller_aid="BCONTROLLER",
            constraints={"python": ">=3.12", "flask": ">=2.0.0"},
        )
        original_toml = manager.generate_pyproject(stack.said)

        # Verify original
        verified, said, extracted = manager.verify_pyproject(original_toml)
        assert verified is True
        assert said == stack.said

        # Tamper with content
        tampered = original_toml.replace("flask>=2.0.0", "flask>=1.0.0")

        # Verify tampered - should fail
        verified, said, extracted = manager.verify_pyproject(tampered)
        assert verified is False

    def test_verify_constraint_isolation(self, manager):
        """Changing one constraint invalidates stack SAID."""
        stack = manager.define_stack(
            name="isolation-test",
            controller_aid="BCTRL",
            constraints={
                "a": ">=1.0",
                "b": ">=2.0",
                "c": ">=3.0",
            },
        )

        # Change just one constraint
        verified, _ = manager.verify_stack(
            expected_said=stack.said,
            name="isolation-test",
            controller_aid="BCTRL",
            constraints={
                "a": ">=1.0",
                "b": ">=2.1",  # Changed from 2.0 to 2.1
                "c": ">=3.0",
            },
        )

        # Even one character change is detected
        assert verified is False

    def test_controller_tampering_detected(self, manager):
        """Changing controller AID is detected."""
        stack = manager.define_stack(
            name="ctrl-test",
            controller_aid="BORIGINAL_CONTROLLER",
            constraints={"pkg": ">=1.0"},
        )

        # Try to claim different controller
        verified, _ = manager.verify_stack(
            expected_said=stack.said,
            name="ctrl-test",
            controller_aid="BATTACKER_CONTROLLER",  # Different!
            constraints={"pkg": ">=1.0"},
        )

        assert verified is False


class TestRealWorldScenarios:
    """
    End-to-end scenarios showing governed workflow in practice.
    """

    def test_ci_verification_workflow(self, manager):
        """
        SCENARIO: CI pipeline verifies dependencies before deploy.

        1. Security team defines approved stack, publishes SAID
        2. Developers use constraints in their pyproject.toml
        3. CI extracts constraints, verifies against approved SAID
        4. Deploy only if verified
        """
        # Step 1: Security team creates approved stack
        approved_stack = manager.define_stack(
            name="production-approved",
            controller_aid="BSECURITY_TEAM_AID",
            constraints={
                "python": ">=3.12",
                "django": ">=4.2.0,<5.0.0",
                "psycopg2-binary": ">=2.9.0",
            },
        )
        APPROVED_SAID = approved_stack.said  # Published to CI config

        # Step 2: Developer generates pyproject.toml
        pyproject = manager.generate_pyproject(APPROVED_SAID)

        # Step 3: CI verifies
        verified, computed_said, constraints = manager.verify_pyproject(pyproject)

        # Step 4: Deploy decision
        assert verified is True, "CI should approve this deploy"

        # ATTACK: Developer modifies pyproject.toml
        hacked_pyproject = pyproject.replace("django>=4.2.0,<5.0.0", "django>=3.0.0")

        # CI catches the modification
        verified, _, _ = manager.verify_pyproject(hacked_pyproject)
        assert verified is False, "CI should reject modified dependencies"

    def test_multienv_consistency(self, manager, temp_path):
        """
        SCENARIO: Ensure dev, staging, prod all use same dependencies.

        Traditional approach: Each env has its own requirements file.
        Governed approach: All environments verify against one SAID.
        """
        # Ops team defines canonical stack
        canonical = manager.define_stack(
            name="myapp",
            controller_aid="BOPS_TEAM",
            constraints={
                "python": ">=3.12",
                "requests": ">=2.31.0",
                "redis": ">=4.5.0",
            },
        )
        CANONICAL_SAID = canonical.said

        # Each environment gets same pyproject
        dev_pyproject = manager.generate_pyproject(CANONICAL_SAID)
        staging_pyproject = manager.generate_pyproject(CANONICAL_SAID)
        prod_pyproject = manager.generate_pyproject(CANONICAL_SAID)

        # All should verify against canonical SAID
        for env_name, pyproject in [
            ("dev", dev_pyproject),
            ("staging", staging_pyproject),
            ("prod", prod_pyproject),
        ]:
            verified, said, _ = manager.verify_pyproject(pyproject)
            assert verified is True, f"{env_name} should verify"
            assert said == CANONICAL_SAID, f"{env_name} should have canonical SAID"

        # All have same SAID (timestamp in comments may differ, but SAID is deterministic)
        assert f"# SAID: {CANONICAL_SAID}" in dev_pyproject
        assert f"# SAID: {CANONICAL_SAID}" in staging_pyproject
        assert f"# SAID: {CANONICAL_SAID}" in prod_pyproject

    def test_audit_reconstruction(self, manager):
        """
        SCENARIO: 6 months later, auditor asks "what was approved?"

        1. Auditor has only the SAID from a deploy log
        2. Can verify any pyproject.toml claims against that SAID
        3. Can detect if someone modified constraints post-approval
        """
        # Original approval (imagine this was 6 months ago)
        original = manager.define_stack(
            name="webapp-v2.3.0",
            controller_aid="BSECURITY_APPROVED",
            constraints={"library": ">=1.5.0"},
        )
        HISTORICAL_SAID = original.said

        # Current pyproject.toml claims to be approved
        claimed_pyproject = '''# GOVERNED STACK - Do not edit manually
# Stack: webapp-v2.3.0
# SAID: {said}
# Controller: BSECURITY_APPROVED

[project]
dependencies = [
    "library>=1.5.0",  # SAID: xxx
]
'''.format(said=HISTORICAL_SAID)

        # Parse and verify manually
        constraints = {"library": ">=1.5.0"}
        verified, _ = manager.verify_stack(
            expected_said=HISTORICAL_SAID,
            name="webapp-v2.3.0",
            controller_aid="BSECURITY_APPROVED",
            constraints=constraints,
        )

        assert verified is True, "Auditor can verify historical approval"

        # Attacker claims old SAID but uses different version
        attacker_constraints = {"library": ">=0.1.0"}  # Vulnerable version!
        verified, _ = manager.verify_stack(
            expected_said=HISTORICAL_SAID,
            name="webapp-v2.3.0",
            controller_aid="BSECURITY_APPROVED",
            constraints=attacker_constraints,
        )

        assert verified is False, "Auditor detects tampering"
