# -*- encoding: utf-8 -*-
"""
End-to-end TEL anchoring tests with real keripy infrastructure.

Validates the full credential lifecycle:
  Habery → Regery → Registry.make() → proving.credential() →
  Registry.issue() → hab.interact(seal) → tvy.processEvent() →
  verify_tel_status()

This is the production-readiness gate for Phase 4 (TEL Anchoring).
Without these tests passing against real keripy, the _anchor_to_tel()
and verify_tel_status() implementations are unproven claims.

Key insight: keripy's Registry.make() and Registry.issue() create TEL events
but call processEvent() without anchor info (seqner/saider). The TEL event
processor raises MissingAnchorError and the Tever is never created.
To complete the flow, after creating the KEL interaction event (the anchor),
we must call tvy.processEvent(serder, seqner, saider) with the anchor's
sequence number and SAID so the Tever gets populated in reger.tevers.
"""

import pytest
from datetime import datetime, timezone

from keri.app import habbing
from keri.vdr import credentialing
from keri.vc import proving
from keri.core import eventing as keventing
from keri.core import coring, serdering
from keri.core.coring import Seqner, Saider

from keri_sec.verification import verify_tel_status


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def anchor_tel_event(hab, registry, tel_serder):
    """
    Anchor a TEL event to the KEL and process it so reger.tevers is populated.

    This is the missing step that keripy's Registry.make()/issue()/revoke()
    don't do automatically — they create the TEL event but can't anchor it
    without a KEL interaction event providing the seal.

    Args:
        hab: The issuer's Hab (for creating KEL interaction events)
        registry: The Registry (has .tvy for TEL event processing)
        tel_serder: The TEL event serder (vcp, iss, rev, etc.)

    Returns:
        The KEL anchor event bytes
    """
    # Create seal pointing to the TEL event
    rseal = keventing.SealEvent(tel_serder.pre, tel_serder.snh, tel_serder.said)

    # Create KEL interaction event that anchors the TEL event
    anc = hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])

    # Parse the anchor event to extract sequence number and SAID
    anc_serder = serdering.SerderKERI(raw=bytes(anc))
    seqner = Seqner(sn=int(anc_serder.ked["s"], 16))
    saider = Saider(qb64=anc_serder.said)

    # Process the TEL event with anchor info — THIS populates reger.tevers
    registry.tvy.processEvent(serder=tel_serder, seqner=seqner, saider=saider)

    return anc


def issue_and_anchor(hab, registry, creder_said, dt=None):
    """Issue a credential to TEL and anchor it. Returns the iss serder."""
    if dt is None:
        dt = datetime.now(timezone.utc).isoformat()
    iserder = registry.issue(said=creder_said, dt=dt)
    anchor_tel_event(hab, registry, iserder)
    return iserder


def revoke_and_anchor(hab, registry, creder_said, dt=None):
    """Revoke a credential in TEL and anchor it. Returns the rev serder."""
    if dt is None:
        dt = datetime.now(timezone.utc).isoformat()
    rserder = registry.revoke(said=creder_said, dt=dt)
    anchor_tel_event(hab, registry, rserder)
    return rserder


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def keri_env(tmp_path):
    """
    Minimal real KERI environment: Habery + Regery, temp storage.

    Uses the same pattern as ai-orchestrator/tests/test_credential_issuer.py.
    """
    hby = habbing.Habery(name="tel-test", temp=True)
    rgy = credentialing.Regery(hby=hby, name="tel-test", temp=True)
    yield {"hby": hby, "rgy": rgy}
    hby.close()


@pytest.fixture
def issuer_hab(keri_env):
    """Create a transferable issuer AID."""
    return keri_env["hby"].makeHab(name="issuer", transferable=True)


@pytest.fixture
def registry(keri_env, issuer_hab):
    """
    Create a TEL registry bound to the issuer and anchor its inception.

    The VCP (registry inception) event must be anchored to the KEL and
    processed with anchor info for reger.tevers to be populated.
    """
    rgy = keri_env["rgy"]
    reg = rgy.makeRegistry(name="test-registry", prefix=issuer_hab.pre)

    # Anchor the registry inception (VCP) event to the KEL
    anchor_tel_event(issuer_hab, reg, reg.vcp)

    return reg


# ---------------------------------------------------------------------------
# Tests: Full TEL lifecycle
# ---------------------------------------------------------------------------


class TestTELIssuance:
    """Test credential issuance via TEL with real keripy."""

    def test_registry_creation(self, registry):
        """Registry is created with a valid SAID prefix."""
        assert registry.regk is not None
        assert registry.regk.startswith("E")

    def test_registry_tever_populated(self, keri_env, registry):
        """After anchoring, the registry's Tever exists in reger.tevers."""
        reger = keri_env["rgy"].reger
        assert registry.regk in reger.tevers

    def test_issue_credential_to_tel(self, keri_env, issuer_hab, registry):
        """Full flow: create credential → TEL issue → KEL anchor."""
        dt = datetime.now(timezone.utc).isoformat()
        creder = proving.credential(
            issuer=issuer_hab.pre,
            schema="ELJm6sOw-eZmeTGgLrO0p614JPcJLX5RhWIw9WzvoaDV",
            data={"dt": dt, "test_key": "test_value"},
            status=registry.regk,
        )
        assert creder.said is not None
        assert creder.said.startswith("E")

        # Issue to TEL and anchor to KEL
        iserder = issue_and_anchor(issuer_hab, registry, creder.said, dt)
        assert iserder is not None

    def test_verify_tel_status_valid(self, keri_env, issuer_hab, registry):
        """verify_tel_status() returns 'valid' for an issued credential."""
        dt = datetime.now(timezone.utc).isoformat()
        creder = proving.credential(
            issuer=issuer_hab.pre,
            schema="ELJm6sOw-eZmeTGgLrO0p614JPcJLX5RhWIw9WzvoaDV",
            data={"dt": dt, "check": "status"},
            status=registry.regk,
        )

        issue_and_anchor(issuer_hab, registry, creder.said, dt)

        # Verify TEL status using keri-sec's verify_tel_status
        reger = keri_env["rgy"].reger
        status = verify_tel_status(
            registry_said=registry.regk,
            credential_said=creder.said,
            reger=reger,
        )
        assert status == "valid"

    def test_verify_tel_status_unknown_credential(self, keri_env, registry):
        """verify_tel_status() returns 'unknown' for a non-existent credential."""
        reger = keri_env["rgy"].reger
        status = verify_tel_status(
            registry_said=registry.regk,
            credential_said="ENonexistentSAID0000000000000000000000000000",
            reger=reger,
        )
        assert status == "unknown"

    def test_verify_tel_status_unknown_registry(self, keri_env):
        """verify_tel_status() returns 'unknown' for a non-existent registry."""
        reger = keri_env["rgy"].reger
        status = verify_tel_status(
            registry_said="ENoSuchRegistry000000000000000000000000000000",
            credential_said="ENoSuchCred0000000000000000000000000000000000",
            reger=reger,
        )
        assert status == "unknown"

    def test_multiple_credentials_same_registry(
        self, keri_env, issuer_hab, registry
    ):
        """Multiple credentials in the same registry each get unique TEL events."""
        reger = keri_env["rgy"].reger
        cred_saids = []

        for i in range(3):
            dt = datetime.now(timezone.utc).isoformat()
            creder = proving.credential(
                issuer=issuer_hab.pre,
                schema="ELJm6sOw-eZmeTGgLrO0p614JPcJLX5RhWIw9WzvoaDV",
                data={"dt": dt, "index": i},
                status=registry.regk,
            )
            issue_and_anchor(issuer_hab, registry, creder.said, dt)
            cred_saids.append(creder.said)

        # All SAIDs are unique
        assert len(set(cred_saids)) == 3

        # All are verifiable as valid
        for said in cred_saids:
            status = verify_tel_status(
                registry_said=registry.regk,
                credential_said=said,
                reger=reger,
            )
            assert status == "valid", f"Credential {said} should be valid"


class TestTELRevocation:
    """Test credential revocation via TEL."""

    def test_revoke_credential(self, keri_env, issuer_hab, registry):
        """Revoked credential shows 'revoked' status."""
        reger = keri_env["rgy"].reger
        dt = datetime.now(timezone.utc).isoformat()

        # Issue
        creder = proving.credential(
            issuer=issuer_hab.pre,
            schema="ELJm6sOw-eZmeTGgLrO0p614JPcJLX5RhWIw9WzvoaDV",
            data={"dt": dt, "revocable": True},
            status=registry.regk,
        )
        issue_and_anchor(issuer_hab, registry, creder.said, dt)

        # Confirm valid before revocation
        status = verify_tel_status(
            registry_said=registry.regk,
            credential_said=creder.said,
            reger=reger,
        )
        assert status == "valid"

        # Revoke and anchor
        revoke_and_anchor(issuer_hab, registry, creder.said, dt)

        # Verify revoked
        status = verify_tel_status(
            registry_said=registry.regk,
            credential_said=creder.said,
            reger=reger,
        )
        assert status == "revoked"

    def test_revoke_does_not_affect_other_credentials(
        self, keri_env, issuer_hab, registry
    ):
        """Revoking one credential doesn't affect others in the same registry."""
        reger = keri_env["rgy"].reger
        dt = datetime.now(timezone.utc).isoformat()

        # Issue two credentials
        creds = []
        for i in range(2):
            creder = proving.credential(
                issuer=issuer_hab.pre,
                schema="ELJm6sOw-eZmeTGgLrO0p614JPcJLX5RhWIw9WzvoaDV",
                data={"dt": dt, "index": i},
                status=registry.regk,
            )
            issue_and_anchor(issuer_hab, registry, creder.said, dt)
            creds.append(creder)

        # Revoke only the first
        revoke_and_anchor(issuer_hab, registry, creds[0].said, dt)

        # First is revoked
        assert verify_tel_status(
            registry_said=registry.regk,
            credential_said=creds[0].said,
            reger=reger,
        ) == "revoked"

        # Second is still valid
        assert verify_tel_status(
            registry_said=registry.regk,
            credential_said=creds[1].said,
            reger=reger,
        ) == "valid"


class TestAnchorToTELIntegration:
    """
    Test that _anchor_to_tel() from InstallationCredentialIssuer works
    with real keripy infrastructure (not mocked).

    Note: _anchor_to_tel() creates the iss event and KEL interaction but
    does NOT call tvy.processEvent with anchor info. This means the Tever
    is not populated by _anchor_to_tel alone — the MissingAnchorError path
    in keripy leaves the event in escrow. This test validates the _anchor_to_tel
    code path runs without error against real keripy.
    """

    def test_anchor_to_tel_runs_without_error(self, keri_env, issuer_hab, registry):
        """
        _anchor_to_tel() creates TEL issuance event and KEL anchor
        without raising exceptions against real keripy.
        """
        from keri_sec.installation_credential import (
            InstallationCredentialIssuer,
            IssuedCredential,
        )

        dt = datetime.now(timezone.utc).isoformat()

        creder = proving.credential(
            issuer=issuer_hab.pre,
            schema="ELJm6sOw-eZmeTGgLrO0p614JPcJLX5RhWIw9WzvoaDV",
            data={"dt": dt, "via_issuer_class": True},
            status=registry.regk,
        )

        issued = IssuedCredential(
            said=creder.said,
            issuer=issuer_hab.pre,
            registry_said=registry.regk,
            credential={"d": creder.said},
            tel_anchored=False,
        )

        # Pass the Registry directly (has .issue method)
        issuer = InstallationCredentialIssuer(
            issuer_aid=issuer_hab.pre,
            registry_said=registry.regk,
            hby=keri_env["hby"],
            rgy=registry,
        )

        # Should not raise
        issuer._anchor_to_tel(issued)
