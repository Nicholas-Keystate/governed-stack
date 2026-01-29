# -*- encoding: utf-8 -*-
"""
One-Relationship Identifier (ORI) Manager

Manages privacy-preserving AIDs where each relationship uses unique identifiers.

Key Privacy Property:
    Two different AIDs are information-theoretically uncorrelatable.
    If Alice uses A₁ with Bob and A₂ with Carol, neither Bob nor Carol
    can determine that A₁ and A₂ belong to the same controller.

Relationship Model:
    - A relationship is a pairing of two AIDs from different controllers
    - Relationships can be: bidirectional, uni-directional (in/out)
    - A context is a set of events using specific AIDs
    - A partition isolates contexts to prevent cross-correlation

Reference: SPAC_Message.md Section "Relationships"

Usage:
    manager = ORIManager(hby)

    # Create AID for new relationship context
    hab = manager.create_relationship(
        context_name="work-acme-corp",
        remote_aid="EAcmeCorpAID...",
    )

    # Use this hab for all interactions with Acme
    essr = ESSRProtocol(hby, hab)
    msg = essr.encrypt_and_sign(payload, "EAcmeCorpAID...")
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set, TYPE_CHECKING

from keri.core.coring import Diger, MtrDex

if TYPE_CHECKING:
    from keri.app import habbing

logger = logging.getLogger(__name__)


# =============================================================================
# Relationship Types
# =============================================================================


class RelationshipDirection(str, Enum):
    """Direction of relationship from local perspective."""

    BIDIRECTIONAL = "bidirectional"  # (A, <>, B) - mutual
    OUTGOING = "outgoing"            # (A, ->, B) - we initiate
    INCOMING = "incoming"            # (A, <-, B) - they initiate


@dataclass
class RelationshipContext:
    """
    A relationship context binding local and remote AIDs.

    Properties:
        - local_aid: Our AID for this relationship
        - remote_aid: Their AID for this relationship
        - context_name: Human-readable context identifier
        - direction: Relationship direction
        - created_at: When relationship was established
        - events: Set of event SAIDs in this context
    """

    local_aid: str
    remote_aid: str
    context_name: str
    direction: RelationshipDirection = RelationshipDirection.BIDIRECTIONAL
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    events: Set[str] = field(default_factory=set)
    metadata: Dict[str, str] = field(default_factory=dict)

    def add_event(self, event_said: str):
        """Record an event in this context."""
        self.events.add(event_said)

    @property
    def event_count(self) -> int:
        """Number of events in this context."""
        return len(self.events)


@dataclass
class RelationshipPartition:
    """
    A partition of mutually disjoint relationship contexts.

    Key property: AIDs in different contexts within a partition
    provide no correlatable information by themselves.

    Use partitions to isolate:
    - Work vs personal relationships
    - Different organizations
    - Different roles (buyer vs seller)
    """

    name: str
    contexts: Dict[str, RelationshipContext] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def add_context(self, context: RelationshipContext):
        """Add a context to this partition."""
        self.contexts[context.context_name] = context

    def get_context(self, context_name: str) -> Optional[RelationshipContext]:
        """Get context by name."""
        return self.contexts.get(context_name)

    def get_contexts_for_remote(self, remote_aid: str) -> List[RelationshipContext]:
        """Get all contexts involving a remote AID."""
        return [c for c in self.contexts.values() if c.remote_aid == remote_aid]


# =============================================================================
# ORI Manager
# =============================================================================


class ORIManager:
    """
    Manages One-Relationship Identifiers for privacy partitioning.

    Core principle: Each relationship context gets unique AIDs that are
    information-theoretically uncorrelatable to external observers.

    Features:
        - Create new AIDs for specific relationship contexts
        - Track which AID to use for which remote party
        - Manage relationship partitions
        - Support relationship formation protocol

    Example:
        manager = ORIManager(hby)

        # Create AID for work context with Acme Corp
        work_hab = manager.create_relationship("work-acme", "EAcmeAID...")

        # Create separate AID for personal context
        personal_hab = manager.create_relationship("personal-bob", "EBobAID...")

        # Acme and Bob cannot correlate these as same controller
    """

    def __init__(self, hby: "habbing.Habery"):
        """
        Initialize ORI manager.

        Args:
            hby: Habery for creating and managing AIDs
        """
        self.hby = hby

        # Context name -> RelationshipContext
        self.relationships: Dict[str, RelationshipContext] = {}

        # Partition name -> RelationshipPartition
        self.partitions: Dict[str, RelationshipPartition] = {}

        # Remote AID -> list of context names (for lookup)
        self._remote_index: Dict[str, List[str]] = {}

        # Local AID -> context name (reverse lookup)
        self._local_index: Dict[str, str] = {}

    def create_relationship(
        self,
        context_name: str,
        remote_aid: str,
        direction: RelationshipDirection = RelationshipDirection.BIDIRECTIONAL,
        partition: Optional[str] = None,
        transferable: bool = True,
        metadata: Optional[Dict[str, str]] = None,
    ) -> "habbing.Hab":
        """
        Create a new AID for a specific relationship context.

        This creates a fresh AID that will only be used for interactions
        with the specified remote party in the named context.

        Args:
            context_name: Human-readable context identifier
            remote_aid: AID of the remote party
            direction: Relationship direction
            partition: Optional partition to add context to
            transferable: Whether AID should support key rotation
            metadata: Optional metadata for the relationship

        Returns:
            Hab for the new relationship AID

        Raises:
            ValueError: If context already exists
        """
        if context_name in self.relationships:
            raise ValueError(f"Relationship context already exists: {context_name}")

        # Generate unique name for the Hab
        # Include truncated remote AID for debugging but not correlation
        hab_name = f"ori-{context_name[:20]}-{remote_aid[:8]}"

        # Create new AID
        logger.info(f"Creating ORI for context '{context_name}' with remote {remote_aid[:16]}...")

        hab = self.hby.makeHab(
            name=hab_name,
            transferable=transferable,
        )

        # Create relationship context
        context = RelationshipContext(
            local_aid=hab.pre,
            remote_aid=remote_aid,
            context_name=context_name,
            direction=direction,
            metadata=metadata or {},
        )

        # Store in indices
        self.relationships[context_name] = context
        self._local_index[hab.pre] = context_name

        if remote_aid not in self._remote_index:
            self._remote_index[remote_aid] = []
        self._remote_index[remote_aid].append(context_name)

        # Add to partition if specified
        if partition:
            if partition not in self.partitions:
                self.partitions[partition] = RelationshipPartition(name=partition)
            self.partitions[partition].add_context(context)

        logger.info(f"Created ORI {hab.pre[:16]}... for context '{context_name}'")

        return hab

    def get_relationship(self, context_name: str) -> Optional[RelationshipContext]:
        """Get relationship context by name."""
        return self.relationships.get(context_name)

    def get_hab_for_context(self, context_name: str) -> Optional["habbing.Hab"]:
        """
        Get the Hab to use for a specific relationship context.

        Args:
            context_name: Name of the relationship context

        Returns:
            Hab for this context, or None if not found
        """
        context = self.relationships.get(context_name)
        if not context:
            return None

        # Find Hab by AID
        return self.hby.habs.get(context.local_aid)

    def get_aid_for_remote(self, remote_aid: str, context_hint: Optional[str] = None) -> Optional[str]:
        """
        Get which local AID to use when communicating with a remote AID.

        If multiple contexts exist with the same remote, use context_hint
        to disambiguate.

        Args:
            remote_aid: The remote party's AID
            context_hint: Optional hint to select among multiple contexts

        Returns:
            Local AID to use, or None if no relationship exists
        """
        context_names = self._remote_index.get(remote_aid, [])

        if not context_names:
            return None

        if len(context_names) == 1:
            return self.relationships[context_names[0]].local_aid

        # Multiple contexts - need hint
        if context_hint and context_hint in context_names:
            return self.relationships[context_hint].local_aid

        # Return first (arbitrary) if no hint
        logger.warning(
            f"Multiple contexts for remote {remote_aid[:16]}, "
            f"using first: {context_names[0]}"
        )
        return self.relationships[context_names[0]].local_aid

    def get_context_for_local_aid(self, local_aid: str) -> Optional[str]:
        """
        Get context name for a local AID.

        Args:
            local_aid: One of our AIDs

        Returns:
            Context name, or None if AID is not an ORI
        """
        return self._local_index.get(local_aid)

    def record_event(self, context_name: str, event_said: str):
        """
        Record an event in a relationship context.

        Useful for tracking interaction history.

        Args:
            context_name: Context where event occurred
            event_said: SAID of the event
        """
        context = self.relationships.get(context_name)
        if context:
            context.add_event(event_said)

    def list_contexts(self, partition: Optional[str] = None) -> List[str]:
        """
        List all relationship context names.

        Args:
            partition: Optional partition to filter by

        Returns:
            List of context names
        """
        if partition:
            part = self.partitions.get(partition)
            if part:
                return list(part.contexts.keys())
            return []
        return list(self.relationships.keys())

    def list_remotes(self) -> List[str]:
        """List all remote AIDs we have relationships with."""
        return list(self._remote_index.keys())

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about managed relationships."""
        total_events = sum(c.event_count for c in self.relationships.values())

        return {
            "total_relationships": len(self.relationships),
            "total_partitions": len(self.partitions),
            "unique_remotes": len(self._remote_index),
            "total_events": total_events,
        }


# =============================================================================
# Relationship Formation Protocol
# =============================================================================


@dataclass
class RelationshipFormationInvite:
    """
    Invitation to form a new relationship (RFI).

    Sent from initiator to invitee to propose a new relationship
    using fresh AIDs.
    """

    initiator_aid: str  # New AID created for this relationship
    context_name: str  # Proposed context name
    nonce: str  # Anti-replay
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RelationshipFormationAccept:
    """
    Acceptance of relationship formation (RFA).

    Sent from invitee to initiator confirming the relationship
    with their own fresh AID.
    """

    acceptor_aid: str  # New AID created by acceptor
    initiator_aid: str  # Confirming which invite this accepts
    context_name: str  # Confirmed context name
    nonce: str  # Echo of invite nonce
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class RelationshipFormationDecline:
    """
    Decline of relationship formation (RFD).

    Sent from invitee to initiator declining the relationship.
    """

    initiator_aid: str  # Which invite this declines
    reason: Optional[str] = None
    nonce: str = ""


class RelationshipFormationProtocol:
    """
    Protocol for forming new ORI-based relationships.

    Flow:
        1. Alice creates new AID A₁ for relationship with Bob
        2. Alice sends RFI to Bob: "Let's form relationship using A₁"
        3. Bob creates new AID B₁ for relationship with Alice
        4. Bob sends RFA to Alice: "I accept, using B₁"
        5. Both now have relationship (A₁, <>, B₁)

    The initial exchange uses existing authenticated channel
    (e.g., existing relationship, OOBI).
    """

    def __init__(self, ori_manager: ORIManager):
        """
        Initialize formation protocol.

        Args:
            ori_manager: ORI manager for creating AIDs
        """
        self.ori_manager = ori_manager
        self.pending_invites: Dict[str, RelationshipFormationInvite] = {}

    def create_invite(
        self,
        context_name: str,
        remote_aid: str,  # Their existing/known AID for sending invite
    ) -> RelationshipFormationInvite:
        """
        Create a relationship formation invite.

        Args:
            context_name: Proposed context name
            remote_aid: Remote's existing AID (for sending the invite)

        Returns:
            RFI to send to remote
        """
        # Create new AID for this relationship
        hab = self.ori_manager.create_relationship(
            context_name=context_name,
            remote_aid=remote_aid,
        )

        # Generate nonce
        nonce = Diger(
            ser=f"{hab.pre}{context_name}{datetime.now().isoformat()}".encode(),
            code=MtrDex.Blake3_256,
        ).qb64

        invite = RelationshipFormationInvite(
            initiator_aid=hab.pre,
            context_name=context_name,
            nonce=nonce,
        )

        self.pending_invites[nonce] = invite

        return invite

    def accept_invite(
        self,
        invite: RelationshipFormationInvite,
    ) -> RelationshipFormationAccept:
        """
        Accept a relationship formation invite.

        Args:
            invite: Received RFI

        Returns:
            RFA to send back
        """
        # Create our AID for this relationship
        hab = self.ori_manager.create_relationship(
            context_name=invite.context_name,
            remote_aid=invite.initiator_aid,
        )

        return RelationshipFormationAccept(
            acceptor_aid=hab.pre,
            initiator_aid=invite.initiator_aid,
            context_name=invite.context_name,
            nonce=invite.nonce,
        )

    def decline_invite(
        self,
        invite: RelationshipFormationInvite,
        reason: Optional[str] = None,
    ) -> RelationshipFormationDecline:
        """
        Decline a relationship formation invite.

        Args:
            invite: Received RFI
            reason: Optional reason for declining

        Returns:
            RFD to send back
        """
        return RelationshipFormationDecline(
            initiator_aid=invite.initiator_aid,
            reason=reason,
            nonce=invite.nonce,
        )

    def complete_formation(
        self,
        accept: RelationshipFormationAccept,
    ) -> bool:
        """
        Complete relationship formation after receiving acceptance.

        Updates the relationship context with the acceptor's AID.

        Args:
            accept: Received RFA

        Returns:
            True if formation completed successfully
        """
        invite = self.pending_invites.get(accept.nonce)
        if not invite:
            logger.warning(f"Unknown invite nonce: {accept.nonce}")
            return False

        # Update relationship with acceptor's AID
        context = self.ori_manager.get_relationship(accept.context_name)
        if context:
            context.remote_aid = accept.acceptor_aid
            logger.info(
                f"Relationship '{accept.context_name}' formed: "
                f"{context.local_aid[:16]} <-> {accept.acceptor_aid[:16]}"
            )

        # Clean up pending
        del self.pending_invites[accept.nonce]

        return True
