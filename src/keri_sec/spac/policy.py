# -*- encoding: utf-8 -*-
"""
SPACPolicy - Composed SPAC Rules for ACDC Credentials.

A SPACPolicy is a composition of independently SAIDified rules-section clauses
that govern disclosure, confidentiality, correlatability, and chain-link terms
for ACDC credentials. The composed policy SAID goes in the credential's `-r` field.

Design Rationale (Sam Smith's "minimally sufficient means"):

    The rules-section approach is the correct locus of control. The credential
    ISSUER decides the disclosure terms (they hold the keys, they set the contract).
    The HOLDER executes disclosure within those terms. The VERIFIER checks compliance.

    No central governance node decides "all credentials use PARTIAL mode" — that
    would violate locus of control. Instead:

    - Primary: Rules-section (-r field) for SPAC constraints per-credential
    - Secondary: Cardinal matrix governs lifecycle of rule templates (who can
      author/rotate/deprecate them), not the content of rules

Composition Semantics:

    Clauses compose via MEET (most restrictive wins) for floor constraints.
    Chain-link terms propagate via edge inheritance: parent credential's
    chain-link terms bind all downstream presentations.

    This follows the existing PolicyAlgebra precedent in keri_sec.testing.policies
    where BLOCK is the absorbing element.

Reference: SPAC_Message.md, ACDC_Spec.md (rules section)

Usage:
    from keri_sec.spac.policy import (
        SPACPolicy, DisclosureClause, ChainLinkClause,
        ESSRClause, ORIClause, compose_policies,
    )

    # Build a policy from clauses
    policy = SPACPolicy(
        name="health-credential-spac",
        disclosure=DisclosureClause(
            floor=DisclosureMode.COMPACT,
            ceiling=DisclosureMode.PARTIAL,
        ),
        chain_link=ChainLinkClause(
            required=True,
            terms="All disclosees bound by HIPAA § 164.502(e)",
        ),
        essr=ESSRClause(required=True),
        ori=ORIClause(required=True, partition_by="relationship"),
    )

    # Compose two policies (meet = most restrictive)
    composed = compose_policies(policy_a, policy_b)

    # Serialize for -r field
    rules_section = policy.to_rules_section()
"""

import json
import logging
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional

from keri.core.coring import Diger, MtrDex

from .disclosure import DisclosureMode

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SAID computation (local, matches codebase pattern)
# ---------------------------------------------------------------------------


def _compute_said(data: dict) -> str:
    """Compute SAID for clause/policy content."""
    ser = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return Diger(ser=ser, code=MtrDex.Blake3_256).qb64


# ---------------------------------------------------------------------------
# Disclosure mode ordering (for meet/join operations)
# ---------------------------------------------------------------------------

# Privacy order: lower ordinal = more private = more restrictive
_DISCLOSURE_ORD: Dict[DisclosureMode, int] = {
    DisclosureMode.COMPACT: 0,
    DisclosureMode.SELECTIVE: 1,
    DisclosureMode.PARTIAL: 2,
    DisclosureMode.FULL: 3,
}

_ORD_TO_DISCLOSURE: Dict[int, DisclosureMode] = {
    v: k for k, v in _DISCLOSURE_ORD.items()
}


def _disclosure_meet(a: DisclosureMode, b: DisclosureMode) -> DisclosureMode:
    """Meet: most restrictive (least revealing) disclosure mode."""
    return _ORD_TO_DISCLOSURE[min(_DISCLOSURE_ORD[a], _DISCLOSURE_ORD[b])]


def _disclosure_join(a: DisclosureMode, b: DisclosureMode) -> DisclosureMode:
    """Join: least restrictive (most revealing) disclosure mode."""
    return _ORD_TO_DISCLOSURE[max(_DISCLOSURE_ORD[a], _DISCLOSURE_ORD[b])]


# ---------------------------------------------------------------------------
# Clause: Disclosure
# ---------------------------------------------------------------------------


@dataclass
class DisclosureClause:
    """
    Controls WHAT is revealed during credential presentation.

    Floor/ceiling define the allowed disclosure window:
    - floor: minimum privacy (most restrictive mode allowed)
    - ceiling: maximum revelation allowed

    Example: floor=COMPACT, ceiling=PARTIAL means the holder can
    disclose in COMPACT or PARTIAL mode, but SELECTIVE and FULL are
    forbidden.

    If floor == ceiling, the mode is fixed (no holder discretion).
    """

    floor: DisclosureMode = DisclosureMode.COMPACT
    ceiling: DisclosureMode = DisclosureMode.FULL

    def __post_init__(self):
        if _DISCLOSURE_ORD[self.floor] > _DISCLOSURE_ORD[self.ceiling]:
            raise ValueError(
                f"Disclosure floor ({self.floor.value}) cannot be more "
                f"revealing than ceiling ({self.ceiling.value})"
            )

    @property
    def said(self) -> str:
        return _compute_said(self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "disclosure",
            "floor": self.floor.value,
            "ceiling": self.ceiling.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DisclosureClause":
        return cls(
            floor=DisclosureMode(data["floor"]),
            ceiling=DisclosureMode(data["ceiling"]),
        )

    def allows(self, mode: DisclosureMode) -> bool:
        """Check if a disclosure mode is permitted by this clause."""
        ord_mode = _DISCLOSURE_ORD[mode]
        return _DISCLOSURE_ORD[self.floor] <= ord_mode <= _DISCLOSURE_ORD[self.ceiling]


# ---------------------------------------------------------------------------
# Clause: Chain-Link Confidentiality
# ---------------------------------------------------------------------------


@dataclass
class ChainLinkClause:
    """
    Contractual privacy protection via chain-link confidentiality.

    From SPAC: "The only sustainable privacy protection mechanism of 1st party
    data disclosed to a 2nd party is contractually protected disclosure with
    chain-link confidentiality."

    When required=True, every disclosee MUST agree to chain-link terms before
    receiving credential data. These terms propagate through ACDC edge sections:
    a root credential's chain-link terms bind all downstream presentations.

    Fields:
        required: Whether chain-link terms must be accepted before disclosure
        terms: Human-readable Ricardian contract text (the legal clause)
        terms_said: SAID of the terms (for compact representation)
        propagation: How terms flow through credential chains
    """

    required: bool = False
    terms: str = ""
    terms_said: Optional[str] = None
    propagation: str = "inherit"  # "inherit" | "override" | "augment"

    def __post_init__(self):
        if self.required and not self.terms and not self.terms_said:
            raise ValueError("Chain-link clause requires terms or terms_said when required=True")
        if self.terms and not self.terms_said:
            self.terms_said = _compute_said({"terms": self.terms})

    @property
    def said(self) -> str:
        return _compute_said(self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "type": "chain_link",
            "required": self.required,
            "propagation": self.propagation,
        }
        if self.terms:
            result["terms"] = self.terms
        if self.terms_said:
            result["terms_said"] = self.terms_said
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChainLinkClause":
        return cls(
            required=data.get("required", False),
            terms=data.get("terms", ""),
            terms_said=data.get("terms_said"),
            propagation=data.get("propagation", "inherit"),
        )


# ---------------------------------------------------------------------------
# Clause: ESSR Transport
# ---------------------------------------------------------------------------


@dataclass
class ESSRClause:
    """
    Controls WHETHER confidential transport is required.

    When required=True, credential presentations MUST use ESSR
    (Encrypt-Sender-Sign-Receiver) for combined authenticity + confidentiality.

    This protects against passive eavesdropping during credential exchange.
    Without ESSR, presentation data is signed but transmitted in cleartext.
    """

    required: bool = False

    @property
    def said(self) -> str:
        return _compute_said(self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "essr",
            "required": self.required,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ESSRClause":
        return cls(required=data.get("required", False))


# ---------------------------------------------------------------------------
# Clause: ORI Requirement
# ---------------------------------------------------------------------------


class ORIPartitionMode(str, Enum):
    """How ORI partitions are scoped."""

    RELATIONSHIP = "relationship"  # One AID per relationship
    CONTEXT = "context"            # One AID per context (group of relationships)
    ROLE = "role"                  # One AID per role (work, personal, etc.)


@dataclass
class ORIClause:
    """
    Controls WHETHER relationship partitioning is required.

    When required=True, the holder MUST use One-Relationship Identifiers
    to prevent cross-context correlation. Two different AIDs are
    information-theoretically uncorrelatable.

    partition_mode controls the granularity:
    - RELATIONSHIP: unique AID per counterparty (strongest privacy)
    - CONTEXT: unique AID per context group (moderate)
    - ROLE: unique AID per role (weakest ORI protection)
    """

    required: bool = False
    partition_mode: ORIPartitionMode = ORIPartitionMode.RELATIONSHIP

    @property
    def said(self) -> str:
        return _compute_said(self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "ori",
            "required": self.required,
            "partition_mode": self.partition_mode.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ORIClause":
        return cls(
            required=data.get("required", False),
            partition_mode=ORIPartitionMode(data.get("partition_mode", "relationship")),
        )


# ---------------------------------------------------------------------------
# SPACPolicy - Composed ruleset
# ---------------------------------------------------------------------------


@dataclass
class SPACPolicy:
    """
    A composed set of SPAC rules-section clauses.

    Each clause is independently SAIDified and can be graduated-disclosed
    (COMPACT → FULL). The policy SAID covers the full composition.

    The policy maps to the ACDC `-r` field as a Ricardian contract with
    both human-readable terms (chain_link.terms) and machine-evaluable
    constraints (disclosure.floor, essr.required, etc.).

    Locus of control:
        - ISSUER authors the policy (credential issuance)
        - HOLDER executes within policy bounds (presentation)
        - VERIFIER checks compliance (verification)
        - CARDINAL MATRIX governs template lifecycle (meta-governance)
    """

    name: str
    disclosure: DisclosureClause = field(default_factory=DisclosureClause)
    chain_link: ChainLinkClause = field(default_factory=ChainLinkClause)
    essr: ESSRClause = field(default_factory=ESSRClause)
    ori: ORIClause = field(default_factory=ORIClause)
    description: str = ""

    @property
    def said(self) -> str:
        """SAID of the full composed policy."""
        return _compute_said(self.to_dict())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "clauses": {
                "disclosure": self.disclosure.to_dict(),
                "chain_link": self.chain_link.to_dict(),
                "essr": self.essr.to_dict(),
                "ori": self.ori.to_dict(),
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SPACPolicy":
        clauses = data.get("clauses", {})
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            disclosure=DisclosureClause.from_dict(clauses["disclosure"]) if "disclosure" in clauses else DisclosureClause(),
            chain_link=ChainLinkClause.from_dict(clauses["chain_link"]) if "chain_link" in clauses else ChainLinkClause(),
            essr=ESSRClause.from_dict(clauses["essr"]) if "essr" in clauses else ESSRClause(),
            ori=ORIClause.from_dict(clauses["ori"]) if "ori" in clauses else ORIClause(),
        )

    def to_rules_section(self) -> Dict[str, Any]:
        """
        Serialize to ACDC rules-section (-r field) format.

        Supports dual representation per ACDC spec:
        - Compact: SAID only (for graduated disclosure)
        - Full: Complete clause content

        Returns the full representation. Use `said` property for compact.
        """
        return {
            "d": self.said,
            "spac": self.to_dict(),
            "usageDisclaimer": {
                "l": (
                    "This credential's disclosure, transport, and "
                    "correlatability requirements are governed by the "
                    "SPAC clauses herein. Acceptance of this credential "
                    "constitutes agreement to these terms."
                ),
            },
        }

    def check_disclosure(self, mode: DisclosureMode) -> bool:
        """Check if a disclosure mode is permitted by this policy."""
        return self.disclosure.allows(mode)

    def check_presentation(
        self,
        mode: DisclosureMode,
        essr_used: bool = False,
        ori_used: bool = False,
        chain_link_accepted: bool = False,
    ) -> "PresentationCheck":
        """
        Check if a presentation complies with this policy.

        Args:
            mode: Disclosure mode being used
            essr_used: Whether ESSR transport is being used
            ori_used: Whether ORI partitioning is being used
            chain_link_accepted: Whether disclosee accepted chain-link terms

        Returns:
            PresentationCheck with compliance status and violations
        """
        violations: List[str] = []

        if not self.disclosure.allows(mode):
            violations.append(
                f"Disclosure mode '{mode.value}' not in allowed range "
                f"[{self.disclosure.floor.value}..{self.disclosure.ceiling.value}]"
            )

        if self.chain_link.required and not chain_link_accepted:
            violations.append(
                "Chain-link confidentiality terms not accepted by disclosee"
            )

        if self.essr.required and not essr_used:
            violations.append(
                "ESSR transport required but not used"
            )

        if self.ori.required and not ori_used:
            violations.append(
                f"ORI partitioning ({self.ori.partition_mode.value}) required but not used"
            )

        return PresentationCheck(
            compliant=len(violations) == 0,
            policy_said=self.said,
            violations=violations,
        )


# ---------------------------------------------------------------------------
# Presentation check result
# ---------------------------------------------------------------------------


@dataclass
class PresentationCheck:
    """Result of checking a presentation against a SPACPolicy."""

    compliant: bool
    policy_said: str
    violations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compliant": self.compliant,
            "policy_said": self.policy_said,
            "violations": self.violations,
        }


# ---------------------------------------------------------------------------
# Policy composition (meet = most restrictive)
# ---------------------------------------------------------------------------


def compose_policies(a: SPACPolicy, b: SPACPolicy) -> SPACPolicy:
    """
    Compose two SPAC policies via MEET (most restrictive wins).

    Composition semantics:
    - disclosure.floor: join (higher = more restrictive floor)
    - disclosure.ceiling: meet (lower = less revealing ceiling)
    - chain_link.required: OR (if either requires, composed requires)
    - chain_link.propagation: "inherit" if either inherits
    - essr.required: OR (if either requires, composed requires)
    - ori.required: OR (if either requires, composed requires)
    - ori.partition_mode: finest granularity wins (RELATIONSHIP > CONTEXT > ROLE)

    This mirrors the PolicyAlgebra absorption pattern: the strictest
    constraint absorbs the weaker one, just as BLOCK + X = BLOCK.
    """
    # Disclosure window: tighten both ends
    new_floor = _disclosure_join(a.disclosure.floor, b.disclosure.floor)
    new_ceiling = _disclosure_meet(a.disclosure.ceiling, b.disclosure.ceiling)

    # If floor exceeds ceiling after composition, the policies are incompatible
    if _DISCLOSURE_ORD[new_floor] > _DISCLOSURE_ORD[new_ceiling]:
        raise PolicyCompositionError(
            f"Incompatible disclosure windows: "
            f"[{a.disclosure.floor.value}..{a.disclosure.ceiling.value}] ∩ "
            f"[{b.disclosure.floor.value}..{b.disclosure.ceiling.value}] = ∅"
        )

    # Chain-link: OR for required, merge terms
    chain_required = a.chain_link.required or b.chain_link.required
    chain_terms = a.chain_link.terms or b.chain_link.terms
    if a.chain_link.terms and b.chain_link.terms and a.chain_link.terms != b.chain_link.terms:
        chain_terms = f"{a.chain_link.terms}\n---\n{b.chain_link.terms}"
    chain_propagation = "inherit" if (
        a.chain_link.propagation == "inherit" or b.chain_link.propagation == "inherit"
    ) else a.chain_link.propagation

    # ORI: finest granularity wins
    _ORI_ORD = {
        ORIPartitionMode.RELATIONSHIP: 0,
        ORIPartitionMode.CONTEXT: 1,
        ORIPartitionMode.ROLE: 2,
    }
    ori_mode = a.ori.partition_mode if (
        _ORI_ORD[a.ori.partition_mode] <= _ORI_ORD[b.ori.partition_mode]
    ) else b.ori.partition_mode

    return SPACPolicy(
        name=f"{a.name}+{b.name}",
        description=f"Composed: {a.name} ∧ {b.name}",
        disclosure=DisclosureClause(floor=new_floor, ceiling=new_ceiling),
        chain_link=ChainLinkClause(
            required=chain_required,
            terms=chain_terms,
            propagation=chain_propagation,
        ),
        essr=ESSRClause(required=a.essr.required or b.essr.required),
        ori=ORIClause(
            required=a.ori.required or b.ori.required,
            partition_mode=ori_mode,
        ),
    )


class PolicyCompositionError(Exception):
    """Raised when two SPAC policies cannot be composed (empty intersection)."""
    pass


# ---------------------------------------------------------------------------
# Pre-defined policies
# ---------------------------------------------------------------------------


# Maximally permissive: no requirements
SPAC_OPEN = SPACPolicy(
    name="spac-open",
    description="No SPAC restrictions. Full disclosure permitted, no transport or privacy requirements.",
    disclosure=DisclosureClause(floor=DisclosureMode.COMPACT, ceiling=DisclosureMode.FULL),
    chain_link=ChainLinkClause(required=False),
    essr=ESSRClause(required=False),
    ori=ORIClause(required=False),
)

# Chain-link required, full disclosure range
SPAC_CHAIN_LINK = SPACPolicy(
    name="spac-chain-link",
    description="Chain-link confidentiality required. All disclosure modes allowed.",
    disclosure=DisclosureClause(floor=DisclosureMode.COMPACT, ceiling=DisclosureMode.FULL),
    chain_link=ChainLinkClause(
        required=True,
        terms=(
            "Disclosee agrees to maintain confidentiality of all disclosed "
            "credential data and to impose equivalent obligations on any "
            "further disclosees per chain-link confidentiality protocol."
        ),
    ),
    essr=ESSRClause(required=False),
    ori=ORIClause(required=False),
)

# Confidential transport: ESSR + chain-link
SPAC_CONFIDENTIAL = SPACPolicy(
    name="spac-confidential",
    description="Confidential transport required. ESSR + chain-link, partial disclosure max.",
    disclosure=DisclosureClause(floor=DisclosureMode.COMPACT, ceiling=DisclosureMode.PARTIAL),
    chain_link=ChainLinkClause(
        required=True,
        terms=(
            "Disclosee agrees to maintain confidentiality of all disclosed "
            "credential data via ESSR-protected channels only and to impose "
            "equivalent obligations on further disclosees."
        ),
    ),
    essr=ESSRClause(required=True),
    ori=ORIClause(required=False),
)

# Maximum privacy: all SPAC protections active
SPAC_MAXIMUM = SPACPolicy(
    name="spac-maximum",
    description=(
        "Maximum SPAC protection. COMPACT-only disclosure, ESSR transport, "
        "chain-link confidentiality, and ORI partitioning all required."
    ),
    disclosure=DisclosureClause(floor=DisclosureMode.COMPACT, ceiling=DisclosureMode.COMPACT),
    chain_link=ChainLinkClause(
        required=True,
        terms=(
            "Disclosee agrees to: (1) maintain strict confidentiality of all "
            "disclosed data; (2) use ESSR-protected channels exclusively; "
            "(3) use ORI-partitioned identifiers for all interactions; "
            "(4) impose equivalent obligations on any further disclosees."
        ),
    ),
    essr=ESSRClause(required=True),
    ori=ORIClause(required=True, partition_mode=ORIPartitionMode.RELATIONSHIP),
)
