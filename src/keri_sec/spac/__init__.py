# -*- encoding: utf-8 -*-
"""
SPAC: Secure Privacy, Authenticity, and Confidentiality

Multi-party credential exchange protocol implementing ESSR (Encrypt-Sender-Sign-Receiver)
for combined strong authenticity (SUF-CMA) and strong confidentiality (IND-CCA2).

Reference: test_data/smith_papers/whitepapers/SPAC_Message.md

PAC Trilemma: "One can have any two of Privacy, Authenticity, Confidentiality
at highest level, but not all three."

ToIP Priority: Authenticity > Confidentiality > Privacy

Components:
    - essr: ESSR protocol implementation (Week 7)
    - cesr_codes: SPAC-specific CESR codes (Week 7)
    - disclosure: ACDC disclosure modes (Week 8)
    - ori_manager: One-Relationship Identifiers (Week 8)
    - oobi_exchange: Cross-org OOBI resolution (Week 9)
"""

# Week 7: ESSR Confidentiality
from keri_sec.spac.essr import (
    ESSRMessage,
    ESSRProtocol,
    ESSRError,
    ESSRVerificationError,
    ESSRDecryptionError,
)

# Week 8: Privacy Layer
from keri_sec.spac.disclosure import (
    DisclosureMode,
    DisclosureRequest,
    DisclosureResponse,
    DisclosureEngine,
    DisclosureVerifier,
    select_disclosure_mode,
)

from keri_sec.spac.ori_manager import (
    ORIManager,
    RelationshipContext,
    RelationshipDirection,
    RelationshipPartition,
    RelationshipFormationProtocol,
    RelationshipFormationInvite,
    RelationshipFormationAccept,
    RelationshipFormationDecline,
)

# Week 9: Cross-Org Integration
from keri_sec.spac.oobi_exchange import (
    OOBIExchangeDoer,
    OOBIRequest,
    OOBIResult,
    OOBIResolutionStatus,
    EndpointConfig,
    EndpointRegistry,
    create_oobi_exchanger,
)

# SPAC Policy (Composed Rules)
from keri_sec.spac.policy import (
    SPACPolicy,
    DisclosureClause,
    ChainLinkClause,
    ESSRClause,
    ORIClause,
    ORIPartitionMode,
    PresentationCheck,
    PolicyCompositionError,
    compose_policies,
    SPAC_OPEN,
    SPAC_CHAIN_LINK,
    SPAC_CONFIDENTIAL,
    SPAC_MAXIMUM,
)

__all__ = [
    # ESSR (Week 7)
    "ESSRMessage",
    "ESSRProtocol",
    "ESSRError",
    "ESSRVerificationError",
    "ESSRDecryptionError",
    # Disclosure (Week 8)
    "DisclosureMode",
    "DisclosureRequest",
    "DisclosureResponse",
    "DisclosureEngine",
    "DisclosureVerifier",
    "select_disclosure_mode",
    # ORI (Week 8)
    "ORIManager",
    "RelationshipContext",
    "RelationshipDirection",
    "RelationshipPartition",
    "RelationshipFormationProtocol",
    "RelationshipFormationInvite",
    "RelationshipFormationAccept",
    "RelationshipFormationDecline",
    # OOBI Exchange (Week 9)
    "OOBIExchangeDoer",
    "OOBIRequest",
    "OOBIResult",
    "OOBIResolutionStatus",
    "EndpointConfig",
    "EndpointRegistry",
    "create_oobi_exchanger",
    # SPAC Policy (Composed Rules)
    "SPACPolicy",
    "DisclosureClause",
    "ChainLinkClause",
    "ESSRClause",
    "ORIClause",
    "ORIPartitionMode",
    "PresentationCheck",
    "PolicyCompositionError",
    "compose_policies",
    "SPAC_OPEN",
    "SPAC_CHAIN_LINK",
    "SPAC_CONFIDENTIAL",
    "SPAC_MAXIMUM",
]

__version__ = "0.4.0"  # SPAC Policy
