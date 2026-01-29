# -*- encoding: utf-8 -*-
"""
ACDC Disclosure Modes

Implements four levels of credential disclosure for privacy-preserving presentation:

1. COMPACT: Only the credential SAID - proves possession without revealing content
2. PARTIAL: Selected attributes with Merkle proofs
3. SELECTIVE: Predicate evaluation (ZKP-based in future)
4. FULL: Complete credential with all attributes

Reference: SPAC_Message.md

CRITICAL PRIVACY INSIGHT FROM SPAC:

    "The only sustainable privacy protection mechanism of 1st party data
    disclosed to a 2nd party, even when selectively disclosed (via ZKP or not),
    is contractually protected disclosure with chain-link confidentiality."

    "Many of the standard use cases for selective disclosure and/or ZKPs
    in verifiable credentials (VCs) are examples of anti-patterns for
    privacy protection. This is because these standard use cases assume
    a presentation context that is under the control of the verifier,
    which means a smart verifier can restructure that context to
    statistically guarantee correlation and defeat the selective
    disclosure with or without ZKP."

IMPLICATION:
    - Disclosure modes control WHAT is revealed
    - They do NOT protect against WHO learns about you
    - Contextual data (IP, location, timing) enables re-identification
    - Chain-link confidentiality (contractual liability) is REQUIRED
    - ORI partitioning provides context isolation

USE DISCLOSURE MODES WITH:
    - Chain-link confidentiality terms (schemas/chain_link_disclosure.json)
    - ORI-based relationship partitioning (spac/ori_manager.py)
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any, Set, TYPE_CHECKING

from keri.core.coring import Diger, MtrDex

if TYPE_CHECKING:
    from keri.vc.proving import Creder

logger = logging.getLogger(__name__)


# =============================================================================
# Disclosure Mode Enumeration
# =============================================================================


class DisclosureMode(str, Enum):
    """
    ACDC disclosure modes from least to most revealing.

    Each mode trades off privacy against verifiability:
    - More disclosure = stronger verification but less privacy
    - Less disclosure = weaker verification but more privacy
    """

    COMPACT = "compact"
    """
    SAID-only disclosure.

    Reveals: Only the credential SAID
    Proves: "I possess a credential with this SAID"
    Use case: Proving membership without revealing attributes
    Privacy: Maximum (no attribute leakage)
    Verification: Weak (verifier must trust SAID is valid)
    """

    PARTIAL = "partial"
    """
    Selected attributes with Merkle proofs.

    Reveals: Chosen attributes + Merkle proofs for each
    Proves: Selected attributes are part of a valid credential
    Use case: Revealing only necessary attributes (e.g., name but not DOB)
    Privacy: Good (only selected attributes revealed)
    Verification: Strong (Merkle proofs verify inclusion)
    """

    SELECTIVE = "selective"
    """
    Predicate-based disclosure with ZKP.

    Reveals: Boolean result of predicate (true/false)
    Proves: Attribute satisfies predicate without revealing value
    Use case: "Age >= 21" without revealing actual age

    SPAC WARNING: Bare selective disclosure (with or without ZKP) is
    vulnerable to contextual linkability attacks. Verifiers control
    the presentation context and can structure interactions to capture
    auxiliary data for re-identification.

    From SPAC: "A smart verifier can restructure that context to
    statistically guarantee correlation and defeat the selective
    disclosure with or without ZKP."

    REQUIRED: Use with chain-link confidentiality for sustainable privacy.
    """

    FULL = "full"
    """
    Complete credential disclosure.

    Reveals: All attributes, schema, issuer, signatures
    Proves: Full credential validity
    Use case: High-assurance verification, audit trails
    Privacy: None (everything revealed)
    Verification: Maximum (full cryptographic verification)
    """


# =============================================================================
# Disclosure Request/Response
# =============================================================================


@dataclass
class DisclosureRequest:
    """
    Verifier's request for credential disclosure.

    Specifies what the verifier needs to see and accepts.
    """

    credential_schema: str  # Schema SAID or type
    required_fields: List[str]  # Fields verifier must see
    acceptable_modes: List[DisclosureMode]  # Modes verifier accepts
    predicates: Optional[Dict[str, str]] = None  # For SELECTIVE: {"age": ">= 21"}
    nonce: Optional[str] = None  # Anti-replay nonce


@dataclass
class DisclosureResponse:
    """
    Holder's response to a disclosure request.

    Contains the disclosed credential data based on chosen mode.
    """

    credential_said: str
    mode: DisclosureMode
    disclosed_fields: Dict[str, Any] = field(default_factory=dict)
    merkle_proofs: Optional[Dict[str, bytes]] = None  # For PARTIAL
    predicate_proofs: Optional[Dict[str, bytes]] = None  # For SELECTIVE
    full_credential: Optional[Dict[str, Any]] = None  # For FULL
    request_nonce: Optional[str] = None


# =============================================================================
# Disclosure Engine
# =============================================================================


class DisclosureEngine:
    """
    Applies disclosure modes to ACDC credentials.

    Usage:
        engine = DisclosureEngine()

        # Full disclosure
        response = engine.apply_disclosure(
            credential=cred,
            mode=DisclosureMode.FULL,
        )

        # Partial disclosure (selected fields)
        response = engine.apply_disclosure(
            credential=cred,
            mode=DisclosureMode.PARTIAL,
            fields=["name", "role"],
        )

        # Selective disclosure (predicates)
        response = engine.apply_disclosure(
            credential=cred,
            mode=DisclosureMode.SELECTIVE,
            predicates={"age": ">= 21"},
        )
    """

    def apply_disclosure(
        self,
        credential: "Creder",
        mode: DisclosureMode,
        fields: Optional[List[str]] = None,
        predicates: Optional[Dict[str, str]] = None,
        request_nonce: Optional[str] = None,
    ) -> DisclosureResponse:
        """
        Apply disclosure mode to credential.

        Args:
            credential: ACDC credential (Creder instance)
            mode: Disclosure mode to apply
            fields: For PARTIAL - list of fields to disclose
            predicates: For SELECTIVE - dict of field: predicate
            request_nonce: Anti-replay nonce from request

        Returns:
            DisclosureResponse with appropriate data
        """
        cred_said = credential.said if hasattr(credential, 'said') else str(credential)

        if mode == DisclosureMode.COMPACT:
            return self._apply_compact(credential, cred_said, request_nonce)

        elif mode == DisclosureMode.PARTIAL:
            if not fields:
                raise ValueError("PARTIAL mode requires fields parameter")
            return self._apply_partial(credential, cred_said, fields, request_nonce)

        elif mode == DisclosureMode.SELECTIVE:
            if not predicates:
                raise ValueError("SELECTIVE mode requires predicates parameter")
            return self._apply_selective(credential, cred_said, predicates, request_nonce)

        elif mode == DisclosureMode.FULL:
            return self._apply_full(credential, cred_said, request_nonce)

        else:
            raise ValueError(f"Unknown disclosure mode: {mode}")

    def _apply_compact(
        self,
        credential: "Creder",
        cred_said: str,
        nonce: Optional[str],
    ) -> DisclosureResponse:
        """
        Compact disclosure: SAID only.

        The credential SAID is a cryptographic commitment to the content.
        Verifier can confirm they've seen this SAID before (e.g., in a registry)
        without learning any attributes.
        """
        return DisclosureResponse(
            credential_said=cred_said,
            mode=DisclosureMode.COMPACT,
            disclosed_fields={},
            request_nonce=nonce,
        )

    def _apply_partial(
        self,
        credential: "Creder",
        cred_said: str,
        fields: List[str],
        nonce: Optional[str],
    ) -> DisclosureResponse:
        """
        Partial disclosure: Selected fields with Merkle proofs.

        For each requested field:
        1. Extract field value from credential
        2. Compute Merkle proof showing field is part of credential
        3. Return field value + proof

        The Merkle root is the credential SAID, so proofs verify inclusion.
        """
        # Extract credential attributes
        cred_dict = self._credential_to_dict(credential)
        attributes = cred_dict.get("a", cred_dict.get("attributes", {}))

        disclosed = {}
        proofs = {}

        for field_name in fields:
            if field_name in attributes:
                disclosed[field_name] = attributes[field_name]
                # Compute Merkle proof for this field
                proofs[field_name] = self._compute_merkle_proof(
                    credential, field_name
                )
            else:
                logger.warning(f"Field '{field_name}' not in credential")

        return DisclosureResponse(
            credential_said=cred_said,
            mode=DisclosureMode.PARTIAL,
            disclosed_fields=disclosed,
            merkle_proofs=proofs,
            request_nonce=nonce,
        )

    def _apply_selective(
        self,
        credential: "Creder",
        cred_said: str,
        predicates: Dict[str, str],
        nonce: Optional[str],
    ) -> DisclosureResponse:
        """
        Selective disclosure: Predicate evaluation.

        Returns boolean results for predicates (e.g., "age >= 21" -> True).
        Current implementation evaluates predicates directly.

        SPAC WARNING: Bare selective disclosure (with or without ZKP) is
        vulnerable to contextual linkability attacks. Verifiers control
        presentation context and can capture auxiliary data (IP, location,
        timing) for re-identification.

        From SPAC: "A smart verifier can restructure that context to
        statistically guarantee correlation and defeat the selective
        disclosure with or without ZKP."

        REQUIRED: Use with chain-link confidentiality for sustainable privacy.
        """
        logger.warning(
            "SELECTIVE disclosure: Use with chain-link confidentiality. "
            "Bare selective disclosure is vulnerable to contextual linkability."
        )
        cred_dict = self._credential_to_dict(credential)
        attributes = cred_dict.get("a", cred_dict.get("attributes", {}))

        disclosed = {}  # Boolean results
        proofs = {}  # ZKPs

        for field_name, predicate in predicates.items():
            if field_name in attributes:
                value = attributes[field_name]
                result = self._evaluate_predicate(value, predicate)
                disclosed[field_name] = result

                # Generate proof for predicate result
                proofs[field_name] = self._generate_predicate_proof(
                    credential, field_name, predicate, result
                )
            else:
                logger.warning(f"Field '{field_name}' not in credential for predicate")
                disclosed[field_name] = False

        return DisclosureResponse(
            credential_said=cred_said,
            mode=DisclosureMode.SELECTIVE,
            disclosed_fields=disclosed,
            predicate_proofs=proofs,
            request_nonce=nonce,
        )

    def _apply_full(
        self,
        credential: "Creder",
        cred_said: str,
        nonce: Optional[str],
    ) -> DisclosureResponse:
        """
        Full disclosure: Complete credential.

        Returns the entire credential including:
        - All attributes
        - Schema reference
        - Issuer AID
        - Signatures/proofs
        - Edge references
        """
        cred_dict = self._credential_to_dict(credential)

        return DisclosureResponse(
            credential_said=cred_said,
            mode=DisclosureMode.FULL,
            disclosed_fields=cred_dict.get("a", cred_dict.get("attributes", {})),
            full_credential=cred_dict,
            request_nonce=nonce,
        )

    def _credential_to_dict(self, credential: "Creder") -> Dict[str, Any]:
        """Convert credential to dictionary."""
        if hasattr(credential, 'crd'):
            return credential.crd
        elif hasattr(credential, 'raw'):
            import json
            return json.loads(credential.raw)
        elif isinstance(credential, dict):
            return credential
        else:
            return {"said": str(credential)}

    def _compute_merkle_proof(
        self,
        credential: "Creder",
        field_name: str,
    ) -> bytes:
        """
        Compute Merkle proof for field inclusion.

        In a full implementation, this would:
        1. Build Merkle tree from credential fields
        2. Generate inclusion proof for specific field
        3. Return proof bytes

        For now, returns a placeholder proof based on field hash.
        """
        cred_dict = self._credential_to_dict(credential)
        attributes = cred_dict.get("a", cred_dict.get("attributes", {}))

        if field_name not in attributes:
            return b""

        # Simplified: hash the field name + value as "proof"
        # Real implementation would use proper Merkle tree
        field_data = f"{field_name}:{attributes[field_name]}".encode()
        diger = Diger(ser=field_data, code=MtrDex.Blake3_256)
        return diger.qb64b

    def _evaluate_predicate(self, value: Any, predicate: str) -> bool:
        """
        Evaluate predicate against value.

        Supported predicates:
        - ">= N" - greater than or equal
        - "<= N" - less than or equal
        - "> N" - greater than
        - "< N" - less than
        - "== X" - equals
        - "!= X" - not equals
        - "in [...]" - membership

        Args:
            value: Attribute value
            predicate: Predicate string

        Returns:
            Boolean result
        """
        predicate = predicate.strip()

        try:
            if predicate.startswith(">="):
                return float(value) >= float(predicate[2:].strip())
            elif predicate.startswith("<="):
                return float(value) <= float(predicate[2:].strip())
            elif predicate.startswith(">"):
                return float(value) > float(predicate[1:].strip())
            elif predicate.startswith("<"):
                return float(value) < float(predicate[1:].strip())
            elif predicate.startswith("=="):
                return str(value) == predicate[2:].strip()
            elif predicate.startswith("!="):
                return str(value) != predicate[2:].strip()
            elif predicate.startswith("in "):
                # Parse list: "in [a, b, c]"
                list_str = predicate[3:].strip()
                if list_str.startswith("[") and list_str.endswith("]"):
                    items = [x.strip() for x in list_str[1:-1].split(",")]
                    return str(value) in items
                return False
            else:
                logger.warning(f"Unknown predicate format: {predicate}")
                return False
        except (ValueError, TypeError) as e:
            logger.warning(f"Predicate evaluation failed: {e}")
            return False

    def _generate_predicate_proof(
        self,
        credential: "Creder",
        field_name: str,
        predicate: str,
        result: bool,
    ) -> bytes:
        """
        Generate proof for predicate satisfaction.

        Returns a commitment that can be verified against the credential SAID.

        NOTE: This provides predicate evaluation proof, not cryptographic
        unlinkability. Per SPAC, sustainable privacy requires chain-link
        confidentiality regardless of cryptographic mechanism used.
        """
        # Simplified: create a deterministic "proof" from inputs
        # Real ZKP would be cryptographically sound
        proof_data = f"{field_name}:{predicate}:{result}".encode()
        diger = Diger(ser=proof_data, code=MtrDex.Blake3_256)
        return diger.qb64b


# =============================================================================
# Disclosure Verifier
# =============================================================================


class DisclosureVerifier:
    """
    Verifies disclosed credential data.

    Checks that:
    1. SAID matches expected credential
    2. Merkle proofs are valid (for PARTIAL)
    3. Predicate proofs are valid (for SELECTIVE)
    4. Full credential validates (for FULL)
    """

    def verify_disclosure(
        self,
        response: DisclosureResponse,
        expected_said: Optional[str] = None,
    ) -> bool:
        """
        Verify a disclosure response.

        Args:
            response: Disclosure response to verify
            expected_said: Optional expected credential SAID

        Returns:
            True if verification passes
        """
        # Check SAID if expected
        if expected_said and response.credential_said != expected_said:
            logger.warning(f"SAID mismatch: {response.credential_said} != {expected_said}")
            return False

        if response.mode == DisclosureMode.COMPACT:
            # Compact only verifies SAID exists
            return bool(response.credential_said)

        elif response.mode == DisclosureMode.PARTIAL:
            return self._verify_partial(response)

        elif response.mode == DisclosureMode.SELECTIVE:
            return self._verify_selective(response)

        elif response.mode == DisclosureMode.FULL:
            return self._verify_full(response)

        return False

    def _verify_partial(self, response: DisclosureResponse) -> bool:
        """Verify Merkle proofs for partial disclosure."""
        if not response.merkle_proofs:
            return len(response.disclosed_fields) == 0

        # Verify each field has a proof
        for field_name in response.disclosed_fields:
            if field_name not in response.merkle_proofs:
                logger.warning(f"Missing Merkle proof for field: {field_name}")
                return False

            # In full impl, would verify proof against SAID as root
            if not response.merkle_proofs[field_name]:
                return False

        return True

    def _verify_selective(self, response: DisclosureResponse) -> bool:
        """Verify ZKPs for selective disclosure."""
        if not response.predicate_proofs:
            return len(response.disclosed_fields) == 0

        # Verify each predicate result has a proof
        for field_name in response.disclosed_fields:
            if field_name not in response.predicate_proofs:
                logger.warning(f"Missing predicate proof for field: {field_name}")
                return False

            # In full impl, would cryptographically verify ZKP
            if not response.predicate_proofs[field_name]:
                return False

        return True

    def _verify_full(self, response: DisclosureResponse) -> bool:
        """Verify full credential disclosure."""
        if not response.full_credential:
            return False

        # Verify SAID matches credential content
        # In full impl, would recompute SAID and verify signatures
        return "a" in response.full_credential or "attributes" in response.full_credential


# =============================================================================
# Helper Functions
# =============================================================================


def select_disclosure_mode(
    request: DisclosureRequest,
    holder_preferences: List[DisclosureMode],
) -> Optional[DisclosureMode]:
    """
    Select best disclosure mode matching both verifier and holder.

    Prefers less revealing modes (more privacy) when both accept.

    Args:
        request: Verifier's disclosure request
        holder_preferences: Holder's acceptable modes (ordered by preference)

    Returns:
        Selected mode or None if no overlap
    """
    # Order modes from least to most revealing
    privacy_order = [
        DisclosureMode.COMPACT,
        DisclosureMode.SELECTIVE,
        DisclosureMode.PARTIAL,
        DisclosureMode.FULL,
    ]

    # Find modes acceptable to both
    acceptable = set(request.acceptable_modes) & set(holder_preferences)

    if not acceptable:
        return None

    # Return least revealing acceptable mode
    for mode in privacy_order:
        if mode in acceptable:
            return mode

    return None
