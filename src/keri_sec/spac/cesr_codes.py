# -*- encoding: utf-8 -*-
"""
SPAC CESR Codes

CESR (Composable Event Streaming Representation) codes for SPAC protocol.

Reference: SPAC_Message.md Appendix "CESR Implementation Details"

SPAC Wrapper Structure:
    Head (plaintext):
        - ESSR wrapper group code: -E## (small) or --E##### (big)
        - Protocol+version field: 0OSPACAABCAA
        - Source AID: CESR-encoded identifier
        - Destination AID: CESR-encoded identifier

    Body (may be encrypted):
        - Payload group code: -Z## or --Z#####
        - Payload type: 3-char code (XHOP, XCTL, XRFI, etc.)
        - Payload-specific fields
        - Mandatory pad field

    Tail (attachments):
        - Attachment group: -C##
        - Indexed signature group: -K##
        - Signatures
"""

from enum import Enum
from typing import Dict, Any


# =============================================================================
# SPAC Protocol Codes
# =============================================================================


class SPACProtocolCode:
    """
    SPAC protocol identifier.

    Format: 10 characters
        - Protocol type (4 chars): SPAC
        - Protocol version (3 chars): AAB = 0.0.1
        - Genus version (3 chars): CAA = 2.0.0
    """

    SPAC_V0_0_1 = "0OSPACAABCAA"  # Current version


# =============================================================================
# SPAC Group Codes
# =============================================================================


class SPACGroupCode:
    """
    CESR group codes for SPAC structures.

    Small codes (2-byte count): -X##
    Big codes (5-byte count): --X#####
    """

    # ESSR Wrapper groups
    ESSR_WRAPPER_SMALL = "-E"      # Small ESSR wrapper: -E##
    ESSR_WRAPPER_BIG = "--E"       # Big ESSR wrapper: --E#####

    # Payload groups
    PAYLOAD_SMALL = "-Z"           # Small payload: -Z##
    PAYLOAD_BIG = "--Z"            # Big payload: --Z#####

    # Attachment groups
    ATTACHMENT_SMALL = "-C"        # Small attachment: -C##
    ATTACHMENT_BIG = "--C"         # Big attachment: --C#####

    # Signature groups
    INDEXED_SIG_SMALL = "-K"       # Small indexed sig: -K##
    INDEXED_SIG_BIG = "--K"        # Big indexed sig: --K#####


# =============================================================================
# Payload Type Codes
# =============================================================================


class PayloadType(str, Enum):
    """
    SPAC payload type codes.

    Each payload type has a 4-character code prefixed with 'X'.
    """

    # Control messages
    CONTROL = "XCTL"              # Control message with nested CESR stream

    # Routing messages
    HOP = "XHOP"                  # Hop list with nested ESSR message

    # Relationship formation
    RFI = "XRFI"                  # Relationship Formation Invitation
    RFA = "XRFA"                  # Relationship Formation Acceptance
    RFD = "XRFD"                  # Relationship Formation Decline

    # Utility
    PAD = "XPAD"                  # Padding packet (traffic analysis resistance)
    SCS = "XSCS"                  # Generic sniffable CESR stream

    # KERI message tunneling
    XIP = "Xxip"                  # Exchange inception
    EXN = "Xexn"                  # Exchange message
    QRY = "Xqry"                  # Query
    RPY = "Xrpy"                  # Reply
    ICP = "Xicp"                  # Inception
    ROT = "Xrot"                  # Rotation
    IXN = "Xixn"                  # Interaction
    DIP = "Xdip"                  # Delegated inception
    DRT = "Xdrt"                  # Delegated rotation


# =============================================================================
# Cipher Codes (from keripy, extended for SPAC)
# =============================================================================


class CipherCode:
    """
    CESR codes for HPKE ciphertext.

    X25519 sealed box codes by lead pad size:
        - 4C, 5C, 6C (small, by lead size 0, 1, 2)
        - 7AAC, 8AAC, 9AAC (big)

    HPKE Base mode:
        - 4F, 5F, 6F (small)
        - 7AAF, 8AAF, 9AAF (big)

    HPKE Auth mode:
        - 4G, 5G, 6G (small)
        - 7AAG, 8AAG, 9AAG (big)
    """

    # X25519 sealed box (used by ESSR)
    X25519_SEAL_L0 = "4C"         # Lead pad 0
    X25519_SEAL_L1 = "5C"         # Lead pad 1
    X25519_SEAL_L2 = "6C"         # Lead pad 2
    X25519_SEAL_BIG_L0 = "7AAC"   # Big, lead pad 0
    X25519_SEAL_BIG_L1 = "8AAC"   # Big, lead pad 1
    X25519_SEAL_BIG_L2 = "9AAC"   # Big, lead pad 2

    # HPKE Base mode
    HPKE_BASE_L0 = "4F"
    HPKE_BASE_L1 = "5F"
    HPKE_BASE_L2 = "6F"

    # HPKE Auth mode
    HPKE_AUTH_L0 = "4G"
    HPKE_AUTH_L1 = "5G"
    HPKE_AUTH_L2 = "6G"


# =============================================================================
# SPAC Message Builder (CESR encoding helpers)
# =============================================================================


def encode_spac_header(
    src_aid: str,
    dst_aid: str,
    protocol_version: str = SPACProtocolCode.SPAC_V0_0_1,
) -> bytes:
    """
    Encode SPAC header in CESR format.

    Args:
        src_aid: Source AID (CESR qb64)
        dst_aid: Destination AID (CESR qb64)
        protocol_version: Protocol version string

    Returns:
        CESR-encoded header bytes
    """
    # For now, return a simple concatenation
    # Full CESR encoding would use proper group codes
    header = protocol_version.encode("utf-8")
    header += src_aid.encode("utf-8")
    header += dst_aid.encode("utf-8")
    return header


def encode_payload_type(payload_type: PayloadType) -> bytes:
    """Encode payload type as bytes."""
    return payload_type.value.encode("utf-8")


def parse_payload_type(raw: bytes) -> PayloadType:
    """Parse payload type from bytes."""
    code = raw[:4].decode("utf-8")
    return PayloadType(code)


# =============================================================================
# SPAC Message Serialization
# =============================================================================


class SPACSerializer:
    """
    Serializer for SPAC messages to/from CESR format.

    This is a simplified implementation. Full CESR compliance would
    require integration with keripy's streaming parser.
    """

    @staticmethod
    def serialize_essr_wrapper(
        src_aid: str,
        dst_aid: str,
        ciphertext: bytes,
        signature: bytes,
    ) -> bytes:
        """
        Serialize ESSR wrapper to CESR format.

        Format:
            [group_code][protocol][src][dst][ciphertext][signature_group]
        """
        # Simplified format for initial implementation
        # Full CESR would use proper group counting
        parts = [
            SPACProtocolCode.SPAC_V0_0_1.encode("utf-8"),
            src_aid.encode("utf-8"),
            b"|",
            dst_aid.encode("utf-8"),
            b"|",
            ciphertext,
            b"|",
            signature,
        ]
        return b"".join(parts)

    @staticmethod
    def deserialize_essr_wrapper(raw: bytes) -> Dict[str, Any]:
        """
        Deserialize ESSR wrapper from CESR format.

        Returns:
            Dict with src_aid, dst_aid, ciphertext, signature
        """
        # Find protocol version
        protocol = raw[:12].decode("utf-8")
        if protocol != SPACProtocolCode.SPAC_V0_0_1:
            raise ValueError(f"Unknown SPAC protocol version: {protocol}")

        # Parse remaining fields (simplified)
        remainder = raw[12:]
        parts = remainder.split(b"|")

        if len(parts) != 4:
            raise ValueError(f"Invalid ESSR wrapper format")

        return {
            "protocol": protocol,
            "src_aid": parts[0].decode("utf-8"),
            "dst_aid": parts[1].decode("utf-8"),
            "ciphertext": parts[2],
            "signature": parts[3],
        }


# =============================================================================
# Utility Functions
# =============================================================================


def compute_lead_pad_size(data_length: int) -> int:
    """
    Compute lead pad size for 24-bit CESR alignment.

    CESR requires 24-bit (3-byte) alignment for composability.

    Args:
        data_length: Length of data in bytes

    Returns:
        Lead pad size (0, 1, or 2 bytes)
    """
    return (3 - (data_length % 3)) % 3


def select_cipher_code(data_length: int, use_big: bool = False) -> str:
    """
    Select appropriate cipher code based on data size.

    Args:
        data_length: Length of plaintext
        use_big: Force big code even for small data

    Returns:
        CESR cipher code string
    """
    lead = compute_lead_pad_size(data_length)

    if use_big:
        return [CipherCode.X25519_SEAL_BIG_L0,
                CipherCode.X25519_SEAL_BIG_L1,
                CipherCode.X25519_SEAL_BIG_L2][lead]
    else:
        return [CipherCode.X25519_SEAL_L0,
                CipherCode.X25519_SEAL_L1,
                CipherCode.X25519_SEAL_L2][lead]
