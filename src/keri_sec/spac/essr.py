# -*- encoding: utf-8 -*-
"""
ESSR: Encrypt-Sender-Sign-Receiver Protocol

Provides combined strong authenticity (SUF-CMA via Ed25519) and strong
confidentiality (IND-CCA2 via X25519 sealed box) with protection against
Key Compromise Impersonation (KCI) attacks.

Message Format:
    <[src AID, dst AID, {src AID, payload}dst]>src

Where:
    {} = encrypt to dst's public key (X25519 sealed box)
    <> = sign with src's private key (Ed25519)
    src AID inside ciphertext = ESSR binding (prevents KCI)
    dst AID in plaintext = receiver binding

Security Properties:
    - TUF-PTXT: Third-party UnForgeability of PlainText
    - TUF-CTXT: Third-party UnForgeability of CipherText
    - RUF-PTXT: Receiver UnForgeability of PlainText
    - RUF-CTXT: Receiver UnForgeability of CipherText

Reference: SPAC_Message.md Section "Modified ESSR"
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, Tuple, TYPE_CHECKING

from keri.core.coring import (
    Matter,
    MtrDex,
    Diger,
    Prefixer,
)
from keri.core.signing import (
    Signer,
    Verfer,
    Encrypter,
    Decrypter,
    Cipher,
)

if TYPE_CHECKING:
    from keri.app import habbing

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================


class ESSRError(Exception):
    """Base exception for ESSR protocol errors."""
    pass


class ESSRVerificationError(ESSRError):
    """Signature verification failed."""
    pass


class ESSRDecryptionError(ESSRError):
    """Decryption failed."""
    pass


class ESSRBindingError(ESSRError):
    """ESSR binding mismatch (src AID in ciphertext != claimed sender)."""
    pass


# =============================================================================
# ESSR Message Structure
# =============================================================================


@dataclass
class ESSRMessage:
    """
    ESSR-wrapped message with CESR encoding support.

    The message contains:
        - src_aid: Sender's AID (in plaintext for DDOS protection/routing)
        - dst_aid: Receiver's AID (in plaintext for routing)
        - ciphertext: {src_aid || payload} encrypted to dst's public key
        - signature: Ed25519 signature over [src, dst, ciphertext]

    The src_aid appears twice (plaintext and inside ciphertext) for ESSR binding.
    This prevents a receiver from claiming they received a different message
    than what was actually sent.
    """

    src_aid: str
    dst_aid: str
    ciphertext: bytes
    signature: bytes
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Optional: SAID of the message for tracking
    said: Optional[str] = None

    def signable_bytes(self) -> bytes:
        """
        Create the bytes that were signed.

        Format: src_aid || dst_aid || ciphertext
        """
        return (
            self.src_aid.encode("utf-8") +
            self.dst_aid.encode("utf-8") +
            self.ciphertext
        )

    def compute_said(self) -> str:
        """Compute SAID of message for tracking/logging."""
        diger = Diger(ser=self.signable_bytes(), code=MtrDex.Blake3_256)
        return diger.qb64

    def __post_init__(self):
        """Compute SAID if not provided."""
        if self.said is None:
            self.said = self.compute_said()


# =============================================================================
# ESSR Protocol Implementation
# =============================================================================


class ESSRProtocol:
    """
    ESSR protocol implementation using keripy primitives.

    Key insight from SPAC: Uses unbounded-term AIDs instead of long-term public keys.
    The public encryption key is derived from the AID's current key state in the KEL.
    This solves the key management hard problem since AIDs can rotate keys while
    maintaining identity.

    Usage:
        # Initialize with habery and hab
        protocol = ESSRProtocol(hby, hab)

        # Encrypt and sign a message to recipient
        msg = protocol.encrypt_and_sign(
            payload=b"Hello, world!",
            recipient_aid="ExxxxRecipient",
        )

        # On recipient side: verify and decrypt
        sender_aid, payload = protocol.verify_and_decrypt(msg)
    """

    def __init__(self, hby: "habbing.Habery", hab: "habbing.Hab"):
        """
        Initialize ESSR protocol.

        Args:
            hby: Habery with access to kevers (key state) for all known AIDs
            hab: Hab representing our identity for signing/decrypting
        """
        self.hby = hby
        self.hab = hab

    def encrypt_and_sign(
        self,
        payload: bytes,
        recipient_aid: str,
        include_src_in_plaintext: bool = True,
    ) -> ESSRMessage:
        """
        Create ESSR message with encryption and signature.

        Steps:
        1. Look up recipient's current encryption pubkey from their KEL
        2. Create sealed box containing {src_aid || payload}
        3. Sign [src_aid, dst_aid, ciphertext] with our signing key

        Args:
            payload: Raw bytes to encrypt and send
            recipient_aid: AID of the recipient
            include_src_in_plaintext: If True, include src AID in plaintext
                for DDOS protection. If False, only in ciphertext (more private
                but requires recipient to try decryption to identify sender).

        Returns:
            ESSRMessage ready for transmission

        Raises:
            ESSRError: If recipient AID is unknown or encryption fails
        """
        # 1. Look up recipient's current key state
        kever = self.hby.kevers.get(recipient_aid)
        if kever is None:
            raise ESSRError(f"Unknown recipient AID: {recipient_aid}. "
                          f"Resolve their OOBI first.")

        # Get recipient's current verification key (Ed25519)
        if not kever.verfers:
            raise ESSRError(f"Recipient {recipient_aid} has no verification keys")

        recipient_verkey = kever.verfers[0]  # Current signing key

        # 2. Create Encrypter from recipient's verkey
        # This derives X25519 public key from Ed25519 verkey
        encrypter = Encrypter(verkey=recipient_verkey.qb64b)

        # 3. Build inner payload: src_aid || payload
        # The src_aid inside ciphertext is the ESSR binding
        inner_payload = self.hab.pre.encode("utf-8") + b"|" + payload

        # 4. Encrypt using sealed box
        # cipher.raw contains the encrypted bytes
        cipher = encrypter.encrypt(ser=inner_payload)
        ciphertext = cipher.raw

        # 5. Build signable bytes: src || dst || ciphertext
        src_aid = self.hab.pre if include_src_in_plaintext else ""
        signable = (
            src_aid.encode("utf-8") +
            recipient_aid.encode("utf-8") +
            ciphertext
        )

        # 6. Sign with our key
        # Hab.sign returns indexed signature group, we need raw signature
        signer = self.hab.mgr.get(self.hab.pre)
        if signer is None:
            # Fallback: use kvy to get signer
            signer = self.hab.kvy.kevers[self.hab.pre].verfers[0]

        # Get the actual Signer for signing
        signers = self.hab.mgr.sign(ser=signable, verfers=self.hab.kvy.kevers[self.hab.pre].verfers)
        if not signers:
            raise ESSRError("Failed to sign message")

        signature = signers[0].raw

        # 7. Build and return ESSR message
        return ESSRMessage(
            src_aid=src_aid if include_src_in_plaintext else self.hab.pre,
            dst_aid=recipient_aid,
            ciphertext=ciphertext,
            signature=signature,
        )

    def verify_and_decrypt(self, msg: ESSRMessage) -> Tuple[str, bytes]:
        """
        Verify signature and decrypt ESSR message.

        Steps:
        1. Verify signature against claimed sender's current key state
        2. Decrypt sealed box with our private key
        3. Verify inner src_aid matches outer src_aid (ESSR binding check)

        Args:
            msg: ESSR message to verify and decrypt

        Returns:
            Tuple of (sender_aid, decrypted_payload)

        Raises:
            ESSRVerificationError: If signature verification fails
            ESSRDecryptionError: If decryption fails
            ESSRBindingError: If ESSR binding check fails
        """
        # 1. Look up sender's current key state
        kever = self.hby.kevers.get(msg.src_aid)
        if kever is None:
            raise ESSRVerificationError(f"Unknown sender AID: {msg.src_aid}")

        # 2. Verify signature
        verfer = kever.verfers[0]  # Current verification key
        signable = msg.signable_bytes()

        if not verfer.verify(sig=msg.signature, ser=signable):
            raise ESSRVerificationError(
                f"Signature verification failed for message from {msg.src_aid}"
            )

        logger.debug(f"Signature verified for message from {msg.src_aid}")

        # 3. Decrypt ciphertext
        # Create Decrypter from our signing seed
        # The hab.mgr has our private keys
        try:
            # Get our signing seed to derive decryption key
            seed = self.hab.mgr.ks.pris.get(self.hab.pre)
            if seed is None:
                raise ESSRDecryptionError("Cannot find our private key for decryption")

            decrypter = Decrypter(seed=seed.qb64b)

            # Create Cipher from raw ciphertext
            cipher = Cipher(raw=msg.ciphertext)

            # Decrypt
            plain = decrypter.decrypt(cipher=cipher, transferable=True)

        except Exception as e:
            raise ESSRDecryptionError(f"Decryption failed: {e}")

        # 4. Parse inner payload: src_aid || "|" || payload
        try:
            inner_src_aid, payload = plain.split(b"|", 1)
            inner_src_aid = inner_src_aid.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as e:
            raise ESSRDecryptionError(f"Failed to parse inner payload: {e}")

        # 5. ESSR binding check: inner src_aid must match outer src_aid
        if inner_src_aid != msg.src_aid:
            raise ESSRBindingError(
                f"ESSR binding mismatch: inner src_aid={inner_src_aid} "
                f"!= outer src_aid={msg.src_aid}. Possible tampering."
            )

        logger.debug(f"ESSR binding verified for message from {msg.src_aid}")

        return msg.src_aid, payload

    def can_decrypt_from(self, sender_aid: str) -> bool:
        """
        Check if we can receive ESSR messages from a sender.

        Returns True if we know the sender's AID (have their KEL).
        """
        return self.hby.kevers.get(sender_aid) is not None

    def can_encrypt_to(self, recipient_aid: str) -> bool:
        """
        Check if we can send ESSR messages to a recipient.

        Returns True if we know the recipient's AID (have their KEL).
        """
        return self.hby.kevers.get(recipient_aid) is not None


# =============================================================================
# Simplified API
# =============================================================================


def create_essr_message(
    hby: "habbing.Habery",
    hab: "habbing.Hab",
    payload: bytes,
    recipient_aid: str,
) -> ESSRMessage:
    """
    Convenience function to create an ESSR message.

    Args:
        hby: Habery with key state access
        hab: Our identity
        payload: Data to send
        recipient_aid: Recipient's AID

    Returns:
        ESSRMessage ready for transmission
    """
    protocol = ESSRProtocol(hby, hab)
    return protocol.encrypt_and_sign(payload, recipient_aid)


def verify_essr_message(
    hby: "habbing.Habery",
    hab: "habbing.Hab",
    msg: ESSRMessage,
) -> Tuple[str, bytes]:
    """
    Convenience function to verify and decrypt an ESSR message.

    Args:
        hby: Habery with key state access
        hab: Our identity
        msg: Message to verify and decrypt

    Returns:
        Tuple of (sender_aid, payload)
    """
    protocol = ESSRProtocol(hby, hab)
    return protocol.verify_and_decrypt(msg)
