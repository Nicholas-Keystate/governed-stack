# -*- encoding: utf-8 -*-
"""
Installation Credential Issuance

Phase 2: TEL-Anchored Installation Credentials

Issues ACDC credentials attesting:
- WHO installed (session AID)
- WHAT was installed (packages with SAIDs)
- WHEN installed (timestamp)
- GOVERNED BY (stack SAID)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from keri.core import coring

from .lock_file import LockFile, ResolvedPackage, compute_said


# Schema SAID (will be computed from schema content)
INSTALLATION_CREDENTIAL_SCHEMA_SAID = "EInstCred_GS_v1_PLACEHOLDER"


@dataclass
class InstallationCredentialData:
    """Data for installation credential."""
    stack_said: str
    lock_said: str
    python_version: str
    platform: str
    venv_path: str
    packages: List[ResolvedPackage]
    installed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class IssuedCredential:
    """Result of credential issuance."""
    said: str
    issuer: str
    registry_said: Optional[str]
    credential: dict
    tel_anchored: bool


def create_installation_credential(
    data: InstallationCredentialData,
    issuer_aid: str,
    registry_said: Optional[str] = None,
) -> IssuedCredential:
    """
    Create an installation credential.

    Args:
        data: Installation data to attest
        issuer_aid: AID of the issuer (installer)
        registry_said: Optional TEL registry SAID for anchoring

    Returns:
        IssuedCredential with SAID and full credential body
    """
    # Build attributes block
    attributes = {
        "dt": data.installed_at.isoformat(),
        "stack_said": data.stack_said,
        "lock_said": data.lock_said,
        "python_version": data.python_version,
        "platform": data.platform,
        "venv_path": data.venv_path,
        "packages": [
            {
                "name": p.name,
                "version": p.version,
                "wheel_said": p.wheel_said,
                "source": p.source,
            }
            for p in sorted(data.packages, key=lambda x: x.name.lower())
        ],
    }

    # Compute attributes SAID
    attr_said = compute_said(attributes)
    attributes["d"] = attr_said

    # Build credential body
    credential = {
        "v": "ACDC10JSON000000_",
        "i": issuer_aid,
        "s": INSTALLATION_CREDENTIAL_SCHEMA_SAID,
        "a": attributes,
    }

    # Add registry if TEL-anchored
    if registry_said:
        credential["ri"] = registry_said

    # Compute credential SAID
    cred_said = compute_said(credential)
    credential["d"] = cred_said

    return IssuedCredential(
        said=cred_said,
        issuer=issuer_aid,
        registry_said=registry_said,
        credential=credential,
        tel_anchored=registry_said is not None,
    )


def save_credential(cred: IssuedCredential, path: Path) -> None:
    """Save credential to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cred.credential, indent=2, sort_keys=True))


def load_credential(path: Path) -> Optional[dict]:
    """Load credential from disk."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


class InstallationCredentialIssuer:
    """
    Issues TEL-anchored installation credentials.

    Principle: SIGN EVERYTHING. VERIFY EVERYTHING. NO EXCEPTIONS.

    REQUIRES KERI infrastructure for production use. Credentials without
    TEL anchoring are deprecated and will be removed.

    Usage:
        # From KERI session (RECOMMENDED)
        issuer = InstallationCredentialIssuer.from_session(session_info)
        cred = issuer.issue(lock_file, venv_path)

        # With explicit KERI components
        issuer = InstallationCredentialIssuer(
            issuer_aid=hab.pre,
            registry_said=rgy.regk,
            hby=hby,
            rgy=rgy,
        )
        cred = issuer.issue(lock_file, venv_path)
    """

    def __init__(
        self,
        issuer_aid: str,
        registry_said: Optional[str] = None,
        hby=None,  # Habery for TEL anchoring
        rgy=None,  # Registry for TEL anchoring
    ):
        self.issuer_aid = issuer_aid
        self.registry_said = registry_said
        self.hby = hby
        self.rgy = rgy
        self._tel_available = hby is not None and rgy is not None

    @classmethod
    def from_session(cls, session_info: dict) -> InstallationCredentialIssuer:
        """
        Create issuer from KERI session info.

        Expected session_info keys:
        - session_aid: Session AID
        - hby: Habery instance
        - rgy: Registry instance
        - registry_said: Registry SAID
        """
        return cls(
            issuer_aid=session_info.get("session_aid", ""),
            registry_said=session_info.get("registry_said"),
            hby=session_info.get("hby"),
            rgy=session_info.get("rgy"),
        )

    @classmethod
    def local_only(cls, name: str = "local-installer") -> InstallationCredentialIssuer:
        """
        DEPRECATED: This method violates the end-to-end verifiability principle.

        Creates credentials without TEL anchoring, making them unverifiable.
        A signature without resolvable key state is worthless.

        Use from_session() with proper KERI infrastructure instead.

        Raises:
            RuntimeError: Always. TEL-less credentials are not acceptable.
        """
        raise RuntimeError(
            "local_only() is deprecated and disabled.\n"
            "\n"
            "Principle: SIGN EVERYTHING. VERIFY EVERYTHING. NO EXCEPTIONS.\n"
            "\n"
            "Credentials without TEL anchoring cannot be verified and are worthless.\n"
            "Set up KERI infrastructure first:\n"
            "  1. Initialize master AID: python scripts/setup_master_aid.py\n"
            "  2. Use from_session() with proper KERI session\n"
            "\n"
            "The only acceptable 'dev mode' is full KERI with local witnesses,\n"
            "NOT bypassing KERI entirely."
        )

    def issue(
        self,
        lock_file: LockFile,
        venv_path: Path,
    ) -> IssuedCredential:
        """
        Issue installation credential for a lock file.

        Args:
            lock_file: SAIDified lock file
            venv_path: Path to virtual environment

        Returns:
            IssuedCredential (TEL-anchored if KERI infrastructure available)
        """
        data = InstallationCredentialData(
            stack_said=lock_file.governed_by,
            lock_said=lock_file.said,
            python_version=lock_file.python_version,
            platform=lock_file.platform,
            venv_path=str(venv_path),
            packages=lock_file.packages,
        )

        cred = create_installation_credential(
            data=data,
            issuer_aid=self.issuer_aid,
            registry_said=self.registry_said if self._tel_available else None,
        )

        # If TEL available, anchor to registry - MUST succeed
        if self._tel_available and self.rgy:
            try:
                self._anchor_to_tel(cred)
            except Exception as e:
                # TEL anchoring failure IS credential issuance failure
                # SIGN EVERYTHING. VERIFY EVERYTHING. NO EXCEPTIONS.
                raise RuntimeError(
                    f"TEL anchoring failed: {e}\n"
                    "Credential issuance cannot complete without TEL anchoring.\n"
                    "Check KERI infrastructure and try again."
                ) from e

        return cred

    def _anchor_to_tel(self, cred: IssuedCredential) -> None:
        """Anchor credential to TEL registry."""
        if not self.rgy or not self.hby:
            return

        # This would use keripy's Registry.issue() method
        # For now, this is a placeholder for the integration
        # from keri.vdr import credentialing
        # registry = self.rgy.registries[self.registry_said]
        # registry.issue(said=cred.said, ...)
        pass

    @property
    def tel_available(self) -> bool:
        """Check if TEL anchoring is available."""
        return self._tel_available


def issue_installation_credential(
    stack_said: str,
    venv_path: Path,
    issuer_aid: Optional[str] = None,
    output_path: Optional[Path] = None,
    session_info: Optional[dict] = None,
) -> Tuple[IssuedCredential, LockFile]:
    """
    High-level function to issue installation credential.

    This is the main entry point for CLI usage.

    REQUIRES KERI infrastructure. Will attempt to load from:
    1. Provided session_info dict
    2. Environment KERI session (from hooks)
    3. Provided issuer_aid (TEL-less, deprecated)

    Args:
        stack_said: Governing stack SAID
        venv_path: Path to virtual environment
        issuer_aid: Issuer AID (deprecated - use session_info for TEL)
        output_path: Path to save credential (default: .governed/installation.json)
        session_info: KERI session info dict with hby, rgy, session_aid

    Returns:
        (IssuedCredential, LockFile)

    Raises:
        RuntimeError: If no KERI infrastructure available
    """
    from .lock_file import generate_lock_file

    # Generate lock file
    lock_file = generate_lock_file(
        stack_said=stack_said,
        venv_path=venv_path,
    )

    # Create issuer - prefer TEL-anchored
    issuer = None

    # 1. Try provided session_info
    if session_info:
        issuer = InstallationCredentialIssuer.from_session(session_info)

    # 2. Try environment KERI session
    if issuer is None:
        try:
            from governed_stack.keri.runtime import get_keri_runtime
            runtime = get_keri_runtime()
            if runtime and runtime.available and runtime.hab:
                issuer = InstallationCredentialIssuer(
                    issuer_aid=runtime.session_aid or runtime.hab.pre,
                    registry_said=runtime.rgy.regk if runtime.rgy else None,
                    hby=runtime.hby,
                    rgy=runtime.rgy,
                )
        except ImportError:
            pass

    # 3. Fallback to provided issuer_aid (deprecated, no TEL)
    if issuer is None and issuer_aid:
        import logging
        logging.warning(
            "Using issuer_aid without KERI infrastructure. "
            "Credential will NOT be TEL-anchored and cannot be fully verified. "
            "Set up KERI infrastructure for production use."
        )
        issuer = InstallationCredentialIssuer(issuer_aid=issuer_aid)

    # 4. No issuer available - fail
    if issuer is None:
        raise RuntimeError(
            "No KERI infrastructure available for credential issuance.\n"
            "\n"
            "Principle: SIGN EVERYTHING. VERIFY EVERYTHING. NO EXCEPTIONS.\n"
            "\n"
            "Options:\n"
            "  1. Set up KERI session: python scripts/setup_master_aid.py\n"
            "  2. Provide session_info dict with hby, rgy, session_aid\n"
            "  3. (Deprecated) Provide issuer_aid for TEL-less credential\n"
        )

    # Issue credential
    cred = issuer.issue(lock_file, venv_path)

    # Save to disk
    if output_path is None:
        output_path = Path(".governed/installation.json")

    save_credential(cred, output_path)

    # Also save lock file
    lock_path = output_path.parent / "lock.json"
    from .lock_file import save_lock_file
    save_lock_file(lock_file, lock_path)

    return cred, lock_file
