# -*- encoding: utf-8 -*-
"""
TEL Anchoring for keri-secs.

Provides cryptographic attestation of stack definitions via KERI TEL.
Without TEL anchoring, stack SAIDs are just computed hashes.
With TEL anchoring, they become verifiable credentials.

Integration:
    When ai-orchestrator is available, uses CredentialService for:
    - Centralized TEL anchoring with WAL (crash-safe)
    - Proper ACDC structure validation
    - Metrics and observability
    - Edge chain verification via KGQL

    When ai-orchestrator is NOT available, uses keripy directly.

Requirements:
- Master AID (issuer) with access to a registry
- Registry for TEL events
- Schema SAIDs registered

Usage:
    from keri_sec.tel_anchoring import StackCredentialIssuer

    issuer = StackCredentialIssuer(hab=master_hab, registry=registry)
    cred_said = issuer.issue_stack_credential(stack)

    # Or get from ai-orchestrator session
    issuer = get_issuer_from_session()
    if issuer:
        issuer.issue_stack_credential(...)
"""

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from keri.core import coring
from keri.core.coring import Saider, MtrDex

if TYPE_CHECKING:
    from keri.app import habbing
    from keri.vdr import credentialing

logger = logging.getLogger(__name__)

# Schema SAIDs (computed from schemas/ via Saider.saidify with label="$id")
STACK_SCHEMA_SAID = "EHofe890uUQJWD6UhU5XDzHrVHMPuqKtDW9McCp4pSsl"
WORKSPACE_SCHEMA_SAID = "EDqrtt3vaINXFk7SbM-E_gEKBU4-NegmgU0hdowSg_jN"

# Try to import ai-orchestrator's credential service
_CREDENTIAL_SERVICE_AVAILABLE = False
_credential_service_module = None

try:
    import sys
    # Add ai-orchestrator to path if not already there
    ai_orch_path = Path(__file__).parent.parent.parent.parent / "ai-orchestrator"
    if ai_orch_path.exists() and str(ai_orch_path) not in sys.path:
        sys.path.insert(0, str(ai_orch_path))

    from agents.credential_service import get_credential_service, CredentialService
    _CREDENTIAL_SERVICE_AVAILABLE = True
    logger.debug("ai-orchestrator CredentialService available")
except ImportError:
    logger.debug("ai-orchestrator not available, using direct keripy integration")


@dataclass
class CredentialIssuanceResult:
    """Result of issuing a credential."""
    success: bool
    credential_said: Optional[str]
    registry_said: Optional[str]
    error: Optional[str] = None


def compute_schema_said(schema_path: Path) -> str:
    """Compute SAID for a schema file."""
    content = schema_path.read_text()
    schema = json.loads(content)

    # Remove $id to compute SAID of content
    schema_copy = schema.copy()
    schema_copy["$id"] = ""

    ser = json.dumps(schema_copy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    saider = Saider(sad=schema_copy, code=MtrDex.Blake3_256, label="$id")

    return saider.qb64


class StackCredentialIssuer:
    """
    Issues TEL-anchored credentials for keri-sec stacks.

    This connects keri-sec to real KERI infrastructure.

    When ai-orchestrator's CredentialService is available, delegates to it
    for proper WAL-backed, metric-tracked credential issuance.

    When not available, uses keripy directly (still TEL-anchored).
    """

    def __init__(
        self,
        hab: Optional["habbing.Hab"] = None,
        registry: Optional["credentialing.Registry"] = None,
        schemas_path: Optional[Path] = None,
        credential_service: Optional[Any] = None,
        hby: Optional["habbing.Habery"] = None,
        rgy: Optional["credentialing.Regery"] = None,
    ):
        """
        Initialize issuer.

        Preferred: Pass credential_service from ai-orchestrator.
        Fallback: Pass hab + registry for direct keripy integration.

        Args:
            hab: KERI Habitat (signing identity)
            registry: KERI Registry for TEL
            schemas_path: Path to schema files (default: ./schemas/)
            credential_service: ai-orchestrator CredentialService (preferred)
            hby: Habery for creating credential_service if needed
            rgy: Regery for creating credential_service if needed
        """
        self.hab = hab
        self.registry = registry
        self.schemas_path = schemas_path or Path(__file__).parent.parent.parent / "schemas"
        self._credential_service = credential_service

        # If we have hby/rgy but no credential_service, try to create one
        if self._credential_service is None and hby is not None and rgy is not None:
            if _CREDENTIAL_SERVICE_AVAILABLE:
                try:
                    self._credential_service = get_credential_service(hby=hby, rgy=rgy)
                    logger.info("Using ai-orchestrator CredentialService for TEL anchoring")
                except Exception as e:
                    logger.warning(f"Could not initialize CredentialService: {e}")

        # Cache schema SAIDs
        self._schema_saids: Dict[str, str] = {}

    def _get_schema_said(self, schema_name: str) -> str:
        """Get or compute schema SAID."""
        if schema_name not in self._schema_saids:
            schema_file = self.schemas_path / f"{schema_name}.json"
            if schema_file.exists():
                self._schema_saids[schema_name] = compute_schema_said(schema_file)
            else:
                # Use placeholder
                if schema_name == "stack_credential":
                    self._schema_saids[schema_name] = STACK_SCHEMA_SAID
                elif schema_name == "workspace_credential":
                    self._schema_saids[schema_name] = WORKSPACE_SCHEMA_SAID
                else:
                    raise ValueError(f"Unknown schema: {schema_name}")

        return self._schema_saids[schema_name]

    def can_issue(self) -> Tuple[bool, str]:
        """Check if we can issue credentials."""
        if not self.hab:
            return False, "No Habitat (signing identity) configured"
        if not self.registry:
            return False, "No Registry (TEL) configured"
        return True, "Ready to issue"

    def issue_stack_credential(
        self,
        stack_name: str,
        stack_said: str,
        constraints: Dict[str, str],
        rationale: str = "",
        workspace_cred_said: Optional[str] = None,
        previous_cred_said: Optional[str] = None,
    ) -> CredentialIssuanceResult:
        """
        Issue a TEL-anchored credential for a stack.

        Args:
            stack_name: Human-readable stack name
            stack_said: Computed SAID of constraint set
            constraints: Package -> version spec mapping
            rationale: Why these constraints
            workspace_cred_said: Optional edge to workspace credential
            previous_cred_said: Optional edge to previous version

        Returns:
            CredentialIssuanceResult with credential SAID or error
        """
        can, reason = self.can_issue()
        if not can:
            return CredentialIssuanceResult(
                success=False,
                credential_said=None,
                registry_said=None,
                error=reason,
            )

        try:
            schema_said = self._get_schema_said("stack_credential")

            # Build attributes with ACDC structure (d placeholder for SAID)
            attrs = {
                "d": "",  # Placeholder for SAID computation
                "dt": datetime.now(timezone.utc).isoformat(),
                "name": stack_name,
                "stackSaid": stack_said,
                "constraints": constraints,
                "constraintCount": len(constraints),
                "rationale": rationale,
            }

            # Build edges with ACDC structure (n for node SAID, s for schema)
            edges = None
            if workspace_cred_said or previous_cred_said:
                edges = {"d": ""}  # Placeholder for edges block SAID
                if workspace_cred_said:
                    edges["workspace"] = {
                        "n": workspace_cred_said,
                        "s": self._get_schema_said("workspace_credential"),
                    }
                if previous_cred_said:
                    edges["previousVersion"] = {
                        "n": previous_cred_said,
                        "s": self._get_schema_said("stack_credential"),
                    }

            # Use CredentialService if available (preferred path)
            if self._credential_service is not None:
                cred_said = self._credential_service.issue_credential(
                    schema_said=schema_said,
                    issuer_hab=self.hab,
                    attributes=attrs,
                    edges=edges,
                    recipient=self.hab.pre,
                )
                registry = self._credential_service._registries.get(self.hab.pre)
                registry_said = registry.regk if registry else self.registry.regk

                logger.info(f"Issued stack credential via CredentialService: {cred_said}")

                return CredentialIssuanceResult(
                    success=True,
                    credential_said=cred_said,
                    registry_said=registry_said,
                )

            # Fallback: Direct keripy integration
            from keri.vc import proving

            creder = proving.credential(
                issuer=self.hab.pre,
                schema=schema_said,
                data=attrs,
                status=self.registry.regk,
                source=edges,
            )

            # Anchor to TEL
            self.registry.issue(said=creder.said, dt=attrs["dt"])

            logger.info(f"Issued stack credential (direct): {creder.said}")

            return CredentialIssuanceResult(
                success=True,
                credential_said=creder.said,
                registry_said=self.registry.regk,
            )

        except Exception as e:
            logger.error(f"Failed to issue credential: {e}")
            return CredentialIssuanceResult(
                success=False,
                credential_said=None,
                registry_said=None,
                error=str(e),
            )

    def issue_workspace_credential(
        self,
        workspace_name: str,
        workspace_said: str,
        unified_constraints: Dict[str, str],
        project_saids: List[str],
    ) -> CredentialIssuanceResult:
        """
        Issue a TEL-anchored credential for a workspace.

        Args:
            workspace_name: Workspace name
            workspace_said: Computed SAID of unified constraints
            unified_constraints: Unified package -> version spec
            project_saids: SAIDs of individual project stacks

        Returns:
            CredentialIssuanceResult
        """
        can, reason = self.can_issue()
        if not can:
            return CredentialIssuanceResult(
                success=False,
                credential_said=None,
                registry_said=None,
                error=reason,
            )

        try:
            schema_said = self._get_schema_said("workspace_credential")
            stack_schema_said = self._get_schema_said("stack_credential")

            # Build attributes with ACDC structure
            attrs = {
                "d": "",  # Placeholder for SAID computation
                "dt": datetime.now(timezone.utc).isoformat(),
                "name": workspace_name,
                "workspaceSaid": workspace_said,
                "unifiedConstraints": unified_constraints,
                "projectCount": len(project_saids),
                "projectSaids": project_saids,
            }

            # Build edges to project stacks with ACDC structure
            edges = {
                "d": "",  # Placeholder for edges block SAID
                "projects": [
                    {
                        "n": said,  # node SAID (target credential)
                        "s": stack_schema_said,  # schema SAID
                    }
                    for said in project_saids
                ]
            }

            # Use CredentialService if available (preferred path)
            if self._credential_service is not None:
                cred_said = self._credential_service.issue_credential(
                    schema_said=schema_said,
                    issuer_hab=self.hab,
                    attributes=attrs,
                    edges=edges,
                    recipient=self.hab.pre,
                )
                registry = self._credential_service._registries.get(self.hab.pre)
                registry_said = registry.regk if registry else self.registry.regk

                logger.info(f"Issued workspace credential via CredentialService: {cred_said}")

                return CredentialIssuanceResult(
                    success=True,
                    credential_said=cred_said,
                    registry_said=registry_said,
                )

            # Fallback: Direct keripy integration
            from keri.vc import proving

            creder = proving.credential(
                issuer=self.hab.pre,
                schema=schema_said,
                data=attrs,
                status=self.registry.regk,
                source=edges,
            )

            self.registry.issue(said=creder.said, dt=attrs["dt"])

            logger.info(f"Issued workspace credential (direct): {creder.said}")

            return CredentialIssuanceResult(
                success=True,
                credential_said=creder.said,
                registry_said=self.registry.regk,
            )

        except Exception as e:
            logger.error(f"Failed to issue workspace credential: {e}")
            return CredentialIssuanceResult(
                success=False,
                credential_said=None,
                registry_said=None,
                error=str(e),
            )


def get_issuer_from_session() -> Optional[StackCredentialIssuer]:
    """
    Try to get an issuer from current KERI session.

    Integration priority:
    1. ai-orchestrator's CredentialService (preferred - full TEL support)
    2. Session hab from hooks (fallback - direct keripy)

    Returns None if KERI infrastructure not available.
    """
    try:
        import sys
        ai_orch_path = Path(__file__).parent.parent.parent.parent / "ai-orchestrator"
        if ai_orch_path.exists() and str(ai_orch_path) not in sys.path:
            sys.path.insert(0, str(ai_orch_path))

        # Try to get the singleton credential service
        from agents.credential_service import _credential_service, get_credential_service

        # If credential service is already initialized, use it
        if _credential_service is not None:
            # Find the first hab in the service's registries
            for issuer_pre, registry in _credential_service._registries.items():
                hab = _credential_service.hby.habByPre(issuer_pre)
                if hab:
                    return StackCredentialIssuer(
                        hab=hab,
                        registry=registry,
                        credential_service=_credential_service,
                    )

        # Try to get session hab from hooks
        try:
            from hooks.pre_prompt import get_session_hab, get_session_hby, get_session_rgy
            session_hab = get_session_hab()
            session_hby = get_session_hby()
            session_rgy = get_session_rgy()

            if session_hab and session_hby and session_rgy:
                # Create or get credential service with session infrastructure
                service = get_credential_service(hby=session_hby, rgy=session_rgy)
                registry = service.get_or_create_registry(session_hab)

                return StackCredentialIssuer(
                    hab=session_hab,
                    registry=registry,
                    credential_service=service,
                    hby=session_hby,
                    rgy=session_rgy,
                )
        except ImportError:
            logger.debug("Session hooks not available")

    except ImportError:
        logger.debug("ai-orchestrator not available")
    except Exception as e:
        logger.debug(f"Could not get issuer from session: {e}")

    return None


def create_issuer_with_keri(
    hby: "habbing.Habery",
    rgy: "credentialing.Regery",
    hab: "habbing.Hab",
) -> StackCredentialIssuer:
    """
    Create an issuer with explicit KERI infrastructure.

    This is the recommended way to create an issuer when you have
    direct access to KERI infrastructure (e.g., in scripts or tests).

    Args:
        hby: Habery for identity management
        rgy: Regery for credential registry management
        hab: Hab for signing

    Returns:
        StackCredentialIssuer configured with credential service
    """
    if _CREDENTIAL_SERVICE_AVAILABLE:
        service = get_credential_service(hby=hby, rgy=rgy)
        registry = service.get_or_create_registry(hab)
        return StackCredentialIssuer(
            hab=hab,
            registry=registry,
            credential_service=service,
            hby=hby,
            rgy=rgy,
        )
    else:
        # Fallback: create registry directly
        from keri.vdr import credentialing as cred_module

        registry = rgy.makeRegistry(
            name=f"{hab.name}-stack-registry",
            prefix=hab.pre,
            noBackers=True,
        )
        return StackCredentialIssuer(hab=hab, registry=registry)
