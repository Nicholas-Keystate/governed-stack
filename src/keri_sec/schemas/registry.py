# -*- encoding: utf-8 -*-
"""
Schema DAID Registry - Governed ACDC Schema Management.

Implements DAID pattern for ACDC schemas, enabling:
- Stable identifier through schema version rotations
- Version pinning for credential issuance
- Governed deprecation with successor references
- Schema evolution tracking

Usage:
    registry = SchemaDAIDRegistry()

    # Register schema from JSON
    schema = registry.register_from_file(
        path="schemas/skill_execution.json",
        namespace="ai-orchestrator",
    )

    # Rotate to new version
    registry.rotate(
        daid=schema.daid,
        new_version="2.0.0",
        new_content=updated_schema_json,
        change_type="major",
        breaking_changes=["Renamed 'skillId' to 'skill_id'"],
    )

    # Pin credential to specific schema version
    pinned_said = schema.pin_version("1.0.0")  # Returns content SAID
"""

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from keri_governance.cardinal import Operation

from ..attestation import Tier, Attestation, create_attestation, compute_said
from ..base_registry import BaseGAIDRegistry

if TYPE_CHECKING:
    from ..governance.gate import GovernanceGate

logger = logging.getLogger(__name__)


class SchemaStatus(Enum):
    """Status of a schema in its lifecycle."""
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    SUPERSEDED = "superseded"


@dataclass
class DeprecationNotice:
    """Deprecation details for a schema."""
    reason: str
    successor_daid: Optional[str] = None
    deadline: Optional[str] = None


@dataclass
class SchemaVersion:
    """A specific version of a schema."""
    version: str
    content_said: str
    content: Dict[str, Any]
    change_type: Optional[str] = None  # major/minor/patch
    breaking_changes: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attestation: Optional[Attestation] = None


@dataclass
class SchemaDAID:
    """
    A governed schema with DAID identity.

    The DAID prefix remains stable across version rotations.
    Each rotation adds a new SchemaVersion to the history.
    """
    daid: str  # Stable identifier (computed from inception)
    name: str
    namespace: str
    credential_type: str
    status: SchemaStatus = SchemaStatus.ACTIVE
    deprecation: Optional[DeprecationNotice] = None

    # Version chain
    versions: List[SchemaVersion] = field(default_factory=list)
    current_version_index: int = 0

    @property
    def current_version(self) -> Optional[SchemaVersion]:
        """Get current (latest) version."""
        if self.versions:
            return self.versions[self.current_version_index]
        return None

    @property
    def current_content_said(self) -> Optional[str]:
        """Get content SAID of current version."""
        if self.current_version:
            return self.current_version.content_said
        return None

    @property
    def is_deprecated(self) -> bool:
        return self.status in (SchemaStatus.DEPRECATED, SchemaStatus.SUPERSEDED)

    @property
    def successor_daid(self) -> Optional[str]:
        if self.deprecation:
            return self.deprecation.successor_daid
        return None

    @property
    def qualified_name(self) -> str:
        """Namespace-qualified name: 'namespace:name'."""
        return f"{self.namespace}:{self.name}"

    def get_version(self, version_str: str) -> Optional[SchemaVersion]:
        """Get specific version by version string."""
        for v in self.versions:
            if v.version == version_str:
                return v
        return None

    def pin_version(self, version_str: str) -> str:
        """
        Get content SAID for a specific version (for version pinning).

        Use this when issuing credentials to pin to a specific schema version.
        """
        ver = self.get_version(version_str)
        if ver is None:
            raise ValueError(f"Version not found: {version_str}")
        return ver.content_said

    def to_dict(self) -> Dict[str, Any]:
        return {
            "daid": self.daid,
            "name": self.name,
            "namespace": self.namespace,
            "qualified_name": self.qualified_name,
            "credential_type": self.credential_type,
            "status": self.status.value,
            "deprecation": {
                "reason": self.deprecation.reason,
                "successor_daid": self.deprecation.successor_daid,
                "deadline": self.deprecation.deadline,
            } if self.deprecation else None,
            "version_count": len(self.versions),
            "current_version": self.current_version.version if self.current_version else None,
            "current_content_said": self.current_content_said,
        }


class SchemaDAIDRegistry(BaseGAIDRegistry[SchemaDAID]):
    """
    Registry of governed schemas with DAID identity.

    Supports:
    - Registration with computed DAID
    - Version rotation (append-only)
    - Version pinning for credential issuance
    - Deprecation with successor references
    - Resolution by DAID, qualified name, or content SAID
    """

    def __init__(self, governance_gate: Optional["GovernanceGate"] = None):
        super().__init__(governance_gate=governance_gate)
        self._by_content_said: Dict[str, str] = {}  # content_said -> daid

    # -- Base class hooks --

    def _resolve_extra(self, identifier: str) -> Optional[SchemaDAID]:
        # Bare name without namespace (searches all namespaces)
        if ":" not in identifier:
            for qualified_name, daid in self._by_name.items():
                if qualified_name.endswith(f":{identifier}"):
                    return self._entities.get(daid)

        # Content SAID lookup
        if identifier in self._by_content_said:
            daid = self._by_content_said[identifier]
            return self._entities.get(daid)
        return None

    def _apply_deprecation(self, obj, reason, successor, deadline):
        obj.status = SchemaStatus.DEPRECATED
        obj.deprecation = DeprecationNotice(
            reason=reason,
            successor_daid=successor,
            deadline=deadline,
        )

    def register(
        self,
        name: str,
        namespace: str,
        version: str,
        content: Dict[str, Any],
        issuer_hab: Any = None,
    ) -> SchemaDAID:
        """
        Register a new schema, creating its DAID.

        The DAID is computed from the inception data (name, namespace, initial content)
        and remains stable across future rotations.

        Args:
            name: Schema name (e.g., 'skill-execution')
            namespace: Schema namespace (e.g., 'ai-orchestrator')
            version: Initial version string
            content: Schema JSON content
            issuer_hab: Issuer for attestation

        Returns:
            Registered SchemaDAID
        """
        self._enforce(Operation.REGISTER, issuer_hab=issuer_hab)

        # Extract credential type from schema
        credential_type = content.get("credentialType", name)

        # Compute content SAID
        content_said = compute_said(content)

        # Compute DAID from inception data
        inception = {
            "name": name,
            "namespace": namespace,
            "credential_type": credential_type,
            "initial_content_said": content_said,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        daid = compute_said(inception)

        # Create initial version
        initial_version = SchemaVersion(
            version=version,
            content_said=content_said,
            content=content,
        )

        # Create attestation if issuer provided
        if issuer_hab:
            try:
                initial_version.attestation = create_attestation(
                    tier=Tier.KEL_ANCHORED,
                    content={
                        "event": "schema_registration",
                        "daid": daid,
                        "name": name,
                        "namespace": namespace,
                        "version": version,
                        "content_said": content_said,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Attestation failed: {e}")

        schema = SchemaDAID(
            daid=daid,
            name=name,
            namespace=namespace,
            credential_type=credential_type,
            versions=[initial_version],
        )

        qualified_name = schema.qualified_name

        self._store(daid, qualified_name, schema)
        with self._lock:
            self._by_content_said[content_said] = daid

        logger.info(f"Registered schema DAID: {qualified_name} -> {daid[:16]}...")
        return schema

    def register_from_file(
        self,
        path: Union[str, Path],
        namespace: str,
        issuer_hab: Any = None,
    ) -> SchemaDAID:
        """
        Register a schema from a JSON file.

        Args:
            path: Path to schema JSON file
            namespace: Schema namespace
            issuer_hab: Issuer for attestation

        Returns:
            Registered SchemaDAID
        """
        path = Path(path)
        content = json.loads(path.read_text())

        # Extract name from title or filename
        name = content.get("title", path.stem).lower().replace(" ", "-")
        version = content.get("version", "1.0.0")

        return self.register(
            name=name,
            namespace=namespace,
            version=version,
            content=content,
            issuer_hab=issuer_hab,
        )

    def rotate(
        self,
        daid: str,
        new_version: str,
        new_content: Dict[str, Any],
        change_type: str = "minor",
        breaking_changes: Optional[List[str]] = None,
        issuer_hab: Any = None,
    ) -> SchemaVersion:
        """
        Rotate a schema to a new version.

        This is an append-only operation - old versions remain accessible.

        Args:
            daid: Schema DAID (or prefix)
            new_version: New version string
            new_content: New schema JSON content
            change_type: Type of change (major/minor/patch)
            breaking_changes: List of breaking changes for major versions
            issuer_hab: Issuer for attestation

        Returns:
            The new SchemaVersion
        """
        self._enforce(Operation.ROTATE, issuer_hab=issuer_hab)

        schema = self.resolve(daid)
        if schema is None:
            raise ValueError(f"Schema not found: {daid}")

        # Compute new content SAID
        content_said = compute_said(new_content)

        # Create new version
        new_ver = SchemaVersion(
            version=new_version,
            content_said=content_said,
            content=new_content,
            change_type=change_type,
            breaking_changes=breaking_changes or [],
        )

        # Create rotation attestation
        if issuer_hab:
            try:
                new_ver.attestation = create_attestation(
                    tier=Tier.KEL_ANCHORED,
                    content={
                        "event": "schema_rotation",
                        "daid": schema.daid,
                        "previous_version": schema.current_version.version,
                        "new_version": new_version,
                        "previous_content_said": schema.current_content_said,
                        "new_content_said": content_said,
                        "change_type": change_type,
                        "breaking_changes": breaking_changes,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Rotation attestation failed: {e}")

        with self._lock:
            schema.versions.append(new_ver)
            schema.current_version_index = len(schema.versions) - 1
            self._by_content_said[content_said] = schema.daid

        logger.info(
            f"Rotated schema {schema.qualified_name}: "
            f"{schema.versions[-2].version} -> {new_version} ({change_type})"
        )
        return new_ver

    def deprecate(
        self,
        daid: str,
        reason: str,
        successor_daid: Optional[str] = None,
        deadline: Optional[str] = None,
        issuer_hab: Any = None,
    ) -> None:
        """Deprecate a schema."""
        super().deprecate(daid, reason, successor=successor_daid, deadline=deadline, issuer_hab=issuer_hab)

        # Create deprecation attestation
        schema = self.resolve(daid)
        if issuer_hab and schema:
            try:
                create_attestation(
                    tier=Tier.KEL_ANCHORED,
                    content={
                        "event": "schema_deprecation",
                        "daid": schema.daid,
                        "qualified_name": schema.qualified_name,
                        "reason": reason,
                        "successor_daid": successor_daid,
                        "deadline": deadline,
                    },
                    issuer_hab=issuer_hab,
                )
            except Exception as e:
                logger.warning(f"Deprecation attestation failed: {e}")

    def list_schemas(self, namespace: Optional[str] = None) -> List[SchemaDAID]:
        """List all schemas, optionally filtered by namespace."""
        schemas = self.list_all()
        if namespace:
            schemas = [s for s in schemas if s.namespace == namespace]
        return schemas

    def get_content_for_version(
        self,
        daid: str,
        version: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get schema content for a specific version.

        Args:
            daid: Schema DAID
            version: Specific version (default: current)

        Returns:
            Schema JSON content
        """
        schema = self.resolve(daid)
        if schema is None:
            raise ValueError(f"Schema not found: {daid}")

        if version:
            ver = schema.get_version(version)
            if ver is None:
                raise ValueError(f"Version not found: {version}")
        else:
            ver = schema.current_version

        return ver.content


# Module-level singleton
_registry: Optional[SchemaDAIDRegistry] = None
_registry_lock = threading.Lock()


def get_schema_registry(
    governance_gate: Optional["GovernanceGate"] = None,
) -> SchemaDAIDRegistry:
    """Get the schema DAID registry singleton.

    Args:
        governance_gate: Optional gate to enable cardinal rule enforcement.
    """
    global _registry
    with _registry_lock:
        if _registry is None:
            _registry = SchemaDAIDRegistry()
            if governance_gate is not None:
                _registry.set_governance_gate(governance_gate)
        return _registry


def reset_schema_registry():
    """Reset the registry (for testing)."""
    global _registry
    with _registry_lock:
        _registry = None
