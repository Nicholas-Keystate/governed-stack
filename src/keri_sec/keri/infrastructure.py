# -*- encoding: utf-8 -*-
"""
Shared KERI Infrastructure for Multi-Project Coordination

Provides process-safe KERI operations using HIO Doer patterns:
- Single persistent Habery with proper lifecycle management
- Atomic operations via file locking
- Buffer-based content storage using HIO Deck
- Agent registry and audit logging

Uses keripy directly for all cryptographic operations.
Built on HIO (Hierarchical Asynchronous I/O) for proper lifecycle management.

Storage layout:
    ~/.keri-agents/
    ├── keri/                      # Shared KERI database (via keripy)
    │   ├── db/                    # LMDB databases (KEL, TEL, credentials)
    │   └── ks/                    # Key store
    ├── agents/
    │   ├── registry.json          # Session → AID mapping
    │   └── sessions/              # Per-session metadata
    ├── content/                   # Disk-persisted content store
    │   └── {SAID}.json            # Content files keyed by SAID
    ├── audit/
    │   └── audit.jsonl            # Global ordered action log
    └── agents.lock                # Process coordination lock
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable, TypeVar
from datetime import datetime
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# HIO imports - for proper lifecycle management
from hio.base import Doer
from hio.help import Deck

# keripy imports - all crypto operations delegated to keripy
from keri.app import habbing
from keri.vdr import credentialing
from keri.core import coring, signing, scheming
from keri.core.coring import Diger, Saider, MtrDex
from keri.core.signing import Salter
from keri.vc import proving

# Import base infrastructure from keri-infra (canonical location)
from keri_infra import (
    KERI_AGENTS_PATH,
    MASTER_AID_CONFIG_PATH,
    FileLock,
    AuditEntry,
    compute_said,
    master_aid_configured,
    get_master_aid_info,
    get_master_aid_prefix,
)

T = TypeVar('T')

# Note: AuditEntry and FileLock are now imported from keri_infra above.
# The following class extends the base keri-infra functionality with
# HIO Doer lifecycle management specific to keri-sec.


class KeriInfrastructure(Doer):
    """
    Shared KERI infrastructure for all projects.

    Extends HIO Doer for proper lifecycle management:
    - enter(): Initialize Habery/Regery resources
    - recur(): Service any pending operations (if needed)
    - exit(): Clean up resources
    - close(): Handle forced exit
    - abort(): Handle exceptions

    Provides:
    - Single persistent Habery with HIO lifecycle
    - Atomic operations via file locking
    - Buffer-based content storage using Deck
    - Recovery from incomplete operations
    """

    def __init__(
        self,
        base_path: Path = KERI_AGENTS_PATH,
        passcode: str = "keri-agents-default-key",
        temp: bool = False,
        **kwa
    ):
        """
        Initialize shared KERI infrastructure.

        Args:
            base_path: Root directory for all storage
            passcode: Passcode for key derivation (min 16 chars)
            temp: If True, use temporary (non-persistent) storage for testing
            **kwa: Additional Doer arguments (tymth, tock, etc.)
        """
        super().__init__(**kwa)

        self.base_path = Path(base_path)
        self._temp = temp
        self.base_path.mkdir(parents=True, exist_ok=True)

        # Storage paths
        self.keri_path = self.base_path / "keri"
        self.agents_path = self.base_path / "agents"
        self.content_path = self.base_path / "content"
        self.audit_path = self.base_path / "audit"
        self.lock_path = self.base_path / "agents.lock"
        self.content_lock_path = self.base_path / "content.lock"

        # Ensure directories exist
        self.keri_path.mkdir(exist_ok=True)
        self.agents_path.mkdir(exist_ok=True)
        (self.agents_path / "sessions").mkdir(exist_ok=True)
        self.content_path.mkdir(exist_ok=True)
        self.audit_path.mkdir(exist_ok=True)

        # Initialize components
        self._lock = FileLock(self.lock_path)
        self._content_lock = FileLock(self.content_lock_path)
        self._passcode = passcode

        # Derive salt from passcode
        raw_salt = passcode.encode()[:16].ljust(16, b'\x00')
        self._salt = signing.Salter(raw=raw_salt).qb64

        # Initialize registry file if needed
        self._registry_path = self.agents_path / "registry.json"
        if not self._registry_path.exists():
            self._write_registry({"sessions": {}, "sequence": 0})

        # Resources initialized in enter(), cleaned up in exit()
        self._hby: Optional[habbing.Habery] = None
        self._rgy: Optional[credentialing.Regery] = None
        self._schemas: Dict[str, scheming.Schemer] = {}

        # Buffer-based content storage using HIO Deck pattern
        self._content_deck = Deck()
        self._content_cache: Dict[str, Dict[str, Any]] = {}

        # Track initialization state
        self._entered = False

    # =========================================================================
    # HIO Doer Lifecycle Methods
    # =========================================================================

    def enter(self, temp=None):
        """Initialize KERI resources on Doer start."""
        if self._entered:
            return

        logger.debug(f"KeriInfrastructure entering: initializing resources at {self.base_path}")

        try:
            hby_kwargs = {
                "name": "keri-agents",
                "salt": self._salt,
                "temp": self._temp,
            }
            if not self._temp:
                hby_kwargs["base"] = ""
            self._hby = habbing.Habery(**hby_kwargs)

            self._rgy = credentialing.Regery(
                hby=self._hby,
                name="keri-agents",
                temp=self._temp
            )

            self._entered = True
            logger.info(f"KeriInfrastructure initialized with {len(self._hby.habs)} identifiers")

            # Register with fracture detection
            from keri_sec.keri.registry import register_keri_consumer
            register_keri_consumer(
                name="keri_sec.keri.infrastructure",
                hby=self._hby,
                rgy=self._rgy,
                purpose="Primary KERI infrastructure singleton",
            )

        except Exception as e:
            logger.error(f"Failed to initialize KeriInfrastructure: {type(e).__name__}: {e}")
            raise

    def recur(self, tyme):
        """Process any pending operations each cycle."""
        if not self._entered:
            self.enter()

        while True:
            op = self._content_deck.pull(emptive=True)
            if op is None:
                break
            self._process_content_op(op)

        return False

    def _process_content_op(self, op: Dict[str, Any]):
        """Process a content operation from the deck."""
        op_type = op.get("type")
        if op_type == "store":
            content = op.get("content")
            said = self.compute_content_said(content)
            self._content_cache[said] = content

    def exit(self):
        """Clean up KERI resources on normal Doer exit."""
        logger.debug("KeriInfrastructure exiting: cleaning up resources")
        self._cleanup_resources()

    def close(self):
        """Handle forced exit."""
        logger.debug("KeriInfrastructure closing: forced cleanup")
        self._cleanup_resources()

    def abort(self, ex):
        """Handle exception during Doer execution."""
        logger.error(f"KeriInfrastructure aborting: {type(ex).__name__}: {ex}")
        self._cleanup_resources()

    def _cleanup_resources(self):
        """Internal method to clean up all resources."""
        if self._hby:
            if hasattr(self._hby, 'db') and self._hby.db:
                try:
                    self._hby.db.close()
                except Exception as e:
                    logger.warning(f"Error closing Habery database: {e}")
            self._hby = None

        if self._rgy:
            if hasattr(self._rgy, 'reger') and self._rgy.reger:
                try:
                    self._rgy.reger.close()
                except Exception as e:
                    logger.warning(f"Error closing Regery database: {e}")
            self._rgy = None

        self._entered = False

    # =========================================================================
    # Resource Access
    # =========================================================================

    @property
    def hby(self) -> habbing.Habery:
        """Get Habery, initializing if needed."""
        if self._hby is None:
            self.enter()
        return self._hby

    @property
    def rgy(self) -> credentialing.Regery:
        """Get Regery, initializing if needed."""
        if self._rgy is None:
            self.enter()
        return self._rgy

    def with_lock(self, operation: Callable[[], T]) -> T:
        """Execute operation with exclusive file lock."""
        with self._lock.locked():
            return operation()

    # =========================================================================
    # Identity Management
    # =========================================================================

    def create_aid(self, alias: str, transferable: bool = False) -> str:
        """Create a new AID."""
        def _create():
            for hab in self.hby.habs.values():
                if hab.name == alias:
                    return hab.pre

            try:
                hab = self.hby.makeHab(
                    name=alias,
                    transferable=transferable,
                    icount=1,
                    isith="1",
                    ncount=1 if transferable else 0,
                    nsith="1" if transferable else "0",
                )
            except Exception as e:
                raise RuntimeError(f"Failed to create AID '{alias}': {e}") from e
            return hab.pre

        return self.with_lock(_create)

    def create_delegated_aid(
        self,
        alias: str,
        delegator_alias: str,
        transferable: bool = False,
    ) -> str:
        """Create AID delegated from another AID."""
        def _create():
            delegator = self._get_hab_by_alias(delegator_alias)
            if not delegator:
                raise ValueError(f"Unknown delegator: {delegator_alias}")

            for hab in self.hby.habs.values():
                if hab.name == alias:
                    return hab.pre

            try:
                hab = self.hby.makeHab(
                    name=alias,
                    transferable=transferable,
                    icount=1,
                    isith="1",
                    ncount=1 if transferable else 0,
                    nsith="1" if transferable else "0",
                    delpre=delegator.pre,
                )
            except Exception as e:
                raise RuntimeError(f"Failed to create delegated AID '{alias}': {e}") from e

            registry = self._read_registry()
            if "delegations" not in registry:
                registry["delegations"] = {}
            registry["delegations"][hab.pre] = {
                "delegator": delegator.pre,
                "delegator_alias": delegator_alias,
                "created_at": datetime.now().isoformat(),
            }
            self._write_registry(registry)

            return hab.pre

        return self.with_lock(_create)

    def get_aid(self, alias: str) -> Optional[str]:
        """Get AID by alias."""
        hab = self._get_hab_by_alias(alias)
        return hab.pre if hab else None

    def _get_hab_by_alias(self, alias: str):
        """Get Hab by alias."""
        for hab in self.hby.habs.values():
            if hab.name == alias:
                return hab
        return None

    # =========================================================================
    # Schema Management
    # =========================================================================

    def register_schema(self, schema_dict: Dict[str, Any]) -> str:
        """Register a JSON schema and return its SAID."""
        try:
            schemer = scheming.Schemer(sed=schema_dict)
        except Exception as e:
            raise ValueError(f"Invalid schema: {e}") from e
        said = schemer.said
        self._schemas[said] = schemer
        return said

    def get_schema(self, said: str) -> Optional[Dict[str, Any]]:
        """Get schema by SAID."""
        if said in self._schemas:
            return self._schemas[said].sed
        return None

    # =========================================================================
    # Credential Operations
    # =========================================================================

    def issue_credential(
        self,
        issuer_alias: str,
        schema_said: str,
        subject_aid: str,
        data: Dict[str, Any],
        registry_name: Optional[str] = None,
    ) -> str:
        """Issue a credential."""
        def _issue():
            issuer = self._get_hab_by_alias(issuer_alias)
            if not issuer:
                raise ValueError(f"Unknown issuer: {issuer_alias}")

            reg_name = registry_name or f"{issuer_alias}-registry"

            registry = self.rgy.registryByName(reg_name)
            if registry is None:
                try:
                    registry = self.rgy.makeRegistry(
                        name=reg_name,
                        prefix=issuer.pre,
                    )
                except Exception as e:
                    raise RuntimeError(f"Failed to create registry: {e}") from e

            creder = proving.credential(
                issuer=issuer.pre,
                recipient=subject_aid,
                schema=schema_said,
                data=data,
            )

            return creder.said

        return self.with_lock(_issue)

    # =========================================================================
    # Registry (Session/Agent Mapping)
    # =========================================================================

    def _read_registry(self) -> Dict[str, Any]:
        """Read agent registry."""
        if self._registry_path.exists():
            with open(self._registry_path) as f:
                return json.load(f)
        return {"sessions": {}, "sequence": 0}

    def _write_registry(self, data: Dict[str, Any]):
        """Write agent registry."""
        with open(self._registry_path, 'w') as f:
            json.dump(data, f, indent=2)

    def get_next_sequence(self) -> int:
        """Get next global sequence number (atomic)."""
        def _get():
            registry = self._read_registry()
            seq = registry.get("sequence", 0) + 1
            registry["sequence"] = seq
            self._write_registry(registry)
            return seq
        return self.with_lock(_get)

    def register_session(
        self,
        session_id: str,
        agent_aid: str,
        parent_session_id: Optional[str] = None,
        parent_aid: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Register a session in the registry."""
        def _register():
            registry = self._read_registry()
            registry["sessions"][session_id] = {
                "agent_aid": agent_aid,
                "parent_session_id": parent_session_id,
                "parent_aid": parent_aid,
                "created_at": datetime.now().isoformat(),
                "metadata": metadata or {},
            }
            self._write_registry(registry)
        self.with_lock(_register)

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session info from registry."""
        registry = self._read_registry()
        return registry.get("sessions", {}).get(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all sessions."""
        registry = self._read_registry()
        sessions = []
        for sid, info in registry.get("sessions", {}).items():
            sessions.append({"session_id": sid, **info})
        return sessions

    # =========================================================================
    # Audit Log
    # =========================================================================

    def append_audit(self, entry: AuditEntry):
        """Append entry to audit log."""
        def _append():
            audit_file = self.audit_path / "audit.jsonl"
            with open(audit_file, 'a') as f:
                f.write(json.dumps(asdict(entry)) + "\n")
        self.with_lock(_append)

    def read_audit(
        self,
        limit: int = 100,
        session_id: Optional[str] = None,
        agent_aid: Optional[str] = None,
    ) -> List[AuditEntry]:
        """Read audit log with optional filters."""
        audit_file = self.audit_path / "audit.jsonl"
        if not audit_file.exists():
            return []

        entries = []
        with open(audit_file) as f:
            for line in f:
                try:
                    data = json.loads(line.strip())
                    if session_id and data.get("session_id") != session_id:
                        continue
                    if agent_aid and data.get("agent_aid") != agent_aid:
                        continue
                    entries.append(AuditEntry(**data))
                    if len(entries) >= limit:
                        break
                except (json.JSONDecodeError, TypeError):
                    continue
        return entries

    # =========================================================================
    # Content Operations
    # =========================================================================

    def compute_content_said(self, content: Dict[str, Any]) -> str:
        """Compute SAID for content."""
        return compute_said(content)

    def store_content(self, content: Dict[str, Any]) -> str:
        """Store content and return its SAID."""
        said = self.compute_content_said(content)
        self._content_cache[said] = content

        content_file = self.content_path / f"{said}.json"

        def _write():
            with open(content_file, 'w') as f:
                json.dump(content, f, indent=2)

        with self._content_lock.locked():
            _write()

        return said

    def get_content(self, said: str) -> Optional[Dict[str, Any]]:
        """Retrieve content by SAID."""
        if said in self._content_cache:
            return self._content_cache[said]

        content_file = self.content_path / f"{said}.json"
        if content_file.exists():
            try:
                with open(content_file, 'r') as f:
                    content = json.load(f)
                self._content_cache[said] = content
                return content
            except (json.JSONDecodeError, Exception):
                return None

        return None

    # =========================================================================
    # Utility
    # =========================================================================

    def compute_hash(self, data: Any) -> str:
        """Compute hash of data using keripy's Diger."""
        if isinstance(data, str):
            serialized = data
        else:
            serialized = json.dumps(data, separators=(',', ':'))
        try:
            diger = Diger(ser=serialized.encode(), code=MtrDex.SHA2_256)
            return diger.qb64
        except Exception as e:
            raise RuntimeError(f"Failed to compute hash: {e}") from e

    def stats(self) -> Dict[str, Any]:
        """Get infrastructure statistics."""
        registry = self._read_registry()

        audit_file = self.audit_path / "audit.jsonl"
        audit_count = 0
        if audit_file.exists():
            with open(audit_file) as f:
                audit_count = sum(1 for _ in f)

        credential_count = 0
        if self._rgy and hasattr(self._rgy, 'reger'):
            try:
                credential_count = len(list(self._rgy.reger.creds.getItemIter()))
            except Exception:
                pass

        return {
            "base_path": str(self.base_path),
            "total_sessions": len(registry.get("sessions", {})),
            "global_sequence": registry.get("sequence", 0),
            "audit_entries": audit_count,
            "credentials": credential_count,
            "identifiers": len(self.hby.habs) if self._hby else 0,
        }


# =============================================================================
# Singleton Management
# =============================================================================

_infrastructure: Optional[KeriInfrastructure] = None


def get_infrastructure(
    base_path: Path = KERI_AGENTS_PATH,
    passcode: str = "keri-agents-default-key",
    temp: bool = False,
) -> KeriInfrastructure:
    """
    Get or create the shared KERI infrastructure instance.

    For HIO Doist usage, the Doist will call enter() when scheduling begins.
    For standalone usage, resources are lazily initialized on first access.

    Args:
        base_path: Root directory for storage
        passcode: Passcode for key derivation
        temp: If True, use temporary storage (for testing)

    Returns:
        KeriInfrastructure singleton (extends Doer)
    """
    global _infrastructure
    if _infrastructure is None:
        _infrastructure = KeriInfrastructure(base_path, passcode, temp=temp)
    return _infrastructure


def reset_infrastructure():
    """Reset the infrastructure singleton (for testing)."""
    global _infrastructure
    if _infrastructure:
        _infrastructure._cleanup_resources()
    _infrastructure = None


# =============================================================================
# Master AID Integration
# =============================================================================
# Note: master_aid_configured, get_master_aid_info, get_master_aid_prefix
# are now imported from keri_infra at the top of this file.
