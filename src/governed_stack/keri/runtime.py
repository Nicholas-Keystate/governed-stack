# -*- encoding: utf-8 -*-
"""
KERI Runtime Provider - Unified Access to KERI Infrastructure.

This module provides a single point of access to KERI infrastructure
(hby, rgy, hab) for all consumers. It prevents singleton fracturing by
ensuring everyone uses the same underlying keripy instances.

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │              governed_stack.keri.runtime                │
    │  - Single source of truth for hby/rgy/hab               │
    │  - Auto-initializes from keripy if available            │
    │  - Registers with fracture detection                    │
    └─────────────────────────────────────────────────────────┘
                          │
            ┌─────────────┼─────────────┐
            ▼             ▼             ▼
       ai-orchestrator  other-project  your-project
       (credential_svc) (uses runtime) (uses runtime)

Integration with ai-orchestrator:
    The runtime can auto-detect ai-orchestrator's KeriInfrastructure
    if available. Otherwise, consumers must call initialize_runtime()
    with explicit hby/rgy.

Usage:
    from governed_stack.keri import get_keri_runtime

    runtime = get_keri_runtime()
    if runtime.available:
        # KERI is ready
        daid_mgr = get_daid_manager(hby=runtime.hby, rgy=runtime.rgy)
    else:
        # Fall back to legacy mode
        logger.warning("Operating without KERI")

Principle: END-TO-END VERIFIABILITY OR BUST
When KERI is available, USE IT. No "lightweight" modes.
"""

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class KeriRuntime:
    """
    Container for KERI runtime components.

    Attributes:
        available: True if KERI infrastructure is ready
        hby: Habery for identity management
        rgy: Regery for credential registry
        hab: Session or master Hab for signing
        session_id: Current session ID (if in session context)
        master_aid: Master AID prefix
        session_aid: Delegated session AID prefix
        tel_available: True if TEL (Transaction Event Log) is available
    """
    available: bool = False
    hby: Optional[Any] = None
    rgy: Optional[Any] = None
    hab: Optional[Any] = None
    session_id: Optional[str] = None
    master_aid: Optional[str] = None
    session_aid: Optional[str] = None
    tel_available: bool = False
    error: Optional[str] = None

    def __bool__(self) -> bool:
        """Allow `if runtime:` checks."""
        return self.available


# Module-level singleton
_runtime: Optional[KeriRuntime] = None
_runtime_lock = threading.Lock()
_initialized = False


def _try_get_ai_orchestrator_infrastructure():
    """Try to get hby/rgy from ai-orchestrator's KeriInfrastructure."""
    try:
        # This import only works if ai-orchestrator is in the path
        from llm_backends.keri_infrastructure import get_infrastructure
        infra = get_infrastructure()
        return infra.hby, infra.rgy
    except ImportError:
        logger.debug("ai-orchestrator KeriInfrastructure not available")
    except Exception as e:
        logger.debug(f"KeriInfrastructure error: {e}")
    return None, None


def _try_get_master_aid():
    """Try to get master AID prefix from config."""
    try:
        import json
        config_path = Path.home() / ".keri" / "cf" / "claude-master.json"
        if config_path.exists():
            with open(config_path) as f:
                data = json.load(f)
                return data.get("prefix")
    except Exception:
        pass
    return None


def initialize_runtime(
    hby: Optional[Any] = None,
    rgy: Optional[Any] = None,
    hab: Optional[Any] = None,
    session_id: Optional[str] = None,
) -> KeriRuntime:
    """
    Explicitly initialize the KERI runtime.

    Call this during application startup (e.g., in pre_prompt.py)
    to provide KERI infrastructure to all consumers.

    Args:
        hby: Habery (identity management)
        rgy: Regery (credential registry)
        hab: Signing Hab (session or master)
        session_id: Current session ID

    Returns:
        Initialized KeriRuntime
    """
    global _runtime, _initialized

    with _runtime_lock:
        master_aid = _try_get_master_aid()
        session_aid = hab.pre if hab else None

        _runtime = KeriRuntime(
            available=hby is not None and rgy is not None,
            hby=hby,
            rgy=rgy,
            hab=hab,
            session_id=session_id,
            master_aid=master_aid,
            session_aid=session_aid,
            tel_available=rgy is not None,
        )
        _initialized = True

        # Register with fracture detection
        if _runtime.available:
            from governed_stack.keri.registry import register_keri_consumer
            register_keri_consumer(
                name="governed_stack.keri.runtime",
                hby=hby,
                rgy=rgy,
                purpose="Unified KERI runtime singleton",
            )

            logger.info(
                f"KERI runtime initialized: session={session_id[:16] if session_id else 'none'}... "
                f"hab={session_aid[:16] if session_aid else 'none'}..."
            )
        else:
            logger.warning("KERI runtime initialized in degraded mode (no hby/rgy)")

        return _runtime


def get_keri_runtime(auto_initialize: bool = True) -> KeriRuntime:
    """
    Get the KERI runtime, auto-initializing if possible.

    This is the primary entry point for all KERI consumers.

    Args:
        auto_initialize: If True, try to initialize from ai-orchestrator

    Returns:
        KeriRuntime with available=True if KERI is ready, False otherwise

    Usage:
        runtime = get_keri_runtime()
        if runtime.available:
            # KERI is ready - use TEL-anchored operations
            pass
        else:
            # KERI not ready - use legacy mode
            logger.warning("Operating without KERI")
    """
    global _runtime, _initialized

    with _runtime_lock:
        # If already initialized, return cached runtime
        if _initialized and _runtime is not None:
            return _runtime

        if not auto_initialize:
            return KeriRuntime(available=False, error="Not initialized")

        # Try to auto-initialize from ai-orchestrator
        hby, rgy = _try_get_ai_orchestrator_infrastructure()

        master_aid = _try_get_master_aid()

        _runtime = KeriRuntime(
            available=hby is not None and rgy is not None,
            hby=hby,
            rgy=rgy,
            master_aid=master_aid,
            tel_available=rgy is not None,
        )
        _initialized = True

        # Register with fracture detection
        if _runtime.available:
            from governed_stack.keri.registry import register_keri_consumer
            register_keri_consumer(
                name="governed_stack.keri.runtime",
                hby=hby,
                rgy=rgy,
                purpose="Unified KERI runtime singleton (auto-initialized)",
            )

        return _runtime


def reset_runtime() -> None:
    """Reset the runtime singleton (for testing)."""
    global _runtime, _initialized
    with _runtime_lock:
        _runtime = None
        _initialized = False


def ensure_keri_available() -> bool:
    """
    Check if KERI is available, logging warning if not.

    Convenience function for modules to call at startup.

    Returns:
        True if KERI is available
    """
    runtime = get_keri_runtime()
    if not runtime.available:
        logger.warning(
            "KERI infrastructure not available. "
            "TEL-anchored operations will fail. "
            "Ensure initialize_runtime() is called before KERI operations."
        )
    return runtime.available


# =============================================================================
# Convenience accessors (ai-orchestrator specific)
# =============================================================================

def get_daid_manager_from_runtime():
    """
    Get DAIDManager using runtime infrastructure.

    Returns:
        DAIDManager if KERI available, None otherwise
    """
    runtime = get_keri_runtime()
    if not runtime.available:
        return None

    try:
        # This import only works with ai-orchestrator
        from agents.daid_manager import get_daid_manager
        return get_daid_manager(hby=runtime.hby, rgy=runtime.rgy)
    except ImportError:
        logger.debug("DAIDManager not available (ai-orchestrator not in path)")
    except Exception as e:
        logger.error(f"Failed to get DAIDManager: {e}")
    return None


def get_credential_service_from_runtime():
    """
    Get CredentialService using runtime infrastructure.

    Returns:
        CredentialService if KERI available, None otherwise
    """
    runtime = get_keri_runtime()
    if not runtime.available:
        return None

    try:
        # This import only works with ai-orchestrator
        from agents.credential_service import get_credential_service
        return get_credential_service(hby=runtime.hby, rgy=runtime.rgy)
    except ImportError:
        logger.debug("CredentialService not available (ai-orchestrator not in path)")
    except Exception as e:
        logger.error(f"Failed to get CredentialService: {e}")
    return None
