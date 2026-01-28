# -*- encoding: utf-8 -*-
"""
KERI Runtime - Unified Access to KERI Infrastructure.

This module provides a single point of access to KERI infrastructure
(hby, rgy, hab) for all consumers. It prevents singleton fracturing by
ensuring everyone uses the same underlying keripy instances.

Usage:
    from keri_sec.keri import get_runtime

    runtime = get_runtime()
    if runtime.available:
        # KERI is ready
        cred = issue_credential(hby=runtime.hby, rgy=runtime.rgy)
    else:
        # Fall back or fail
        raise RuntimeError("KERI not available")

Principle: END-TO-END VERIFIABILITY OR BUST
When KERI is available, USE IT. No "lightweight" modes.
"""

import logging
import threading
from dataclasses import dataclass
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
        tel_available: True if TEL is available
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


def initialize_runtime(
    hby: Optional[Any] = None,
    rgy: Optional[Any] = None,
    hab: Optional[Any] = None,
    session_id: Optional[str] = None,
) -> KeriRuntime:
    """
    Explicitly initialize the KERI runtime.

    Call this during application startup to provide KERI infrastructure
    to all consumers.

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
        from keri_sec.keri.infrastructure import get_master_aid_prefix

        master_aid = get_master_aid_prefix()
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
            from keri_sec.keri.registry import register_keri_consumer
            register_keri_consumer(
                name="keri_sec.keri.runtime",
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


def get_runtime(auto_initialize: bool = True) -> KeriRuntime:
    """
    Get the KERI runtime, auto-initializing if possible.

    This is the primary entry point for all KERI consumers.

    Args:
        auto_initialize: If True, try to initialize from infrastructure

    Returns:
        KeriRuntime with available=True if KERI is ready, False otherwise

    Usage:
        runtime = get_runtime()
        if runtime.available:
            # KERI is ready - use TEL-anchored operations
            pass
        else:
            # KERI not ready - fail or warn
            logger.warning("Operating without KERI")
    """
    global _runtime, _initialized

    with _runtime_lock:
        # If already initialized, return cached runtime
        if _initialized and _runtime is not None:
            return _runtime

        if not auto_initialize:
            return KeriRuntime(available=False, error="Not initialized")

        # Try to auto-initialize from infrastructure
        try:
            from keri_sec.keri.infrastructure import get_infrastructure, get_master_aid_prefix

            infra = get_infrastructure()
            hby = infra.hby
            rgy = infra.rgy
            master_aid = get_master_aid_prefix()

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
                from keri_sec.keri.registry import register_keri_consumer
                register_keri_consumer(
                    name="keri_sec.keri.runtime",
                    hby=hby,
                    rgy=rgy,
                    purpose="Unified KERI runtime singleton (auto-initialized)",
                )

        except Exception as e:
            logger.warning(f"Failed to auto-initialize KERI runtime: {e}")
            _runtime = KeriRuntime(available=False, error=str(e))
            _initialized = True

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
    runtime = get_runtime()
    if not runtime.available:
        logger.warning(
            "KERI infrastructure not available. "
            "TEL-anchored operations will fail. "
            "Ensure initialize_runtime() is called before KERI operations."
        )
    return runtime.available
