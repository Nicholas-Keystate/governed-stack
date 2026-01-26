# -*- encoding: utf-8 -*-
"""
KERI Singleton Management for Governed Stack.

This module provides centralized KERI infrastructure management to prevent
singleton fracturing across projects. All KERI consumers should use these
exports rather than creating their own Habery/Regery instances.

Usage:
    from governed_stack.keri import get_keri_runtime, KeriRuntime

    runtime = get_keri_runtime()
    if runtime.available:
        # Use runtime.hby, runtime.rgy, runtime.hab
        pass

Fracture Prevention:
    from governed_stack.keri import register_keri_consumer, check_for_fractures

    # Register your component as a KERI consumer
    register_keri_consumer("my_module", runtime.hby)

    # Check if multiple Habery instances exist (indicates fracture)
    fractures = check_for_fractures()
    if fractures:
        logger.warning(f"KERI fractures detected: {fractures}")

Credit:
    - KERI by Samuel M. Smith - https://keri.one
    - Transit pattern by Cognitect - https://github.com/cognitect/transit-format
"""

from governed_stack.keri.runtime import (
    KeriRuntime,
    get_keri_runtime,
    initialize_runtime,
    reset_runtime,
    ensure_keri_available,
    get_daid_manager_from_runtime,
    get_credential_service_from_runtime,
)

from governed_stack.keri.registry import (
    register_keri_consumer,
    get_registered_consumers,
    check_for_fractures,
    KeriConsumer,
    FractureReport,
)

__all__ = [
    # Runtime
    "KeriRuntime",
    "get_keri_runtime",
    "initialize_runtime",
    "reset_runtime",
    "ensure_keri_available",
    "get_daid_manager_from_runtime",
    "get_credential_service_from_runtime",
    # Fracture prevention
    "register_keri_consumer",
    "get_registered_consumers",
    "check_for_fractures",
    "KeriConsumer",
    "FractureReport",
]
