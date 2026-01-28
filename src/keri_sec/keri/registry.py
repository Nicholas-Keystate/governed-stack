# -*- encoding: utf-8 -*-
"""
KERI Consumer Registry - Fracture Prevention.

This module tracks all components that use KERI infrastructure to detect
and prevent singleton fracturing (multiple Habery/Regery instances).

Problem:
    When multiple modules create their own Habery/Regery, credentials and
    keys can get out of sync. This is "singleton fracturing."

Solution:
    1. All KERI consumers register themselves
    2. Registry tracks which Habery each consumer uses
    3. check_for_fractures() detects if multiple Habery instances exist
    4. Warnings/errors raised before damage occurs

Usage:
    from keri_sec.keri import register_keri_consumer, check_for_fractures

    # When your module initializes KERI:
    register_keri_consumer(
        name="my_module",
        hby=runtime.hby,
        purpose="credential issuance",
    )

    # Periodically or at startup:
    report = check_for_fractures()
    if report.fractured:
        logger.error(f"KERI fracture detected: {report}")
"""

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class KeriConsumer:
    """A registered KERI consumer."""
    name: str
    hby_id: int  # id() of Habery instance
    rgy_id: Optional[int] = None
    purpose: str = ""
    registered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    module_path: Optional[str] = None


@dataclass
class FractureReport:
    """Report of KERI singleton fractures."""
    fractured: bool
    hby_count: int
    rgy_count: int
    consumers: List[KeriConsumer] = field(default_factory=list)
    hby_groups: Dict[int, List[str]] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def __str__(self) -> str:
        if not self.fractured:
            return f"No fractures ({len(self.consumers)} consumers, 1 Habery)"
        return (
            f"FRACTURE DETECTED: {self.hby_count} Habery instances across "
            f"{len(self.consumers)} consumers. Groups: {dict(self.hby_groups)}"
        )


# Module-level registry
_consumers: Dict[str, KeriConsumer] = {}
_registry_lock = threading.Lock()


def register_keri_consumer(
    name: str,
    hby: Any,
    rgy: Optional[Any] = None,
    purpose: str = "",
    module_path: Optional[str] = None,
) -> KeriConsumer:
    """
    Register a KERI consumer for fracture detection.

    Call this when your module initializes KERI infrastructure.
    This allows check_for_fractures() to detect if multiple
    Habery instances exist (which indicates a problem).

    Args:
        name: Unique name for this consumer
        hby: The Habery instance this consumer uses
        rgy: Optional Regery instance
        purpose: What this consumer does with KERI
        module_path: Optional module path for debugging

    Returns:
        KeriConsumer registration record
    """
    consumer = KeriConsumer(
        name=name,
        hby_id=id(hby) if hby else 0,
        rgy_id=id(rgy) if rgy else None,
        purpose=purpose,
        module_path=module_path,
    )

    with _registry_lock:
        if name in _consumers:
            old = _consumers[name]
            if old.hby_id != consumer.hby_id:
                logger.warning(
                    f"KERI consumer '{name}' re-registered with DIFFERENT Habery! "
                    f"Old: {old.hby_id}, New: {consumer.hby_id}"
                )
        _consumers[name] = consumer

    logger.debug(f"Registered KERI consumer: {name} (hby={consumer.hby_id})")
    return consumer


def get_registered_consumers() -> List[KeriConsumer]:
    """Get all registered KERI consumers."""
    with _registry_lock:
        return list(_consumers.values())


def check_for_fractures() -> FractureReport:
    """
    Check for KERI singleton fractures.

    A fracture occurs when multiple consumers use different Habery instances.
    This can cause credentials and keys to get out of sync.

    Returns:
        FractureReport with fracture details
    """
    with _registry_lock:
        consumers = list(_consumers.values())

    if not consumers:
        return FractureReport(
            fractured=False,
            hby_count=0,
            rgy_count=0,
            warnings=["No KERI consumers registered"],
        )

    # Group consumers by Habery id
    hby_groups: Dict[int, List[str]] = {}
    rgy_ids: Set[int] = set()

    for consumer in consumers:
        if consumer.hby_id not in hby_groups:
            hby_groups[consumer.hby_id] = []
        hby_groups[consumer.hby_id].append(consumer.name)

        if consumer.rgy_id:
            rgy_ids.add(consumer.rgy_id)

    hby_count = len(hby_groups)
    rgy_count = len(rgy_ids) if rgy_ids else 0
    fractured = hby_count > 1

    warnings = []
    if fractured:
        warnings.append(
            f"FRACTURE: {hby_count} different Habery instances detected. "
            f"All KERI consumers should use the same Habery."
        )
        for hby_id, names in hby_groups.items():
            warnings.append(f"  Habery {hby_id}: {', '.join(names)}")

    return FractureReport(
        fractured=fractured,
        hby_count=hby_count,
        rgy_count=rgy_count,
        consumers=consumers,
        hby_groups=hby_groups,
        warnings=warnings,
    )


def reset_registry() -> None:
    """Reset the consumer registry (for testing)."""
    global _consumers
    with _registry_lock:
        _consumers = {}
