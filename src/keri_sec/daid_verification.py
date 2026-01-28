# -*- encoding: utf-8 -*-
"""
DAID Verification - Integrate Schema and Algorithm DAIDs into verification.

Provides DAID-aware verification for:
- Schema resolution and deprecation checking
- Algorithm agility and security level verification
- Credential schema pinning validation

Usage:
    from keri_sec.daid_verification import DAIDVerifier

    verifier = DAIDVerifier()

    # Verify schema SAID against registry
    result = verifier.verify_schema_said(
        schema_said="ESAID...",
        expected_name="skill-execution",
    )

    # Check algorithm deprecation before use
    check = verifier.check_algorithm_status("blake3")
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

from .schemas import (
    SchemaDAID,
    SchemaDAIDRegistry,
    SchemaStatus,
    get_schema_registry,
)
from .algorithms import (
    AlgorithmDAID,
    AlgorithmDAIDRegistry,
    AlgorithmStatus,
    AlgorithmCategory,
    get_algorithm_daid_registry,
)

logger = logging.getLogger(__name__)


@dataclass
class SchemaVerificationResult:
    """Result of schema DAID verification."""
    verified: bool
    schema_said: str
    daid: Optional[str] = None
    name: Optional[str] = None
    namespace: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = None
    deprecation_warning: Optional[str] = None
    successor_daid: Optional[str] = None
    error: Optional[str] = None


@dataclass
class AlgorithmVerificationResult:
    """Result of algorithm DAID verification."""
    verified: bool
    algorithm_name: str
    daid: Optional[str] = None
    category: Optional[str] = None
    security_level: int = 0
    cesr_code: Optional[str] = None
    status: Optional[str] = None
    deprecation_warning: Optional[str] = None
    successor_daid: Optional[str] = None
    error: Optional[str] = None


@dataclass
class CredentialVerificationResult:
    """Result of verifying a credential's schema and algorithm DAIDs."""
    verified: bool
    credential_said: str
    schema_result: Optional[SchemaVerificationResult] = None
    algorithm_results: List[AlgorithmVerificationResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    verified_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class DAIDVerifier:
    """
    DAID-aware verifier for schemas and algorithms.

    Integrates SchemaDAIDRegistry and AlgorithmDAIDRegistry to provide:
    - Schema SAID verification against registered DAIDs
    - Algorithm deprecation checking
    - Security level validation
    - Migration path recommendations
    """

    def __init__(
        self,
        schema_registry: Optional[SchemaDAIDRegistry] = None,
        algorithm_registry: Optional[AlgorithmDAIDRegistry] = None,
        min_security_level: int = 128,
        warn_on_deprecated: bool = True,
    ):
        """
        Initialize DAID verifier.

        Args:
            schema_registry: Schema DAID registry (default: singleton)
            algorithm_registry: Algorithm DAID registry (default: singleton)
            min_security_level: Minimum acceptable algorithm security level
            warn_on_deprecated: Log warnings for deprecated schemas/algorithms
        """
        self._schema_registry = schema_registry or get_schema_registry()
        self._algorithm_registry = algorithm_registry or get_algorithm_daid_registry()
        self._min_security_level = min_security_level
        self._warn_on_deprecated = warn_on_deprecated

    def verify_schema_said(
        self,
        schema_said: str,
        expected_name: Optional[str] = None,
        expected_namespace: Optional[str] = None,
        expected_version: Optional[str] = None,
    ) -> SchemaVerificationResult:
        """
        Verify a schema SAID against the DAID registry.

        Checks:
        1. Schema SAID is registered
        2. Schema matches expected name/namespace if provided
        3. Schema is not deprecated (warns if it is)
        4. Version matches if pinned

        Args:
            schema_said: The content SAID to verify
            expected_name: Expected schema name (optional)
            expected_namespace: Expected namespace (optional)
            expected_version: Expected version for pinning validation (optional)

        Returns:
            SchemaVerificationResult with status and any warnings
        """
        # Resolve by content SAID
        schema = self._schema_registry.resolve(schema_said)

        if schema is None:
            return SchemaVerificationResult(
                verified=False,
                schema_said=schema_said,
                error=f"Schema SAID not found in registry: {schema_said[:20]}...",
            )

        # Verify name if expected
        if expected_name and schema.name != expected_name:
            return SchemaVerificationResult(
                verified=False,
                schema_said=schema_said,
                daid=schema.daid,
                name=schema.name,
                error=f"Schema name mismatch: expected '{expected_name}', got '{schema.name}'",
            )

        # Verify namespace if expected
        if expected_namespace and schema.namespace != expected_namespace:
            return SchemaVerificationResult(
                verified=False,
                schema_said=schema_said,
                daid=schema.daid,
                namespace=schema.namespace,
                error=f"Schema namespace mismatch: expected '{expected_namespace}', got '{schema.namespace}'",
            )

        # Check version pinning
        version = None
        if expected_version:
            try:
                pinned_said = schema.pin_version(expected_version)
                if pinned_said != schema_said:
                    return SchemaVerificationResult(
                        verified=False,
                        schema_said=schema_said,
                        daid=schema.daid,
                        version=expected_version,
                        error=f"Version {expected_version} has SAID {pinned_said[:16]}..., not {schema_said[:16]}...",
                    )
                version = expected_version
            except ValueError as e:
                return SchemaVerificationResult(
                    verified=False,
                    schema_said=schema_said,
                    daid=schema.daid,
                    error=str(e),
                )
        else:
            # Find which version this SAID corresponds to
            for v in schema.versions:
                if v.content_said == schema_said:
                    version = v.version
                    break

        # Check deprecation
        deprecation_warning = None
        successor_daid = None
        if schema.is_deprecated:
            deprecation_warning = (
                f"Schema '{schema.qualified_name}' is deprecated: "
                f"{schema.deprecation.reason if schema.deprecation else 'No reason provided'}"
            )
            successor_daid = schema.successor_daid

            if self._warn_on_deprecated:
                logger.warning(deprecation_warning)

        return SchemaVerificationResult(
            verified=True,
            schema_said=schema_said,
            daid=schema.daid,
            name=schema.name,
            namespace=schema.namespace,
            version=version,
            status=schema.status.value,
            deprecation_warning=deprecation_warning,
            successor_daid=successor_daid,
        )

    def check_algorithm_status(
        self,
        identifier: str,
        required_category: Optional[AlgorithmCategory] = None,
    ) -> AlgorithmVerificationResult:
        """
        Check algorithm status and deprecation.

        Args:
            identifier: Algorithm DAID, name, or CESR code
            required_category: Required category (e.g., HASH for digest algorithms)

        Returns:
            AlgorithmVerificationResult with status and any warnings
        """
        algorithm = self._algorithm_registry.resolve(identifier)

        if algorithm is None:
            return AlgorithmVerificationResult(
                verified=False,
                algorithm_name=identifier,
                error=f"Algorithm not found in registry: {identifier}",
            )

        # Verify category if required
        if required_category and algorithm.category != required_category:
            return AlgorithmVerificationResult(
                verified=False,
                algorithm_name=algorithm.name,
                daid=algorithm.daid,
                category=algorithm.category.value,
                error=f"Algorithm category mismatch: expected '{required_category.value}', got '{algorithm.category.value}'",
            )

        # Check security level
        if algorithm.security_level < self._min_security_level:
            return AlgorithmVerificationResult(
                verified=False,
                algorithm_name=algorithm.name,
                daid=algorithm.daid,
                security_level=algorithm.security_level,
                error=f"Algorithm security level {algorithm.security_level} below minimum {self._min_security_level}",
            )

        # Check deprecation
        deprecation_warning = None
        successor_daid = None
        if algorithm.is_deprecated:
            deprecation_warning = (
                f"Algorithm '{algorithm.name}' is deprecated: "
                f"{algorithm.deprecation.reason if algorithm.deprecation else 'No reason provided'}"
            )
            successor_daid = algorithm.successor_daid

            if self._warn_on_deprecated:
                logger.warning(deprecation_warning)

        return AlgorithmVerificationResult(
            verified=True,
            algorithm_name=algorithm.name,
            daid=algorithm.daid,
            category=algorithm.category.value,
            security_level=algorithm.security_level,
            cesr_code=algorithm.cesr_code,
            status=algorithm.status.value,
            deprecation_warning=deprecation_warning,
            successor_daid=successor_daid,
        )

    def verify_credential_daids(
        self,
        credential: Dict[str, Any],
        expected_schema_name: Optional[str] = None,
    ) -> CredentialVerificationResult:
        """
        Verify all DAIDs referenced by a credential.

        Checks:
        1. Schema SAID is registered and not deprecated
        2. Any algorithm references are valid
        3. Security levels meet requirements

        Args:
            credential: ACDC credential dict
            expected_schema_name: Expected schema name (optional)

        Returns:
            CredentialVerificationResult with all checks
        """
        credential_said = credential.get("d", "")
        warnings: List[str] = []
        errors: List[str] = []

        # Verify schema
        schema_said = credential.get("s", "")
        schema_result = None

        if schema_said:
            schema_result = self.verify_schema_said(
                schema_said=schema_said,
                expected_name=expected_schema_name,
            )

            if not schema_result.verified:
                errors.append(f"Schema: {schema_result.error}")
            elif schema_result.deprecation_warning:
                warnings.append(schema_result.deprecation_warning)

        # Check for algorithm references in attributes
        algorithm_results: List[AlgorithmVerificationResult] = []
        attrs = credential.get("a", {})

        # Check common algorithm reference patterns
        for key in ["algorithm", "hash_algorithm", "signature_algorithm", "digest_algorithm"]:
            if key in attrs:
                algo_ref = attrs[key]
                if isinstance(algo_ref, str):
                    algo_result = self.check_algorithm_status(algo_ref)
                    algorithm_results.append(algo_result)

                    if not algo_result.verified:
                        errors.append(f"Algorithm ({key}): {algo_result.error}")
                    elif algo_result.deprecation_warning:
                        warnings.append(algo_result.deprecation_warning)

        verified = len(errors) == 0 and (schema_result is None or schema_result.verified)

        return CredentialVerificationResult(
            verified=verified,
            credential_said=credential_said,
            schema_result=schema_result,
            algorithm_results=algorithm_results,
            warnings=warnings,
            errors=errors,
        )

    def resolve_schema_for_issuance(
        self,
        name: str,
        namespace: Optional[str] = None,
        version: Optional[str] = None,
    ) -> Optional[str]:
        """
        Resolve schema content SAID for credential issuance.

        Validates schema exists, is not deprecated (or warns), and returns
        the appropriate content SAID for the credential's 's' field.

        Args:
            name: Schema name or qualified name
            namespace: Namespace (optional if qualified name used)
            version: Specific version to pin (optional, uses current if not specified)

        Returns:
            Content SAID for credential issuance, or None if not found
        """
        # Build qualified name if namespace provided
        identifier = f"{namespace}:{name}" if namespace else name

        schema = self._schema_registry.resolve(identifier)
        if schema is None:
            logger.error(f"Schema not found: {identifier}")
            return None

        if schema.is_deprecated and self._warn_on_deprecated:
            logger.warning(
                f"Issuing credential with deprecated schema '{schema.qualified_name}'. "
                f"Consider migrating to {schema.successor_daid}"
            )

        if version:
            try:
                return schema.pin_version(version)
            except ValueError as e:
                logger.error(f"Failed to pin schema version: {e}")
                return None

        return schema.current_content_said

    def get_algorithm_for_digest(
        self,
        preferred: str = "blake3",
    ) -> Optional[AlgorithmDAID]:
        """
        Get a non-deprecated algorithm for digest computation.

        If preferred algorithm is deprecated, returns its successor.

        Args:
            preferred: Preferred algorithm name

        Returns:
            AlgorithmDAID for an active algorithm, or None if none available
        """
        algorithm = self._algorithm_registry.resolve(preferred)

        if algorithm is None:
            return None

        # Follow deprecation chain
        max_hops = 5
        while algorithm.is_deprecated and algorithm.successor_daid and max_hops > 0:
            successor = self._algorithm_registry.resolve(algorithm.successor_daid)
            if successor is None:
                break
            algorithm = successor
            max_hops -= 1

        if algorithm.is_deprecated:
            logger.warning(f"No active algorithm found in deprecation chain from {preferred}")
            return None

        return algorithm


# Module-level convenience functions

def verify_schema(
    schema_said: str,
    expected_name: Optional[str] = None,
) -> SchemaVerificationResult:
    """Verify schema SAID against default registry."""
    verifier = DAIDVerifier()
    return verifier.verify_schema_said(schema_said, expected_name=expected_name)


def check_algorithm(
    identifier: str,
    category: Optional[AlgorithmCategory] = None,
) -> AlgorithmVerificationResult:
    """Check algorithm status against default registry."""
    verifier = DAIDVerifier()
    return verifier.check_algorithm_status(identifier, required_category=category)


def get_schema_said_for_issuance(
    name: str,
    version: Optional[str] = None,
) -> Optional[str]:
    """Get schema content SAID for credential issuance."""
    verifier = DAIDVerifier()
    return verifier.resolve_schema_for_issuance(name, version=version)
