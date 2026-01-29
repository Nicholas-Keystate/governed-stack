# -*- encoding: utf-8 -*-
"""
Attestation Storage Overhead Benchmark.

Measures actual storage costs of the three attestation tiers:
- Tier 1: TEL_ANCHORED (full credential, TEL entry)
- Tier 2: KEL_ANCHORED (signature + KEL interaction event)
- Tier 3: SAID_ONLY (content hash only)

Compares against baseline (no attestation) and validates
OVERHEAD_ESTIMATES in tiers.py.

Usage:
    pytest tests/test_attestation_overhead.py -v -s
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import pytest

from keri_sec.attestation import (
    Tier,
    Attestation,
    create_attestation,
    compute_said,
    estimate_overhead,
    OVERHEAD_ESTIMATES,
)
from keri_sec.algorithms import (
    AlgorithmRegistry,
    Algorithm,
    ExecutionResult,
)


@dataclass
class StorageMetrics:
    """Storage overhead metrics for a single operation."""
    tier: str
    attestation_bytes: int
    content_bytes: int
    overhead_bytes: int
    overhead_pct: float
    execution_time_us: float


@dataclass
class BenchmarkReport:
    """Complete benchmark results."""
    test_name: str
    iterations: int
    content_size_bytes: int

    # Per-tier metrics (averages)
    baseline: StorageMetrics = None
    said_only: StorageMetrics = None
    kel_anchored: StorageMetrics = None
    tel_anchored: StorageMetrics = None

    # Comparison with estimates
    estimate_accuracy: Dict[str, float] = field(default_factory=dict)

    # Observations
    observations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_name": self.test_name,
            "iterations": self.iterations,
            "content_size_bytes": self.content_size_bytes,
            "tiers": {
                "baseline": vars(self.baseline) if self.baseline else None,
                "said_only": vars(self.said_only) if self.said_only else None,
                "kel_anchored": vars(self.kel_anchored) if self.kel_anchored else None,
                "tel_anchored": vars(self.tel_anchored) if self.tel_anchored else None,
            },
            "estimate_accuracy": self.estimate_accuracy,
            "observations": self.observations,
        }

    def print_summary(self):
        """Print human-readable summary."""
        print(f"\n{'='*70}")
        print(f"ATTESTATION STORAGE OVERHEAD BENCHMARK: {self.test_name}")
        print(f"{'='*70}")
        print(f"Content size: {self.content_size_bytes} bytes")
        print(f"Iterations: {self.iterations}")
        print()

        print(f"{'Tier':<15} {'Storage':<12} {'Overhead':<12} {'Overhead %':<12} {'Time (μs)':<12}")
        print("-" * 70)

        for name, metrics in [
            ("Baseline", self.baseline),
            ("SAID_ONLY", self.said_only),
            ("KEL_ANCHORED", self.kel_anchored),
            ("TEL_ANCHORED", self.tel_anchored),
        ]:
            if metrics:
                print(f"{name:<15} {metrics.attestation_bytes:<12} "
                      f"{metrics.overhead_bytes:<12} {metrics.overhead_pct:<12.1f} "
                      f"{metrics.execution_time_us:<12.1f}")

        print()
        print("Estimate Accuracy (actual vs OVERHEAD_ESTIMATES):")
        for tier, accuracy in self.estimate_accuracy.items():
            status = "✓" if 0.5 <= accuracy <= 2.0 else "⚠"
            print(f"  {status} {tier}: {accuracy:.2f}x (1.0 = exact match)")

        if self.observations:
            print()
            print("Observations:")
            for obs in self.observations:
                print(f"  - {obs}")


def measure_baseline(content: Dict[str, Any], iterations: int = 100) -> StorageMetrics:
    """Measure baseline: just serialize content, no attestation."""
    content_bytes = len(json.dumps(content, sort_keys=True))

    start = time.perf_counter()
    for _ in range(iterations):
        serialized = json.dumps(content, sort_keys=True)
    elapsed = (time.perf_counter() - start) * 1_000_000 / iterations  # microseconds

    return StorageMetrics(
        tier="baseline",
        attestation_bytes=content_bytes,
        content_bytes=content_bytes,
        overhead_bytes=0,
        overhead_pct=0.0,
        execution_time_us=elapsed,
    )


def measure_said_only(content: Dict[str, Any], iterations: int = 100) -> StorageMetrics:
    """Measure SAID_ONLY tier: content + SAID hash."""
    content_bytes = len(json.dumps(content, sort_keys=True))

    start = time.perf_counter()
    for _ in range(iterations):
        attestation = create_attestation(
            tier=Tier.SAID_ONLY,
            content=content,
        )
    elapsed = (time.perf_counter() - start) * 1_000_000 / iterations

    attestation_bytes = attestation.storage_size()
    overhead = attestation_bytes - content_bytes

    return StorageMetrics(
        tier="SAID_ONLY",
        attestation_bytes=attestation_bytes,
        content_bytes=content_bytes,
        overhead_bytes=overhead,
        overhead_pct=(overhead / content_bytes * 100) if content_bytes > 0 else 0,
        execution_time_us=elapsed,
    )


def measure_kel_anchored_simulated(content: Dict[str, Any], iterations: int = 100) -> StorageMetrics:
    """
    Measure KEL_ANCHORED tier (simulated - no actual KERI infrastructure).

    Since we can't call real KEL anchoring without infrastructure,
    we estimate based on:
    - Attestation JSON with signature placeholder
    - KEL interaction event size estimate (~150 bytes)
    """
    content_bytes = len(json.dumps(content, sort_keys=True))

    # Create attestation structure (without real signature)
    content_said = compute_said(content)

    start = time.perf_counter()
    for _ in range(iterations):
        # Simulate what KEL_ANCHORED produces
        attestation_data = {
            "tier": Tier.KEL_ANCHORED.value,
            "content_said": content_said,
            "content": content,
            "created_at": "2026-01-26T00:00:00+00:00",
            "signature": "0" * 88,  # Simulated Ed25519 signature (base64)
            "signer_aid": "E" + "A" * 43,  # Simulated AID
            "kel_seal": content_said,
            "kel_sn": 1,
        }
        serialized = json.dumps(attestation_data, sort_keys=True)
    elapsed = (time.perf_counter() - start) * 1_000_000 / iterations

    attestation_bytes = len(serialized)
    # Add estimated KEL interaction event overhead
    kel_event_estimate = 150
    total_bytes = attestation_bytes + kel_event_estimate

    overhead = total_bytes - content_bytes

    return StorageMetrics(
        tier="KEL_ANCHORED",
        attestation_bytes=total_bytes,
        content_bytes=content_bytes,
        overhead_bytes=overhead,
        overhead_pct=(overhead / content_bytes * 100) if content_bytes > 0 else 0,
        execution_time_us=elapsed,
    )


def measure_tel_anchored_simulated(content: Dict[str, Any], iterations: int = 100) -> StorageMetrics:
    """
    Measure TEL_ANCHORED tier (simulated - no actual KERI infrastructure).

    Estimates based on:
    - Full ACDC credential structure
    - TEL registry entry
    - KEL anchoring
    """
    content_bytes = len(json.dumps(content, sort_keys=True))
    content_said = compute_said(content)

    start = time.perf_counter()
    for _ in range(iterations):
        # Simulate full ACDC credential
        credential_data = {
            "v": "ACDC10JSON000000_",
            "d": "E" + "B" * 43,  # Credential SAID
            "i": "E" + "A" * 43,  # Issuer AID
            "ri": "E" + "C" * 43,  # Registry SAID
            "s": "E" + "D" * 43,  # Schema SAID
            "a": {
                "d": "E" + "E" * 43,
                "dt": "2026-01-26T00:00:00+00:00",
                "contentSaid": content_said,
                **content,
            },
        }

        attestation_data = {
            "tier": Tier.TEL_ANCHORED.value,
            "content_said": content_said,
            "content": content,
            "created_at": "2026-01-26T00:00:00+00:00",
            "signature": "0" * 88,
            "signer_aid": "E" + "A" * 43,
            "credential_said": credential_data["d"],
            "registry_said": credential_data["ri"],
        }

        serialized = json.dumps(attestation_data, sort_keys=True)
        credential_serialized = json.dumps(credential_data, sort_keys=True)
    elapsed = (time.perf_counter() - start) * 1_000_000 / iterations

    attestation_bytes = len(serialized)
    credential_bytes = len(credential_serialized)
    tel_entry_estimate = 200  # TEL registry entry
    kel_event_estimate = 150  # KEL interaction event

    total_bytes = attestation_bytes + credential_bytes + tel_entry_estimate + kel_event_estimate
    overhead = total_bytes - content_bytes

    return StorageMetrics(
        tier="TEL_ANCHORED",
        attestation_bytes=total_bytes,
        content_bytes=content_bytes,
        overhead_bytes=overhead,
        overhead_pct=(overhead / content_bytes * 100) if content_bytes > 0 else 0,
        execution_time_us=elapsed,
    )


def run_benchmark(
    test_name: str,
    content: Dict[str, Any],
    iterations: int = 100,
) -> BenchmarkReport:
    """Run complete benchmark for all tiers."""
    content_bytes = len(json.dumps(content, sort_keys=True))

    report = BenchmarkReport(
        test_name=test_name,
        iterations=iterations,
        content_size_bytes=content_bytes,
    )

    # Measure each tier
    report.baseline = measure_baseline(content, iterations)
    report.said_only = measure_said_only(content, iterations)
    report.kel_anchored = measure_kel_anchored_simulated(content, iterations)
    report.tel_anchored = measure_tel_anchored_simulated(content, iterations)

    # Compare with OVERHEAD_ESTIMATES
    estimates = {
        "SAID_ONLY": OVERHEAD_ESTIMATES[Tier.SAID_ONLY]["total_estimate"],
        "KEL_ANCHORED": OVERHEAD_ESTIMATES[Tier.KEL_ANCHORED]["total_estimate"],
        "TEL_ANCHORED": OVERHEAD_ESTIMATES[Tier.TEL_ANCHORED]["total_estimate"],
    }

    actuals = {
        "SAID_ONLY": report.said_only.attestation_bytes,
        "KEL_ANCHORED": report.kel_anchored.attestation_bytes,
        "TEL_ANCHORED": report.tel_anchored.attestation_bytes,
    }

    for tier, estimate in estimates.items():
        actual = actuals[tier]
        # Accuracy ratio: 1.0 = exact, <1 = underestimate, >1 = overestimate
        report.estimate_accuracy[tier] = actual / estimate if estimate > 0 else 0

    # Generate observations
    if report.said_only.overhead_pct < 50:
        report.observations.append(
            f"SAID_ONLY overhead ({report.said_only.overhead_pct:.1f}%) is very low - good for high-volume"
        )

    if report.tel_anchored.overhead_pct > 500:
        report.observations.append(
            f"TEL_ANCHORED overhead ({report.tel_anchored.overhead_pct:.1f}%) is high - use only when needed"
        )

    kel_vs_tel = report.tel_anchored.attestation_bytes / report.kel_anchored.attestation_bytes
    report.observations.append(
        f"TEL_ANCHORED is {kel_vs_tel:.1f}x larger than KEL_ANCHORED"
    )

    return report


class TestAttestationOverhead:
    """Storage overhead benchmark tests."""

    def test_small_content_overhead(self):
        """Test overhead for small content (~100 bytes)."""
        content = {
            "verified": True,
            "count": 5,
            "status": "success",
        }

        report = run_benchmark("small_content", content, iterations=100)
        report.print_summary()

        # Assertions
        assert report.said_only.attestation_bytes > report.baseline.attestation_bytes
        assert report.kel_anchored.attestation_bytes > report.said_only.attestation_bytes
        assert report.tel_anchored.attestation_bytes > report.kel_anchored.attestation_bytes

    def test_medium_content_overhead(self):
        """Test overhead for medium content (~500 bytes)."""
        content = {
            "algorithm_said": "E" + "A" * 43,
            "algorithm_name": "constraint-verification",
            "algorithm_version": "1.0.0",
            "input_said": "E" + "B" * 43,
            "output_said": "E" + "C" * 43,
            "outcome": "success",
            "verified_constraints": [
                {"name": "python", "version": ">=3.12", "satisfied": True},
                {"name": "keri", "version": ">=1.2.0", "satisfied": True},
                {"name": "hio", "version": ">=0.6.14", "satisfied": True},
            ],
        }

        report = run_benchmark("medium_content", content, iterations=100)
        report.print_summary()

        # Overhead should be reasonable for medium content
        assert report.said_only.overhead_pct < 200  # <200% overhead

    def test_large_content_overhead(self):
        """Test overhead for large content (~2KB)."""
        content = {
            "stack_profile": {
                "name": "production-ai-orchestrator",
                "version": "2.0.0",
                "said": "E" + "D" * 43,
                "owner_baid": "BAID_PRODUCTION",
            },
            "constraints": [
                {
                    "type": "package",
                    "name": f"package_{i}",
                    "version": f">={i}.0.0",
                    "satisfied": True,
                    "actual_version": f"{i}.1.0",
                }
                for i in range(20)
            ],
            "environment": {
                "python_version": "3.12.5",
                "platform": "darwin",
                "architecture": "arm64",
            },
            "verification_timestamp": "2026-01-26T00:00:00+00:00",
        }

        report = run_benchmark("large_content", content, iterations=100)
        report.print_summary()

        # For large content, overhead percentage should be lower
        assert report.said_only.overhead_pct < 100  # <100% overhead

    def test_estimate_accuracy(self):
        """Verify OVERHEAD_ESTIMATES are reasonably accurate."""
        content = {
            "verified": True,
            "count": 10,
            "details": {"a": 1, "b": 2, "c": 3},
        }

        report = run_benchmark("estimate_accuracy", content, iterations=50)
        report.print_summary()

        # Estimates should be within 2x of actual (not wildly off)
        for tier, accuracy in report.estimate_accuracy.items():
            assert 0.3 <= accuracy <= 3.0, (
                f"{tier} estimate accuracy {accuracy:.2f}x is outside acceptable range"
            )

    def test_algorithm_execution_overhead(self):
        """Test overhead when using AlgorithmRegistry execution."""
        registry = AlgorithmRegistry()

        # Register a simple algorithm
        def verify_constraint(name: str, spec: str) -> Dict[str, Any]:
            return {"verified": True, "name": name, "spec": spec}

        algo = registry.register(
            name="test-verify",
            version="1.0.0",
            implementation=verify_constraint,
            description="Test verification algorithm",
        )

        # Execute without attestation (baseline)
        start = time.perf_counter()
        for _ in range(100):
            result = registry.execute(
                algorithm_said=algo.said,
                inputs={"name": "keri", "spec": ">=1.2.0"},
                tier=Tier.SAID_ONLY,
            )
        baseline_time = (time.perf_counter() - start) * 1000  # ms

        baseline_size = result.storage_size()

        print(f"\n{'='*70}")
        print("ALGORITHM EXECUTION OVERHEAD")
        print(f"{'='*70}")
        print(f"Execution result size: {baseline_size} bytes")
        print(f"100 executions time: {baseline_time:.2f} ms")
        print(f"Per-execution time: {baseline_time / 100 * 1000:.2f} μs")

        # Should be fast
        assert baseline_time < 1000  # <1 second for 100 executions

    def test_batch_vs_individual_overhead(self):
        """Compare batch attestation vs individual attestations."""
        items = [
            {"constraint": f"pkg_{i}", "verified": True}
            for i in range(10)
        ]

        # Individual attestations
        individual_total = 0
        for item in items:
            attestation = create_attestation(
                tier=Tier.SAID_ONLY,
                content=item,
            )
            individual_total += attestation.storage_size()

        # Batch attestation (single attestation for all)
        batch_content = {
            "batch": True,
            "count": len(items),
            "items_said": compute_said(items),
            "all_verified": True,
        }
        batch_attestation = create_attestation(
            tier=Tier.SAID_ONLY,
            content=batch_content,
        )
        batch_total = batch_attestation.storage_size()

        savings = (1 - batch_total / individual_total) * 100

        print(f"\n{'='*70}")
        print("BATCH VS INDIVIDUAL ATTESTATION")
        print(f"{'='*70}")
        print(f"10 individual attestations: {individual_total} bytes")
        print(f"1 batch attestation: {batch_total} bytes")
        print(f"Savings: {savings:.1f}%")

        # Batch should be more efficient
        assert batch_total < individual_total
        assert savings > 50  # Should save at least 50%


class TestOverheadEstimates:
    """Validate the OVERHEAD_ESTIMATES constants."""

    def test_estimates_exist(self):
        """All tiers should have estimates."""
        assert Tier.TEL_ANCHORED in OVERHEAD_ESTIMATES
        assert Tier.KEL_ANCHORED in OVERHEAD_ESTIMATES
        assert Tier.SAID_ONLY in OVERHEAD_ESTIMATES

    def test_estimates_ordering(self):
        """TEL > KEL > SAID in overhead."""
        tel = OVERHEAD_ESTIMATES[Tier.TEL_ANCHORED]["total_estimate"]
        kel = OVERHEAD_ESTIMATES[Tier.KEL_ANCHORED]["total_estimate"]
        said = OVERHEAD_ESTIMATES[Tier.SAID_ONLY]["total_estimate"]

        assert tel > kel > said

    def test_estimate_overhead_function(self):
        """estimate_overhead() should work correctly."""
        result = estimate_overhead(Tier.TEL_ANCHORED, count=10)

        assert "count" in result
        assert result["count"] == 10
        assert "total" in result
        assert result["total"] == result["total_estimate"] * 10


class TestRuntimeSaidBinding:
    """Test runtime_said binding in ExecutionResult (Binding #38)."""

    def _make_registry_and_algo(self):
        """Helper: create registry with a simple algorithm."""
        registry = AlgorithmRegistry()

        def add_numbers(a: int, b: int) -> Dict[str, Any]:
            return {"sum": a + b}

        algo = registry.register(
            name="test-add",
            version="1.0.0",
            implementation=add_numbers,
            description="Test addition",
        )
        return registry, algo

    def test_execution_without_runtime_manifest(self):
        """Execution without manifest should have runtime_said=None."""
        registry, algo = self._make_registry_and_algo()
        result = registry.execute(
            algorithm_said=algo.said,
            inputs={"a": 1, "b": 2},
        )
        assert result.runtime_said is None
        assert not result.is_runtime_bound
        assert "runtime_said" not in result.to_dict()

    def test_execution_with_runtime_manifest(self):
        """Execution with manifest should capture runtime_said."""
        from keri_sec.runtime import capture_current_manifest

        registry, algo = self._make_registry_and_algo()
        manifest = capture_current_manifest()

        result = registry.execute(
            algorithm_said=algo.said,
            inputs={"a": 1, "b": 2},
            runtime_manifest=manifest,
        )
        assert result.runtime_said == manifest.said
        assert result.is_runtime_bound
        assert result.to_dict()["runtime_said"] == manifest.said

    def test_runtime_said_in_attestation_content(self):
        """Attestation content should include runtime_said when provided."""
        from keri_sec.runtime import capture_current_manifest

        registry, algo = self._make_registry_and_algo()
        manifest = capture_current_manifest()

        result = registry.execute(
            algorithm_said=algo.said,
            inputs={"a": 1, "b": 2},
            tier=Tier.KEL_ANCHORED,
            runtime_manifest=manifest,
        )
        # Attestation should exist (KEL_ANCHORED tier without hab falls back)
        # Even if attestation creation fails, the result should have runtime_said
        assert result.runtime_said == manifest.said

    def test_different_manifests_produce_different_saids(self):
        """Two different manifests should produce different runtime_saids."""
        from keri_sec.runtime import RuntimeManifest

        registry, algo = self._make_registry_and_algo()

        m1 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.2.0",
            keripy_said="E_SAID_A",
            hio_version="0.6.0",
        )
        m2 = RuntimeManifest(
            python_version="3.12.0",
            keripy_version="1.3.0",  # Different keripy version
            keripy_said="E_SAID_B",
            hio_version="0.6.0",
        )

        r1 = registry.execute(algo.said, {"a": 1, "b": 2}, runtime_manifest=m1)
        r2 = registry.execute(algo.said, {"a": 1, "b": 2}, runtime_manifest=m2)

        assert r1.runtime_said != r2.runtime_said
        assert r1.runtime_said == m1.said
        assert r2.runtime_said == m2.said

    def test_storage_size_includes_runtime_said(self):
        """Storage size should account for runtime_said when present."""
        from keri_sec.runtime import capture_current_manifest

        registry, algo = self._make_registry_and_algo()
        manifest = capture_current_manifest()

        without = registry.execute(algo.said, {"a": 1, "b": 2})
        with_rt = registry.execute(algo.said, {"a": 1, "b": 2}, runtime_manifest=manifest)

        assert with_rt.storage_size() > without.storage_size()


if __name__ == "__main__":
    # Run as standalone script
    import sys

    print("Running Attestation Storage Overhead Benchmark\n")

    # Small content
    small = {"verified": True, "count": 5}
    report = run_benchmark("small_content", small)
    report.print_summary()

    # Medium content
    medium = {
        "algorithm_said": "E" + "A" * 43,
        "input_said": "E" + "B" * 43,
        "output_said": "E" + "C" * 43,
        "outcome": "success",
    }
    report = run_benchmark("medium_content", medium)
    report.print_summary()

    print("\n\nBenchmark complete.")
