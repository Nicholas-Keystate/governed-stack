# -*- encoding: utf-8 -*-
"""Tests for Package DAID - Supply Chain Security."""

import pytest
import tempfile
from pathlib import Path

from keri_sec.packages import (
    PackageDAID,
    PackageDAIDRegistry,
    PackageStatus,
    PackageVersion,
    VerificationResult,
    get_package_daid_registry,
    reset_package_daid_registry,
)


class TestPackageDAIDRegistry:
    """Test Package DAID registration and resolution."""

    def setup_method(self):
        """Reset registry before each test."""
        reset_package_daid_registry()

    def test_register_package(self):
        """Register a package creates DAID."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(
            name="mypackage",
            publisher_aid="EPUBLISHER_AID_PREFIX",
        )

        assert pkg.daid is not None
        assert pkg.daid.startswith("E")  # SAID prefix
        assert pkg.name == "mypackage"
        assert pkg.publisher_aid == "EPUBLISHER_AID_PREFIX"
        assert pkg.status == PackageStatus.ACTIVE

    def test_register_with_pypi_name(self):
        """Register with different PyPI name."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(
            name="my-package",
            publisher_aid="EPUB...",
            pypi_name="my_package",  # PyPI normalizes names
        )

        assert pkg.name == "my-package"
        assert pkg.pypi_name == "my_package"

    def test_resolve_by_daid(self):
        """Resolve package by DAID."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="test", publisher_aid="EPUB...")
        resolved = registry.resolve(pkg.daid)

        assert resolved is not None
        assert resolved.daid == pkg.daid

    def test_resolve_by_daid_prefix(self):
        """Resolve package by DAID prefix."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="test", publisher_aid="EPUB...")
        resolved = registry.resolve(pkg.daid[:10])  # Short prefix

        assert resolved is not None
        assert resolved.daid == pkg.daid

    def test_resolve_by_name(self):
        """Resolve package by name."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="keri", publisher_aid="EPUB...")
        resolved = registry.resolve("keri")

        assert resolved is not None
        assert resolved.name == "keri"

    def test_resolve_by_pypi_name(self):
        """Resolve package by PyPI name."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(
            name="my-package",
            publisher_aid="EPUB...",
            pypi_name="my_package",
        )
        resolved = registry.resolve("my_package")

        assert resolved is not None
        assert resolved.name == "my-package"

    def test_resolve_unknown_returns_none(self):
        """Resolving unknown package returns None."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))
        resolved = registry.resolve("nonexistent")
        assert resolved is None


class TestPackageVersions:
    """Test package version management."""

    def setup_method(self):
        reset_package_daid_registry()

    def test_add_version(self):
        """Add version to package."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="test", publisher_aid="EPUB...")
        ver = registry.add_version(
            daid=pkg.daid,
            version="1.0.0",
            source_said="ESOURCE_SAID_12345678901234567890",
        )

        assert ver.version == "1.0.0"
        assert ver.source_said == "ESOURCE_SAID_12345678901234567890"

        # Check package was updated
        pkg = registry.resolve("test")
        assert pkg.current_version is not None
        assert pkg.current_version.version == "1.0.0"

    def test_add_version_with_wheels(self):
        """Add version with wheel SAIDs."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="test", publisher_aid="EPUB...")
        registry.add_version(
            daid=pkg.daid,
            version="1.0.0",
            source_said="ESOURCE...",
            wheel_saids={
                "py3": "EWHEEL_PY3...",
                "cp312-macos": "EWHEEL_CP312_MACOS...",
            },
        )

        pkg = registry.resolve("test")
        ver = pkg.get_version("1.0.0")

        assert ver.get_wheel_said("py3") == "EWHEEL_PY3..."
        assert ver.get_wheel_said("cp312-macos") == "EWHEEL_CP312_MACOS..."

    def test_get_version_said(self):
        """Get SAID for specific version."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="test", publisher_aid="EPUB...")
        registry.add_version(
            daid=pkg.daid,
            version="1.0.0",
            source_said="ESOURCE_V1...",
        )
        registry.add_version(
            daid=pkg.daid,
            version="2.0.0",
            source_said="ESOURCE_V2...",
        )

        pkg = registry.resolve("test")

        assert pkg.get_version_said("1.0.0") == "ESOURCE_V1..."
        assert pkg.get_version_said("2.0.0") == "ESOURCE_V2..."
        assert pkg.get_version_said("3.0.0") is None  # Doesn't exist

    def test_multiple_versions_updates_current(self):
        """Adding versions updates current version."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="test", publisher_aid="EPUB...")
        registry.add_version(daid=pkg.daid, version="1.0.0", source_said="EV1...")
        registry.add_version(daid=pkg.daid, version="2.0.0", source_said="EV2...")

        pkg = registry.resolve("test")
        assert pkg.current_version.version == "2.0.0"


class TestPackageVerification:
    """Test package content verification."""

    def setup_method(self):
        reset_package_daid_registry()

    def test_verify_matching_said(self):
        """Verify succeeds when SAIDs match."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="test", publisher_aid="EPUB...")
        registry.add_version(
            daid=pkg.daid,
            version="1.0.0",
            source_said="ESOURCE_EXPECTED_SAID",
        )

        result = registry.verify_package(
            name="test",
            version="1.0.0",
            actual_said="ESOURCE_EXPECTED_SAID",
        )

        assert result.verified is True
        assert result.error is None

    def test_verify_mismatched_said(self):
        """Verify fails when SAIDs don't match."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="test", publisher_aid="EPUB...")
        registry.add_version(
            daid=pkg.daid,
            version="1.0.0",
            source_said="ESOURCE_EXPECTED",
        )

        result = registry.verify_package(
            name="test",
            version="1.0.0",
            actual_said="ESOURCE_DIFFERENT",
        )

        assert result.verified is False
        assert "mismatch" in result.error.lower()

    def test_verify_unknown_package(self):
        """Verify returns warning for unknown package."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        result = registry.verify_package(
            name="unknown",
            version="1.0.0",
            actual_said="ESOURCE...",
        )

        assert result.verified is False
        assert "not in DAID registry" in result.error

    def test_verify_unknown_version(self):
        """Verify fails for unknown version."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="test", publisher_aid="EPUB...")
        registry.add_version(daid=pkg.daid, version="1.0.0", source_said="EV1...")

        result = registry.verify_package(
            name="test",
            version="2.0.0",  # Doesn't exist
            actual_said="ESOURCE...",
        )

        assert result.verified is False
        assert "not found" in result.error.lower()

    def test_verify_deprecated_package_warns(self):
        """Verify warns for deprecated package."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="old-pkg", publisher_aid="EPUB...")
        registry.add_version(daid=pkg.daid, version="1.0.0", source_said="ESOURCE...")
        registry.deprecate(daid=pkg.daid, reason="Use new-pkg instead")

        result = registry.verify_package(
            name="old-pkg",
            version="1.0.0",
            actual_said="ESOURCE...",
        )

        assert result.verified is True  # Still verifies
        assert len(result.warnings) > 0
        assert "deprecated" in result.warnings[0].lower()


class TestPackageDeprecation:
    """Test package deprecation handling."""

    def setup_method(self):
        reset_package_daid_registry()

    def test_deprecate_with_successor(self):
        """Deprecate package with successor."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        old_pkg = registry.register(name="old", publisher_aid="EPUB...")
        new_pkg = registry.register(name="new", publisher_aid="EPUB...")

        registry.deprecate(
            daid=old_pkg.daid,
            reason="Renamed to 'new'",
            successor_daid=new_pkg.daid,
        )

        old_pkg = registry.resolve("old")
        assert old_pkg.status == PackageStatus.DEPRECATED
        assert old_pkg.is_deprecated is True
        assert old_pkg.successor_daid == new_pkg.daid

    def test_mark_hijacked(self):
        """Mark package as hijacked."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="compromised", publisher_aid="EPUB...")
        registry.add_version(daid=pkg.daid, version="1.0.0", source_said="ESAFE...")
        registry.add_version(daid=pkg.daid, version="1.0.1", source_said="EBAD...")

        registry.mark_hijacked(
            daid=pkg.daid,
            reason="Publisher account compromised",
            safe_versions=["1.0.0"],
        )

        pkg = registry.resolve("compromised")
        assert pkg.status == PackageStatus.HIJACKED

        # Safe version not yanked
        v1 = pkg.get_version("1.0.0")
        assert v1.yanked is False

        # Unsafe version yanked
        v2 = pkg.get_version("1.0.1")
        assert v2.yanked is True


class TestPackageYanking:
    """Test version yanking."""

    def setup_method(self):
        reset_package_daid_registry()

    def test_yank_version(self):
        """Yank a specific version."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(name="test", publisher_aid="EPUB...")
        registry.add_version(daid=pkg.daid, version="1.0.0", source_said="ESOURCE...")

        registry.yank_version(
            daid=pkg.daid,
            version="1.0.0",
            reason="Security vulnerability",
        )

        pkg = registry.resolve("test")
        ver = pkg.get_version("1.0.0")
        assert ver.yanked is True
        assert ver.yank_reason == "Security vulnerability"


class TestPackagePersistence:
    """Test package persistence to disk."""

    def test_packages_persist(self):
        """Packages persist across registry instances."""
        base_path = Path(tempfile.mkdtemp())

        # First registry instance
        registry1 = PackageDAIDRegistry(base_path=base_path)
        pkg = registry1.register(name="persistent", publisher_aid="EPUB...")
        registry1.add_version(daid=pkg.daid, version="1.0.0", source_said="ESOURCE...")
        daid = pkg.daid

        # Second registry instance (loads from disk)
        registry2 = PackageDAIDRegistry(base_path=base_path)
        loaded = registry2.resolve("persistent")

        assert loaded is not None
        assert loaded.daid == daid
        assert loaded.current_version.version == "1.0.0"


class TestPackageDAIDSerialization:
    """Test PackageDAID serialization."""

    def test_to_dict(self):
        """to_dict produces expected structure."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        pkg = registry.register(
            name="test",
            publisher_aid="EPUB...",
            repository_url="https://github.com/test/test",
        )
        registry.add_version(daid=pkg.daid, version="1.0.0", source_said="ESOURCE...")

        pkg = registry.resolve("test")
        data = pkg.to_dict()

        assert data["name"] == "test"
        assert data["publisher_aid"] == "EPUB..."
        assert data["repository_url"] == "https://github.com/test/test"
        assert data["version_count"] == 1
        assert data["current_version"] == "1.0.0"


class TestListAndFilter:
    """Test listing and filtering packages."""

    def setup_method(self):
        reset_package_daid_registry()

    def test_list_all_packages(self):
        """List all packages."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        registry.register(name="pkg1", publisher_aid="EPUB1...")
        registry.register(name="pkg2", publisher_aid="EPUB2...")

        packages = registry.list_packages()
        assert len(packages) == 2

    def test_filter_by_status(self):
        """Filter packages by status."""
        registry = PackageDAIDRegistry(base_path=Path(tempfile.mkdtemp()))

        active = registry.register(name="active", publisher_aid="EPUB...")
        deprecated = registry.register(name="deprecated", publisher_aid="EPUB...")
        registry.deprecate(daid=deprecated.daid, reason="Old")

        active_packages = registry.list_packages(status=PackageStatus.ACTIVE)
        assert len(active_packages) == 1
        assert active_packages[0].name == "active"

        deprecated_packages = registry.list_packages(status=PackageStatus.DEPRECATED)
        assert len(deprecated_packages) == 1
        assert deprecated_packages[0].name == "deprecated"
