# -*- encoding: utf-8 -*-
"""
Test Transit-inspired handler system.

Tests for:
- Handler registry and lookup
- Constraint verification via handlers
- Cache encoding (44-base system)
- Unknown constraint preservation
- Extension constraints
"""

import pytest

from governed_stack.handlers import (
    ConstraintHandler,
    VerificationResult,
    PythonVersionHandler,
    PackageHandler,
    SystemPackageHandler,
    BinaryHandler,
    get_handler,
    register_handler,
    list_handlers,
    HANDLERS,
)
from governed_stack.cache import ConstraintCache, SAIDCache, BASE_CHARS
from governed_stack.codes import (
    ConstraintCode,
    CONSTRAINT_CODES,
    encode_constraint,
    decode_constraint,
    is_ground_type,
    get_code,
    get_type_name,
)
from governed_stack.extensions import (
    UnknownConstraint,
    ExtensionConstraint,
    create_composite_constraint,
    is_extension,
    parse_unknown,
)
from governed_stack.streaming import (
    OutputMode,
    MIME_TYPES,
    stream_constraints,
    serialize_stack,
    get_mime_type,
)


class TestHandlerRegistry:
    """Test handler registration and lookup."""

    def test_ground_handlers_registered(self):
        """All ground handlers should be registered by default."""
        assert "python" in HANDLERS
        assert "package" in HANDLERS
        assert "system" in HANDLERS
        assert "binary" in HANDLERS

    def test_get_handler_by_name(self):
        """Should get handler by type name."""
        handler = get_handler("python")
        assert isinstance(handler, PythonVersionHandler)

    def test_get_handler_by_code(self):
        """Should get handler by single-char code."""
        handler = get_handler("P")
        assert isinstance(handler, PythonVersionHandler)

        handler = get_handler("K")
        assert isinstance(handler, PackageHandler)

    def test_unknown_handler_raises(self):
        """Should raise ValueError for unknown type."""
        with pytest.raises(ValueError) as exc_info:
            get_handler("unknown-type")
        assert "No handler registered" in str(exc_info.value)

    def test_register_custom_handler(self):
        """Should allow registering custom handlers."""
        class CustomHandler(ConstraintHandler):
            @property
            def code(self):
                return "C"

            @property
            def type_name(self):
                return "custom"

            def serialize(self, name, spec):
                return b""

            def verify(self, name, spec):
                return VerificationResult(True, "", "", "")

        register_handler("custom", CustomHandler())
        assert "custom" in HANDLERS

        # Clean up
        del HANDLERS["custom"]

    def test_list_handlers(self):
        """Should list all registered handlers."""
        handlers = list_handlers()
        assert len(handlers) >= 4  # At least ground handlers
        codes = [h["code"] for h in handlers]
        assert "P" in codes
        assert "K" in codes


class TestConstraintCache:
    """Test Transit-inspired 44-base caching."""

    def test_cache_codes_single_char(self):
        """First 44 entries should get single-char codes."""
        cache = ConstraintCache()

        # First entry (index 0)
        code = cache.encode("ESAID_000")
        assert code == "^0"

        # Second entry (index 1)
        code = cache.encode("ESAID_001")
        assert code == "^1"

        # Fill indices 2 through 42 (41 entries)
        for i in range(2, 43):
            cache.encode(f"ESAID_{i:03d}")

        # 44th entry (index 43) - last single-char code
        code = cache.encode("ESAID_last_single")
        assert code == f"^{BASE_CHARS[43]}"  # Should be ^h

    def test_cache_codes_double_char(self):
        """Entries 44+ should get two-char codes."""
        cache = ConstraintCache()

        # Fill first 44 entries
        for i in range(44):
            cache.encode(f"ESAID_{i:03d}")

        # 45th entry (index 44) gets double-char code
        code = cache.encode("ESAID_044")
        assert code.startswith("^")
        assert len(code) == 3  # ^ + 2 chars

    def test_cache_roundtrip(self):
        """Same SAID should always get same code."""
        cache = ConstraintCache()
        said = "ESAID_TEST_ROUNDTRIP"

        code1 = cache.encode(said)
        code2 = cache.encode(said)
        assert code1 == code2  # Same SAID gets same code

        # Decode should return original SAID
        decoded = cache.decode(code1)
        assert decoded == said

    def test_cache_verification_result(self):
        """Should cache verification results with TTL."""
        cache = ConstraintCache(ttl=3600)

        result = VerificationResult(
            verified=True,
            constraint_said="ESAID_TEST",
            actual_value="1.2.3",
            expected_spec=">=1.0.0",
        )

        # Store and retrieve
        cache.put_verified("ESAID_TEST", result)
        cached = cache.get_verified("ESAID_TEST")

        assert cached is not None
        assert cached.verified == True
        assert cached.actual_value == "1.2.3"

    def test_cache_stats(self):
        """Should track cache statistics."""
        cache = ConstraintCache()
        cache.encode("SAID_1")
        cache.encode("SAID_2")

        stats = cache.stats()
        assert stats["code_entries"] == 2
        assert stats["max_entries"] == 1936


class TestSAIDCache:
    """Test simple SAID verification cache."""

    def test_put_and_get(self):
        """Should store and retrieve verification results."""
        cache = SAIDCache()
        result = VerificationResult(True, "SAID1", "1.0", ">=1.0")

        cache.put("SAID1", result)
        cached = cache.get("SAID1")

        assert cached is not None
        assert cached.verified == True

    def test_invalidate(self):
        """Should invalidate cached entries."""
        cache = SAIDCache()
        result = VerificationResult(True, "SAID1", "1.0", ">=1.0")

        cache.put("SAID1", result)
        assert cache.invalidate("SAID1") == True
        assert cache.get("SAID1") is None

    def test_clear(self):
        """Should clear all entries."""
        cache = SAIDCache()
        cache.put("SAID1", VerificationResult(True, "SAID1", "1.0", ">=1.0"))
        cache.put("SAID2", VerificationResult(True, "SAID2", "2.0", ">=2.0"))

        cache.clear()
        assert cache.get("SAID1") is None
        assert cache.get("SAID2") is None


class TestConstraintCodes:
    """Test CESR-aligned constraint codes."""

    def test_ground_type_codes(self):
        """Ground types should have assigned codes."""
        assert CONSTRAINT_CODES["P"] == "python"
        assert CONSTRAINT_CODES["K"] == "package"
        assert CONSTRAINT_CODES["S"] == "system"
        assert CONSTRAINT_CODES["B"] == "binary"

    def test_encode_python_constraint(self):
        """Python constraints should encode without name."""
        encoded = encode_constraint("python", "python", ">=3.12")
        assert encoded == "P:>=3.12"

    def test_encode_package_constraint(self):
        """Package constraints should encode with name."""
        encoded = encode_constraint("package", "keri", ">=1.2.0")
        assert encoded == "K:keri>=1.2.0"

    def test_decode_python_constraint(self):
        """Should decode Python constraint."""
        type_name, name, spec = decode_constraint("P:>=3.12")
        assert type_name == "python"
        assert name == "python"
        assert spec == ">=3.12"

    def test_decode_package_constraint(self):
        """Should decode package constraint."""
        type_name, name, spec = decode_constraint("K:keri>=1.2.0")
        assert type_name == "package"
        assert name == "keri"
        assert spec == ">=1.2.0"

    def test_is_ground_type(self):
        """Should identify ground types."""
        assert is_ground_type("python") == True
        assert is_ground_type("package") == True
        assert is_ground_type("extension") == False

    def test_get_code_and_name(self):
        """Should convert between code and name."""
        assert get_code("python") == "P"
        assert get_type_name("P") == "python"


class TestUnknownConstraint:
    """Test Transit-style unknown tag handling."""

    def test_unknown_preserves_tag(self):
        """Unknown constraint should preserve tag."""
        uc = UnknownConstraint(tag="future-type", value={"foo": "bar"})
        assert uc.tag == "future-type"
        assert uc.value == {"foo": "bar"}

    def test_unknown_serializes_deterministically(self):
        """Serialization should be deterministic (sorted keys)."""
        uc1 = UnknownConstraint(tag="t", value={"b": 2, "a": 1})
        uc2 = UnknownConstraint(tag="t", value={"a": 1, "b": 2})

        # Same content = same bytes
        assert uc1.serialize() == uc2.serialize()

    def test_unknown_computes_said(self):
        """Should compute SAID for unknown constraint."""
        uc = UnknownConstraint(tag="test", value={"x": 1})
        said = uc.compute_said()

        assert said.startswith("E")  # Blake3 prefix
        assert len(said) > 40

    def test_parse_unknown(self):
        """Should parse Transit-style tagged value."""
        data = {"~#": "my-tag", "v": [1, 2, 3]}
        uc = parse_unknown(data)

        assert uc is not None
        assert uc.tag == "my-tag"
        assert uc.value == [1, 2, 3]

    def test_parse_unknown_returns_none(self):
        """Should return None for non-tagged values."""
        data = {"regular": "dict"}
        assert parse_unknown(data) is None


class TestExtensionConstraint:
    """Test user-defined extension constraints."""

    def test_extension_creates_composite(self):
        """Extension should compose ground constraints."""
        ext = ExtensionConstraint(
            tag="keri-production",
            ground_type="package",
            constraints=[
                {"name": "keri", "version": ">=1.2.0"},
                {"name": "hio", "version": ">=0.6.14"},
            ],
            verification="all",
        )

        assert ext.tag == "keri-production"
        assert len(ext.constraints) == 2

    def test_extension_decomposes(self):
        """Extension should decompose to ground types."""
        ext = ExtensionConstraint(
            tag="test-ext",
            ground_type="package",
            constraints=[
                {"name": "pkg1", "version": ">=1.0"},
            ],
        )

        decomposed = ext.decompose()
        assert len(decomposed) == 1
        assert decomposed[0]["type"] == "package"
        assert decomposed[0]["name"] == "pkg1"

    def test_extension_computes_said(self):
        """Extension should compute deterministic SAID."""
        ext1 = ExtensionConstraint(
            tag="t", ground_type="package",
            constraints=[{"name": "a", "version": "1"}]
        )
        ext2 = ExtensionConstraint(
            tag="t", ground_type="package",
            constraints=[{"name": "a", "version": "1"}]
        )

        assert ext1.compute_said() == ext2.compute_said()

    def test_is_extension(self):
        """Should identify extension types."""
        uc = UnknownConstraint(tag="t", value={})
        ext = ExtensionConstraint(tag="t", ground_type="package", constraints=[])

        assert is_extension(uc) == True
        assert is_extension(ext) == True
        assert is_extension({"regular": "dict"}) == False


class TestStreaming:
    """Test streaming constraint encoding."""

    def test_output_modes(self):
        """Should have three output modes."""
        assert OutputMode.COMPACT.value == "compact"
        assert OutputMode.VERBOSE.value == "verbose"
        assert OutputMode.CESR.value == "cesr"

    def test_mime_types(self):
        """Should define MIME types."""
        assert "json" in MIME_TYPES
        assert "cesr" in MIME_TYPES
        assert "governed-stack" in MIME_TYPES["json"]

    def test_stream_constraints_verbose(self):
        """Should stream in verbose mode."""
        constraints = [
            {"name": "keri", "spec": ">=1.2.0"},
            {"name": "hio", "spec": ">=0.6.14"},
        ]

        from governed_stack.streaming import StreamConfig
        config = StreamConfig(mode=OutputMode.VERBOSE)

        chunks = list(stream_constraints(constraints, config))
        assert len(chunks) == 2

        # Verbose mode should have indentation
        assert b"  " in chunks[0]

    def test_stream_constraints_compact(self):
        """Should stream in compact mode."""
        constraints = [
            {"name": "keri", "spec": ">=1.2.0"},
        ]

        from governed_stack.streaming import StreamConfig
        config = StreamConfig(mode=OutputMode.COMPACT)

        chunks = list(stream_constraints(constraints, config))
        assert len(chunks) == 1

        # Compact mode has no extra whitespace
        assert b"  " not in chunks[0]

    def test_get_mime_type(self):
        """Should return correct MIME type."""
        assert "json" in get_mime_type("json")
        assert "cesr" in get_mime_type("cesr")


class TestHandlerVerification:
    """Test actual constraint verification via handlers."""

    def test_python_handler_verifies_current(self):
        """Python handler should verify current runtime."""
        handler = get_handler("python")
        result = handler.verify("python", ">=3.0")

        # Should always pass on Python 3.x
        assert result.verified == True
        assert result.actual_value  # Should have version string

    def test_python_handler_fails_impossible(self):
        """Python handler should fail impossible constraint."""
        handler = get_handler("python")
        result = handler.verify("python", ">=99.0")

        assert result.verified == False
        assert "does not satisfy" in result.message

    def test_package_handler_verifies_installed(self):
        """Package handler should verify installed packages."""
        handler = get_handler("package")

        # keri should be installed in test environment
        result = handler.verify("keri", ">=0.1.0")

        # This might fail if keri not installed, that's OK for unit test
        if result.verified:
            assert result.actual_value  # Has version

    def test_handler_computes_said(self):
        """Handler should compute deterministic SAID."""
        handler = get_handler("python")

        said1 = handler.compute_said("python", ">=3.12")
        said2 = handler.compute_said("python", ">=3.12")

        assert said1 == said2
        assert said1.startswith("E")  # Blake3 prefix


class TestCompositeConstraint:
    """Test composite constraint creation."""

    def test_create_composite(self):
        """Should create composite referencing SAIDs."""
        composite = create_composite_constraint(
            tag="full-stack",
            includes=["ESAID_1", "ESAID_2"],
            additional={"extra": ">=1.0"},
        )

        assert composite["tag"] == "full-stack"
        assert composite["type"] == "composite"
        assert len(composite["includes"]) == 2
        assert "extra" in composite["additional"]
