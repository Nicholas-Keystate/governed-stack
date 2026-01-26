# -*- encoding: utf-8 -*-
"""
SAID Caching - Transit-inspired 44-base encoding.

Transit uses a caching mechanism for repeated keys/symbols to reduce
message size. This module implements a similar pattern for constraint SAIDs.

Credit: Transit format by Cognitect (Rich Hickey et al.)
        https://github.com/cognitect/transit-format

The 44-base system:
- First 44 entries: ^0 through ^Z (single char after ^)
- Entries 44-1935: ^00 through ^zz (two char after ^)
- Formula: hi = index / 44; lo = index % 44; char_value = ascii_code + 48

This provides compact encoding for frequently-referenced SAIDs while
maintaining deterministic encoding/decoding.
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from governed_stack.handlers import VerificationResult


# Base for 44-character encoding (0-9, A-Z, a-z minus some)
# Transit uses digits + uppercase + lowercase = ~62 chars, we use 44
BASE_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
assert len(BASE_CHARS) == 44, f"Expected 44 chars, got {len(BASE_CHARS)}"


@dataclass
class CacheEntry:
    """Entry in the verification cache."""
    said: str
    result: VerificationResult
    timestamp: float
    hits: int = 0


class ConstraintCache:
    """
    Transit-inspired 44-base cache for constraint SAIDs.

    This cache provides two capabilities:
    1. Compact encoding for repeated SAIDs (write optimization)
    2. Verification result caching (read optimization)

    The 44-base encoding:
    - First 44 entries: ^0 through ^h (single char)
    - Entries 44-1935: ^00 through ^hh (two char)
    - Maximum 1936 entries (44 + 44*44)

    Synchronized write/read counters ensure deterministic encoding.
    When capacity is reached, cache wraps around.
    """

    MAX_ENTRIES = 1936  # 44 + 44*44

    def __init__(self, ttl: int = 3600):
        """
        Initialize cache.

        Args:
            ttl: Time-to-live in seconds for verification results (default: 1 hour)
        """
        self._ttl = ttl

        # SAID → cache code mapping
        self._said_to_code: Dict[str, str] = {}

        # Cache code → SAID mapping (for decoding)
        self._code_to_said: Dict[str, str] = {}

        # Index tracking for code assignment
        self._counter = 0

        # Verification result cache: SAID → CacheEntry
        self._results: Dict[str, CacheEntry] = {}

    def encode(self, said: str) -> str:
        """
        Return cache code for SAID, registering if new.

        Transit pattern: First occurrence returns full SAID,
        subsequent occurrences can use cached code.

        Args:
            said: Full SAID to encode

        Returns:
            Cache code (e.g., '^0', '^A', '^0a')
        """
        if said in self._said_to_code:
            return self._said_to_code[said]

        # Wrap around if at capacity
        if self._counter >= self.MAX_ENTRIES:
            self._counter = 0
            self._said_to_code.clear()
            self._code_to_said.clear()

        code = self._index_to_code(self._counter)
        self._said_to_code[said] = code
        self._code_to_said[code] = said
        self._counter += 1

        return code

    def decode(self, code: str) -> Optional[str]:
        """
        Decode cache code to full SAID.

        Args:
            code: Cache code (e.g., '^0', '^A')

        Returns:
            Full SAID if cached, None otherwise
        """
        return self._code_to_said.get(code)

    def _index_to_code(self, idx: int) -> str:
        """
        Convert index to cache code.

        Args:
            idx: Index (0 to MAX_ENTRIES-1)

        Returns:
            Cache code string
        """
        if idx < 44:
            # Single character: ^0 through ^h
            return f"^{BASE_CHARS[idx]}"
        else:
            # Two characters: ^00 through ^hh
            hi = (idx - 44) // 44
            lo = (idx - 44) % 44
            return f"^{BASE_CHARS[hi]}{BASE_CHARS[lo]}"

    def _code_to_index(self, code: str) -> int:
        """
        Convert cache code to index.

        Args:
            code: Cache code (must start with ^)

        Returns:
            Index value
        """
        if not code.startswith("^"):
            raise ValueError(f"Invalid cache code: {code}")

        chars = code[1:]  # Remove ^

        if len(chars) == 1:
            return BASE_CHARS.index(chars)
        elif len(chars) == 2:
            hi = BASE_CHARS.index(chars[0])
            lo = BASE_CHARS.index(chars[1])
            return 44 + hi * 44 + lo
        else:
            raise ValueError(f"Invalid cache code length: {code}")

    # =========================================================================
    # Verification Result Caching
    # =========================================================================

    def get_verified(self, said: str) -> Optional[VerificationResult]:
        """
        Return cached verification result if still valid.

        Args:
            said: Constraint SAID to look up

        Returns:
            Cached VerificationResult if valid, None otherwise
        """
        entry = self._results.get(said)
        if entry is None:
            return None

        # Check TTL
        if time.time() - entry.timestamp > self._ttl:
            del self._results[said]
            return None

        entry.hits += 1
        return entry.result

    def put_verified(self, said: str, result: VerificationResult) -> None:
        """
        Cache verification result.

        Args:
            said: Constraint SAID
            result: Verification result to cache
        """
        self._results[said] = CacheEntry(
            said=said,
            result=result,
            timestamp=time.time(),
            hits=0,
        )

    def invalidate(self, said: str) -> bool:
        """
        Invalidate cached result for a SAID.

        Args:
            said: SAID to invalidate

        Returns:
            True if entry was removed, False if not found
        """
        if said in self._results:
            del self._results[said]
            return True
        return False

    def clear(self) -> None:
        """Clear all caches."""
        self._said_to_code.clear()
        self._code_to_said.clear()
        self._results.clear()
        self._counter = 0

    def stats(self) -> Dict:
        """
        Return cache statistics.

        Returns:
            Dict with cache metrics
        """
        total_hits = sum(e.hits for e in self._results.values())
        return {
            "code_entries": len(self._said_to_code),
            "result_entries": len(self._results),
            "total_hits": total_hits,
            "counter": self._counter,
            "max_entries": self.MAX_ENTRIES,
            "ttl_seconds": self._ttl,
        }


class SAIDCache:
    """
    Simple SAID verification cache.

    A streamlined version of ConstraintCache focused only on
    verification result caching (no 44-base encoding).
    """

    def __init__(self, ttl: int = 3600):
        """
        Initialize cache.

        Args:
            ttl: Time-to-live in seconds (default: 1 hour)
        """
        self._cache: Dict[str, CacheEntry] = {}
        self._ttl = ttl

    def get(self, said: str) -> Optional[VerificationResult]:
        """Get cached result if valid."""
        entry = self._cache.get(said)
        if entry is None:
            return None

        if time.time() - entry.timestamp > self._ttl:
            del self._cache[said]
            return None

        entry.hits += 1
        return entry.result

    def put(self, said: str, result: VerificationResult) -> None:
        """Cache verification result."""
        self._cache[said] = CacheEntry(
            said=said,
            result=result,
            timestamp=time.time(),
            hits=0,
        )

    def invalidate(self, said: str) -> bool:
        """Invalidate cached entry."""
        if said in self._cache:
            del self._cache[said]
            return True
        return False

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()

    def stats(self) -> Dict:
        """Return cache statistics."""
        total_hits = sum(e.hits for e in self._cache.values())
        return {
            "entries": len(self._cache),
            "total_hits": total_hits,
            "ttl_seconds": self._ttl,
        }
