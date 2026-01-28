# -*- encoding: utf-8 -*-
"""
Permission Parser - Semantic analysis of Claude Code permission entries.

Parses settings.local.json permission entries, categorizes them, detects
redundancy, shell fragments, and overly broad wildcards. Suggests
consolidation to reduce permission bloat.

Classification:
    - Authorization-class: Security-meaningful (git push, pip install, kill)
    - Convenience-class: UX-only (ls, cat, grep, git status)

KERI integration: Each normalized entry gets a SAID for content-addressable
tracking. Permission changes are detectable via SAID drift.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class PermissionCategory(str, Enum):
    """Category of a permission entry."""
    CLEAN = "clean"
    WILDCARD_BROAD = "wildcard_broad"
    FRAGMENT = "fragment"
    REDUNDANT = "redundant"
    ENV_MIXED = "env_mixed"
    ONE_TIME = "one_time"
    DANGEROUS = "dangerous"
    MCP = "mcp"
    WEBFETCH = "webfetch"
    JUNK = "junk"


class PermissionClass(str, Enum):
    """Security classification."""
    AUTHORIZATION = "authorization"
    CONVENIENCE = "convenience"


class PatternType(str, Enum):
    """How the pattern matches."""
    PREFIX = "prefix"       # Bash(cmd:*) - matches cmd with any args
    GLOB = "glob"           # Bash(cmd *) - matches cmd with glob
    EXACT = "exact"         # Bash(cmd arg arg) - exact match only


@dataclass
class PermissionEntry:
    """Parsed and analyzed permission entry."""
    raw: str
    tool_type: str                              # Bash, WebFetch, mcp, WebSearch
    pattern: str                                # Extracted pattern (command/domain/tool)
    category: PermissionCategory = PermissionCategory.CLEAN
    permission_class: PermissionClass = PermissionClass.CONVENIENCE
    pattern_type: PatternType = PatternType.EXACT
    env_vars: list[str] = field(default_factory=list)
    base_command: str = ""                      # Command without env vars or paths
    subsumes: list[str] = field(default_factory=list)
    subsumed_by: list[str] = field(default_factory=list)
    said: str = ""

    def __post_init__(self):
        if not self.said:
            self.said = self._compute_said()

    def _compute_said(self) -> str:
        """Compute SAID of normalized entry."""
        try:
            from keri.core.coring import Saider
            content = json.dumps({
                "tool_type": self.tool_type,
                "pattern": self.pattern,
                "pattern_type": self.pattern_type.value,
            }, sort_keys=True).encode()
            return Saider(raw=content).qb64
        except (ImportError, Exception):
            # Fallback: use hashlib if keri not available
            import hashlib
            content = json.dumps({
                "tool_type": self.tool_type,
                "pattern": self.pattern,
                "pattern_type": self.pattern_type.value,
            }, sort_keys=True).encode()
            return f"E{hashlib.blake2b(content, digest_size=32).hexdigest()}"


@dataclass
class ConsolidationSuggestion:
    """A suggested consolidation of permission entries."""
    entries: list[PermissionEntry]
    replacement: str
    rationale: str
    category: str  # "redundant", "fragment", "tighten", "remove"


@dataclass
class PermissionAnalysis:
    """Full analysis of a permission settings file."""
    entries: list[PermissionEntry]
    total: int = 0
    by_category: dict[str, int] = field(default_factory=dict)
    by_tool: dict[str, int] = field(default_factory=dict)
    by_class: dict[str, int] = field(default_factory=dict)
    fragments: list[list[PermissionEntry]] = field(default_factory=list)
    redundancy_groups: list[list[PermissionEntry]] = field(default_factory=list)
    suggestions: list[ConsolidationSuggestion] = field(default_factory=list)
    settings_said: str = ""

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            f"Permission Analysis: {self.total} entries",
            f"  Settings SAID: {self.settings_said[:30]}..." if self.settings_said else "",
            "",
            "  By category:",
        ]
        for cat, count in sorted(self.by_category.items()):
            pct = (count / self.total * 100) if self.total else 0
            lines.append(f"    {cat}: {count} ({pct:.0f}%)")
        lines.append("")
        lines.append("  By tool:")
        for tool, count in sorted(self.by_tool.items()):
            lines.append(f"    {tool}: {count}")
        lines.append("")
        lines.append("  By security class:")
        for cls, count in sorted(self.by_class.items()):
            lines.append(f"    {cls}: {count}")
        if self.fragments:
            lines.append(f"\n  Shell fragments detected: {len(self.fragments)} groups")
        if self.redundancy_groups:
            lines.append(f"  Redundancy groups: {len(self.redundancy_groups)}")
        if self.suggestions:
            lines.append(f"  Consolidation suggestions: {len(self.suggestions)}")
        return "\n".join(lines)


class PermissionPolicy:
    """Policy rules for permission hygiene."""

    def __init__(
        self,
        max_entries: int = 50,
        warn_entries: int = 40,
        no_bare_wildcards: bool = True,
        dangerous_patterns: Optional[set[str]] = None,
        authorization_commands: Optional[set[str]] = None,
    ):
        self.max_entries = max_entries
        self.warn_entries = warn_entries
        self.no_bare_wildcards = no_bare_wildcards
        self.dangerous_patterns = dangerous_patterns or {
            "kill", "rm -rf", "chmod 777", "rm -r /",
            "git push --force", "git reset --hard",
        }
        self.authorization_commands = authorization_commands or {
            # Repository mutations
            "git commit", "git push", "git reset", "git checkout",
            "git rebase", "git merge",
            # Package installation
            "pip install", "uv pip install", ".venv/bin/pip install",
            "brew install",
            # System operations
            "kill", "chmod", "codesign", "launchctl",
            "swiftc", "xattr",
            # GitHub operations
            "gh repo create", "gh release create", "gh pr create",
            # Network
            "curl",
            # Source execution
            "source",
        }

    def check(self, analysis: PermissionAnalysis) -> list[str]:
        """Check analysis against policy. Returns list of violations."""
        violations = []
        if analysis.total > self.max_entries:
            violations.append(
                f"Exceeds max entries: {analysis.total} > {self.max_entries}"
            )
        elif analysis.total > self.warn_entries:
            violations.append(
                f"Approaching max entries: {analysis.total} / {self.max_entries}"
            )
        junk = analysis.by_category.get("junk", 0)
        if junk > 0:
            violations.append(f"Junk entries present: {junk}")
        fragments = analysis.by_category.get("fragment", 0)
        if fragments > 0:
            violations.append(f"Shell fragments present: {fragments}")
        dangerous = analysis.by_category.get("dangerous", 0)
        if dangerous > 0:
            violations.append(f"Dangerous patterns present: {dangerous}")
        return violations


# Shell fragment patterns - incomplete shell constructs
_FRAGMENT_PATTERNS = [
    re.compile(r"^(done|fi|do|then|else|esac)$"),
    re.compile(r"^(while|for|if)\s+"),
    re.compile(r"^do\s+(if|echo|for)"),
    re.compile(r"^then\s+echo"),
]

# Broad wildcard commands that need tightening
_BROAD_WILDCARDS = {
    "python", "python3", "source", "kill",
}

# Commands that are authorization-class
_AUTH_COMMANDS = {
    "git commit", "git push", "git reset", "git checkout",
    "git rebase", "git merge", "git init", "git remote",
    "pip install", "uv pip install", "brew install",
    "kill", "chmod", "codesign", "launchctl",
    "swiftc", "xattr", "curl",
    "gh repo create", "gh release create",
    "source",
}


class PermissionParser:
    """Parse and analyze Claude Code permission entries."""

    def __init__(self, policy: Optional[PermissionPolicy] = None):
        self.policy = policy or PermissionPolicy()

    def parse(self, settings_path: Path) -> PermissionAnalysis:
        """Parse settings file and produce full analysis."""
        content = settings_path.read_text()
        data = json.loads(content)

        raw_entries = data.get("permissions", {}).get("allow", [])

        # Compute settings SAID
        settings_said = self._compute_said(content)

        entries = [self._parse_entry(raw) for raw in raw_entries]

        # Detect fragments
        fragments = self.detect_fragments(entries)
        for group in fragments:
            for entry in group:
                entry.category = PermissionCategory.FRAGMENT

        # Detect redundancy (after fragment detection)
        redundancy_groups = self.detect_redundancy(entries)

        # Detect env mixing
        for entry in entries:
            if entry.env_vars and entry.category == PermissionCategory.CLEAN:
                entry.category = PermissionCategory.ENV_MIXED

        # Build analysis
        analysis = PermissionAnalysis(
            entries=entries,
            total=len(entries),
            by_category=self._count_by(entries, lambda e: e.category.value),
            by_tool=self._count_by(entries, lambda e: e.tool_type),
            by_class=self._count_by(entries, lambda e: e.permission_class.value),
            fragments=fragments,
            redundancy_groups=redundancy_groups,
            settings_said=settings_said,
        )

        # Generate suggestions
        analysis.suggestions = self.suggest_consolidation(analysis)

        return analysis

    def parse_entries(self, raw_entries: list[str]) -> list[PermissionEntry]:
        """Parse a list of raw permission strings."""
        return [self._parse_entry(raw) for raw in raw_entries]

    def _parse_entry(self, raw: str) -> PermissionEntry:
        """Parse a single permission entry string."""
        tool_type, pattern, pattern_type = self._extract_tool_and_pattern(raw)
        env_vars = self._extract_env_vars(raw) if tool_type == "Bash" else []
        base_command = self._extract_base_command(pattern) if tool_type == "Bash" else pattern
        category = self._categorize(raw, tool_type, pattern, base_command, env_vars)
        perm_class = self._classify_security(tool_type, base_command)

        return PermissionEntry(
            raw=raw,
            tool_type=tool_type,
            pattern=pattern,
            category=category,
            permission_class=perm_class,
            pattern_type=pattern_type,
            env_vars=env_vars,
            base_command=base_command,
        )

    def _extract_tool_and_pattern(self, raw: str) -> tuple[str, str, PatternType]:
        """Extract tool type, pattern, and pattern type from raw entry."""
        # MCP tools
        if raw.startswith("mcp__"):
            return "mcp", raw, PatternType.EXACT

        # WebSearch (no pattern)
        if raw == "WebSearch":
            return "WebSearch", "", PatternType.EXACT

        # WebFetch(domain:xxx)
        m = re.match(r"WebFetch\(domain:(.+)\)", raw)
        if m:
            return "WebFetch", m.group(1), PatternType.EXACT

        # Bash(cmd:*) - prefix wildcard
        m = re.match(r"Bash\((.+):(\*)\)", raw)
        if m:
            return "Bash", m.group(1), PatternType.PREFIX

        # Bash(cmd *) - glob wildcard (space before *)
        m = re.match(r"Bash\((.+)\s+\*\)", raw)
        if m:
            return "Bash", m.group(1), PatternType.GLOB

        # Bash(exact command) - exact match
        m = re.match(r"Bash\((.+)\)", raw)
        if m:
            return "Bash", m.group(1), PatternType.EXACT

        return "unknown", raw, PatternType.EXACT

    def _extract_env_vars(self, raw: str) -> list[str]:
        """Extract environment variable assignments from a Bash pattern."""
        m = re.match(r"Bash\((.+)\)", raw)
        if not m:
            return []
        content = m.group(1)
        env_vars = []
        # Match FOO=bar or FOO="bar" at start of command
        for match in re.finditer(r'([A-Z_][A-Z0-9_]*)=("[^"]*"|\S+)', content):
            env_vars.append(match.group(1))
        return env_vars

    def _extract_base_command(self, pattern: str) -> str:
        """Extract the base command from a pattern, stripping env vars and paths."""
        cmd = pattern
        # Strip env var assignments
        cmd = re.sub(r'[A-Z_][A-Z0-9_]*=("[^"]*"|\S+)\s+', '', cmd)
        # Normalize absolute paths to relative form
        cmd = re.sub(r'/Users/[^/]+/Documents/KERI/[^/]+/\.venv/bin/', '.venv/bin/', cmd)
        cmd = re.sub(r'/Users/[^/]+/Documents/KERI/[^/]+/', '', cmd)
        cmd = re.sub(r'/opt/homebrew/bin/', '', cmd)
        cmd = re.sub(r'/opt/homebrew/opt/python@[0-9.]+/bin/', '', cmd)
        return cmd.strip()

    def _categorize(
        self, raw: str, tool_type: str, pattern: str,
        base_command: str, env_vars: list[str],
    ) -> PermissionCategory:
        """Categorize a permission entry."""
        if tool_type == "mcp":
            return PermissionCategory.MCP
        if tool_type == "WebFetch":
            return PermissionCategory.WEBFETCH
        if tool_type == "WebSearch":
            return PermissionCategory.CLEAN

        if tool_type != "Bash":
            return PermissionCategory.CLEAN

        # Check for shell fragments (incomplete constructs)
        for frag_re in _FRAGMENT_PATTERNS:
            if frag_re.match(pattern):
                return PermissionCategory.JUNK

        # Check for dangerous patterns
        for dangerous in self.policy.dangerous_patterns:
            if base_command.startswith(dangerous):
                return PermissionCategory.DANGEROUS

        # Check for broad wildcards
        # e.g., Bash(python:*) or Bash(python3:*) without path qualifier
        bare_cmd = base_command.split()[0] if base_command else ""
        if bare_cmd in _BROAD_WILDCARDS and ":" in raw and raw.endswith("*)"):
            return PermissionCategory.WILDCARD_BROAD

        # Check for env var mixing
        if env_vars:
            return PermissionCategory.ENV_MIXED

        # Check for one-time specific commands (very long exact matches)
        if ":" not in raw and "*" not in raw and tool_type == "Bash" and len(pattern) > 80:
            return PermissionCategory.ONE_TIME

        return PermissionCategory.CLEAN

    def _classify_security(self, tool_type: str, base_command: str) -> PermissionClass:
        """Classify whether entry is authorization or convenience."""
        if tool_type in ("mcp", "WebFetch", "WebSearch"):
            return PermissionClass.CONVENIENCE

        # Check against auth commands, also matching path-qualified versions
        # e.g., .venv/bin/pip install should match "pip install"
        for auth_cmd in _AUTH_COMMANDS:
            if base_command.startswith(auth_cmd):
                return PermissionClass.AUTHORIZATION
            # Check if the last path component matches
            parts = base_command.split("/")
            tail = parts[-1] if parts else base_command
            # Rejoin tail with any remaining args
            idx = base_command.find(tail)
            tail_with_args = base_command[idx:] if idx >= 0 else base_command
            if tail_with_args.startswith(auth_cmd):
                return PermissionClass.AUTHORIZATION

        return PermissionClass.CONVENIENCE

    def detect_fragments(self, entries: list[PermissionEntry]) -> list[list[PermissionEntry]]:
        """Detect groups of entries that look like shell loop fragments."""
        fragment_keywords = {"done", "fi", "do", "then", "else", "esac"}
        loop_starters = {"while", "for", "if"}

        fragments: list[PermissionEntry] = []
        for entry in entries:
            if entry.tool_type != "Bash":
                continue
            pat = entry.pattern.strip()
            # Exact match on shell keywords
            if pat in fragment_keywords:
                fragments.append(entry)
                continue
            # Starts with loop/conditional keyword and isn't a real command
            first_word = pat.split()[0] if pat else ""
            if first_word in loop_starters:
                fragments.append(entry)
                continue
            # Pattern like: do if [...], then echo [...]
            if first_word in ("do", "then"):
                fragments.append(entry)
                continue

        if fragments:
            return [fragments]
        return []

    def detect_redundancy(self, entries: list[PermissionEntry]) -> list[list[PermissionEntry]]:
        """Detect groups of entries where one subsumes another."""
        groups: list[list[PermissionEntry]] = []
        bash_entries = [e for e in entries if e.tool_type == "Bash"
                        and e.category not in (PermissionCategory.FRAGMENT, PermissionCategory.JUNK)]

        # Group by base command similarity
        cmd_groups: dict[str, list[PermissionEntry]] = {}
        for entry in bash_entries:
            # Use the full base command (first token, possibly path-qualified)
            # as the grouping key. This catches prefix patterns that subsume exact ones.
            words = entry.base_command.split()
            if not words:
                continue
            # Primary key: first word (the executable)
            key = words[0]
            cmd_groups.setdefault(key, []).append(entry)

        for key, group in cmd_groups.items():
            if len(group) < 2:
                continue

            # Check if any prefix pattern subsumes exact patterns
            prefix_entries = [e for e in group if e.pattern_type == PatternType.PREFIX]
            exact_entries = [e for e in group if e.pattern_type in (PatternType.EXACT, PatternType.GLOB)]

            if prefix_entries and exact_entries:
                # The prefix pattern subsumes the exact ones
                for prefix_entry in prefix_entries:
                    subsumed = []
                    for exact_entry in exact_entries:
                        if exact_entry.base_command.startswith(prefix_entry.base_command):
                            exact_entry.subsumed_by.append(prefix_entry.raw)
                            prefix_entry.subsumes.append(exact_entry.raw)
                            exact_entry.category = PermissionCategory.REDUNDANT
                            subsumed.append(exact_entry)
                    if subsumed:
                        groups.append([prefix_entry] + subsumed)

            # Check for path-variant redundancy (same command, different paths)
            if len(group) >= 2 and not prefix_entries:
                base_cmds = set()
                path_variants = []
                for e in group:
                    bc = e.base_command
                    if bc in base_cmds:
                        path_variants.append(e)
                    base_cmds.add(bc)
                if path_variants:
                    groups.append(group)
                    for e in path_variants:
                        if e.category == PermissionCategory.CLEAN:
                            e.category = PermissionCategory.REDUNDANT

        return groups

    def detect_env_mixed(self, entry: str) -> tuple[str, str]:
        """
        Split a permission entry into env vars and command.

        Returns (env_string, command_string).
        """
        m = re.match(r"Bash\((.+)\)", entry)
        if not m:
            return "", entry
        content = m.group(1)
        env_parts = []
        remaining = content
        while True:
            match = re.match(r'([A-Z_][A-Z0-9_]*=(?:"[^"]*"|\S+))\s+(.*)', remaining)
            if match:
                env_parts.append(match.group(1))
                remaining = match.group(2)
            else:
                break
        return " ".join(env_parts), remaining

    def suggest_consolidation(self, analysis: PermissionAnalysis) -> list[ConsolidationSuggestion]:
        """Generate consolidation suggestions from analysis."""
        suggestions = []

        # 1. Remove junk/fragments
        junk = [e for e in analysis.entries if e.category in (
            PermissionCategory.JUNK, PermissionCategory.FRAGMENT)]
        if junk:
            suggestions.append(ConsolidationSuggestion(
                entries=junk,
                replacement="(remove)",
                rationale=f"Shell fragments and junk entries ({len(junk)} entries)",
                category="remove",
            ))

        # 2. Remove redundant entries
        redundant = [e for e in analysis.entries if e.category == PermissionCategory.REDUNDANT]
        if redundant:
            suggestions.append(ConsolidationSuggestion(
                entries=redundant,
                replacement="(remove - covered by broader patterns)",
                rationale=f"Redundant entries subsumed by prefix patterns ({len(redundant)} entries)",
                category="redundant",
            ))

        # 3. Tighten broad wildcards
        broad = [e for e in analysis.entries if e.category == PermissionCategory.WILDCARD_BROAD]
        for entry in broad:
            if entry.base_command.startswith("python") or entry.base_command.startswith("python3"):
                suggestions.append(ConsolidationSuggestion(
                    entries=[entry],
                    replacement="Bash(.venv/bin/python:*)",
                    rationale=f"Bare '{entry.base_command}' executes ANY python; scope to .venv",
                    category="tighten",
                ))
            elif entry.base_command == "source":
                suggestions.append(ConsolidationSuggestion(
                    entries=[entry],
                    replacement="Bash(source .venv/bin/activate)",
                    rationale="Bare 'source' can source any script; restrict to venv activation",
                    category="tighten",
                ))
            elif entry.base_command == "kill":
                suggestions.append(ConsolidationSuggestion(
                    entries=[entry],
                    replacement="(remove or restrict to specific PIDs)",
                    rationale="Bare 'kill' can terminate any process",
                    category="tighten",
                ))

        # 4. Consolidate env-mixed entries
        env_mixed = [e for e in analysis.entries if e.category == PermissionCategory.ENV_MIXED]
        if len(env_mixed) > 3:
            # Group by the underlying command (without env vars)
            cmd_groups: dict[str, list[PermissionEntry]] = {}
            for e in env_mixed:
                cmd_groups.setdefault(e.base_command, []).append(e)
            for cmd, group in cmd_groups.items():
                if len(group) >= 2:
                    suggestions.append(ConsolidationSuggestion(
                        entries=group,
                        replacement=f"Bash({cmd}:*)",
                        rationale=(
                            f"{len(group)} entries differ only in env vars for '{cmd}'; "
                            "consider single prefix pattern"
                        ),
                        category="redundant",
                    ))

        return suggestions

    def _compute_said(self, content: str) -> str:
        """Compute SAID of settings content."""
        try:
            from keri.core.coring import Saider
            return Saider(raw=content.encode()).qb64
        except (ImportError, Exception):
            import hashlib
            return f"E{hashlib.blake2b(content.encode(), digest_size=32).hexdigest()}"

    @staticmethod
    def _count_by(entries: list[PermissionEntry], key_fn) -> dict[str, int]:
        """Count entries by a key function."""
        counts: dict[str, int] = {}
        for entry in entries:
            k = key_fn(entry)
            counts[k] = counts.get(k, 0) + 1
        return counts

    def generate_clean_permissions(self, analysis: PermissionAnalysis) -> list[str]:
        """Generate a cleaned permission list from analysis."""
        to_remove = set()
        for suggestion in analysis.suggestions:
            if suggestion.category in ("remove", "redundant"):
                for entry in suggestion.entries:
                    to_remove.add(entry.raw)

        # Build replacement map for tighten suggestions
        replacements: dict[str, str] = {}
        for suggestion in analysis.suggestions:
            if suggestion.category == "tighten":
                for entry in suggestion.entries:
                    replacements[entry.raw] = suggestion.replacement

        clean = []
        seen = set()
        for entry in analysis.entries:
            raw = entry.raw
            if raw in to_remove:
                continue
            if raw in replacements:
                replacement = replacements[raw]
                if replacement.startswith("("):
                    # This is a removal suggestion, skip
                    continue
                raw = replacement
            if raw not in seen:
                clean.append(raw)
                seen.add(raw)

        return sorted(clean, key=lambda x: (
            0 if x.startswith("Bash") else 1 if x.startswith("mcp") else 2 if x.startswith("Web") else 3,
            x,
        ))

    def apply_cleanup(self, settings_path: Path, dry_run: bool = True) -> tuple[list[str], list[str]]:
        """
        Apply cleanup to settings file.

        Returns (removed_entries, final_entries).
        If dry_run=True, does not write to disk.
        """
        analysis = self.parse(settings_path)
        clean = self.generate_clean_permissions(analysis)

        removed = [e.raw for e in analysis.entries if e.raw not in clean]

        if not dry_run:
            data = json.loads(settings_path.read_text())
            data["permissions"]["allow"] = clean
            settings_path.write_text(json.dumps(data, indent=2) + "\n")

        return removed, clean
