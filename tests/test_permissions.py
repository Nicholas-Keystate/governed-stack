# -*- encoding: utf-8 -*-
"""
Tests for Permission Parser - semantic analysis of Claude Code permission entries.
"""

import json
import tempfile
from pathlib import Path

import pytest

from keri_sec.permissions import (
    ConsolidationSuggestion,
    PatternType,
    PermissionAnalysis,
    PermissionCategory,
    PermissionClass,
    PermissionEntry,
    PermissionParser,
    PermissionPolicy,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def parser():
    return PermissionParser()


@pytest.fixture
def sample_settings(tmp_path):
    """Create a sample settings file with representative entries."""
    data = {
        "permissions": {
            "allow": [
                # Clean patterns
                "Bash(ls:*)",
                "Bash(git add:*)",
                "Bash(git commit:*)",
                "Bash(.venv/bin/python:*)",
                "Bash(.venv/bin/pip install:*)",
                # MCP
                "mcp__KERI-vLEI-wiki-knowledgebase__keri_search",
                "mcp__smart-context__rlm_process",
                # WebFetch
                "WebFetch(domain:github.com)",
                "WebFetch(domain:arxiv.org)",
                # WebSearch
                "WebSearch",
                # Broad wildcards
                "Bash(python:*)",
                "Bash(python3:*)",
                "Bash(source:*)",
                "Bash(kill:*)",
                # Shell fragments (junk)
                "Bash(done)",
                "Bash(fi)",
                "Bash(while read dir)",
                "Bash(do if [ -f \"$dir/__init__.py\" ])",
                "Bash(then echo \"Package: $dir\")",
                # Env mixed
                "Bash(PYTHONPATH=src .venv/bin/python:*)",
                "Bash(DYLD_LIBRARY_PATH=\"/opt/homebrew/lib:$DYLD_LIBRARY_PATH\" .venv/bin/python:*)",
                # Redundant (subsumed by .venv/bin/python:*)
                "Bash(.venv/bin/python -m pytest tests/test_rlm_sandbox.py tests/test_rlm_agent.py -v --tb=short)",
                # Path variants
                "Bash(/Users/hun-magnon/Documents/KERI/ai-orchestrator/.venv/bin/python:*)",
                # One-time specific
                "Bash(git -C /Users/hun-magnon/.claude/plans status)",
            ]
        }
    }
    path = tmp_path / "settings.local.json"
    path.write_text(json.dumps(data, indent=2))
    return path


@pytest.fixture
def real_settings():
    """Path to the actual settings file (for integration tests)."""
    path = Path("/Users/hun-magnon/Documents/KERI/.claude/settings.local.json")
    if path.exists():
        return path
    pytest.skip("Real settings file not found")


# =============================================================================
# Parsing Tests
# =============================================================================

class TestPermissionParsing:
    """Test basic entry parsing."""

    def test_parse_bash_prefix(self, parser):
        entries = parser.parse_entries(["Bash(git commit:*)"])
        assert len(entries) == 1
        e = entries[0]
        assert e.tool_type == "Bash"
        assert e.pattern == "git commit"
        assert e.pattern_type == PatternType.PREFIX

    def test_parse_bash_glob(self, parser):
        entries = parser.parse_entries(["Bash(git commit *)"])
        assert len(entries) == 1
        e = entries[0]
        assert e.tool_type == "Bash"
        assert e.pattern == "git commit"
        assert e.pattern_type == PatternType.GLOB

    def test_parse_bash_exact(self, parser):
        entries = parser.parse_entries(["Bash(git status)"])
        assert len(entries) == 1
        e = entries[0]
        assert e.tool_type == "Bash"
        assert e.pattern == "git status"
        assert e.pattern_type == PatternType.EXACT

    def test_parse_mcp(self, parser):
        entries = parser.parse_entries(["mcp__smart-context__rlm_process"])
        assert len(entries) == 1
        e = entries[0]
        assert e.tool_type == "mcp"
        assert e.category == PermissionCategory.MCP

    def test_parse_webfetch(self, parser):
        entries = parser.parse_entries(["WebFetch(domain:github.com)"])
        assert len(entries) == 1
        e = entries[0]
        assert e.tool_type == "WebFetch"
        assert e.pattern == "github.com"
        assert e.category == PermissionCategory.WEBFETCH

    def test_parse_websearch(self, parser):
        entries = parser.parse_entries(["WebSearch"])
        assert len(entries) == 1
        e = entries[0]
        assert e.tool_type == "WebSearch"
        assert e.category == PermissionCategory.CLEAN


# =============================================================================
# Categorization Tests
# =============================================================================

class TestCategorization:
    """Test entry categorization."""

    def test_clean_pattern(self, parser):
        entries = parser.parse_entries(["Bash(ls:*)"])
        assert entries[0].category == PermissionCategory.CLEAN

    def test_broad_wildcard_python(self, parser):
        entries = parser.parse_entries(["Bash(python:*)"])
        assert entries[0].category == PermissionCategory.WILDCARD_BROAD

    def test_broad_wildcard_python3(self, parser):
        entries = parser.parse_entries(["Bash(python3:*)"])
        assert entries[0].category == PermissionCategory.WILDCARD_BROAD

    def test_broad_wildcard_source(self, parser):
        entries = parser.parse_entries(["Bash(source:*)"])
        assert entries[0].category == PermissionCategory.WILDCARD_BROAD

    def test_broad_wildcard_kill(self, parser):
        entries = parser.parse_entries(["Bash(kill:*)"])
        # kill is both broad and dangerous; dangerous takes precedence in categorization
        assert entries[0].category in (
            PermissionCategory.WILDCARD_BROAD,
            PermissionCategory.DANGEROUS,
        )

    def test_shell_fragment_done(self, parser):
        entries = parser.parse_entries(["Bash(done)"])
        assert entries[0].category == PermissionCategory.JUNK

    def test_shell_fragment_fi(self, parser):
        entries = parser.parse_entries(["Bash(fi)"])
        assert entries[0].category == PermissionCategory.JUNK

    def test_shell_fragment_while(self, parser):
        entries = parser.parse_entries(["Bash(while read dir)"])
        assert entries[0].category == PermissionCategory.JUNK

    def test_shell_fragment_do_if(self, parser):
        entries = parser.parse_entries(["Bash(do if [ -f \"$dir/__init__.py\" ])"])
        assert entries[0].category == PermissionCategory.JUNK

    def test_shell_fragment_then_echo(self, parser):
        entries = parser.parse_entries(["Bash(then echo \"Package: $dir\")"])
        assert entries[0].category == PermissionCategory.JUNK

    def test_env_mixed(self, parser):
        entries = parser.parse_entries(["Bash(PYTHONPATH=src .venv/bin/python:*)"])
        assert entries[0].category == PermissionCategory.ENV_MIXED
        assert "PYTHONPATH" in entries[0].env_vars

    def test_env_mixed_dyld(self, parser):
        entries = parser.parse_entries([
            'Bash(DYLD_LIBRARY_PATH="/opt/homebrew/lib:$DYLD_LIBRARY_PATH" .venv/bin/python:*)'
        ])
        assert entries[0].category == PermissionCategory.ENV_MIXED
        assert "DYLD_LIBRARY_PATH" in entries[0].env_vars

    def test_mcp_category(self, parser):
        entries = parser.parse_entries(["mcp__soul-daid__resolve_jewel"])
        assert entries[0].category == PermissionCategory.MCP

    def test_webfetch_category(self, parser):
        entries = parser.parse_entries(["WebFetch(domain:arxiv.org)"])
        assert entries[0].category == PermissionCategory.WEBFETCH


# =============================================================================
# Security Classification Tests
# =============================================================================

class TestSecurityClassification:
    """Test authorization vs convenience classification."""

    def test_git_commit_is_authorization(self, parser):
        entries = parser.parse_entries(["Bash(git commit:*)"])
        assert entries[0].permission_class == PermissionClass.AUTHORIZATION

    def test_git_push_is_authorization(self, parser):
        entries = parser.parse_entries(["Bash(git push:*)"])
        assert entries[0].permission_class == PermissionClass.AUTHORIZATION

    def test_pip_install_is_authorization(self, parser):
        entries = parser.parse_entries(["Bash(.venv/bin/pip install:*)"])
        assert entries[0].permission_class == PermissionClass.AUTHORIZATION

    def test_curl_is_authorization(self, parser):
        entries = parser.parse_entries(["Bash(curl:*)"])
        assert entries[0].permission_class == PermissionClass.AUTHORIZATION

    def test_kill_is_authorization(self, parser):
        entries = parser.parse_entries(["Bash(kill:*)"])
        assert entries[0].permission_class == PermissionClass.AUTHORIZATION

    def test_ls_is_convenience(self, parser):
        entries = parser.parse_entries(["Bash(ls:*)"])
        assert entries[0].permission_class == PermissionClass.CONVENIENCE

    def test_grep_is_convenience(self, parser):
        entries = parser.parse_entries(["Bash(grep:*)"])
        assert entries[0].permission_class == PermissionClass.CONVENIENCE

    def test_mcp_is_convenience(self, parser):
        entries = parser.parse_entries(["mcp__smart-context__rlm_process"])
        assert entries[0].permission_class == PermissionClass.CONVENIENCE


# =============================================================================
# Fragment Detection Tests
# =============================================================================

class TestFragmentDetection:
    """Test detection of shell loop fragments."""

    def test_detects_fragment_group(self, parser):
        entries = parser.parse_entries([
            "Bash(for dir in */)",
            "Bash(do if [ -d \"$dir/.git\" ])",
            "Bash(then echo \"$dir\")",
            "Bash(fi)",
            "Bash(done)",
        ])
        groups = parser.detect_fragments(entries)
        assert len(groups) == 1
        assert len(groups[0]) == 5

    def test_no_fragments_in_clean(self, parser):
        entries = parser.parse_entries([
            "Bash(ls:*)",
            "Bash(git status:*)",
        ])
        groups = parser.detect_fragments(entries)
        assert len(groups) == 0


# =============================================================================
# Redundancy Detection Tests
# =============================================================================

class TestRedundancyDetection:
    """Test detection of redundant permission entries."""

    def test_prefix_subsumes_exact(self, parser):
        entries = parser.parse_entries([
            "Bash(.venv/bin/python:*)",
            "Bash(.venv/bin/python -m pytest tests/test_foo.py -v)",
        ])
        groups = parser.detect_redundancy(entries)
        assert len(groups) >= 1
        # The exact entry should be marked redundant
        exact = [e for e in entries if e.pattern_type == PatternType.EXACT]
        assert any(e.category == PermissionCategory.REDUNDANT for e in exact)

    def test_no_redundancy_different_commands(self, parser):
        entries = parser.parse_entries([
            "Bash(ls:*)",
            "Bash(cat:*)",
        ])
        groups = parser.detect_redundancy(entries)
        assert len(groups) == 0


# =============================================================================
# Env Var Detection Tests
# =============================================================================

class TestEnvVarDetection:
    """Test environment variable extraction."""

    def test_detect_single_env(self, parser):
        env, cmd = parser.detect_env_mixed("Bash(PYTHONPATH=src .venv/bin/python:*)")
        assert env == "PYTHONPATH=src"
        assert ".venv/bin/python" in cmd

    def test_detect_quoted_env(self, parser):
        env, cmd = parser.detect_env_mixed(
            'Bash(DYLD_LIBRARY_PATH="/opt/homebrew/lib" .venv/bin/python:*)'
        )
        assert "DYLD_LIBRARY_PATH" in env
        assert ".venv/bin/python" in cmd

    def test_detect_multiple_env(self, parser):
        env, cmd = parser.detect_env_mixed(
            "Bash(PYTHONPATH=src DYLD_LIBRARY_PATH=/opt/homebrew/lib .venv/bin/python:*)"
        )
        assert "PYTHONPATH" in env
        assert "DYLD_LIBRARY_PATH" in env

    def test_no_env(self, parser):
        env, cmd = parser.detect_env_mixed("Bash(ls:*)")
        assert env == ""


# =============================================================================
# Consolidation Suggestion Tests
# =============================================================================

class TestConsolidationSuggestions:
    """Test consolidation suggestion generation."""

    def test_suggests_removing_junk(self, parser, sample_settings):
        analysis = parser.parse(sample_settings)
        remove_suggestions = [s for s in analysis.suggestions if s.category == "remove"]
        assert len(remove_suggestions) > 0
        # Should include the shell fragments
        all_entries = []
        for s in remove_suggestions:
            all_entries.extend(s.entries)
        raws = {e.raw for e in all_entries}
        assert "Bash(done)" in raws or "Bash(fi)" in raws

    def test_suggests_tightening_python(self, parser, sample_settings):
        analysis = parser.parse(sample_settings)
        tighten = [s for s in analysis.suggestions if s.category == "tighten"]
        python_tighten = [s for s in tighten
                          if any("python" in e.raw for e in s.entries)]
        assert len(python_tighten) > 0

    def test_suggests_tightening_source(self, parser, sample_settings):
        analysis = parser.parse(sample_settings)
        tighten = [s for s in analysis.suggestions if s.category == "tighten"]
        source_tighten = [s for s in tighten
                          if any("source" in e.raw for e in s.entries)]
        assert len(source_tighten) > 0


# =============================================================================
# Full Analysis Tests
# =============================================================================

class TestFullAnalysis:
    """Test full analysis pipeline."""

    def test_analysis_counts(self, parser, sample_settings):
        analysis = parser.parse(sample_settings)
        assert analysis.total > 0
        assert sum(analysis.by_category.values()) == analysis.total
        assert sum(analysis.by_tool.values()) == analysis.total
        assert sum(analysis.by_class.values()) == analysis.total

    def test_analysis_has_said(self, parser, sample_settings):
        analysis = parser.parse(sample_settings)
        assert analysis.settings_said
        assert len(analysis.settings_said) > 10

    def test_analysis_summary(self, parser, sample_settings):
        analysis = parser.parse(sample_settings)
        summary = analysis.summary()
        assert "Permission Analysis" in summary
        assert "By category" in summary
        assert "By tool" in summary

    def test_generate_clean_permissions(self, parser, sample_settings):
        analysis = parser.parse(sample_settings)
        clean = parser.generate_clean_permissions(analysis)
        # Should have fewer entries than original
        assert len(clean) < analysis.total
        # Should not contain junk
        assert "Bash(done)" not in clean
        assert "Bash(fi)" not in clean

    def test_dry_run_does_not_modify(self, parser, sample_settings):
        original = sample_settings.read_text()
        parser.apply_cleanup(sample_settings, dry_run=True)
        assert sample_settings.read_text() == original

    def test_apply_modifies_file(self, parser, sample_settings):
        original_data = json.loads(sample_settings.read_text())
        original_count = len(original_data["permissions"]["allow"])

        removed, final = parser.apply_cleanup(sample_settings, dry_run=False)

        new_data = json.loads(sample_settings.read_text())
        new_count = len(new_data["permissions"]["allow"])

        assert new_count < original_count
        assert len(removed) > 0
        assert new_count == len(final)


# =============================================================================
# Policy Tests
# =============================================================================

class TestPermissionPolicy:
    """Test policy enforcement."""

    def test_exceeds_max_entries(self):
        policy = PermissionPolicy(max_entries=10)
        analysis = PermissionAnalysis(
            entries=[],
            total=15,
            by_category={},
            by_tool={},
            by_class={},
        )
        violations = policy.check(analysis)
        assert any("Exceeds max" in v for v in violations)

    def test_warn_threshold(self):
        policy = PermissionPolicy(max_entries=50, warn_entries=40)
        analysis = PermissionAnalysis(
            entries=[],
            total=45,
            by_category={},
            by_tool={},
            by_class={},
        )
        violations = policy.check(analysis)
        assert any("Approaching" in v for v in violations)

    def test_junk_violation(self):
        policy = PermissionPolicy()
        analysis = PermissionAnalysis(
            entries=[],
            total=10,
            by_category={"junk": 3},
            by_tool={},
            by_class={},
        )
        violations = policy.check(analysis)
        assert any("Junk" in v for v in violations)

    def test_fragment_violation(self):
        policy = PermissionPolicy()
        analysis = PermissionAnalysis(
            entries=[],
            total=10,
            by_category={"fragment": 2},
            by_tool={},
            by_class={},
        )
        violations = policy.check(analysis)
        assert any("fragment" in v.lower() for v in violations)

    def test_clean_passes(self):
        policy = PermissionPolicy()
        analysis = PermissionAnalysis(
            entries=[],
            total=30,
            by_category={"clean": 20, "mcp": 5, "webfetch": 5},
            by_tool={},
            by_class={},
        )
        violations = policy.check(analysis)
        assert len(violations) == 0


# =============================================================================
# SAID Tests
# =============================================================================

class TestSAID:
    """Test SAID computation for permission entries."""

    def test_entry_has_said(self, parser):
        entries = parser.parse_entries(["Bash(ls:*)"])
        assert entries[0].said
        assert entries[0].said.startswith("E")

    def test_same_entry_same_said(self, parser):
        e1 = parser.parse_entries(["Bash(ls:*)"])[0]
        e2 = parser.parse_entries(["Bash(ls:*)"])[0]
        assert e1.said == e2.said

    def test_different_entry_different_said(self, parser):
        e1 = parser.parse_entries(["Bash(ls:*)"])[0]
        e2 = parser.parse_entries(["Bash(cat:*)"])[0]
        assert e1.said != e2.said

    def test_settings_said_deterministic(self, parser, sample_settings):
        a1 = parser.parse(sample_settings)
        a2 = parser.parse(sample_settings)
        assert a1.settings_said == a2.settings_said


# =============================================================================
# Base Command Extraction Tests
# =============================================================================

class TestBaseCommandExtraction:
    """Test base command normalization."""

    def test_strips_absolute_path(self, parser):
        entries = parser.parse_entries([
            "Bash(/Users/hun-magnon/Documents/KERI/ai-orchestrator/.venv/bin/python:*)"
        ])
        assert entries[0].base_command == ".venv/bin/python"

    def test_strips_env_vars(self, parser):
        entries = parser.parse_entries([
            "Bash(PYTHONPATH=src .venv/bin/python:*)"
        ])
        assert entries[0].base_command == ".venv/bin/python"

    def test_strips_homebrew_path(self, parser):
        entries = parser.parse_entries([
            "Bash(/opt/homebrew/bin/ollama list:*)"
        ])
        assert entries[0].base_command == "ollama list"

    def test_preserves_relative_path(self, parser):
        entries = parser.parse_entries([
            "Bash(.venv/bin/python:*)"
        ])
        assert entries[0].base_command == ".venv/bin/python"


# =============================================================================
# Integration Test (Against Real Settings)
# =============================================================================

class TestRealSettings:
    """Integration tests against the actual settings file."""

    def test_parse_real_settings(self, parser, real_settings):
        analysis = parser.parse(real_settings)
        assert analysis.total > 100  # We know there are 143+
        assert analysis.settings_said
        # Should detect multiple categories
        assert len(analysis.by_category) >= 3
        # Should find fragments (categorized as "fragment" after detect_fragments runs)
        fragment_count = (
            analysis.by_category.get("junk", 0)
            + analysis.by_category.get("fragment", 0)
        )
        assert fragment_count > 0

    def test_real_cleanup_reduces_count(self, parser, real_settings):
        analysis = parser.parse(real_settings)
        clean = parser.generate_clean_permissions(analysis)
        # Should reduce significantly
        assert len(clean) < analysis.total
        print(f"\nReal settings: {analysis.total} -> {len(clean)} entries")
        print(analysis.summary())
