"""Tests for scorer.py — per-analyzer caps and risk level thresholds."""

import pytest

from pkgxray.analyzers.base import Finding, Severity
from pkgxray.scorer import ANALYZER_CAPS, calculate_risk_score, get_summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(analyzer_name: str, severity: Severity) -> Finding:
    return Finding(
        severity=severity,
        description="test finding",
        filename="test.py",
        line_number=1,
        code_snippet="",
        analyzer_name=analyzer_name,
    )


def findings_for(analyzer_name: str, severity: Severity, count: int):
    return [make_finding(analyzer_name, severity) for _ in range(count)]


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_no_findings_returns_zero_low():
    score, level = calculate_risk_score([])
    assert score == 0
    assert level == "LOW"


def test_single_low_finding():
    findings = findings_for("env_access", Severity.LOW, 1)
    score, level = calculate_risk_score(findings)
    assert score == 1
    assert level == "LOW"


# ---------------------------------------------------------------------------
# Per-analyzer caps
# ---------------------------------------------------------------------------

def test_env_access_capped_at_5():
    """50 LOW env_access findings should not exceed the env_access cap."""
    cap = ANALYZER_CAPS["env_access"]  # 5
    findings = findings_for("env_access", Severity.LOW, 50)
    score, _ = calculate_risk_score(findings)
    assert score == cap


def test_network_capped_at_8():
    """130 HIGH network findings (like requests) should be capped at 8."""
    cap = ANALYZER_CAPS["network"]  # 8
    findings = findings_for("network", Severity.HIGH, 130)
    score, _ = calculate_risk_score(findings)
    assert score == cap


def test_obfuscation_cap_is_20():
    """obfuscation cap must stay at 20 — high-confidence findings need full weight."""
    cap = ANALYZER_CAPS["obfuscation"]
    assert cap == 20


def test_setup_scripts_cap_is_20():
    """setup_scripts cap must stay at 20 — install hooks are high-confidence."""
    cap = ANALYZER_CAPS["setup_scripts"]
    assert cap == 20


def test_unknown_analyzer_uses_default_cap():
    """An analyzer not listed in ANALYZER_CAPS should use _DEFAULT_CAP."""
    from pkgxray.scorer import _DEFAULT_CAP
    findings = findings_for("future_analyzer", Severity.CRITICAL, 100)
    score, _ = calculate_risk_score(findings)
    assert score == _DEFAULT_CAP


# ---------------------------------------------------------------------------
# Threshold boundaries
# ---------------------------------------------------------------------------

def test_threshold_low_boundary():
    """Score of exactly 15 should be LOW."""
    # obfuscation weight=15 for one CRITICAL finding, cap=20 → score=15
    findings = findings_for("obfuscation", Severity.CRITICAL, 1)
    score, level = calculate_risk_score(findings)
    assert score == 15
    assert level == "LOW"


def test_threshold_moderate_lower():
    """Score of 16 should be MODERATE."""
    # obfuscation CRITICAL (15) + env_access LOW (1) = 16
    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 1)
        + findings_for("env_access", Severity.LOW, 1)
    )
    score, level = calculate_risk_score(findings)
    assert score == 16
    assert level == "MODERATE"


def test_threshold_moderate_upper():
    """Score of exactly 35 should be MODERATE."""
    # obfuscation(15) + code_exec(15) + env_access(5) = 35
    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 1)
        + findings_for("code_exec", Severity.CRITICAL, 1)
        + findings_for("env_access", Severity.CRITICAL, 10)  # capped at 5
    )
    score, level = calculate_risk_score(findings)
    assert score == 35
    assert level == "MODERATE"


def test_threshold_high_lower():
    """Score of 36 should be HIGH."""
    # obfuscation(15) + code_exec(15) + env_access(5) + network(1 LOW) = 36
    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 1)
        + findings_for("code_exec", Severity.CRITICAL, 1)
        + findings_for("env_access", Severity.CRITICAL, 10)
        + findings_for("network", Severity.LOW, 1)
    )
    score, level = calculate_risk_score(findings)
    assert score == 36
    assert level == "HIGH"


def test_threshold_critical():
    """Score above 60 should be CRITICAL."""
    # obfuscation(20) + setup_scripts(20) + code_exec(15) + subprocess(12) = 67
    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 2)
        + findings_for("setup_scripts", Severity.CRITICAL, 2)
        + findings_for("code_exec", Severity.CRITICAL, 1)
        + findings_for("subprocess", Severity.CRITICAL, 1)
    )
    score, level = calculate_risk_score(findings)
    assert score > 60
    assert level == "CRITICAL"


def test_global_cap_at_100():
    """Score must never exceed 100, even if per-analyzer caps sum beyond it."""
    # Each analyzer contributes its full cap. Current caps sum to 98 which is
    # already under the global ceiling, so we also add unknown analyzers to
    # push the raw total above 100 and verify the clamp holds.
    findings = []
    for analyzer_name in ANALYZER_CAPS:
        findings += findings_for(analyzer_name, Severity.CRITICAL, 20)
    # Add extra unknown analyzers to push total over 100
    for i in range(5):
        findings += findings_for(f"extra_analyzer_{i}", Severity.CRITICAL, 20)
    score, _ = calculate_risk_score(findings)
    assert score == 100


# ---------------------------------------------------------------------------
# Baseline calibration: known-clean packages (simulated findings)
# ---------------------------------------------------------------------------

def test_requests_profile_is_moderate():
    """Simulates the findings profile of 'requests': heavy network + some env + filesystem."""
    findings = (
        findings_for("network", Severity.HIGH, 130)     # HTTP calls throughout the lib
        + findings_for("env_access", Severity.LOW, 6)   # proxy env vars
        + findings_for("env_access", Severity.MEDIUM, 9)
        + findings_for("filesystem", Severity.HIGH, 4)
        + findings_for("filesystem", Severity.CRITICAL, 1)
        + findings_for("dynamic_imports", Severity.HIGH, 2)
    )
    score, level = calculate_risk_score(findings)
    assert level == "MODERATE", f"requests profile should be MODERATE, got {level} ({score})"
    assert score <= 35


def test_click_profile_is_moderate():
    """Simulates the findings profile of 'click': env reads + subprocess + filesystem."""
    findings = (
        findings_for("env_access", Severity.LOW, 13)
        + findings_for("env_access", Severity.MEDIUM, 11)
        + findings_for("filesystem", Severity.HIGH, 5)
        + findings_for("subprocess", Severity.CRITICAL, 5)
        + findings_for("subprocess", Severity.HIGH, 4)
    )
    score, level = calculate_risk_score(findings)
    assert level == "MODERATE", f"click profile should be MODERATE, got {level} ({score})"
    assert score <= 35


def test_malicious_package_profile_is_critical():
    """A package with obfuscation + install hook + module-level subprocess must be CRITICAL."""
    findings = (
        findings_for("obfuscation", Severity.CRITICAL, 1)    # exec(b64decode)
        + findings_for("setup_scripts", Severity.CRITICAL, 1) # install hook
        + findings_for("subprocess", Severity.CRITICAL, 1)    # module-level Popen
        + findings_for("code_exec", Severity.CRITICAL, 1)     # bare exec()
        + findings_for("network", Severity.HIGH, 1)           # exfil call
    )
    score, level = calculate_risk_score(findings)
    assert level == "CRITICAL", f"malicious profile should be CRITICAL, got {level} ({score})"


# ---------------------------------------------------------------------------
# get_summary
# ---------------------------------------------------------------------------

def test_get_summary_counts():
    findings = (
        findings_for("network", Severity.LOW, 2)
        + findings_for("subprocess", Severity.HIGH, 1)
        + findings_for("obfuscation", Severity.CRITICAL, 1)
    )
    summary = get_summary(findings)
    assert summary["low"] == 2
    assert summary["medium"] == 0
    assert summary["high"] == 1
    assert summary["critical"] == 1
    assert summary["total"] == 4


def test_get_summary_empty():
    summary = get_summary([])
    assert summary["total"] == 0
    assert all(summary[k] == 0 for k in ["low", "medium", "high", "critical"])
