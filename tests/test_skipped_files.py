"""Tests for skipped_files tracking in the scanner and reporter."""

import pytest

from pkgxray.analyzers.base import ScanResult, Severity
from pkgxray.scanner import scan
from pkgxray.reporter import generate_json_report


# ---------------------------------------------------------------------------
# ScanResult default
# ---------------------------------------------------------------------------

def test_scan_result_skipped_files_defaults_to_empty():
    """ScanResult must accept no skipped_files and default to empty list."""
    result = ScanResult(
        package_name="test",
        version="1.0",
        scan_date="2025-01-01T00:00:00+00:00",
        findings=[],
        risk_score=0,
        risk_level="LOW",
        files_analyzed=0,
        summary={"low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0},
    )
    assert result.skipped_files == []


# ---------------------------------------------------------------------------
# Scanner tracks syntax errors
# ---------------------------------------------------------------------------

def _make_result_with_skipped(skipped):
    """Helper: build a ScanResult with a given skipped_files list."""
    return ScanResult(
        package_name="test-pkg",
        version="1.0.0",
        scan_date="2025-01-01T00:00:00+00:00",
        findings=[],
        risk_score=0,
        risk_level="LOW",
        files_analyzed=3,
        summary={"low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0},
        skipped_files=skipped,
    )


def test_skipped_files_contains_filename_and_reason():
    skipped = [{"filename": "pkg/broken.py", "reason": "syntax_error"}]
    result = _make_result_with_skipped(skipped)
    assert result.skipped_files[0]["filename"] == "pkg/broken.py"
    assert result.skipped_files[0]["reason"] == "syntax_error"


def test_multiple_skipped_files():
    skipped = [
        {"filename": "pkg/a.py", "reason": "syntax_error"},
        {"filename": "pkg/b.py", "reason": "parse_error"},
    ]
    result = _make_result_with_skipped(skipped)
    assert len(result.skipped_files) == 2


# ---------------------------------------------------------------------------
# Scanner integration: syntax-broken file is tracked, not silently dropped
# ---------------------------------------------------------------------------

def test_scanner_tracks_unparseable_file(monkeypatch):
    """When a .py file has a syntax error the scanner records it in skipped_files."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.downloader as dl_mod
    import pkgxray.extractor as ext_mod
    from pkgxray.analyzers.base import ExtractedFile

    # Stub out download and extraction
    monkeypatch.setattr(dl_mod, "download_package", lambda *a, **kw: ("/fake/path", "1.0.0"))
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: [
        ExtractedFile(filename="clean.py",   content="x = 1\n"),
        ExtractedFile(filename="broken.py",  content="def bad(:\n  pass\n"),
    ])

    result = scanner_mod.scan("fake-pkg")

    skipped_names = [s["filename"] for s in result.skipped_files]
    assert "broken.py" in skipped_names
    assert "clean.py" not in skipped_names


def test_scanner_clean_files_not_skipped(monkeypatch):
    """Files that parse successfully must not appear in skipped_files."""
    import pkgxray.scanner as scanner_mod
    import pkgxray.downloader as dl_mod
    import pkgxray.extractor as ext_mod
    from pkgxray.analyzers.base import ExtractedFile

    monkeypatch.setattr(dl_mod, "download_package", lambda *a, **kw: ("/fake/path", "1.0.0"))
    monkeypatch.setattr(ext_mod, "extract_python_files", lambda _: [
        ExtractedFile(filename="utils.py", content="def add(a, b):\n    return a + b\n"),
    ])

    result = scanner_mod.scan("fake-pkg")
    assert result.skipped_files == []


# ---------------------------------------------------------------------------
# JSON reporter includes skipped_files
# ---------------------------------------------------------------------------

def test_json_report_includes_skipped_files():
    import json
    skipped = [{"filename": "pkg/broken.py", "reason": "syntax_error"}]
    result = _make_result_with_skipped(skipped)
    data = json.loads(generate_json_report(result))

    assert "skipped_files" in data
    assert "files_skipped" in data
    assert data["files_skipped"] == 1
    assert data["skipped_files"][0]["filename"] == "pkg/broken.py"


def test_json_report_skipped_files_empty_when_none():
    import json
    result = _make_result_with_skipped([])
    data = json.loads(generate_json_report(result))
    assert data["skipped_files"] == []
    assert data["files_skipped"] == 0


# ---------------------------------------------------------------------------
# HTML reporter includes warning when files were skipped
# ---------------------------------------------------------------------------

def test_html_report_shows_warning_when_files_skipped():
    from pkgxray.reporter import generate_html_report
    skipped = [{"filename": "broken.py", "reason": "syntax_error"}]
    result = _make_result_with_skipped(skipped)
    html = generate_html_report(result)
    assert "Advertencia" in html
    assert "broken.py" in html


def test_html_report_no_warning_when_nothing_skipped():
    from pkgxray.reporter import generate_html_report
    result = _make_result_with_skipped([])
    html = generate_html_report(result)
    # Warning div should not be present
    assert "fff3cd" not in html  # yellow warning background color
