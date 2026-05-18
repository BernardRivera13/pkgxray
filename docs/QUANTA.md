# pkgxray — Project Quanta

Every building block (quantum) of pkgxray: what it is, what it does, its current state, and what needs attention.

**Version:** 0.2.2

---

## Pipeline at a Glance

```
User / CLI
    |
    v
scanner.scan()              <- single public entry-point
    |
    +-> downloader           <- fetches metadata + archive from PyPI (no install)
    |       |
    |       +-> extractor    <- opens .tar.gz / .whl; yields ExtractedFile objects
    |               |
    |               +-> analyzers (x8)   <- AST-based detection per file
    |                       |
    |                       +-> scorer   <- weights + caps -> risk_score 0-100
    |
    +-> ScanResult           <- returned to caller
            |
            +-> reporter     <- terminal (rich), JSON, or HTML
```

---

## Core Modules

### `scanner.py` — Pipeline Orchestrator

**What it does:** The single `scan(package_name, version=None)` function that drives the entire pipeline. Creates a temp dir, calls each stage in order, tears down the temp dir in a `finally` block.

**Key behaviours:**
- Analyser isolation: a crash in any `analyzer.analyze()` call never aborts the scan
- `SetupScriptAnalyzer` is short-circuited for non-`setup.py` files (double-gated with the analyser itself)
- Returns a `ScanResult` with the concrete version scanned, not just "latest"

**Raises:** `PackageNotFoundError`, `DownloadError`

**Status:** Stable. No known correctness issues.

---

### `downloader.py` — PyPI Client

**What it does:** Fetches package metadata from the PyPI JSON API and downloads the archive to a temp directory. Uses only `urllib` from stdlib (no `requests`).

**Distribution priority:**
1. `sdist` / `.tar.gz` — preferred (includes `setup.py`)
2. Platform-independent wheel (`any` in filename)
3. First available URL (fallback)

**Known issues:**
- `User-Agent` header is hardcoded as `pkgxray/0.1.0` (stale — should be `0.2.2`)
- No offline/cache mode — every scan hits the network

**Status:** Functional. Minor cosmetic issue with User-Agent.

---

### `extractor.py` — Archive Parser

**What it does:** Opens a downloaded `.tar.gz`, `.tgz`, `.whl`, or `.zip` archive and returns all Python-relevant files as in-memory `ExtractedFile` objects.

**Guards applied per file:**
- Skips directories
- Skips path traversal (`".." in name`)
- Skips files > 5 MB
- Skips non-Python files (`.py`, `setup.cfg`, `pyproject.toml`)

**Known issues:**
- `setup.cfg` and `pyproject.toml` are extracted but `ast.parse()` silently fails on them (TOML/INI format). No analyzer handles them yet.
- `ExtractedFile.is_setup` flag is set correctly but never consumed by any downstream code.

**Status:** Functional. The unused `is_setup` flag is dead code.

---

### `scorer.py` — Risk Scoring Engine

**What it does:** Converts a list of `Finding` objects into a single integer risk score (0–100) and a risk level label.

**Scoring logic:**

| Severity | Weight |
|----------|--------|
| LOW      | 1      |
| MEDIUM   | 3      |
| HIGH     | 7      |
| CRITICAL | 15     |

Two-level capping:
1. **Per-analyser cap: 20 points** — prevents a single analyser from dominating the score
2. **Global cap: 100 points**

**Risk level thresholds:**

| Score   | Level    |
|---------|----------|
| 0–20    | LOW      |
| 21–40   | MODERATE |
| 41–70   | HIGH     |
| 71–100  | CRITICAL |

**Current problem — over-sensitivity:** Legitimate packages (e.g. `requests`, `paramiko`) score HIGH/CRITICAL because many common patterns (network calls, subprocess, env access) are flagged without enough context. The per-analyser cap of 20 is too high relative to the weights.

**What needs fixing:**
- Recalibrate weights and/or thresholds against a baseline of 20-30 known-clean packages
- Consider per-analyser weight adjustments (e.g. `env_access` findings should weigh less than `obfuscation`)

**Status:** NEEDS WORK — primary source of false positives.

---

### `reporter.py` — Output Formatter

**What it does:** Converts a `ScanResult` into terminal (rich), JSON, or HTML output.

**Known issues:**
- `Console(width=200)` ignores the terminal's actual width — output wraps awkwardly on narrow terminals.

**Status:** Functional. Width issue is cosmetic.

---

### `cli.py` — Command-Line Interface

**What it does:** Exposes `pkgxray scan <package>` via `click`. Supports `--version`, `--format`, `--output` flags.

**Known issues:**
- `@click.version_option(version="0.1.0")` is stale — shows `0.1.0` when the package is `0.2.2`.

**Status:** Functional. Version string needs updating.

---

### `utils.py` — Utilities

**What it does:** Nothing. Empty placeholder file.

**Status:** Empty. Reserved for future shared helpers.

---

## Analyzers (`src/pkgxray/analyzers/`)

All analyzers inherit `BaseAnalyzer`. They receive a file's source code as a string and return a list of `Finding` objects. All use `ast.parse()` — never execute code.

### `base.py` — Shared Primitives

Defines `Severity`, `Finding`, `ExtractedFile`, `ScanResult`, `BaseAnalyzer`, `build_parent_map()`, `is_module_level()`.

**`is_module_level(node)` — key behaviour:** Returns `True` if the node has no `FunctionDef`, `AsyncFunctionDef`, or `ClassDef` ancestor. Used to escalate severity to CRITICAL (code running at import time is the highest-risk case).

**Known issue:** Code inside a class body (but outside any method) runs at import time but `is_module_level()` returns `False` for it (it has a `ClassDef` ancestor). This is a correctness gap.

**`build_parent_map()` performance:** Called independently by `CodeExecAnalyzer`, `NetworkAnalyzer`, and `SubprocessAnalyzer` — the AST is traversed 3 times for the same purpose per file. Not a correctness issue but wasteful.

---

### `code_exec.py` — Dynamic Code Execution

**Detects:** `eval()`, `exec()`, `compile()` calls.

**Severities:** `eval` → HIGH, `exec` → CRITICAL, `compile` → HIGH. Escalated to CRITICAL if at module level.

**Does NOT detect:**
- `obj.exec()` (attribute call)
- Aliased: `e = eval; e(...)`
- `getattr(builtins, "exec")(...)`

**Status:** Functional. Alias bypass is a known limitation.

---

### `network.py` — Network Calls

**Detects:** `urlopen`, `create_connection` (always), `connect` (with DB receiver exclusion), HTTP methods (`get`, `post`, etc.) when receiver is in a known HTTP-client set.

**Does NOT detect:**
- `self.session.get(url)` — chained attributes resolve to an empty receiver string, so the call is missed. This is the most common false-negative for OOP HTTP clients.

**Status:** NEEDS WORK — chained attribute case is a significant false-negative.

---

### `filesystem.py` — Filesystem Access

**Detects:** `remove`, `unlink`, `rmtree` calls (any receiver) + string literals matching sensitive paths (`/etc/passwd`, `~/.ssh/`, etc.).

**Known false positive:** `my_list.remove(x)` is flagged as a destructive filesystem call because there is no receiver filtering for `remove`. This is a direct cause of over-sensitivity in clean packages.

**Status:** NEEDS WORK — `remove` needs receiver filtering.

---

### `env_access.py` — Environment Variables

**Detects:** `os.environ[key]`, `os.getenv(key)`, `os.environ.get(key)`.

**Severity:** HIGH if key name matches a sensitive keyword (API_KEY, TOKEN, SECRET, etc.), MEDIUM if dynamic, LOW otherwise.

**Known issue:** Severity is based on the key name only, not what the code does with the value. Reading `os.getenv("HOME")` is LOW; reading `os.getenv("SECRET")` is HIGH — even if the value is just printed.

**Status:** Functional but produces noise. Contributes to over-sensitivity in packages that legitimately read environment variables.

---

### `subprocess_calls.py` — OS Command Execution

**Detects:** `subprocess.run/call/Popen/check_output/check_call` (receiver must be exactly `subprocess`) and `os.system/popen/execvp/execv` (receiver must be exactly `os`).

**Does NOT detect:**
- `import subprocess as sp; sp.run(...)` — receiver check is exact name match
- `os.spawn*` family
- `pty.spawn()`, `commands.getoutput()`

**Status:** Functional. Alias bypass is a known limitation.

---

### `obfuscation.py` — Code Obfuscation

**Detects:**
- `exec(base64.b64decode(...))` / `eval(base64.b64decode(...))` → CRITICAL
- `codecs.decode(data, "rot...")` → MEDIUM
- `.fromhex(...)` calls → MEDIUM
- Strings with 10+ consecutive `\xNN` escapes and length > 100 chars → HIGH

**Note:** `base64.b64decode()` alone is NOT flagged — it is ubiquitous in legitimate code. Only the `exec(b64decode(...))` combination is flagged.

**Status:** Well-calibrated. Low false-positive risk.

---

### `setup_scripts.py` — Installation Hooks

**Detects (in `setup.py` only):**
- Classes inheriting from setuptools command base classes (`install`, `develop`, etc.) that define `run` or `__init__` → CRITICAL
- Dangerous imports in `setup.py` (`subprocess`, `socket`, `urllib`, etc.) → HIGH
- Dangerous direct calls in `setup.py` (`eval`, `exec`, `urlopen`, `os.system`, etc.) → CRITICAL

**Note:** `subprocess.run()` is NOT in the dangerous-calls list by design — it is common in legitimate setup.py for dependency checking.

**Status:** Well-targeted. Low false-positive risk.

---

### `dynamic_imports.py` — Dynamic Imports

**Detects:** `__import__(...)` (HIGH), `importlib.import_module(...)` (MEDIUM if literal arg, HIGH if dynamic).

**Known false positive:** Any `obj.import_module()` is flagged, not just `importlib.import_module()`.

**Status:** Functional. Receiver check for `import_module` is missing.

---

## Known Issues Summary

| Priority | Location | Issue |
|----------|----------|-------|
| HIGH | `filesystem.py` | `list.remove()` flagged as destructive filesystem call |
| HIGH | `scorer.py` | Per-analyser cap too high, legitimate packages score CRITICAL |
| HIGH | `network.py` | Chained attribute HTTP calls missed (`self.session.get(...)`) |
| MEDIUM | `base.py` | Class-body code not classified as module-level (runs at import time) |
| MEDIUM | `subprocess_calls.py` | Aliased module imports bypassed |
| LOW | `cli.py` | `--version` shows `0.1.0` instead of `0.2.2` |
| LOW | `downloader.py` | `User-Agent` header shows `0.1.0` |
| LOW | `extractor.py` | `ExtractedFile.is_setup` field is set but never consumed |
| LOW | `utils.py` | Empty placeholder file |
