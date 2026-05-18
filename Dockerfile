# ── base: shared deps ────────────────────────────────────────────────────────
FROM python:3.11-slim AS base

LABEL maintainer="pkgxray contributors"
LABEL description="Analyze PyPI packages for suspicious behavior"

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir .

# ── test: adds test deps + test files ────────────────────────────────────────
FROM base AS test

RUN pip install --no-cache-dir ".[dev]"

COPY tests/ tests/

ENTRYPOINT ["pytest"]
CMD ["tests/", "-v", "--tb=short", "-m", "not slow"]

# ── prod: minimal runtime image ──────────────────────────────────────────────
FROM base AS prod

ENTRYPOINT ["pkgxray"]
CMD ["--help"]
