"""Sistema de puntuación de riesgo para los resultados de escaneo de pkgxray."""

from collections import defaultdict
from typing import List, Tuple

from pkgxray.analyzers.base import Finding, Severity

SEVERITY_WEIGHTS = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 7,
    Severity.CRITICAL: 15,
}

# Per-analyzer score caps.
#
# The cap controls how much any single analyzer can contribute to the final
# score, regardless of how many findings it produces.  Analyzers whose
# patterns are almost exclusively malicious (obfuscation, setup_scripts) keep
# a high ceiling.  Analyzers that fire frequently on legitimate packages
# (network calls in an HTTP library, env reads in a CLI tool) are capped low
# so they add signal without dominating the result.
#
# Calibrated against baseline scans of: more-itertools, attrs, click,
# requests, paramiko.  Targets: requests → MODERATE, paramiko → HIGH,
# a package with exec(b64decode)+setup hook+module-level subprocess → CRITICAL.
ANALYZER_CAPS = {
    "obfuscation":     20,  # exec(b64decode) — almost never legitimate
    "setup_scripts":   20,  # install hooks — high-confidence attack vector
    "code_exec":       15,  # eval/exec — suspicious but has legitimate uses
    "subprocess":      12,  # subprocess calls — common in build tools
    "filesystem":      12,  # destructive calls + sensitive paths
    "network":          8,  # HTTP calls — normal for HTTP libraries
    "dynamic_imports":  6,  # importlib — used in plugin systems
    "env_access":       5,  # env reads — ubiquitous in CLI tools
}
_DEFAULT_CAP = 10  # fallback for any analyzer not listed above


def calculate_risk_score(findings: List[Finding]) -> Tuple[int, str]:
    """Calcula un puntaje de riesgo de 0 a 100 a partir de una lista de hallazgos.

    El puntaje se calcula sumando los pesos por severidad de cada analizador,
    aplicando un tope individual por analizador (ANALYZER_CAPS) para que los
    patrones legítimos frecuentes no inflen el score.  El resultado refleja
    cuántos *tipos* distintos de comportamiento sospechoso están presentes y
    cuán peligrosos son, no cuántas veces se repite un mismo patrón.

    Args:
        findings: Lista de objetos Finding producidos por los analizadores.

    Returns:
        Tupla (puntaje, nivel) donde nivel es uno de:
        "LOW", "MODERATE", "HIGH", "CRITICAL".
    """
    if not findings:
        return 0, "LOW"

    weight_by_analyzer: dict = defaultdict(int)
    for f in findings:
        weight_by_analyzer[f.analyzer_name] += SEVERITY_WEIGHTS.get(f.severity, 0)

    capped_total = sum(
        min(w, ANALYZER_CAPS.get(name, _DEFAULT_CAP))
        for name, w in weight_by_analyzer.items()
    )
    score = min(100, capped_total)

    if score <= 15:
        level = "LOW"
    elif score <= 35:
        level = "MODERATE"
    elif score <= 60:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return score, level


def get_summary(findings: List[Finding]) -> dict:
    """Cuenta los hallazgos por nivel de severidad.

    Args:
        findings: Lista de objetos Finding.

    Returns:
        Diccionario con conteos por severidad y un total, p. ej.:
        {"low": 2, "medium": 5, "high": 1, "critical": 0, "total": 8}
    """
    summary = {"low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0}
    for f in findings:
        key = f.severity.value
        if key in summary:
            summary[key] += 1
    summary["total"] = len(findings)
    return summary
