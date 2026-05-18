"""Analizador de archivos de configuración: pyproject.toml y setup.cfg."""

import configparser
import io
from typing import List

from pkgxray.analyzers.base import BaseAnalyzer, Finding, Severity

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

# Paquetes de build que son sospechosos en [build-system].requires.
# Paquetes legítimos comunes (setuptools, hatchling, flit, etc.) no están aquí.
_SUSPICIOUS_BUILD_DEPS = {
    "requests", "httpx", "urllib3", "paramiko", "fabric",
    "boto3", "google-cloud", "azure",
}

# Prefijos de comandos de shell en entrypoints que no deberían estar ahí.
_SHELL_KEYWORDS = {"curl", "wget", "bash", "sh", "nc", "ncat", "python -c", "eval"}

# Campos de pyproject.toml donde se pueden definir scripts/entrypoints.
_SCRIPT_FIELDS = {"scripts", "gui-scripts", "entry-points", "entry_points"}


def _check_pyproject(content: str, filename: str) -> List[Finding]:
    """Analiza un archivo pyproject.toml en busca de configuraciones sospechosas."""
    if tomllib is None:
        return []

    findings = []
    try:
        data = tomllib.loads(content)
    except Exception:
        return []

    # --- [build-system].requires -------------------------------------------
    build_system = data.get("build-system", {})
    requires = build_system.get("requires", [])
    if isinstance(requires, list):
        for dep in requires:
            dep_name = str(dep).split("[")[0].split(">=")[0].split("==")[0].strip().lower()
            if dep_name in _SUSPICIOUS_BUILD_DEPS:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    description=(
                        f"Dependencia de build sospechosa en [build-system].requires: '{dep}' — "
                        "paquetes de red/cloud rara vez son necesarios en tiempo de build"
                    ),
                    filename=filename,
                    line_number=0,
                    code_snippet=f"requires = [..., \"{dep}\", ...]",
                    analyzer_name="config_files",
                ))

    # --- [project].scripts / entry-points ----------------------------------
    project = data.get("project", {})
    for field in _SCRIPT_FIELDS:
        scripts = project.get(field, {})
        if not isinstance(scripts, dict):
            continue
        for name, target in scripts.items():
            target_str = str(target)
            for kw in _SHELL_KEYWORDS:
                if kw in target_str:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        description=(
                            f"Entrypoint '{name}' contiene comando de shell sospechoso: '{kw}'"
                        ),
                        filename=filename,
                        line_number=0,
                        code_snippet=f"{name} = {target_str[:120]}",
                        analyzer_name="config_files",
                    ))
                    break

    # --- [tool.hatch] / [tool.*] post-install hooks ------------------------
    tool = data.get("tool", {})
    for tool_name, tool_cfg in tool.items():
        if not isinstance(tool_cfg, dict):
            continue
        hooks = tool_cfg.get("hooks", {})
        if isinstance(hooks, dict) and hooks:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                description=(
                    f"Se detectaron hooks definidos en [tool.{tool_name}].hooks — "
                    "revisar que no ejecuten código arbitrario en tiempo de instalación"
                ),
                filename=filename,
                line_number=0,
                code_snippet=str(list(hooks.keys()))[:120],
                analyzer_name="config_files",
            ))

    return findings


def _check_setup_cfg(content: str, filename: str) -> List[Finding]:
    """Analiza un archivo setup.cfg en busca de configuraciones sospechosas."""
    findings = []
    parser = configparser.ConfigParser()
    try:
        parser.read_file(io.StringIO(content))
    except Exception:
        return []

    # --- [options].install_requires ----------------------------------------
    install_requires = ""
    if parser.has_option("options", "install_requires"):
        install_requires = parser.get("options", "install_requires")
    for line in install_requires.splitlines():
        dep_name = line.strip().split("[")[0].split(">=")[0].split("==")[0].strip().lower()
        if dep_name in _SUSPICIOUS_BUILD_DEPS:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                description=(
                    f"Dependencia sospechosa en [options].install_requires: '{line.strip()}'"
                ),
                filename=filename,
                line_number=0,
                code_snippet=line.strip()[:120],
                analyzer_name="config_files",
            ))

    # --- [options.entry_points] --------------------------------------------
    if parser.has_section("options.entry_points"):
        for key, value in parser.items("options.entry_points"):
            for kw in _SHELL_KEYWORDS:
                if kw in value:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        description=(
                            f"Entrypoint '{key}' contiene comando de shell sospechoso: '{kw}'"
                        ),
                        filename=filename,
                        line_number=0,
                        code_snippet=f"{key} = {value[:120]}",
                        analyzer_name="config_files",
                    ))
                    break

    return findings


class ConfigFileAnalyzer(BaseAnalyzer):
    name = "config_files"
    description = "Analiza pyproject.toml y setup.cfg en busca de configuraciones sospechosas"

    def analyze(self, source_code: str, filename: str) -> List[Finding]:
        lower = filename.lower()
        if lower.endswith("pyproject.toml"):
            return _check_pyproject(source_code, filename)
        if lower.endswith("setup.cfg"):
            return _check_setup_cfg(source_code, filename)
        return []
