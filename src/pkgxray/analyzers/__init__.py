"""Analizadores de seguridad para pkgxray."""

from pkgxray.analyzers.base import BaseAnalyzer, ExtractedFile, Finding, Severity, ScanResult
from pkgxray.analyzers.code_exec import CodeExecAnalyzer
from pkgxray.analyzers.network import NetworkAnalyzer
from pkgxray.analyzers.filesystem import FilesystemAnalyzer
from pkgxray.analyzers.env_access import EnvAccessAnalyzer
from pkgxray.analyzers.subprocess_calls import SubprocessAnalyzer
from pkgxray.analyzers.obfuscation import ObfuscationAnalyzer
from pkgxray.analyzers.setup_scripts import SetupScriptAnalyzer
from pkgxray.analyzers.dynamic_imports import DynamicImportAnalyzer
from pkgxray.analyzers.config_files import ConfigFileAnalyzer


def get_all_analyzers() -> list:
    """Retorna una instancia de cada analizador de seguridad."""
    return [
        CodeExecAnalyzer(),
        NetworkAnalyzer(),
        FilesystemAnalyzer(),
        EnvAccessAnalyzer(),
        SubprocessAnalyzer(),
        ObfuscationAnalyzer(),
        SetupScriptAnalyzer(),
        DynamicImportAnalyzer(),
        ConfigFileAnalyzer(),
    ]


__all__ = [
    "BaseAnalyzer",
    "ExtractedFile",
    "Finding",
    "Severity",
    "ScanResult",
    "CodeExecAnalyzer",
    "NetworkAnalyzer",
    "FilesystemAnalyzer",
    "EnvAccessAnalyzer",
    "SubprocessAnalyzer",
    "ObfuscationAnalyzer",
    "SetupScriptAnalyzer",
    "DynamicImportAnalyzer",
    "ConfigFileAnalyzer",
    "get_all_analyzers",
]
