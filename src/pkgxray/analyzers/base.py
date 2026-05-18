"""Modelos de datos base y analizador abstracto para pkgxray."""

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


def build_parent_map(tree) -> dict:
    """Devuelve un dict que mapea id(nodo_hijo) → nodo_padre para todo el AST."""
    parent_map: dict = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent_map[id(child)] = node
    return parent_map


def is_module_level(node, parent_map: dict) -> bool:
    """Retorna True si *node* no está anidado dentro de ninguna función o clase.

    Las llamadas a nivel de módulo se ejecutan automáticamente al importar el
    paquete — sin que el usuario las invoque — lo que las hace mucho más peligrosas.
    """
    current_id = id(node)
    while current_id in parent_map:
        parent = parent_map[current_id]
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return False
        current_id = id(parent)
    return True


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    severity: Severity
    description: str
    filename: str
    line_number: int
    code_snippet: str
    analyzer_name: str


class BaseAnalyzer(ABC):
    name: str = ""
    description: str = ""

    @abstractmethod
    def analyze(self, source_code: str, filename: str) -> list:
        """Analiza el código fuente y retorna una lista de objetos Finding."""
        ...

    def _parse_ast(self, source_code: str):
        """Parsea el código fuente a un AST; retorna None si falla."""
        try:
            return ast.parse(source_code)
        except SyntaxError:
            return None
        except Exception:
            return None


@dataclass
class ExtractedFile:
    filename: str
    content: str
    is_setup: bool = False


@dataclass
class ScanResult:
    package_name: str
    version: str
    scan_date: str
    findings: list
    risk_score: int
    risk_level: str
    files_analyzed: int
    summary: dict
    skipped_files: list = field(default_factory=list)
    # Each entry: {"filename": str, "reason": "syntax_error" | "parse_error"}
