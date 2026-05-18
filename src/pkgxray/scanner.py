"""Orquestador principal del escáner de pkgxray."""

import ast
import shutil
import tempfile
from datetime import datetime, timezone
from typing import Optional

from pkgxray import downloader, extractor, scorer
from pkgxray.analyzers import get_all_analyzers
from pkgxray.analyzers.base import ScanResult
from pkgxray.analyzers.setup_scripts import SetupScriptAnalyzer
from pkgxray.downloader import DownloadError, PackageNotFoundError


def scan(package_name: str, version: Optional[str] = None) -> ScanResult:
    """Analiza un paquete de PyPI en busca de comportamiento sospechoso sin instalarlo.

    Descarga el archivo del paquete, extrae los archivos Python, ejecuta todos los
    analizadores, calcula el puntaje de riesgo y retorna un ScanResult completo.

    Args:
        package_name: Nombre del paquete de PyPI a analizar.
        version: Versión específica opcional. Si es None, analiza la última versión.

    Returns:
        ScanResult con todos los hallazgos, puntaje y metadatos.

    Raises:
        PackageNotFoundError: Si el paquete no se encuentra en PyPI.
        DownloadError: Si el paquete no puede descargarse.
    """
    tmp_dir = tempfile.mkdtemp(prefix="pkgxray_scan_")
    try:
        # Paso 1: Descarga
        archive_path, actual_version = downloader.download_package(
            package_name, version, dest_dir=tmp_dir
        )

        # Paso 2: Extracción
        extracted_files = extractor.extract_python_files(archive_path)

        # Paso 3: Análisis
        analyzers = get_all_analyzers()
        all_findings = []
        skipped_files = []

        for extracted_file in extracted_files:
            # Para archivos .py: verificar parseabilidad antes de correr los analizadores.
            # Los archivos de config (pyproject.toml, setup.cfg) tienen su propio analizador
            # y no pasan por ast.parse(), así que se excluyen de esta comprobación.
            if extracted_file.filename.lower().endswith(".py"):
                try:
                    ast.parse(extracted_file.content)
                except SyntaxError:
                    skipped_files.append({
                        "filename": extracted_file.filename,
                        "reason": "syntax_error",
                    })
                    continue
                except Exception:
                    skipped_files.append({
                        "filename": extracted_file.filename,
                        "reason": "parse_error",
                    })
                    continue

            for analyzer in analyzers:
                # SetupScriptAnalyzer solo corre en archivos setup.py
                if isinstance(analyzer, SetupScriptAnalyzer):
                    if "setup.py" not in extracted_file.filename.lower():
                        continue
                try:
                    findings = analyzer.analyze(extracted_file.content, extracted_file.filename)
                    all_findings.extend(findings)
                except Exception:
                    # Un fallo individual en un analizador no debe abortar el escaneo completo
                    continue

        # Paso 4: Puntaje
        risk_score, risk_level = scorer.calculate_risk_score(all_findings)
        summary = scorer.get_summary(all_findings)

        # Paso 5: Retornar resultado
        return ScanResult(
            package_name=package_name,
            version=actual_version,
            scan_date=datetime.now(timezone.utc).isoformat(),
            findings=all_findings,
            risk_score=risk_score,
            risk_level=risk_level,
            files_analyzed=len(extracted_files),
            summary=summary,
            skipped_files=skipped_files,
        )

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
