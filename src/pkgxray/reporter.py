"""Genera reportes de seguridad en formato terminal, JSON y HTML."""

import json
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from pkgxray.analyzers.base import ScanResult, Severity

_SEVERITY_COLORS = {
    "low": "green",
    "medium": "yellow",
    "high": "orange3",
    "critical": "red",
}

_LEVEL_COLORS = {
    "LOW": "green",
    "MODERATE": "yellow",
    "HIGH": "orange3",
    "CRITICAL": "red",
}

_console = Console()


def print_terminal_report(result: ScanResult) -> None:
    """Imprime un reporte con colores en la terminal usando rich.

    Args:
        result: ScanResult obtenido del escaneo de un paquete.
    """
    console = Console(width=200)

    # Encabezado
    console.print(Panel(
        f"[bold]Paquete:[/bold] {result.package_name}  "
        f"[bold]Versión:[/bold] {result.version}  "
        f"[bold]Fecha:[/bold] {result.scan_date}",
        title="[bold blue]pkgxray — Reporte de Seguridad[/bold blue]",
        border_style="blue",
    ))

    # Puntaje de riesgo
    level_color = _LEVEL_COLORS.get(result.risk_level, "white")
    score_text = Text(
        f"Puntaje de riesgo: {result.risk_score}/100  [{result.risk_level}]",
        style=f"bold {level_color}",
    )
    console.print(Panel(score_text, border_style=level_color))

    # Resumen
    s = result.summary
    console.print(
        f"[bold]Se encontraron {s['total']} problema(s):[/bold] "
        f"[red]{s['critical']} crítico(s)[/red]  "
        f"[orange3]{s['high']} alto(s)[/orange3]  "
        f"[yellow]{s['medium']} medio(s)[/yellow]  "
        f"[green]{s['low']} bajo(s)[/green]  "
        f"  [dim]{result.files_analyzed} archivos analizados[/dim]"
    )

    # Advertencia de archivos omitidos
    if result.skipped_files:
        skipped_names = ", ".join(s["filename"].split("/")[-1] for s in result.skipped_files[:5])
        more = f" (+{len(result.skipped_files) - 5} más)" if len(result.skipped_files) > 5 else ""
        console.print(Panel(
            f"[bold yellow]Advertencia:[/bold yellow] {len(result.skipped_files)} archivo(s) no pudieron analizarse "
            f"(error de sintaxis o versión de Python incompatible): {skipped_names}{more}",
            border_style="yellow",
        ))

    if not result.findings:
        console.print("\n[bold green]¡No se encontraron patrones sospechosos![/bold green]\n")
        return

    # Tabla de hallazgos
    table = Table(show_header=True, header_style="bold", border_style="dim")
    table.add_column("Severidad", style="bold", width=10)
    table.add_column("Analizador", width=16)
    table.add_column("Archivo", width=30)
    table.add_column("Línea", width=6, justify="right")
    table.add_column("Descripción")

    for finding in result.findings:
        sev_val = finding.severity.value
        color = _SEVERITY_COLORS.get(sev_val, "white")
        table.add_row(
            Text(sev_val.upper(), style=f"bold {color}"),
            finding.analyzer_name,
            finding.filename[-30:] if len(finding.filename) > 30 else finding.filename,
            str(finding.line_number),
            finding.description,
        )

    console.print(table)
    console.print()


def generate_json_report(result: ScanResult) -> str:
    """Serializa un ScanResult a una cadena JSON con formato legible.

    Args:
        result: ScanResult obtenido del escaneo de un paquete.

    Returns:
        Cadena JSON con toda la información del escaneo.
    """
    def _serialize(obj):
        if isinstance(obj, Severity):
            return obj.value
        raise TypeError(f"El objeto de tipo {type(obj)} no es serializable a JSON")

    data = {
        "package_name": result.package_name,
        "version": result.version,
        "scan_date": result.scan_date,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "files_analyzed": result.files_analyzed,
        "files_skipped": len(result.skipped_files),
        "skipped_files": result.skipped_files,
        "summary": result.summary,
        "findings": [
            {
                "severity": f.severity.value,
                "description": f.description,
                "filename": f.filename,
                "line_number": f.line_number,
                "code_snippet": f.code_snippet,
                "analyzer_name": f.analyzer_name,
            }
            for f in result.findings
        ],
    }
    return json.dumps(data, indent=2, default=_serialize)


def generate_html_report(result: ScanResult) -> str:
    """Genera un reporte HTML autocontenido con CSS en línea.

    Args:
        result: ScanResult obtenido del escaneo de un paquete.

    Returns:
        Cadena HTML con estilos CSS en línea.
    """
    level_colors = {
        "LOW": "#2ecc71",
        "MODERATE": "#f39c12",
        "HIGH": "#e67e22",
        "CRITICAL": "#e74c3c",
    }
    sev_colors = {
        "low": "#2ecc71",
        "medium": "#f39c12",
        "high": "#e67e22",
        "critical": "#e74c3c",
    }
    score_color = level_colors.get(result.risk_level, "#95a5a6")

    rows_html = ""
    for f in result.findings:
        sev = f.severity.value
        bg = sev_colors.get(sev, "#ecf0f1")
        snippet = f.code_snippet.replace("<", "&lt;").replace(">", "&gt;")
        rows_html += f"""
        <tr style="border-bottom:1px solid #dee2e6;">
          <td style="padding:8px;font-weight:bold;color:{bg};">{sev.upper()}</td>
          <td style="padding:8px;">{f.analyzer_name}</td>
          <td style="padding:8px;font-size:0.85em;word-break:break-all;">{f.filename}</td>
          <td style="padding:8px;text-align:right;">{f.line_number}</td>
          <td style="padding:8px;">{f.description}</td>
          <td style="padding:8px;font-family:monospace;font-size:0.8em;">{snippet[:120]}</td>
        </tr>"""

    no_findings_msg = ""
    if not result.findings:
        no_findings_msg = '<p style="color:#2ecc71;font-weight:bold;font-size:1.1em;">¡No se encontraron patrones sospechosos!</p>'

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>pkgxray — Reporte de Seguridad — {result.package_name}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; padding: 20px; background: #f8f9fa; color: #212529; }}
    .container {{ max-width: 1100px; margin: 0 auto; }}
    .header {{ background: #343a40; color: white; padding: 20px 24px; border-radius: 8px; margin-bottom: 20px; }}
    .score-box {{ background: {score_color}; color: white; padding: 16px 24px; border-radius: 8px; margin-bottom: 20px; display: inline-block; }}
    .summary {{ background: white; padding: 16px 24px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
    table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }}
    th {{ background: #343a40; color: white; padding: 10px 8px; text-align: left; font-size: 0.9em; }}
    .footer {{ margin-top: 20px; color: #6c757d; font-size: 0.85em; text-align: center; }}
  </style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1 style="margin:0 0 6px 0;">pkgxray — Reporte de Seguridad</h1>
    <div><strong>Paquete:</strong> {result.package_name} &nbsp; <strong>Versión:</strong> {result.version} &nbsp; <strong>Fecha:</strong> {result.scan_date}</div>
  </div>
  <div class="score-box">
    <div style="font-size:2em;font-weight:bold;">{result.risk_score}/100</div>
    <div style="font-size:1.1em;">Nivel de riesgo: {result.risk_level}</div>
  </div>
  <div class="summary">
    <strong>Archivos analizados:</strong> {result.files_analyzed} &nbsp;|&nbsp;
    <strong>Hallazgos totales:</strong> {result.summary['total']} &nbsp;|&nbsp;
    <span style="color:#e74c3c;">{result.summary['critical']} crítico(s)</span> &nbsp;
    <span style="color:#e67e22;">{result.summary['high']} alto(s)</span> &nbsp;
    <span style="color:#f39c12;">{result.summary['medium']} medio(s)</span> &nbsp;
    <span style="color:#2ecc71;">{result.summary['low']} bajo(s)</span>
  </div>
  {f'<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:8px;padding:12px 24px;margin-bottom:20px;"><strong>Advertencia:</strong> {len(result.skipped_files)} archivo(s) no pudieron analizarse por errores de sintaxis o versión de Python incompatible: ' + ', '.join(s["filename"].split("/")[-1] for s in result.skipped_files[:5]) + ('...' if len(result.skipped_files) > 5 else '') + '</div>' if result.skipped_files else ''}
  {no_findings_msg}
  {'<table><thead><tr><th>Severidad</th><th>Analizador</th><th>Archivo</th><th>Línea</th><th>Descripción</th><th>Fragmento</th></tr></thead><tbody>' + rows_html + '</tbody></table>' if result.findings else ''}
  <div class="footer">Generado por <strong>pkgxray</strong></div>
</div>
</body>
</html>"""


def generate_report(
    result: ScanResult,
    format: str = "terminal",
    output_path: Optional[str] = None,
) -> Optional[str]:
    """Genera un reporte en el formato solicitado.

    Args:
        result: ScanResult obtenido del escaneo de un paquete.
        format: Uno de "terminal", "json", "html".
        output_path: Si se indica, escribe el reporte en ese archivo.

    Returns:
        La cadena del reporte para los formatos json/html, o None para terminal.
    """
    if format == "terminal":
        print_terminal_report(result)
        return None
    elif format == "json":
        report = generate_json_report(result)
    elif format == "html":
        report = generate_html_report(result)
    else:
        raise ValueError(f"Formato desconocido: {format!r}. Opciones válidas: terminal, json, html")

    if output_path:
        Path(output_path).write_text(report, encoding="utf-8")

    return report
