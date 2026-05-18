"""Extrae archivos Python de los archivos comprimidos de paquetes descargados."""

import io
import tarfile
import zipfile
from pathlib import Path
from typing import List

from pkgxray.analyzers.base import ExtractedFile

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


def extract_python_files(archive_path: Path) -> List[ExtractedFile]:
    """Extrae los archivos fuente Python de un archivo de paquete.

    Soporta archivos .tar.gz, .tgz, .whl y .zip.

    Args:
        archive_path: Ruta al archivo comprimido descargado.

    Returns:
        Lista de objetos ExtractedFile con el contenido de los archivos.

    Raises:
        ValueError: Si el formato del archivo no es soportado.
    """
    name = archive_path.name.lower()
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        return _extract_from_tarball(archive_path)
    elif name.endswith(".whl") or name.endswith(".zip"):
        return _extract_from_zip(archive_path)
    else:
        raise ValueError(f"Formato de archivo no soportado: {archive_path.name}")


def _extract_from_tarball(archive_path: Path) -> List[ExtractedFile]:
    """Extrae archivos Python de un archivo .tar.gz.

    Args:
        archive_path: Ruta al tarball.

    Returns:
        Lista de objetos ExtractedFile.
    """
    extracted = []
    try:
        with tarfile.open(archive_path, "r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                # Seguridad: ignorar intentos de path traversal
                if ".." in member.name:
                    continue
                # Seguridad: ignorar archivos demasiado grandes
                if member.size > MAX_FILE_SIZE:
                    continue
                if not _is_python_file(member.name):
                    continue

                try:
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    content = f.read().decode("utf-8", errors="ignore")
                    extracted.append(
                        ExtractedFile(
                            filename=member.name,
                            content=content,
                            is_setup=_is_setup_file(member.name),
                        )
                    )
                except Exception:
                    continue
    except tarfile.TarError:
        pass
    return extracted


def _extract_from_zip(archive_path: Path) -> List[ExtractedFile]:
    """Extrae archivos Python de un archivo .whl o .zip.

    Args:
        archive_path: Ruta al archivo zip.

    Returns:
        Lista de objetos ExtractedFile.
    """
    extracted = []
    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                # Seguridad: ignorar intentos de path traversal
                if ".." in info.filename:
                    continue
                # Seguridad: ignorar archivos demasiado grandes
                if info.file_size > MAX_FILE_SIZE:
                    continue
                if not _is_python_file(info.filename):
                    continue

                try:
                    content = zf.read(info.filename).decode("utf-8", errors="ignore")
                    extracted.append(
                        ExtractedFile(
                            filename=info.filename,
                            content=content,
                            is_setup=_is_setup_file(info.filename),
                        )
                    )
                except Exception:
                    continue
    except zipfile.BadZipFile:
        pass
    return extracted


def _is_python_file(filename: str) -> bool:
    """Retorna True si el archivo debe ser extraído para análisis.

    Incluye código Python (.py) y archivos de configuración del paquete que
    tienen su propio analizador dedicado (ConfigFileAnalyzer).  Estos últimos
    NO son pasados a ast.parse() — el analizador los interpreta directamente
    como TOML o INI según su extensión.
    """
    lower = filename.lower()
    return (
        lower.endswith(".py")
        or lower.endswith("setup.cfg")
        or lower.endswith("pyproject.toml")
    )


def _is_setup_file(filename: str) -> bool:
    """Retorna True si el archivo es un script de instalación (setup.py o setup.cfg)."""
    basename = Path(filename).name.lower()
    return basename in {"setup.py", "setup.cfg"}
