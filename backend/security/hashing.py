"""Cryptographic hashing utilities for security intelligence."""

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_CHUNK_SIZE = 65536  # 64 KB chunks for memory-efficient file hashing


def calculate_sha256(
    file_path: str | Path, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> str | None:
    """Calculate the SHA-256 hash of a file on disk.

    Args:
        file_path: Path to the executable or binary file.
        chunk_size: Size of read chunks in bytes (default: 64KB).

    Returns:
        Hexadecimal SHA-256 string, or None if the file cannot be read.
    """
    path = Path(file_path) if isinstance(file_path, str) else file_path

    if not path.is_file():
        logger.warning("Target path is not a file: %s", path)
        return None

    sha256_hash = hashlib.sha256()

    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except (PermissionError, FileNotFoundError, OSError) as exc:
        logger.warning("Failed to calculate SHA-256 hash for %s: %s", path, exc)
        return None
