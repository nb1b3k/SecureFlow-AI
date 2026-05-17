"""Path-based classifiers shared by sensitive detection and reachability.

These are cheap heuristics over file paths. They are not authoritative.
"""

from __future__ import annotations

from pathlib import PurePosixPath


def _norm(path: str) -> PurePosixPath:
    return PurePosixPath(path.replace("\\", "/"))


def is_under(path: str, dirs: list[str]) -> bool:
    """True if any segment of `path` matches a dir in `dirs` (case-insensitive)."""
    p = _norm(path)
    parts_lower = {part.lower() for part in p.parts}
    return any(d.strip("/").lower() in parts_lower for d in dirs)


def matches_prefix_any(path: str, prefixes: list[str]) -> bool:
    """True if `path` starts with any of the given prefixes (forward-slash form)."""
    p = str(_norm(path))
    return any(p.startswith(prefix.rstrip("/") + "/") or p == prefix.rstrip("/") for prefix in prefixes)


def file_extension(path: str) -> str:
    return _norm(path).suffix.lower().lstrip(".")


LANG_BY_EXT: dict[str, str] = {
    "py": "python",
    "js": "javascript",
    "jsx": "javascript",
    "ts": "typescript",
    "tsx": "typescript",
    "go": "go",
    "rb": "ruby",
    "java": "java",
    "kt": "kotlin",
    "rs": "rust",
    "cs": "csharp",
    "c": "c",
    "h": "c",
    "cpp": "cpp",
    "hpp": "cpp",
    "php": "php",
    "sh": "shell",
    "yml": "yaml",
    "yaml": "yaml",
    "json": "json",
    "tf": "terraform",
}


def language_of(path: str) -> str | None:
    return LANG_BY_EXT.get(file_extension(path))
