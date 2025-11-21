"""Core package for the Call Graph Reconstruction project."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("call-graph-win11")
except PackageNotFoundError:  # pragma: no cover - package metadata absent in dev mode
    __version__ = "0.0.0"

__all__ = ["__version__"]
