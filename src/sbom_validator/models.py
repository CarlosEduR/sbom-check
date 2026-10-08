"""Shared models used by SBOM validators."""

from enum import Enum


class DocumentFormat(str, Enum):
    """Supported SBOM document formats."""

    SPDX = "SPDX"
    SPDX3 = "SPDX3"
    UNKNOWN = "unknown"
