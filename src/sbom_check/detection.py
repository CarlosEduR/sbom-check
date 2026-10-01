# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Format and specification-version detection for SBOM JSON documents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sbom_check.models import DocumentFormat
from spdx_validator.engine import ValidationEngine
from spdx3_validator.engine import ValidationEngine as SPDX3ValidationEngine


SPDX_VERSION = "SPDX-2.3"


@dataclass(frozen=True, slots=True)
class DetectedDocument:
    """Format metadata detected from a parsed JSON document."""

    format: DocumentFormat
    spec_version: str | None
    validator_class: type[Any]


class UnsupportedDocumentError(ValueError):
    """Raised when a JSON object is not a supported SBOM document."""

    def __init__(self, message: str, *, rule_id: str = "unsupported_format") -> None:
        super().__init__(message)
        self.rule_id = rule_id


def detect_document(data: Any) -> DetectedDocument:
    """Detect the supported SBOM format and declared specification version.

    Detection is deliberately limited to top-level format markers. It does not
    perform schema validation and never invokes an SBOM validator.

    Args:
        data: Parsed JSON value.

    Returns:
        Detected format and declared specification version.

    Raises:
        UnsupportedDocumentError: If the input is malformed, unsupported, or
            contains conflicting format markers.
    """
    if not isinstance(data, dict):
        raise UnsupportedDocumentError(
            "Unsupported input: the JSON document must be a top-level object"
        )

    has_spdx_marker = any(
        marker in data
        for marker in ("SPDXID", "documentNamespace", "creationInfo", "dataLicense", "spdxVersion")
    )

    if has_spdx_marker:
        return _detect_spdx(data)

    has_spdx3_marker = "@graph" in data
    if has_spdx3_marker:
        return _detect_spdx3(data)

    raise UnsupportedDocumentError(
        "Unsupported input: document does not declare SPDX format",
        rule_id="unsupported_format",
    )


def _detect_spdx(data: dict[str, Any]) -> DetectedDocument:
    version = data.get("spdxVersion")
    spec_version = (
        version.removeprefix("SPDX-")
        if isinstance(version, str) and version
        else None
    )
    return DetectedDocument(DocumentFormat.SPDX, spec_version, ValidationEngine)

def _detect_spdx3(data: dict[str, Any]) -> DetectedDocument:
    return DetectedDocument(DocumentFormat.SPDX3, "3.0.1", SPDX3ValidationEngine)

__all__ = [
    "SPDX_VERSION",
    "DetectedDocument",
    "DocumentFormat",
    "UnsupportedDocumentError",
    "detect_document",
]