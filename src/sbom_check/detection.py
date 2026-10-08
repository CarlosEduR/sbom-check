# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Format and specification-version detection for SBOM JSON documents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sbom_check.models import DocumentFormat
from spdx3_validator.engine import ValidationEngine as SPDX3ValidationEngine
from spdx_validator.engine import ValidationEngine


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
        for marker in (
            "SPDXID",
            "documentNamespace",
            "creationInfo",
            "dataLicense",
            "spdxVersion",
        )
    )

    if has_spdx_marker:
        return _detect_spdx(data)

    if isinstance(data.get("@graph"), list):
        return _detect_spdx3(data)

    raise UnsupportedDocumentError(
        "Unsupported input: document does not declare SPDX format",
        rule_id="unsupported_format",
    )


def _detect_spdx_version(data: dict[str, Any]) -> str | None:
    version = data.get("spdxVersion")
    spec_version = (
        version.removeprefix("SPDX-") if isinstance(version, str) and version else None
    )

    return spec_version


def _detect_spdx3_version(data: dict[str, Any]) -> str | None:
    graph = data.get("@graph", [])
    spec_version = None

    for item in graph:
        if isinstance(item, dict) and item.get("type") == "CreationInfo":
            version = item.get("specVersion")
            if isinstance(version, str) and version:
                spec_version = version
                break

    return spec_version


def _detect_spdx(data: dict[str, Any]) -> DetectedDocument:
    spec_version = _detect_spdx_version(data)
    return DetectedDocument(DocumentFormat.SPDX, spec_version, ValidationEngine)


def _detect_spdx3(data: dict[str, Any]) -> DetectedDocument:
    spec_version = _detect_spdx3_version(data)
    return DetectedDocument(DocumentFormat.SPDX3, spec_version, SPDX3ValidationEngine)


def get_document_version(
    document_format: DocumentFormat, data: dict[str, Any]
) -> str | None:
    version_detector = {
        DocumentFormat.SPDX: _detect_spdx_version,
        DocumentFormat.SPDX3: _detect_spdx3_version,
    }

    return version_detector[document_format](data)


__all__ = [
    "DetectedDocument",
    "DocumentFormat",
    "UnsupportedDocumentError",
    "detect_document",
]
