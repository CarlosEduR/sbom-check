# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Abstract interfaces shared by SBOM validation engines."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path


class ValidatorEngine(ABC):
    """Interface required by every format-specific validation engine."""

    @abstractmethod
    def __init__(
        self,
        schema_path: str | Path | None = None,
        enable_schema_validation: bool = True,
        enable_semantic_validation: bool = True,
    ) -> None:
        """Initialize the validator with validation settings."""

    @abstractmethod
    def validate(self, document: dict[str, Any], file_path: str | None = None) -> Any:
        """Validate a parsed SBOM document against its declared schema."""


__all__ = ["ValidatorEngine"]
