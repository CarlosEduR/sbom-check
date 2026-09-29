from dataclasses import dataclass

from sbom_check.models import ValidationMessage

@dataclass
class ValidationResult:
    """Result of SPDX 3.0.1 document validation."""

    is_valid: bool
    messages: list[ValidationMessage]
    schema_valid: bool = True
    semantic_valid: bool = True