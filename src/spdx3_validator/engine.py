# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""SPDX 3.0.1 validation engine."""

import json
from collections.abc import Generator
from contextlib import contextmanager
from json import JSONDecodeError
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.error import URLError

from spdx3_validate import validate
from spdx3_validate.core import SpdxValidateError, UnknownVersionError
from spdx3_validate.core import ValidationError as CustomValidationError
from spdx3_validate.core import ValidationResult as CustomValidationResult

from sbom_validator.engine import ValidatorEngine
from spdx3_validator.diagnostics import ShaclDiagnosticParser
from spdx3_validator.models import (
    ValidationMessage,
    ValidationResult,
    ValidationSeverity,
)

SPDX_VERSION = "3.0.1"


@contextmanager
def _validation_source(
    document: dict[str, Any] | None,
    file_path: str | Path | None,
) -> Generator[Path]:
    """Provide a file path for the file-based SPDX 3 validator."""
    if file_path is not None:
        yield Path(file_path)
        return

    if document is None:
        raise ValueError("Either document or file_path must be provided")

    with TemporaryDirectory() as temp_dir:
        source_path = Path(temp_dir) / "document.spdx.json"
        source_path.write_text(json.dumps(document), encoding="utf-8")
        yield source_path


class ValidationEngine(ValidatorEngine):
    def __init__(self) -> None:
        """Initialize the validation engine for SPDX 3.0.1."""

    @staticmethod
    def _unique_errors(
        errors: list[CustomValidationError],
    ) -> list[CustomValidationError]:
        """
        Remove duplicate validation errors caused by lossy schema-error formatting.

        The underlying validator can produce distinct schema errors that are rendered
        with the same source, kind, and message. Keep only the first occurrence for
        clearer user-facing output.
        """
        seen = set()
        unique = []

        for error in errors:
            if  (key := (error.source, error.kind, error.message)) not in seen:
                seen.add(key)
                unique.append(error)

        return unique

    def validate(  # pylint: disable=too-many-return-statements  # noqa: PLR0911
        self, document: dict[str, Any] | None = None, file_path: str | Path | None = None
    ) -> ValidationResult:
        """
        Validate SPDX 3.0.1 document from file.

        Args:
            document: Parsed SPDX 3.0.1 document to validate.
            file_path: Path to SPDX JSON file.

        Returns:
            Validation result
        """
        all_messages: list[ValidationMessage] = []
        schema_valid = True
        semantic_valid = True
        try:
            with _validation_source(document, file_path) as source_path:
                result: CustomValidationResult = validate(
                    sources=str(source_path), version=SPDX_VERSION
                )
            if result.valid:
                return ValidationResult(
                    is_valid=True,
                    messages=all_messages,
                    schema_valid=schema_valid,
                    semantic_valid=semantic_valid,
                )

            errors = self._unique_errors(result.errors)
            schema_errors = [error for error in errors if error.kind == "schema"]
            for error in schema_errors:
                schema_valid = False
                all_messages.append(
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Schema validation error: {error.message}",
                        rule_id="json_schema",
                        field_path=(
                            error.message.split(":", 1)[0]
                            if error.message.startswith("$")
                            else None
                        ),
                    )
                )

            shacl_errors = [error for error in errors if error.kind == "shacl"]
            for error in shacl_errors:
                semantic_valid = False
                shacl_error = ShaclDiagnosticParser.parse_shacl_error(error.message)
                all_messages.append(shacl_error)

            return ValidationResult(
                is_valid=False,
                messages=all_messages,
                schema_valid=schema_valid,
                semantic_valid=semantic_valid,
            )
        except UnknownVersionError as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Unsupported SPDX version: {e}",
                        rule_id="unsupported_spdx_version",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
        except SpdxValidateError as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"SPDX validation error: {e}",
                        rule_id="spdx_validate_error",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
        except FileNotFoundError:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"File not found: {file_path}",
                        rule_id="file_read_error",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
        except (URLError, TimeoutError, ConnectionError) as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "SPDX validation could not be completed because a "
                            f"required remote resource was unavailable: {e}"
                        ),
                        rule_id="spdx3_remote_resource_unavailable",
                        remediation=(
                            "Make the required SPDX validation resources available "
                            "and run validation again."
                        ),
                    )
                ],
                # Resource availability is neither a schema nor a semantic
                # failure in the submitted SBOM.
                schema_valid=True,
                semantic_valid=True,
            )
        except JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Invalid JSON: {e!s}",
                        rule_id="json_parse_error",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
        except ValueError as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Invalid SPDX 3 validation input: {e}",
                        rule_id="spdx3_validation_input_error",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
