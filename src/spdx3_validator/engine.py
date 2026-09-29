from sbom_check.models import ValidationMessage, ValidationSeverity
from spdx3_validate import validate
from spdx3_validate.core import ValidationResult as CustomValidationResult
from spdx3_validate.core import ValidationError as CustomValidationError
from spdx3_validator.diagnostics import ShaclDiagnosticParser
from spdx3_validator.models import ValidationResult

SPDX_VERSION = "3.0.1"


class ValidationEngine:
    def __init__(self):
        """Initialize the validation enginer for SPDX 3.0.1."""

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
            key = (error.source, error.kind, error.message)
            if key not in seen:
                seen.add(key)
                unique.append(error)

        return unique

    def validate_file(self, file_path: str) -> ValidationResult:
        """
        Validate SPDX 3.0.1 document from file.

        Args:
            file_path: Path to SPDX JSON file

        Returns:
            Validation result
        """
        print("Running validation on file:", file_path)
        all_messages: list[ValidationMessage] = []
        schema_valid = True
        semantic_valid = True
        try:
            result: CustomValidationResult = validate(
                sources=file_path, version=SPDX_VERSION
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
            if schema_errors:
                for error in schema_errors:
                    schema_valid = False
                    all_messages.append(
                        ValidationMessage(
                            severity=ValidationSeverity.ERROR,
                            message=f"Schema validation error: {error.message}",
                            rule_id="json_schema",
                        )
                    )

                return ValidationResult(
                    is_valid=False,
                    messages=all_messages,
                    schema_valid=False,
                    semantic_valid=False,
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
