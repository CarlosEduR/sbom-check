# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the SPDX 3 validation engine."""

from unittest.mock import Mock, patch

from spdx3_validate.core import (
    SpdxValidateError,
    UnknownVersionError,
    ValidationError as CustomValidationError,
    ValidationResult as CustomValidationResult,
)

from spdx3_validator.engine import ValidationEngine


class TestValidationEngine:
    """Test cases for the SPDX 3 validation engine."""

    def test_validate_without_document_or_file_path(self):
        """Test handling of missing validation input."""
        result = ValidationEngine().validate()

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "spdx3_validation_input_error"
        assert result.messages[0].message == (
            "Invalid SPDX 3 validation input: "
            "Either document or file_path must be provided"
        )

    @patch("spdx3_validator.engine.validate")
    def test_validate_file_success(self, mock_validate: Mock) -> None:
        """Test successful validation without invoking the real validator."""
        mock_validate.return_value = CustomValidationResult()

        result = ValidationEngine().validate(file_path="test.spdx.json")

        assert result.is_valid is True
        assert result.schema_valid is True
        assert result.semantic_valid is True
        assert result.messages == []
        mock_validate.assert_called_once_with(sources="test.spdx.json", version="3.0.1")

    @patch("spdx3_validator.engine.validate")
    def test_validate_file_missing_context(self, mock_validate: Mock) -> None:
        """Test handling of a document without an @context."""
        mock_validate.side_effect = SpdxValidateError(
            "No @context found in test.spdx.json"
        )

        result = ValidationEngine().validate(file_path="test.spdx.json")

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "spdx_validate_error"
        assert result.messages[0].message == (
            "SPDX validation error: No @context found in test.spdx.json"
        )

    @patch("spdx3_validator.engine.validate")
    def test_validate_file_unknown_version(self, mock_validate: Mock) -> None:
        """Test handling of an unsupported SPDX context version."""
        mock_validate.side_effect = UnknownVersionError(
            "test.spdx.json has unknown version"
        )

        result = ValidationEngine().validate(file_path="test.spdx.json")

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "unsupported_spdx_version"
        assert result.messages[0].message == (
            "Unsupported SPDX version: test.spdx.json has unknown version"
        )

    @patch("spdx3_validator.engine.validate")
    def test_validate_file_schema_and_shacl_errors(self, mock_validate: Mock) -> None:
        """Test conversion of both schema and SHACL errors."""
        schema_error = CustomValidationError(
            "test.spdx.json",
            "schema",
            "Document does not conform to the SPDX schema",
        )
        shacl_error = CustomValidationError(
            "test.spdx.json",
            "shacl",
            """Violation of type sh:ClassConstraintComponent:
                sh:class <https://spdx.org/rdf/3.0.1/terms/Core/CreationInfo>
                Focus Node: <https://example.com/package/example>
                Value Node: _:CreationInfo2
                Result path: <https://spdx.org/rdf/3.0.1/terms/Core/creationInfo>
                Message: Value does not have class ns1:CreationInfo""",
        )
        mock_validate.return_value = CustomValidationResult(
            errors=[schema_error, shacl_error]
        )

        result = ValidationEngine().validate(file_path="test.spdx.json")

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 2

        schema_message, shacl_message = result.messages
        assert schema_message.rule_id == "json_schema"
        assert schema_message.field_path is None
        assert schema_message.message == (
            "Schema validation error: Document does not conform to the SPDX schema"
        )
        assert shacl_message.rule_id == "spdx3_shacl_class_constraint"
        assert shacl_message.affected_element == "https://example.com/package/example"
        assert shacl_message.field_path == "creationInfo"
        assert shacl_message.found_value == "_:CreationInfo2"

    @patch("spdx3_validator.engine.validate")
    def test_validate_file_shacl_error_preserves_affected_element(
        self, mock_validate: Mock
    ) -> None:
        """Test conversion of SHACL focus nodes into affected elements."""
        error = CustomValidationError(
            "test.spdx.json",
            "shacl",
            """Violation of type sh:ClassConstraintComponent:
                sh:class <https://spdx.org/rdf/3.0.1/terms/Core/CreationInfo>
                Focus Node: <https://example.com/package/example>
                Value Node: _:CreationInfo2
                Result path: <https://spdx.org/rdf/3.0.1/terms/Core/creationInfo>
                Message: Value does not have class ns1:CreationInfo""",
        )
        mock_validate.return_value = CustomValidationResult(errors=[error])

        result = ValidationEngine().validate(file_path="test.spdx.json")

        assert result.is_valid is False
        assert result.schema_valid is True
        assert result.semantic_valid is False
        assert len(result.messages) == 1

        message = result.messages[0]
        assert message.rule_id == "spdx3_shacl_class_constraint"
        assert message.affected_element == "https://example.com/package/example"
        assert message.field_path == "creationInfo"
        assert message.found_value == "_:CreationInfo2"
