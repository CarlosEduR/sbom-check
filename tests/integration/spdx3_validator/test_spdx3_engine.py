# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Integration tests for the SPDX 3 validation engine."""

import json
import socket
from pathlib import Path

import pytest

from spdx3_validator.engine import ValidationEngine

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
MINIMAL_DOCUMENT = FIXTURES_DIR / "minimal-spdx3.0.1.spdx.json"


class TestSpdx3ValidationIntegration:
    """Tests that exercise the real spdx3-validate integration."""

    def test_valid_minimal_document(self) -> None:
        """Validate a minimal SPDX 3.0.1 document successfully."""
        result = ValidationEngine().validate_file(str(MINIMAL_DOCUMENT))

        assert result.is_valid is True
        assert result.schema_valid is True
        assert result.semantic_valid is True
        assert result.messages == []

    def test_missing_required_attribute_reports_schema_message(
        self, tmp_path: Path
    ) -> None:
        """Report a schema error when a required object attribute is missing."""
        document_data = json.loads(MINIMAL_DOCUMENT.read_text(encoding="utf-8"))
        agent = next(
            node for node in document_data["@graph"] if node.get("type") == "Agent"
        )
        del agent["type"]
        invalid_document = tmp_path / "missing-agent-type.spdx.json"
        invalid_document.write_text(json.dumps(document_data), encoding="utf-8")

        result = ValidationEngine().validate_file(str(invalid_document))

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        message = result.messages[0]
        assert message.rule_id == "json_schema"
        assert message.field_path == "$['@graph'][2]"
        assert message.message == (
            "Schema validation error: $['@graph'][2]: Is not valid"
        )

    def test_remote_resource_failure_is_not_reported_as_content_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Report unavailable remote resources separately from SBOM failures."""

        def deny_network(*args: object, **kwargs: object) -> None:
            raise OSError("network disabled")

        monkeypatch.setattr(socket.socket, "connect", deny_network)

        result = ValidationEngine().validate_file(str(MINIMAL_DOCUMENT))

        assert result.is_valid is False
        assert result.schema_valid is True
        assert result.semantic_valid is True
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "spdx3_remote_resource_unavailable"
        assert "required remote resource was unavailable" in result.messages[0].message

    def test_invalid_shacl_document_reports_affected_elements(
        self, tmp_path: Path
    ) -> None:
        """Preserve SHACL focus nodes as affected elements."""
        document_data = json.loads(MINIMAL_DOCUMENT.read_text(encoding="utf-8"))
        document_data["@graph"][0]["creationInfo"] = "_:MissingCreationInfo"
        invalid_document = tmp_path / "invalid-shacl.spdx.json"
        invalid_document.write_text(json.dumps(document_data), encoding="utf-8")

        result = ValidationEngine().validate_file(str(invalid_document))

        assert result.is_valid is False
        assert result.semantic_valid is False
        assert result.messages
        assert any(
            message.affected_element and message.field_path == "creationInfo"
            for message in result.messages
        )

    def test_unknown_spdx_version_returns_validation_message(
        self, tmp_path: Path
    ) -> None:
        """Reject a document using an unknown SPDX version."""
        document_data = json.loads(MINIMAL_DOCUMENT.read_text(encoding="utf-8"))
        document_data["@context"] = "https://spdx.org/rdf/4.0.0/spdx-context.jsonld"
        unknown_version = tmp_path / "unknown-version.spdx.json"
        unknown_version.write_text(json.dumps(document_data), encoding="utf-8")

        result = ValidationEngine().validate_file(str(unknown_version))

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "unsupported_spdx_version"
        assert "Unsupported SPDX version" in result.messages[0].message

    def test_recognized_but_incompatible_spdx_version_returns_validation_message(
        self, tmp_path: Path
    ) -> None:
        """Reject a recognized SPDX version other than the requested version."""
        document_data = json.loads(MINIMAL_DOCUMENT.read_text(encoding="utf-8"))
        document_data["@context"] = "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"
        incompatible_version = tmp_path / "incompatible-version.spdx.json"
        incompatible_version.write_text(json.dumps(document_data), encoding="utf-8")

        result = ValidationEngine().validate_file(str(incompatible_version))

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "spdx_validate_error"
        assert "incompatible version 3.0.0" in result.messages[0].message

    def test_missing_required_agent_reports_formatted_message(
        self, tmp_path: Path
    ) -> None:
        """Report a missing agent referenced by the document."""
        document_data = json.loads(MINIMAL_DOCUMENT.read_text(encoding="utf-8"))
        document_data["@graph"] = [
            node for node in document_data["@graph"] if node.get("type") != "Agent"
        ]
        missing_agent = tmp_path / "missing-agent.spdx.json"
        missing_agent.write_text(json.dumps(document_data), encoding="utf-8")

        result = ValidationEngine().validate_file(str(missing_agent))

        assert result.is_valid is False
        assert result.schema_valid is True
        assert result.semantic_valid is False
        assert len(result.messages) == 2
        assert {message.affected_element for message in result.messages} == {
            "_:ci",
            "_:ci2",
        }
        for message in result.messages:
            assert message.rule_id == "spdx3_shacl_class_constraint"
            assert message.message == (
                "The 'createdBy' value must reference an SPDX Agent element."
            )
            assert message.field_path == "createdBy"
            assert message.found_value == "https://example.com/agent"
            assert message.expected_value == "SPDX Agent"
            assert message.remediation == (
                "Provide a reference to an SPDX Agent element and ensure the "
                "referenced element has the required type."
            )

    def test_invalid_json_returns_validation_message(self, tmp_path: Path) -> None:
        """Report a document that cannot be decoded as JSON."""
        invalid_document = tmp_path / "invalid-json.spdx.json"
        invalid_document.write_text('{"@context":', encoding="utf-8")

        result = ValidationEngine().validate_file(str(invalid_document))

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "json_parse_error"
        assert "Invalid JSON" in result.messages[0].message

    def test_missing_context_returns_validation_message(self, tmp_path: Path) -> None:
        """Report a document that does not contain an @context."""
        document = tmp_path / "missing-context.spdx.json"
        document.write_text(json.dumps({"@graph": []}), encoding="utf-8")

        result = ValidationEngine().validate_file(str(document))

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "spdx_validate_error"
        assert "No @context found" in result.messages[0].message
