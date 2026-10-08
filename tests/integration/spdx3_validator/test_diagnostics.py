# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Integration tests for SPDX 3 SHACL diagnostic translation."""

import json
from pathlib import Path

import pytest
from spdx3_validate import validate

from spdx3_validator.diagnostics import ShaclDiagnosticParser

FIXTURE = Path(__file__).parent.parent / "fixtures" / "minimal-spdx3.0.1.spdx.json"


def _shacl_messages(document: dict, path: Path) -> list:
    """Validate a document and translate only its SHACL errors."""
    path.write_text(json.dumps(document), encoding="utf-8")
    result = validate(str(path), version="3.0.1")
    return [
        ShaclDiagnosticParser.parse_shacl_error(error.message)
        for error in result.errors
        if error.kind == "shacl"
    ]


@pytest.mark.integration
class TestShaclDiagnosticParser:
    """Integration tests for SHACL diagnostic translation."""

    def test_parser_translates_mincount_constraint(self, tmp_path: Path):
        """Translate a missing required property."""
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        document["@graph"][1].pop("createdBy")

        messages = _shacl_messages(document, tmp_path / "mincount-diagnostic.spdx.json")

        assert len(messages) == 1
        message = messages[0]
        assert message.rule_id == "spdx3_shacl_mincount_constraint"
        assert message.section_reference == "SPDX 3.0.1 SHACL validation"
        assert message.field_path == "createdBy"
        assert message.found_value == "-"
        assert message.expected_value == "at least 1 value(s)"
        assert message.message == (
            "The 'createdBy' property must contain at least 1 value(s)."
        )
        assert message.remediation == "Provide at least 1 value(s)."

    def test_parser_translates_maxcount_constraint(self, tmp_path: Path):
        """Translate a property with too many values."""
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        document["@graph"][2]["name"] = ["a", "b"]

        messages = _shacl_messages(document, tmp_path / "maxcount-diagnostic.spdx.json")

        assert len(messages) == 1
        message = messages[0]
        assert message.rule_id == "spdx3_shacl_maxcount_constraint"
        assert message.section_reference == "SPDX 3.0.1 SHACL validation"
        assert message.field_path == "name"
        assert message.found_value == "-"
        assert message.expected_value == "at most 1 value(s)"
        assert message.message == (
            "The 'name' property must contain at most 1 value(s)."
        )
        assert message.remediation == "Provide at most 1 value(s)."

    def test_parser_translates_pattern_constraint(self, tmp_path: Path):
        """Translate a value that does not match a required pattern."""
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        document["@graph"][1]["created"] = "not-a-date"

        messages = _shacl_messages(document, tmp_path / "pattern-diagnostic.spdx.json")

        assert len(messages) == 1
        message = messages[0]
        assert message.rule_id == "spdx3_shacl_pattern_constraint"
        assert message.section_reference == "SPDX 3.0.1 SHACL validation"
        assert message.field_path == "created"
        assert message.found_value == (
            '"not-a-date"^^<http://www.w3.org/2001/XMLSchema#dateTimeStamp>'
        )
        assert message.expected_value == r"^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ$"
        assert message.message == (
            "The 'created' value does not match the required pattern."
        )
        assert message.remediation == (
            "Provide a value that matches the required SPDX format."
        )

    def test_parser_translates_datatype_constraint(self, tmp_path: Path):
        """Translate a value with an invalid datatype."""
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        document["@graph"][2]["name"] = 123

        messages = _shacl_messages(document, tmp_path / "datatype-diagnostic.spdx.json")

        assert len(messages) == 1
        message = messages[0]
        assert message.rule_id == "spdx3_shacl_datatype_constraint"
        assert message.section_reference == "SPDX 3.0.1 SHACL validation"
        assert message.field_path == "name"
        assert message.found_value == (
            '"123"^^<http://www.w3.org/2001/XMLSchema#string>'
        )
        assert message.expected_value == "xsd:string"
        assert message.message == "The 'name' value must have datatype xsd:string."
        assert message.remediation == "Provide a value with datatype xsd:string."

    def test_parser_translates_repeated_class_constraints(self, tmp_path: Path):
        """Preserve the current specialized translation for repeated class errors."""
        document = json.loads(FIXTURE.read_text(encoding="utf-8"))
        document["@graph"][2]["type"] = "NotAnAgent"

        messages = _shacl_messages(document, tmp_path / "class-diagnostic.spdx.json")

        assert len(messages) == 2
        assert {message.affected_element for message in messages} == {
            "_:ci",
            "_:ci2",
        }
        for message in messages:
            assert message.rule_id == "spdx3_shacl_class_constraint"
            assert message.section_reference == "SPDX 3.0.1 SHACL validation"
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
