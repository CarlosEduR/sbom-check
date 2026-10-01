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


def _document() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("mutate", "rule_id", "field_path", "found_value"),
    [
        (
            lambda document: document["@graph"][1].pop("createdBy"),
            "spdx3_shacl_mincountconstraintcomponent",
            "createdBy",
            "-",
        ),
        (
            lambda document: document["@graph"][2].__setitem__(
                "name", ["a", "b"]
            ),
            "spdx3_shacl_maxcountconstraintcomponent",
            "name",
            "-",
        ),
        (
            lambda document: document["@graph"][1].__setitem__(
                "created", "not-a-date"
            ),
            "spdx3_shacl_patternconstraintcomponent",
            "created",
            '"not-a-date"^^<http://www.w3.org/2001/XMLSchema#dateTimeStamp>',
        ),
        (
            lambda document: document["@graph"][2].__setitem__("name", 123),
            "spdx3_shacl_datatypeconstraintcomponent",
            "name",
            '"123"^^<http://www.w3.org/2001/XMLSchema#string>',
        ),
    ],
    ids=["missing-createdBy", "multiple-agent-names", "invalid-created", "numeric-agent-name"],
)
def test_parser_translates_generic_shacl_constraints(
    mutate: object,
    rule_id: str,
    field_path: str,
    found_value: str,
    tmp_path: Path,
) -> None:
    """Preserve the current generic translation for common constraints."""
    document = _document()
    mutate(document)  # type: ignore[operator]

    messages = _shacl_messages(document, tmp_path / "diagnostic.spdx.json")

    assert len(messages) == 1
    message = messages[0]
    assert message.rule_id == rule_id
    assert message.field_path == field_path
    assert message.found_value == found_value
    assert message.expected_value is None
    assert message.remediation == "Review the referenced SPDX 3.0.1 property and value."
    assert message.message.startswith("SPDX 3.0.1 constraint violation: ")


def test_parser_translates_repeated_class_constraints(tmp_path: Path) -> None:
    """Preserve the current specialized translation for repeated class errors."""
    document = _document()
    document["@graph"][2]["type"] = "NotAnAgent"

    messages = _shacl_messages(document, tmp_path / "class-diagnostic.spdx.json")

    assert len(messages) == 2
    assert {message.affected_element for message in messages} == {"_:ci", "_:ci2"}
    for message in messages:
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
