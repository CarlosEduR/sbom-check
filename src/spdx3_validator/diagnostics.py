# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Translate SPDX 3 SHACL validation errors into diagnostic messages."""

import re

from spdx3_validator.models import ValidationMessage, ValidationSeverity

SHACL_SECTION_REFERENCE = "SPDX 3.0.1 SHACL validation"


def _local_name(value: str | None) -> str | None:
    if not value or value == "-":
        return None
    return value.rsplit("/", 1)[-1]


def _match_value(match: re.Match[str] | None) -> str | None:
    if not match:
        return None
    return match.group(1) or match.group(2)


def _shape_value(error_text: str, property_name: str) -> str | None:
    match = re.search(rf"sh:{property_name}\s+([^;\n]+)", error_text)
    return match.group(1).strip() if match else None


def _property_label(field_name: str | None) -> str:
    return f"'{field_name}'" if field_name else "this property"


class ShaclDiagnosticParser:
    """Parse spdx3-validate SHACL output into vendor-facing messages."""

    @staticmethod
    def parse_shacl_error(  # pylint: disable=too-many-locals,too-many-return-statements  # noqa: PLR0911
        error_text: str,
    ) -> ValidationMessage:
        """Translate only facts explicitly present in the SHACL result.

        The result text does not reliably contain enough information to classify
        a class failure as a missing, untyped, or incorrectly typed target, so
        this parser intentionally reports the common, accurate constraint.
        """
        constraint = re.search(r"Violation of type sh:(\w+)", error_text)
        focus = re.search(r"Focus Node:\s*(?:<([^>]+)>|(\S+))", error_text)
        value = re.search(r"Value Node:\s*(?:<([^>]+)>|(\S+))", error_text)
        result_path = re.search(r"Result path:\s*(?:<([^>]+)>|(\S+))", error_text)
        expected_class = re.search(r"sh:class <([^>]+)>", error_text)
        detail = re.search(r"Message:\s*(.+)", error_text)

        constraint_name = constraint.group(1) if constraint else "GenericViolation"
        focus_node = _match_value(focus)
        value_node = _match_value(value)
        path = _match_value(result_path)
        expected = _local_name(expected_class.group(1)) if expected_class else None

        # A SHACL result path of '-' means that the violation is on the node,
        # rather than on a property.  _local_name deliberately maps it to None.
        field_name = _local_name(path)
        detail_text = detail.group(1).strip() if detail else "SHACL validation failed"

        if constraint_name == "ClassConstraintComponent" and expected:
            property_label = _property_label(field_name)
            return ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message=(
                    f"The {property_label} value must reference an SPDX {expected} "
                    "element."
                ),
                rule_id="spdx3_shacl_class_constraint",
                field_path=field_name,
                section_reference=SHACL_SECTION_REFERENCE,
                affected_element=focus_node,
                expected_value=f"SPDX {expected}",
                found_value=value_node,
                remediation=(
                    f"Provide a reference to an SPDX {expected} element and ensure "
                    "the referenced element has the required type."
                ),
            )

        property_label = _property_label(field_name)

        if constraint_name == "MinCountConstraintComponent":
            minimum = _shape_value(error_text, "minCount")
            expected_value = f"at least {minimum} value(s)" if minimum else None
            return ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message=(
                    f"The {property_label} property must contain "
                    f"{expected_value or 'the minimum required number of values'}."
                ),
                rule_id="spdx3_shacl_mincount_constraint",
                field_path=field_name,
                section_reference=SHACL_SECTION_REFERENCE,
                affected_element=focus_node,
                found_value=value_node,
                expected_value=expected_value,
                remediation=(
                    f"Provide {expected_value or 'the required number of values'}."
                ),
            )

        if constraint_name == "MaxCountConstraintComponent":
            maximum = _shape_value(error_text, "maxCount")
            expected_value = f"at most {maximum} value(s)" if maximum else None
            return ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message=(
                    f"The {property_label} property must contain "
                    f"{expected_value or 'no more than the maximum allowed number of values'}."
                ),
                rule_id="spdx3_shacl_maxcount_constraint",
                field_path=field_name,
                section_reference=SHACL_SECTION_REFERENCE,
                affected_element=focus_node,
                found_value=value_node,
                expected_value=expected_value,
                remediation=(
                    f"Provide {expected_value or 'no more than the allowed number of values'}."
                ),
            )

        if constraint_name == "DatatypeConstraintComponent":
            datatype = _shape_value(error_text, "datatype")
            datatype_name = _local_name(datatype.strip("<>") if datatype else None)
            expected_value = datatype_name or datatype
            return ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message=(
                    f"The {property_label} value must have datatype "
                    f"{expected_value or 'the required datatype'}."
                ),
                rule_id="spdx3_shacl_datatype_constraint",
                field_path=field_name,
                section_reference=SHACL_SECTION_REFERENCE,
                affected_element=focus_node,
                found_value=value_node,
                expected_value=expected_value,
                remediation=(
                    f"Provide a value with datatype "
                    f"{expected_value or 'required by the SPDX property'}."
                ),
            )

        if constraint_name == "PatternConstraintComponent":
            if pattern := _shape_value(error_text, "pattern"):
                pattern = pattern.rstrip(" .").strip("'\"").replace("\\\\", "\\")
            return ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message=f"The {property_label} value does not match the required pattern.",
                rule_id="spdx3_shacl_pattern_constraint",
                field_path=field_name,
                section_reference=SHACL_SECTION_REFERENCE,
                affected_element=focus_node,
                found_value=value_node,
                expected_value=pattern,
                remediation="Provide a value that matches the required SPDX format.",
            )

        if constraint_name == "InConstraintComponent":
            return ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message=f"The {property_label} value is not one of the allowed values.",
                rule_id="spdx3_shacl_in_constraint",
                field_path=field_name,
                section_reference=SHACL_SECTION_REFERENCE,
                affected_element=focus_node,
                found_value=value_node,
                remediation="Use one of the values allowed by the SPDX property.",
            )

        if constraint_name == "NodeKindConstraintComponent":
            return ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message=(
                    "An SPDX element is represented as an anonymous blank node, "
                    "but this element must have an IRI identifier."
                ),
                rule_id="spdx3_shacl_node_kind_constraint",
                field_path=field_name,
                section_reference=SHACL_SECTION_REFERENCE,
                affected_element=focus_node,
                found_value=value_node,
                expected_value="IRI",
                remediation=(
                    "Add a unique spdxId to the SPDX element and ensure references "
                    "use that identifier."
                ),
            )

        return ValidationMessage(
            severity=ValidationSeverity.ERROR,
            message=f"SPDX 3.0.1 constraint violation: {detail_text}",
            rule_id=f"spdx3_shacl_{constraint_name.lower()}",
            field_path=field_name,
            section_reference=SHACL_SECTION_REFERENCE,
            affected_element=focus_node,
            found_value=value_node,
            remediation="Review the referenced SPDX 3.0.1 property and value.",
        )
