import re
from sbom_check.models import ValidationMessage, ValidationSeverity


class ShaclDiagnosticParser:
    """Parse spdx3-validate SHACL output into vendor-facing messages."""

    @staticmethod
    def _local_name(value: str | None) -> str | None:
        if not value or value == "-":
            return None
        return value.rsplit("/", 1)[-1]

    @staticmethod
    def _match_value(match: re.Match[str] | None) -> str | None:
        if not match:
            return None
        return match.group(1) or match.group(2)

    @staticmethod
    def parse_shacl_error(error_text: str) -> ValidationMessage:
        constraint = re.search(r"Violation of type sh:(\w+)", error_text)
        focus = re.search(r"Focus Node:\s*(?:<([^>]+)>|(\S+))", error_text)
        value = re.search(r"Value Node:\s*(?:<([^>]+)>|(\S+))", error_text)
        result_path = re.search(r"Result path:\s*(?:<([^>]+)>|(\S+))", error_text)
        expected_class = re.search(r"sh:class <([^>]+)>", error_text)
        detail = re.search(r"Message:\s*(.+)", error_text)

        constraint_name = constraint.group(1) if constraint else "GenericViolation"
        focus_node = ShaclDiagnosticParser._match_value(focus)
        value_node = ShaclDiagnosticParser._match_value(value)
        path = ShaclDiagnosticParser._match_value(result_path)
        expected = (
            ShaclDiagnosticParser._local_name(expected_class.group(1))
            if expected_class
            else None
        )

        field_name = ShaclDiagnosticParser._local_name(path)
        detail_text = detail.group(1).strip() if detail else "SHACL validation failed"

        if constraint_name == "ClassConstraintComponent" and expected:
            if value_node and value_node.startswith("http"):
                message = (
                    f"The value referenced by '{field_name}' does not resolve to "
                    f"a declared SPDX {expected} element."
                )
                remediation = (
                    f"Ensure the referenced element exists and is declared with "
                    f"the correct SPDX type, such as {expected}."
                )
            else:
                message = (
                    f"The '{field_name}' value must reference an SPDX {expected} "
                    "element."
                )
                remediation = (
                    f"Provide a valid reference to an SPDX {expected} element."
                )

            return ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message=message,
                rule_id="spdx3_shacl_class_constraint",
                field_path=field_name,
                expected_value=f"SPDX {expected}",
                found_value=value_node,
                remediation=remediation,
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
            found_value=value_node,
            remediation="Review the referenced SPDX 3.0.1 property and value.",
        )
