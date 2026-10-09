# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the SPDX 3 validator CLI."""

from unittest.mock import patch

from click.testing import CliRunner

from spdx3_validator.cli import main
from spdx3_validator.models import (
    ValidationMessage,
    ValidationResult,
    ValidationSeverity,
)


def test_remote_resource_failure_has_distinct_exit_code(tmp_path):
    """Use a distinct exit code when SPDX resources are unavailable."""
    document = tmp_path / "document.spdx.json"
    document.write_text("{}", encoding="utf-8")
    validation_result = ValidationResult(
        is_valid=False,
        schema_valid=None,
        semantic_valid=None,
        messages=[
            ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message="remote resource unavailable",
                rule_id="spdx3_remote_resource_unavailable",
            )
        ],
    )

    with patch("spdx3_validator.cli.validate_single_file") as validate_file:
        validate_file.return_value = (document, validation_result)
        result = CliRunner().invoke(main, [str(document)])

    assert result.exit_code == 4
