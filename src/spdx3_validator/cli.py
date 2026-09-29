from pathlib import Path

import sys
import click
from typing import Any

from sbom_check.models import ValidationSeverity
from spdx3_validator.engine import ValidationEngine
from spdx_validator.models import ValidationResult

def collect_spdx_files(
    paths: tuple[Path, ...], recursive: bool, pattern: str
) -> list[Path]:
    """Collect all SPDX files from the given paths."""
    files = []

    for path in paths:
        if path.is_file():
            files.append(path.resolve())
        elif path.is_dir():
            if recursive:
                files.extend(p.resolve() for p in path.rglob(pattern))
            else:
                files.extend(p.resolve() for p in path.glob(pattern))
        else:
            click.echo(f"Warning: {path} is neither a file nor directory", err=True)

    # Sort for consistent output
    return sorted(files)



def output_text(result: Any, file_path: Path) -> None:
    """Output validation results in human-readable text format."""
    click.echo(f"Validating: {file_path}")

    # Color-coded validation status
    if result.is_valid:
        status_text = click.style("Valid: True ✅", fg="green", bold=True)
    else:
        status_text = click.style("Valid: False ❌", fg="red", bold=True)
    click.echo(status_text)

    if result.messages:
        click.echo("\nValidation Messages:")
        click.echo("-" * 50)

        for msg in result.messages:
            severity_color = {
                ValidationSeverity.ERROR: "red",
                ValidationSeverity.WARNING: "yellow",
                ValidationSeverity.INFO: "blue",
            }.get(msg.severity, "white")

            click.echo(
                f"[{click.style(msg.severity.value.upper(), fg=severity_color)}] "
                f"{msg.message}"
            )

            if msg.rule_id:
                click.echo(f"  Rule: {msg.rule_id}")

            click.echo()

    # Summary
    error_count = sum(
        1 for msg in result.messages if msg.severity == ValidationSeverity.ERROR
    )
    warning_count = sum(
        1 for msg in result.messages if msg.severity == ValidationSeverity.WARNING
    )

    click.echo(f"Summary: {error_count} errors, {warning_count} warnings")

def output_text_multiple(results: list[tuple[Path, ValidationResult]]) -> None:
    """Output validation results for multiple files in human-readable text format."""
    total_files = len(results)
    valid_files = sum(1 for _, result in results if result.is_valid)
    invalid_files = total_files - valid_files

    # Color-coded summary header
    valid_text = click.style(f"{valid_files} valid", fg="green", bold=True)
    invalid_text = click.style(f"{invalid_files} invalid", fg="red", bold=True)
    click.echo(f"Validated {total_files} files: {valid_text}, {invalid_text}")
    click.echo("=" * 80)

    for file_path, result in results:
        output_text(result, file_path)
        if result != results[-1][1]:  # Not the last result
            click.echo()

    # Color-coded overall summary
    click.echo("=" * 80)
    if valid_files == total_files:
        summary_color = "green"
        summary_text = f"Overall: {valid_files}/{total_files} files valid ✅"
    elif valid_files == 0:
        summary_color = "red"
        summary_text = f"Overall: {valid_files}/{total_files} files valid ❌"
    else:
        summary_color = "yellow"
        summary_text = f"Overall: {valid_files}/{total_files} files valid ⚠️"

    click.echo(click.style(summary_text, fg=summary_color, bold=True))



@click.command()
@click.argument(
    "paths",
    nargs=-1,
    required=True,
    # type=click.Path(exists=True, path_type=Path)
)
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format for validation results",
)
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help="Recursively scan directories for SPDX files",
)
@click.option(
    "--pattern",
    default="*.spdx.json",
    help="File pattern to match when scanning directories (default: *.spdx.json)",
)
def main(
    paths: tuple[Path, ...],
    output_format: str,
    recursive: bool,
    pattern: str,
):
    """Validate SPDX 3.0.1 JSON-LD format documents."""

    # if not (files_to_validate := collect_spdx_files(paths, recursive, pattern)):
    #     click.echo("No SPDX files found to validate.", err=True)
    #     sys.exit(1)

    engine = ValidationEngine()
    results = []

    # if len(files_to_validate) == 1:
    #     # Single file - no need for parallel processing
    #     file_path = files_to_validate[0]
    #     result = engine.validate_file(str(file_path))

    file_path = str(paths[0])
    result = engine.validate_file(file_path)
    results.append((file_path, result))

    # Output results
    output_text_multiple(results)