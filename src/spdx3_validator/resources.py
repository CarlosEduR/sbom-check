# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Process-local SPDX 3 validation resources."""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass
from functools import lru_cache
from urllib.request import urlopen

import jsonschema
import rdflib
from spdx3_validate.core import SpdxValidateError, schema_validator
from spdx3_validate.spdx_versions import SpdxVersion, find_version

SPDX_VERSION = "3.0.1"
SPDX_CONTEXT_URL = f"https://spdx.org/rdf/{SPDX_VERSION}/spdx-context.jsonld"
SPDX_SCHEMA_URL = "https://spdx.org/schema/3.0.1/spdx-json-schema.json"
SPDX_SHACL_URL = "https://spdx.org/rdf/3.0.1/spdx-model.ttl"
VALIDATION_RESOURCE_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class ValidationResources:
    """Cached resources required to validate SPDX documents."""

    schema_validator: jsonschema.protocols.Validator
    shacl_graph: rdflib.Graph
    version: SpdxVersion


def configure_network_timeout() -> None:
    """Set the default socket timeout used by rdflib context resolution."""
    socket.setdefaulttimeout(VALIDATION_RESOURCE_TIMEOUT_SECONDS)


@lru_cache(maxsize=1)
def load_validation_resources() -> ValidationResources:
    """Load and cache SPDX schema and SHACL resources for this process."""
    if (version := find_version(SPDX_CONTEXT_URL)) is None:
        raise SpdxValidateError(f"Unknown SPDX version {SPDX_VERSION}")

    # Keep these URLs fixed rather than passing values from SpdxVersion to
    # urlopen. urllib supports file:// URLs, so using a URL supplied by a
    # mutable dependency object could turn resource loading into local-file
    # access. SPDX_VERSION is fixed by this validator, and these are the
    # corresponding canonical SPDX 3.0.1 resources.
    with urlopen(
        "https://spdx.org/schema/3.0.1/spdx-json-schema.json",
        timeout=VALIDATION_RESOURCE_TIMEOUT_SECONDS,
    ) as response:
        schema = json.load(response)

    with urlopen(
        "https://spdx.org/rdf/3.0.1/spdx-model.ttl",
        timeout=VALIDATION_RESOURCE_TIMEOUT_SECONDS,
    ) as response:
        shacl_data = response.read()

    shacl_graph = rdflib.Graph()
    shacl_graph.parse(
        data=shacl_data.decode("utf-8"),
        format="turtle",
        publicID=SPDX_SHACL_URL,
    )

    try:
        validator = schema_validator(schema)
    except jsonschema.exceptions.SchemaError as error:
        raise SpdxValidateError(f"Invalid schema {SPDX_SCHEMA_URL}: {error}") from error

    return ValidationResources(validator, shacl_graph, version)
