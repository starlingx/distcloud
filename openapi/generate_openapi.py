#!/usr/bin/env python3
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
OpenAPI Specification Generator for StarlingX Distributed Cloud Manager API

Functionality:
    Automatically generates OpenAPI 3.0.2 specification from Pecan controller docstrings
    in the StarlingX Distributed Cloud Manager project. Extracts API documentation
    embedded in method docstrings and combines it with predefined schemas to create
    a complete, standards-compliant OpenAPI specification.

Implementation Details:
    - Scans Pecan controller files for methods with OpenAPI YAML in docstrings
    - Extracts YAML content after '---' delimiter in method docstrings
    - Loads additional schemas from openapi_schemas.yaml
    - Uses apispec library to build OpenAPI 3.0.2 specification
    - Includes OpenStack Keystone authentication (X-Auth-Token) and OIDC
      authentication (OIDC-Token)
    - Maps controller files to API paths for comprehensive coverage
    - Validates generated specification structure
    - Outputs openapi_spec.yaml for use with documentation generators

Usage:
    python3 generate_openapi.py

Output:
    - openapi_spec.yaml: Complete OpenAPI specification
    - Console output: Generation progress and validation results
    - Next steps: Commands for generating documentation and client libraries
"""

import json
import os
import re
import sys
import textwrap

from apispec import APISpec
import yaml


class WrappingDumper(yaml.Dumper):
    """Custom YAML dumper that wraps long strings."""

    pass


def _str_representer(dumper, data):
    """Represent strings using block style when needed."""
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


WrappingDumper.add_representer(str, _str_representer)


def _get_indent(line):
    """Return the number of leading spaces."""
    return len(line) - len(line.lstrip())


def wrap_yaml_lines(text, max_width=80):
    """Wrap long lines in generated YAML output.

    Handles plain scalars, quoted strings, and
    continuation lines while preserving YAML structure.
    """
    lines = text.split("\n")
    result = []
    for line in lines:
        if len(line) <= max_width:
            result.append(line)
            continue
        indent = _get_indent(line)
        stripped = line.strip()
        # Skip $ref lines - cannot be wrapped
        if stripped.startswith("$ref:"):
            result.append(line)
            continue
        # Handle key: value lines
        m = re.match(r"^(\s*(?:-\s+)?\S+:\s)(.+)$", line)
        if m:
            prefix = m.group(1)
            value = m.group(2)
            cont_indent = " " * (indent + 2)
            wrapped = textwrap.fill(
                value,
                width=max_width,
                initial_indent=prefix,
                subsequent_indent=cont_indent,
            )
            result.append(wrapped)
            continue
        # Handle continuation lines
        cont_indent = " " * indent
        wrapped = textwrap.fill(
            stripped,
            width=max_width,
            initial_indent=cont_indent,
            subsequent_indent=cont_indent,
        )
        result.append(wrapped)
    return "\n".join(result)


def get_script_dir():
    """Get the directory where this script is located."""
    return os.path.dirname(os.path.abspath(__file__))


def get_project_root():
    """Get the project root directory (distcloud)."""
    script_dir = get_script_dir()
    # Navigate up from api-ref to distcloud root
    return os.path.dirname(script_dir)


def validate_openapi_spec(spec_file):
    """Basic validation of OpenAPI specification structure."""
    print("\nValidating OpenAPI specification...")
    try:
        with open(spec_file, "r") as f:
            spec_data = yaml.safe_load(f)

        # Basic structure validation
        required_fields = ["openapi", "info", "paths"]
        missing_fields = [field for field in required_fields if field not in spec_data]

        if missing_fields:
            print(f"✗ Missing required fields: {missing_fields}")
            return False

        # Check if we have any paths
        if not spec_data.get("paths"):
            print("✗ No API paths found")
            return False

        print(f"✓ OpenAPI specification is structurally valid")
        print(f"  - OpenAPI version: {spec_data.get('openapi')}")
        print(f"  - API paths: {len(spec_data.get('paths', {}))}")
        print(f"  - Schemas: {len(spec_data.get('components', {}).get('schemas', {}))}")
        return True

    except yaml.YAMLError as e:
        print(f"✗ YAML parsing error: {e}")
        return False
    except Exception as e:
        print(f"✗ Validation error: {e}")
        return False


def extract_yaml_from_docstring(docstring):
    """Extract YAML content from docstring after --- marker."""
    if not docstring or "---" not in docstring:
        return None

    parts = docstring.split("---", 1)
    if len(parts) < 2:
        return None

    yaml_content = textwrap.dedent(parts[1])

    try:
        return yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        print(f"  Warning: YAML parsing error: {e}")
        return None


def scan_controller_file(filepath):
    """Scan a controller file and extract API operations from docstrings."""
    operations = {}

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        print(f"  Error reading file: {e}")
        return operations

    # Find method definitions with docstrings containing ---
    pattern = r'def\s+(\w+)\s*\([^)]*\):\s*"""(.*?)"""'
    matches = re.finditer(pattern, content, re.DOTALL | re.MULTILINE)

    for match in matches:
        method_name = match.group(1)
        docstring = match.group(2)

        if "---" in docstring:
            yaml_ops = extract_yaml_from_docstring(docstring)
            if yaml_ops:
                # Handle multiple paths in a single docstring
                for key, value in yaml_ops.items():
                    if key.startswith("/"):
                        # This is a path definition
                        if key not in operations:
                            operations[key] = {}
                        operations[key].update(value)
                    else:
                        # This is an HTTP method
                        operations[key] = value

    return operations


def build_openapi_spec():
    """Build complete OpenAPI specification from Pecan controllers using apispec."""

    project_root = get_project_root()

    spec = APISpec(
        title="StarlingX Distributed Cloud Manager API",
        version="1.0.0",
        openapi_version="3.0.2",
        info={
            "description": (
                "REST API for managing distributed cloud"
                " subclouds, peer groups, system peers,"
                " and orchestrated updates across"
                " multiple sites."
            ),
            "contact": {"name": "StarlingX", "url": "https://www.starlingx.io"},
            "license": {
                "name": "Apache 2.0",
                "url": "https://www.apache.org/licenses/LICENSE-2.0.html",
            },
        },
        servers=[
            {
                "url": "https://{host}:{port}",
                "variables": {
                    "host": {"default": "localhost"},
                    "port": {"default": "8119"},
                },
            }
        ],
        security=[{"XAuthToken": []}, {"OIDCToken": []}],
    )

    # Add security schemes
    spec.components.security_scheme(
        "XAuthToken",
        {
            "type": "apiKey",
            "in": "header",
            "name": "X-Auth-Token",
            "description": "OpenStack Keystone authentication token",
        },
    )

    spec.components.security_scheme(
        "OIDCToken",
        {
            "type": "apiKey",
            "in": "header",
            "name": "OIDC-Token",
            "description": "OIDC authentication token",
        },
    )

    # Add tag descriptions
    spec.tag(
        {
            "name": "root",
            "description": (
                "Root API endpoint provides version"
                " information for the Distributed"
                " Cloud Manager API."
            ),
        }
    )
    spec.tag(
        {
            "name": "subclouds",
            "description": "Subclouds are systems managed by a central System Controller.",
        }
    )
    spec.tag(
        {
            "name": "subcloud-groups",
            "description": (
                "Subcloud Groups are logical groupings"
                " managed by a central System Controller."
                " Subclouds in a group can be updated in"
                " parallel when applying patches or"
                " software upgrades."
            ),
        }
    )
    spec.tag(
        {
            "name": "subcloud-peer-groups",
            "description": (
                "Subcloud Peer Groups are logical"
                " groupings managed by a central System"
                " Controller. Each Subcloud Peer Group"
                " maintains information for subcloud"
                " migration and rehoming in"
                " Geo-Redundancy deployment."
            ),
        }
    )
    spec.tag(
        {
            "name": "system-peers",
            "description": (
                "System Peers are logical entities which"
                " are managed by a central System"
                " Controller. Each System Peer maintains"
                " the information which is used for"
                " health check and data synchronization"
                " in the protection group in"
                " Geo-Redundancy deployment."
            ),
        }
    )
    spec.tag(
        {
            "name": "peer-group-associations",
            "description": (
                "Peer Group Associations are logical"
                " connections managed by a central System"
                " Controller. They link subcloud peer"
                " groups with system peers for"
                " Geo-Redundancy operations."
            ),
        }
    )
    spec.tag(
        {
            "name": "sw-update-strategy",
            "description": (
                "Software Update Strategy manages"
                " orchestrated updates across subclouds"
                " including firmware, Kubernetes,"
                " kube-rootca-update, prestage, and"
                " software deployments."
            ),
        }
    )
    spec.tag(
        {
            "name": "sw-update-options",
            "description": (
                "Software Update Options are configurable"
                " settings that control how software"
                " updates are applied to subclouds."
            ),
        }
    )
    spec.tag(
        {
            "name": "alarms",
            "description": (
                "Subcloud alarms are aggregated on the"
                " System Controller for centralized"
                " monitoring."
            ),
        }
    )
    spec.tag(
        {
            "name": "subcloud-backup",
            "description": (
                "Subcloud Backups allow for essential"
                " subcloud system data and optionally"
                " container images to be backed up and"
                " restored."
            ),
        }
    )
    spec.tag(
        {
            "name": "subcloud-deploy",
            "description": (
                "Subcloud Deploy APIs allow for the"
                " display and upload of deployment"
                " manager common files and helm charts."
            ),
        }
    )
    spec.tag(
        {
            "name": "phased-subcloud-deploy",
            "description": (
                "Phased Subcloud Deploy APIs allow for"
                " subcloud deployment to be done in"
                " phases: install, bootstrap, and configure."
            ),
        }
    )
    spec.tag(
        {
            "name": "notifications",
            "description": (
                "Notifications API allows external"
                " systems to send notifications to the"
                " System Controller."
            ),
        }
    )

    # Load schemas from schemas.yaml using relative path
    schemas_file = os.path.join(get_script_dir(), "schemas.yaml")
    if os.path.exists(schemas_file):
        print("Loading schemas from schemas.yaml...")
        with open(schemas_file, "r") as f:
            schemas_data = yaml.safe_load(f)
            if "components" in schemas_data and "schemas" in schemas_data["components"]:
                for schema_name, schema_def in schemas_data["components"][
                    "schemas"
                ].items():
                    spec.components.schema(schema_name, schema_def)
                print(f"  Loaded {len(schemas_data['components']['schemas'])} schemas")

    # Map controller files to API paths using relative paths
    base_path = os.path.join(
        project_root,
        "distributedcloud",
        "dcmanager",
        "api",
        "controllers",
    )

    controller_mapping = {
        "/": "root.py",
        "/v1.0/subclouds": "v1/subclouds.py",
        "/v1.0/alarms": "v1/alarm_manager.py",
        "/v1.0/sw-update-strategy": "v1/sw_update_strategy.py",
        "/v1.0/sw-update-options": "v1/sw_update_options.py",
        "/v1.0/subcloud-groups": "v1/subcloud_group.py",
        "/v1.0/notifications": "v1/notifications.py",
        "/v1.0/subcloud-deploy": "v1/subcloud_deploy.py",
        "/v1.0/subcloud-backup": "v1/subcloud_backup.py",
        "/v1.0/phased-subcloud-deploy": "v1/phased_subcloud_deploy.py",
        "/v1.0/subcloud-peer-groups": "v1/subcloud_peer_group.py",
        "/v1.0/system-peers": "v1/system_peers.py",
        "/v1.0/peer-group-associations": "v1/peer_group_association.py",
    }

    total_operations = 0

    for api_path, controller_file in controller_mapping.items():
        filepath = os.path.join(base_path, controller_file)

        if os.path.exists(filepath):
            operations = scan_controller_file(filepath)

            if operations:
                # Separate path-based operations from method-based operations
                path_operations = {}
                method_operations = {}

                for key, value in operations.items():
                    if key.startswith("/"):
                        path_operations[key] = value
                    else:
                        method_operations[key] = value

                # Add method-based operations to the mapped path
                if method_operations:
                    for op_method, op_def in method_operations.items():
                        if "security" in op_def:
                            del op_def["security"]
                    spec.path(path=api_path, operations=method_operations)
                    total_operations += len(method_operations)
                    print(f"{controller_file}: {list(method_operations.keys())}")

                # Add path-based operations
                for path, path_ops in path_operations.items():
                    for op_method, op_def in path_ops.items():
                        if "security" in op_def:
                            del op_def["security"]
                    spec.path(path=path, operations=path_ops)
                    total_operations += len(path_ops)
                    print(f"{controller_file} ({path}): {list(path_ops.keys())}")
        else:
            print(f"Warning: File not found: {filepath}")

    return spec, total_operations


if __name__ == "__main__":
    print("=" * 70)
    print("Generating OpenAPI Specification from Pecan Controllers")
    print("=" * 70)
    print()

    spec, total_ops = build_openapi_spec()

    # Use relative path for output
    output_file = os.path.join(get_script_dir(), "dc-openapi.yaml")

    raw_yaml = yaml.dump(
        spec.to_dict(),
        Dumper=WrappingDumper,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=80,
    )
    wrapped_yaml = wrap_yaml_lines(raw_yaml)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(wrapped_yaml)

    print()
    print("=" * 70)
    print("✓ OpenAPI Specification Generated Successfully")
    print("=" * 70)
    print(f"Output file: {output_file}")
    spec_dict = spec.to_dict()
    print(f"Total API paths: {len(spec_dict.get('paths', {}))}")
    print(f"Total operations: {total_ops}")
    print(f"Total schemas: {len(spec_dict.get('components', {}).get('schemas', {}))}")

    # Validate the generated specification
    validate_openapi_spec(output_file)

    print()
    print("Next steps:")
    print("  1. View in Swagger Editor: https://editor.swagger.io/")
    print("=" * 70)
