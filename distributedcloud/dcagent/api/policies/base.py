#
# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_policy import policy

ADMIN_IN_SYSTEM_PROJECTS = "admin_in_system_projects"
READER_OR_OPERATOR_IN_SYSTEM_PROJECTS = "reader_or_operator_system_projects"


base_rules = [
    policy.RuleDefault(
        name=ADMIN_IN_SYSTEM_PROJECTS,
        check_str="role:admin and (project_name:admin or project_name:services)",
        description="Base rule.",
    ),
    policy.RuleDefault(
        name=READER_OR_OPERATOR_IN_SYSTEM_PROJECTS,
        check_str="(role:reader or role:operator) and (project_name:admin or "
        + "project_name:services)",
        description="Base rule.",
    ),
]


def list_rules():
    return base_rules
