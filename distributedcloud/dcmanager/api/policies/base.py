#
# Copyright (c) 2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_policy import policy

ADMIN_IN_SYSTEM_PROJECTS = "admin_in_system_projects"
READER_IN_SYSTEM_PROJECTS = "reader_in_system_projects"


base_rules = [
    policy.RuleDefault(
        name=ADMIN_IN_SYSTEM_PROJECTS,
        check_str="role:admin and (project_name:admin or project_name:services)",
        description="Base rule.",
    ),
    policy.RuleDefault(
        name=READER_IN_SYSTEM_PROJECTS,
        check_str="role:reader and (project_name:admin or project_name:services)",
        description="Base rule.",
    ),
]


def list_rules():
    return base_rules
