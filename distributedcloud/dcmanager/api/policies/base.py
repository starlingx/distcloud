#
# Copyright (c) 2022,2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_policy import policy

ADMIN_OR_CONFIGURATOR = "admin_or_configurator"
READER_OR_OPERATOR_OR_CONFIGURATOR = "reader_or_operator_or_configurator"
ADMIN_OR_OPERATOR_OR_CONFIGURATOR = "admin_or_operator_or_configurator"


base_rules = [
    policy.RuleDefault(
        name=ADMIN_OR_CONFIGURATOR,
        check_str="(role:admin or role:configurator) and (project_name:admin or "
        + "project_name:services)",
        description="admin,configurator roles of admin,services projects",
    ),
    policy.RuleDefault(
        name=ADMIN_OR_OPERATOR_OR_CONFIGURATOR,
        check_str="(role:admin or role:operator or role:configurator) and "
        + "(project_name:admin or project_name:services)",
        description="admin,operator,configurator roles of admin,services projects",
    ),
    policy.RuleDefault(
        name=READER_OR_OPERATOR_OR_CONFIGURATOR,
        check_str="(role:reader or role:operator or role:configurator) and "
        + "(project_name:admin or project_name:services)",
        description="reader,operator,configurator roles of admin,services projects",
    ),
]


def list_rules():
    return base_rules
