#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_policy import policy

from dcmanager.api.policies import base

POLICY_ROOT = "dc_api:subcloud_backup_config:%s"


subcloud_backup_config_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "get",
        check_str="rule:" + base.READER_OR_OPERATOR_OR_CONFIGURATOR,
        description="Get subcloud backup configuration.",
        operations=[{"method": "GET", "path": "/v1.0/subcloud-backup-config"}],
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "modify",
        check_str="rule:" + base.ADMIN_OR_CONFIGURATOR,
        description="Modify subcloud backup configuration.",
        operations=[{"method": "PATCH", "path": "/v1.0/subcloud-backup-config"}],
    ),
]


def list_rules():
    return subcloud_backup_config_rules
