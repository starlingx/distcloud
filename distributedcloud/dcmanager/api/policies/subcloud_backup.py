#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.api.policies import base
from oslo_policy import policy

POLICY_ROOT = 'dc_api:subcloud_backup:%s'


subcloud_backup_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'create',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Create new subcloud backup.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/subcloud-backup'
            }
        ]
    )
]


def list_rules():
    return subcloud_backup_rules
