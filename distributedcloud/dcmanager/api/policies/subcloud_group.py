#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.api.policies import base
from oslo_policy import policy

POLICY_ROOT = 'dc_api:subcloud_groups:%s'


subcloud_groups_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'create',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Create subcloud group.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/subcloud-groups'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'delete',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Delete subcloud group.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/v1.0/subcloud-groups/{subcloud_group}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'get',
        check_str='rule:' + base.READER_IN_SYSTEM_PROJECTS,
        description="Get subcloud groups.",
        operations=[
            {
                'method': 'GET',
                'path': '/v1.0/subcloud-groups'
            },
            {
                'method': 'GET',
                'path': '/v1.0/subcloud-groups/{subcloud_group}'
            },
            {
                'method': 'GET',
                'path': '/v1.0/subcloud-groups/{subcloud_group}/subclouds'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'modify',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Modify subcloud group.",
        operations=[
            {
                'method': 'PATCH',
                'path': '/v1.0/subcloud-groups/{subcloud_group}'
            }
        ]
    )
]


def list_rules():
    return subcloud_groups_rules
