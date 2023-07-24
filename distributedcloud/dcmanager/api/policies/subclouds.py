#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.api.policies import base
from oslo_policy import policy

POLICY_ROOT = 'dc_api:subclouds:%s'


subclouds_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'create',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Create a subcloud.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/subclouds'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'delete',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Delete a subcloud.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/v1.0/subclouds/{alarm_uuid}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'get',
        check_str='rule:' + base.READER_IN_SYSTEM_PROJECTS,
        description="Get subclouds data.",
        operations=[
            {
                'method': 'GET',
                'path': '/v1.0/subclouds'
            },
            {
                'method': 'GET',
                'path': '/v1.0/subclouds/{subcloud}'
            },
            {
                'method': 'GET',
                'path': '/v1.0/subclouds/{subcloud}/detail'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'modify',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Modify a subcloud.",
        operations=[
            {
                'method': 'PATCH',
                'path': '/v1.0/subclouds/{subcloud}'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/subclouds/{subcloud}/prestage'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/subclouds/{subcloud}/reconfigure'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/subclouds/{subcloud}/reinstall'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/subclouds/{subcloud}/redeploy'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/subclouds/{subcloud}/restore'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/subclouds/{subcloud}/update_status'
            }
        ]
    )
]


def list_rules():
    return subclouds_rules
