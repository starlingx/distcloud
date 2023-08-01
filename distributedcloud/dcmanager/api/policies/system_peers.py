# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.api.policies import base
from oslo_policy import policy

POLICY_ROOT = 'dc_api:system_peers:%s'


system_peers_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'create',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Create system peer.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/system-peers'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'delete',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Delete system peer.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/v1.0/system-peers/{system_peer}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'get',
        check_str='rule:' + base.READER_IN_SYSTEM_PROJECTS,
        description="Get system peers.",
        operations=[
            {
                'method': 'GET',
                'path': '/v1.0/system-peers'
            },
            {
                'method': 'GET',
                'path': '/v1.0/system-peers/{system_peer}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'modify',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Modify system peer.",
        operations=[
            {
                'method': 'PATCH',
                'path': '/v1.0/system-peers/{system_peer}'
            }
        ]
    )
]


def list_rules():
    return system_peers_rules
