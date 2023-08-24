#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.api.policies import base
from oslo_policy import policy

POLICY_ROOT = 'dc_api:peer_group_associations:%s'


peer_group_associations_rules = [

    # CRUD of peer_group_associations entity
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'create',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Create peer group association.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/peer-group-associations'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'delete',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Delete peer group association.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/v1.0/peer-group-associations/{associate_id}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'get',
        check_str='rule:' + base.READER_IN_SYSTEM_PROJECTS,
        description="Get peer group associations.",
        operations=[
            {
                'method': 'GET',
                'path': '/v1.0/peer-group-associations'
            },
            {
                'method': 'GET',
                'path': '/v1.0/peer-group-associations/{associate_id}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'modify',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Modify peer group association.",
        operations=[
            {
                'method': 'PATCH',
                'path': '/v1.0/peer-group-associations/{associate_id}'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/peer-group-associations/{associate_id}/sync'
            }
        ]
    )
]


def list_rules():
    return peer_group_associations_rules
