#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.api.policies import base
from oslo_policy import policy

POLICY_ROOT = 'dc_api:subcloud_peer_groups:%s'


_subcloud_peer_groups_rules = [

    # CRUD of subcloud-peer-groups entity
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'create',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Create subcloud peer group.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/subcloud-peer-groups'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'delete',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Delete subcloud peer group.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/v1.0/subcloud-peer-groups/{subcloud_peer_group}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'get',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Get Subcloud Peer Group data",
        operations=[
            {
                'method': 'GET',
                'path': '/v1.0/subcloud-peer-groups/'
            },
            # Show details of a specified Subcloud Peer Group
            {
                'method': 'GET',
                'path': '/v1.0/subcloud-peer-groups/{subcloud_peer_group}'
            },
            # Show subclouds status of the subcloud-peer-group
            {
                'method': 'GET',
                'path': '/v1.0/subcloud-peer-groups/{subcloud_peer_group}/status'
            },
            # List Subclouds assigned to the given Subcloud Peer Group
            {
                'method': 'GET',
                'path': '/v1.0/subcloud-peer-groups/{subcloud_peer_group}/subclouds'
            }
        ]
    ),
    # Update a Subcloud Peer Group with specified configuration
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'modify',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Update a Subcloud Peer Group with specified configuration",
        operations=[
            {
                'method': 'PATCH',
                'path': '/v1.0/subcloud-peer-groups/{subcloud_peer_group}'
            },
            # Migrate subclouds entity of the subcloud-peer-group
            {
                'method': 'PATCH',
                'path': '/v1.0/subcloud-peer-groups/{subcloud_peer_group}/migrate'
            }
        ]
    )
]


def list_rules():
    return _subcloud_peer_groups_rules
