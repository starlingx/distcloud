#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.api.policies import base
from oslo_policy import policy

POLICY_ROOT = 'dc_api:sw_update_strategy:%s'


sw_update_strategy_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'abort',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Abort update strategy execution.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/sw-update-strategy/actions'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'apply',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Apply update strategy.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/sw-update-strategy/actions'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'create',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Create update strategy.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/sw-update-strategy'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'delete',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Delete update strategy.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/v1.0/sw-update-strategy'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'get',
        check_str='rule:' + base.READER_IN_SYSTEM_PROJECTS,
        description="Get update strategy.",
        operations=[
            {
                'method': 'GET',
                'path': '/v1.0/sw-update-strategy'
            },
            {
                'method': 'GET',
                'path': '/v1.0/sw-update-strategy/steps'
            },
            {
                'method': 'GET',
                'path': '/v1.0/sw-update-strategy/steps/{cloud_name}'
            }
        ],
    )
]


def list_rules():
    return sw_update_strategy_rules
