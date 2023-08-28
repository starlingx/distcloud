#
# Copyright (c) 2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_policy import policy

from dcmanager.api.policies import base

POLICY_ROOT = 'dc_api:sw_update_options:%s'


sw_update_options_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'delete',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Delete per subcloud sw-update options.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/v1.0/sw-update-options/{subcloud}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'get',
        check_str='rule:' + base.READER_IN_SYSTEM_PROJECTS,
        description="Get sw-update options.",
        operations=[
            {
                'method': 'GET',
                'path': '/v1.0/sw-update-options'
            },
            {
                'method': 'GET',
                'path': '/v1.0/sw-update-options/{subcloud}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'update',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Update sw-update options (defaults or per subcloud).",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/sw-update-options/{subcloud}'
            }
        ]
    )
]


def list_rules():
    return sw_update_options_rules
