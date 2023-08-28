#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_policy import policy

from dcmanager.api.policies import base

POLICY_ROOT = 'dc_api:phased_subcloud_deploy:%s'


phased_subcloud_deploy_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'create',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Create a subcloud",
        operations=[
            {
                'method': 'POST',
                'path': '/v1.0/phased-subcloud-deploy'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'modify',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Modify the subcloud deployment.",
        operations=[
            {
                'method': 'PATCH',
                'path': '/v1.0/phased-subcloud-deploy/{subcloud}/abort'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/phased-subcloud-deploy/{subcloud}/resume'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/phased-subcloud-deploy/{subcloud}/install'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/phased-subcloud-deploy/{subcloud}/bootstrap'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/phased-subcloud-deploy/{subcloud}/configure'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/phased-subcloud-deploy/{subcloud}/complete'
            }
        ]
    )
]


def list_rules():
    return phased_subcloud_deploy_rules
