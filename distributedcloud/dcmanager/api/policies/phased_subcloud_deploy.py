#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.api.policies import base
from oslo_policy import policy

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
                'path': '/v1.0/phased-subcloud-deploy/{subcloud}/install'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/phased-subcloud-deploy/{subcloud}/bootstrap'
            },
            {
                'method': 'PATCH',
                'path': '/v1.0/phased-subcloud-deploy/{subcloud}/configure'
            }
        ]
    )
]


def list_rules():
    return phased_subcloud_deploy_rules