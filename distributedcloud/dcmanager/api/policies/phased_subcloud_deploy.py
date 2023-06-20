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
]


def list_rules():
    return phased_subcloud_deploy_rules
