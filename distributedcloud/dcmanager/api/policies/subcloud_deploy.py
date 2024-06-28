#
# Copyright (c) 2022-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_policy import policy

from dcmanager.api.policies import base

POLICY_ROOT = "dc_api:subcloud_deploy:%s"


subcloud_deploy_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "upload",
        check_str="rule:" + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Upload subcloud deploy files.",
        operations=[{"method": "POST", "path": "/v1.0/subcloud-deploy"}],
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "get",
        check_str="rule:" + base.READER_IN_SYSTEM_PROJECTS,
        description="Show subcloud deploy files.",
        operations=[
            {"method": "GET", "path": "/v1.0/subcloud-deploy"},
            {"method": "GET", "path": "/v1.0/subcloud-deploy/{release}"},
        ],
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "delete",
        check_str="rule:" + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Delete subcloud deploy files.",
        operations=[
            {"method": "DELETE", "path": "/v1.0/subcloud-deploy"},
            {"method": "DELETE", "path": "/v1.0/subcloud-deploy/{release}"},
        ],
    ),
]


def list_rules():
    return subcloud_deploy_rules
