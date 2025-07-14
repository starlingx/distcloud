#
# Copyright (c) 2022,2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_policy import policy

from dcmanager.api.policies import base

POLICY_ROOT = "dc_api:sw_update_strategy:%s"


sw_update_strategy_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "abort",
        check_str="rule:" + base.ADMIN_OR_CONFIGURATOR,
        description="Abort update strategy execution.",
        operations=[{"method": "POST", "path": "/v1.0/sw-update-strategy/actions"}],
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "apply",
        check_str="rule:" + base.ADMIN_OR_CONFIGURATOR,
        description="Apply update strategy.",
        operations=[{"method": "POST", "path": "/v1.0/sw-update-strategy/actions"}],
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "create",
        check_str="rule:" + base.ADMIN_OR_CONFIGURATOR,
        description="Create update strategy.",
        operations=[{"method": "POST", "path": "/v1.0/sw-update-strategy"}],
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "delete",
        check_str="rule:" + base.ADMIN_OR_CONFIGURATOR,
        description="Delete update strategy.",
        operations=[{"method": "DELETE", "path": "/v1.0/sw-update-strategy"}],
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "get",
        check_str="rule:" + base.READER_OR_OPERATOR_OR_CONFIGURATOR,
        description="Get update strategy.",
        operations=[
            {"method": "GET", "path": "/v1.0/sw-update-strategy"},
            {"method": "GET", "path": "/v1.0/sw-update-strategy/steps"},
            {"method": "GET", "path": "/v1.0/sw-update-strategy/steps/{cloud_name}"},
        ],
    ),
]


def list_rules():
    return sw_update_strategy_rules
