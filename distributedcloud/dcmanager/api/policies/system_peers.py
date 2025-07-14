# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_policy import policy

from dcmanager.api.policies import base

POLICY_ROOT = "dc_api:system_peers:%s"


system_peers_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "create",
        check_str="rule:" + base.ADMIN_OR_CONFIGURATOR,
        description="Create system peer.",
        operations=[{"method": "POST", "path": "/v1.0/system-peers"}],
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "delete",
        check_str="rule:" + base.ADMIN_OR_CONFIGURATOR,
        description="Delete system peer.",
        operations=[{"method": "DELETE", "path": "/v1.0/system-peers/{system_peer}"}],
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "get",
        check_str="rule:" + base.READER_OR_OPERATOR_OR_CONFIGURATOR,
        description="Get system peers.",
        operations=[
            {"method": "GET", "path": "/v1.0/system-peers"},
            # Show details of a specified System Peer
            {"method": "GET", "path": "/v1.0/system-peers/{system_peer}"},
            # List Subcloud Peer Groups associated with the given System Peer
            {
                "method": "GET",
                "path": "/v1.0/system-peers/{system_peer}/subcloud-peer-groups",
            },
        ],
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % "modify",
        check_str="rule:" + base.ADMIN_OR_CONFIGURATOR,
        description="Modify system peer.",
        operations=[{"method": "PATCH", "path": "/v1.0/system-peers/{system_peer}"}],
    ),
]


def list_rules():
    return system_peers_rules
