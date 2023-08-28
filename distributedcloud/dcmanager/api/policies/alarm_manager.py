#
# Copyright (c) 2022, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_policy import policy

from dcmanager.api.policies import base

POLICY_ROOT = 'dc_api:alarm_manager:%s'


alarm_manager_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'get',
        check_str='rule:' + base.READER_IN_SYSTEM_PROJECTS,
        description="Get alarms from subclouds.",
        operations=[
            {
                'method': 'GET',
                'path': '/v1.0/alarms'
            }
        ]
    )
]


def list_rules():
    return alarm_manager_rules
