#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate


class TestSwUpgradeState(TestSwUpdate):
    # Setting DEFAULT_STRATEGY_TYPE to upgrade will setup the upgrade
    # orchestration worker, and will mock away the other orch threads
    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_UPGRADE

    def setUp(self):
        super(TestSwUpgradeState, self).setUp()
