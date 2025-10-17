#
# Copyright (c) 2021, 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate


class TestKubeRootCaUpgradeState(TestSwUpdate):
    def setUp(self):
        super().setUp()

        # Setting strategy_type to upgrade will setup kube rootca upgrade
        # orchestration worker, and will mock away the other orch threads
        self.strategy_type = consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE
        self.strategy = fake_strategy.create_fake_strategy(self.ctx, self.strategy_type)
