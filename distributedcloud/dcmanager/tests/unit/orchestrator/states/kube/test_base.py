#
# Copyright (c) 2020-2021, 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate


class TestKubeUpgradeState(TestSwUpdate):
    def setUp(self):
        super().setUp()

        # Setting strategy_type to upgrade will setup the kube upgrade
        # orchestration worker, and will mock away the other orch threads
        self.strategy_type = consts.SW_UPDATE_TYPE_KUBERNETES
