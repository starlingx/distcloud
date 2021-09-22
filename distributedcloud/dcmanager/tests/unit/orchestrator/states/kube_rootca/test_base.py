#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate


class TestKubeRootCaUpgradeState(TestSwUpdate):
    # Setting DEFAULT_STRATEGY_TYPE to upgrade will setup kube rootca upgrade
    # orchestration worker, and will mock away the other orch threads
    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE

    def setUp(self):
        super(TestKubeRootCaUpgradeState, self).setUp()
