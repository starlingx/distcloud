#
# Copyright (c) 2020, 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate


class TestSwUpgradeState(TestSwUpdate):
    # Setting DEFAULT_STRATEGY_TYPE to upgrade will setup the upgrade
    # orchestration worker, and will mock away the other orch threads
    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_UPGRADE

    def setUp(self):
        super(TestSwUpgradeState, self).setUp()
        self.region_one_client_patch = mock.patch('dcmanager.orchestrator.states.upgrade.cache.'
                                                  'region_one_patching_cache.'
                                                  'RegionOnePatchingCache._get_patching_client',
                                                  return_value=self.patching_client)
        self.region_one_client_patch.start()

    def tearDown(self):
        self.region_one_client_patch.stop()
        super(TestSwUpgradeState, self).tearDown()
