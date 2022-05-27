#
# Copyright (c) 2020, 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate

CACHE_CLIENT_PATH = 'dcmanager.orchestrator.states.upgrade.cache.clients'


class TestSwUpgradeState(TestSwUpdate):
    # Setting DEFAULT_STRATEGY_TYPE to upgrade will setup the upgrade
    # orchestration worker, and will mock away the other orch threads
    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_UPGRADE

    def setUp(self):
        super(TestSwUpgradeState, self).setUp()

        # Modify cache helpers to return client mocks
        self.patch_cache_client_mock = mock.patch('%s.get_patching_client' %
                                                  CACHE_CLIENT_PATH,
                                                  return_value=self.patching_client)
        self.sysinv_cache_client_mock = mock.patch('%s.get_sysinv_client' %
                                                   CACHE_CLIENT_PATH,
                                                   return_value=self.sysinv_client)
        self.patch_cache_client_mock.start()
        self.sysinv_cache_client_mock.start()

    def tearDown(self):
        self.patch_cache_client_mock.stop()
        self.sysinv_cache_client_mock.stop()
        super(TestSwUpgradeState, self).tearDown()
