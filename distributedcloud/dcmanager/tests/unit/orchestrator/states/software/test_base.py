#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common import consts
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate

CACHE_CLIENT_PATH = "dcmanager.orchestrator.states.software.cache.clients"


class TestSoftwareOrchestrator(TestSwUpdate):
    # Setting DEFAULT_STRATEGY_TYPE to software will setup the software
    # orchestration worker, and will mock away the other orch threads
    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_SOFTWARE

    def setUp(self):
        super(TestSoftwareOrchestrator, self).setUp()

        # Modify cache helpers to return client mocks
        self.software_cache_client_mock = mock.patch(
            "%s.get_software_client" % CACHE_CLIENT_PATH,
            return_value=self.software_client,
        )
        self.sysinv_cache_client_mock = mock.patch(
            "%s.get_sysinv_client" % CACHE_CLIENT_PATH,
            return_value=self.sysinv_client
        )
        self.software_cache_client_mock.start()
        self.sysinv_cache_client_mock.start()

    def tearDown(self):
        self.software_cache_client_mock.stop()
        self.sysinv_cache_client_mock.stop()
        super(TestSoftwareOrchestrator, self).tearDown()
