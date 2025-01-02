#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.orchestrator.cache import clients
from dcmanager.tests.unit.orchestrator.test_base import TestSwUpdate


class TestSoftwareOrchestrator(TestSwUpdate):
    # Setting DEFAULT_STRATEGY_TYPE to software will setup the software
    # orchestration worker, and will mock away the other orch threads
    DEFAULT_STRATEGY_TYPE = consts.SW_UPDATE_TYPE_SOFTWARE

    def setUp(self):
        super().setUp()

        # Modify cache helpers to return client mocks
        mock_get_software_client = self._mock_object(clients, "get_software_client")
        mock_get_software_client.return_value = self.software_client

        mock_get_sysinv_client = self._mock_object(clients, "get_sysinv_client")
        mock_get_sysinv_client.return_value = self.sysinv_client
