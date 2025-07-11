# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy

from dccommon.endpoint_cache import EndpointCache
from dcmanager.common import consts
from dcmanager.common.exceptions import InvalidParameterValue
from dcmanager.orchestrator.cache import clients
from dcmanager.orchestrator.cache.cache_specifications import (
    REGION_ONE_LICENSE_CACHE_TYPE,
)
from dcmanager.orchestrator.cache.cache_specifications import (
    REGION_ONE_RELEASE_USM_CACHE_TYPE,
)
from dcmanager.orchestrator.cache.shared_cache_repository import SharedCacheRepository
from dcmanager.tests.base import DCManagerTestCase

SOFTWARE_CLIENT_QUERY_RETURN = [
    {
        "sw_version": "23.09.0",
        "state": "available",
        "reboot_required": "N",
        "release_id": "stx_23.09.0",
    },
    {
        "sw_version": "23.09.1",
        "state": "available",
        "reboot_required": "N",
        "release_id": "stx_23.09.1",
    },
    {
        "sw_version": "23.09.2",
        "state": "unavailable",
        "reboot_required": "N",
        "release_id": "stx_23.09.2",
    },
]


class TestSharedCacheRepository(DCManagerTestCase):
    def setUp(self):
        """Initializes the shared cache repository"""

        super().setUp()

        self.mock_sysinv_client = self._mock_object(clients, "SysinvClient")
        self.mock_software_client = self._mock_object(clients, "SoftwareClient")
        self.mock_software_client().list.return_value = SOFTWARE_CLIENT_QUERY_RETURN
        self._mock_object(EndpointCache, "get_admin_session")

        self.shared_cache_repository = SharedCacheRepository(
            operation_type=consts.SW_UPDATE_TYPE_SOFTWARE
        )
        self.shared_cache_repository.initialize_caches()

    def test_read_succeeds_with_license_cache_type(self):
        """Test read cache succeeds when using the REGION_ONE_LICENSE_CACHE_TYPE"""

        self.mock_sysinv_client().get_license.return_value = "fake license"

        response = self.shared_cache_repository.read(REGION_ONE_LICENSE_CACHE_TYPE)

        self.assertEqual(response, "fake license")

    def test_read_succeeds_with_release_usm_cache_type(self):
        """Test read cache succeeds when using REGION_ONE_RELEASE_USM_CACHE_TYPE"""

        response = self.shared_cache_repository.read(REGION_ONE_RELEASE_USM_CACHE_TYPE)

        self.assertEqual(response, SOFTWARE_CLIENT_QUERY_RETURN)

    def test_read_fails_with_invalid_cache_type(self):
        """Test read cache fails when using an invalid cache type"""

        self.assertRaises(
            InvalidParameterValue, self.shared_cache_repository.read, "fake parameter"
        )

    def test_read_succeeds_with_filter_params(self):
        """Test read cache succeeds when filter_params is sent"""

        response = self.shared_cache_repository.read(
            REGION_ONE_RELEASE_USM_CACHE_TYPE, state="available"
        )

        expected_response = copy.copy(SOFTWARE_CLIENT_QUERY_RETURN)
        del expected_response[2]

        self.assertEqual(response, expected_response)

    def test_read_fails_with_invalid_filter_params(self):
        """Test read cache succeeds when and invalid filter_params is sent"""

        self.assertRaises(
            InvalidParameterValue,
            self.shared_cache_repository.read,
            REGION_ONE_RELEASE_USM_CACHE_TYPE,
            invalid="available",
        )
