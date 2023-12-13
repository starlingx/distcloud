# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import mock

from keystoneauth1 import exceptions as keystone_exceptions

from dcmanager.common import consts
from dcmanager.common.exceptions import InvalidParameterValue
from dcmanager.orchestrator.states.software.cache.cache_specifications import \
    REGION_ONE_LICENSE_CACHE_TYPE
from dcmanager.orchestrator.states.software.cache.cache_specifications import \
    REGION_ONE_RELEASE_USM_CACHE_TYPE
from dcmanager.orchestrator.states.software.cache.cache_specifications import \
    REGION_ONE_SYSTEM_INFO_CACHE_TYPE
from dcmanager.orchestrator.states.software.cache import clients
from dcmanager.orchestrator.states.software.cache.shared_cache_repository import \
    SharedCacheRepository
from dcmanager.tests import base

SOFTWARE_CLIENT_QUERY_RETURN = {
    "stx_23.09.0": {
        "sw_version": "23.09.0",
        "state": "available",
        "reboot_required": "N",
    },
    "stx_23.09.1": {
        "sw_version": "23.09.1",
        "state": "available",
        "reboot_required": "N",
    },
    "stx_23.09.2": {
        "sw_version": "23.09.2",
        "state": "unavailable",
        "reboot_required": "N",
    }
}


class TestSharedCacheRepository(base.DCManagerTestCase):
    def setUp(self):
        """Initializes the shared cache repository"""

        super().setUp()

        self._mock_openstack_driver(clients)
        self._mock_sysinv_client(clients)
        self._mock_software_client()

        self.shared_cache_repository = SharedCacheRepository(
            operation_type=consts.SW_UPDATE_TYPE_SOFTWARE
        )
        self.shared_cache_repository.initialize_caches()

        self.software_client().query.return_value = SOFTWARE_CLIENT_QUERY_RETURN

    def _mock_software_client(self):
        mock_patch = mock.patch.object(clients, 'SoftwareClient')
        self.software_client = mock_patch.start()
        self.addCleanup(mock_patch.stop)

    def test_read_succeeds_with_license_cache_type(self):
        """Test read cache succeeds when using the REGION_ONE_LICENSE_CACHE_TYPE"""

        self.mock_sysinv_client().get_license.return_value = 'fake license'

        response = self.shared_cache_repository.read(REGION_ONE_LICENSE_CACHE_TYPE)

        self.assertEqual(response, 'fake license')

    def test_read_succeeds_with_system_info_cache_type(self):
        """Test read cache succeeds when using REGION_ONE_SYSTEM_INFO_CACHE_TYPE"""

        self.mock_sysinv_client().get_system.return_value = 'fake system info'

        response = \
            self.shared_cache_repository.read(REGION_ONE_SYSTEM_INFO_CACHE_TYPE)

        self.assertEqual(response, 'fake system info')

    def test_read_succeeds_with_release_usm_cache_type(self):
        """Test read cache succeeds when using REGION_ONE_RELEASE_USM_CACHE_TYPE"""

        response = \
            self.shared_cache_repository.read(REGION_ONE_RELEASE_USM_CACHE_TYPE)

        self.assertEqual(response, SOFTWARE_CLIENT_QUERY_RETURN)

    def test_read_fails_with_invalid_cache_type(self):
        """Test read cache fails when using an invalid cache type"""

        self.assertRaises(
            InvalidParameterValue,
            self.shared_cache_repository.read,
            'fake parameter'
        )

    def test_read_fails_when_openstack_driver_raises_exception(self):
        """Test read cache fails when the OpenStackDriver raises an Exception"""

        self.mock_openstack_driver.side_effect = \
            keystone_exceptions.ConnectFailure()

        self.assertRaises(
            keystone_exceptions.ConnectFailure,
            self.shared_cache_repository.read,
            REGION_ONE_RELEASE_USM_CACHE_TYPE
        )

    def test_read_succeeds_with_filter_params(self):
        """Test read cache succeeds when filter_params is sent"""

        response = self.shared_cache_repository.read(
            REGION_ONE_RELEASE_USM_CACHE_TYPE,
            state='available'
        )

        expected_response = copy.copy(SOFTWARE_CLIENT_QUERY_RETURN)
        del expected_response["stx_23.09.2"]

        self.assertEqual(response, expected_response)

    def test_read_fails_with_invalid_filter_params(self):
        """Test read cache succeeds when and invalid filter_params is sent"""

        self.assertRaises(
            InvalidParameterValue,
            self.shared_cache_repository.read,
            REGION_ONE_RELEASE_USM_CACHE_TYPE,
            invalid='available'
        )
