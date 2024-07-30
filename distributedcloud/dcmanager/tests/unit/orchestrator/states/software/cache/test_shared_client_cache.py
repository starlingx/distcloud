# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import socket

import mock

from dcmanager.orchestrator.states.software.cache.cache_specifications import (
    CacheSpecification,
)
from dcmanager.orchestrator.states.software.cache.cache_specifications import (
    REGION_ONE_LICENSE_CACHE_SPECIFICATION,
)
from dcmanager.orchestrator.states.software.cache.cache_specifications import (
    REGION_ONE_LICENSE_CACHE_TYPE,
)
from dcmanager.orchestrator.states.software.cache import clients
from dcmanager.orchestrator.states.software.cache.shared_client_cache import (
    SharedClientCache,
)
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
}


class TestSharedClientCache(base.DCManagerTestCase):
    def setUp(self):
        """Initializes the shared client cache"""

        super().setUp()

        self._mock_openstack_driver(clients)
        self._mock_sysinv_client(clients)

    def test_read_succeeds_when_cache_data_is_stored(self):
        """Test read cache succeeds when the data is cached after the first request

        In the second request, instead of reacquiring the data using get_system,
        the previously stored information should be returned
        """

        shared_client_cache = SharedClientCache(
            REGION_ONE_LICENSE_CACHE_TYPE, REGION_ONE_LICENSE_CACHE_SPECIFICATION
        )

        self.mock_sysinv_client().get_license.return_value = "fake license"

        self.assertIsNone(shared_client_cache._cache)

        response = shared_client_cache.read()

        self.assertEqual(response, "fake license")
        self.mock_sysinv_client().get_license.assert_called_once()
        self.assertIsNotNone(shared_client_cache._cache)

        response = shared_client_cache.read()

        self.assertEqual(response, "fake license")
        self.mock_sysinv_client().get_license.assert_called_once()

    def test_read_fails_when_client_lock_is_writer_and_cache_is_not_stored(self):
        """Test read cache fails with writer client lock and without cache stored"""

        shared_client_cache = SharedClientCache(
            REGION_ONE_LICENSE_CACHE_TYPE, REGION_ONE_LICENSE_CACHE_SPECIFICATION
        )

        with shared_client_cache._client_lock.write_lock():
            self.assertRaises(RuntimeError, shared_client_cache.read)

    def test_read_succeeds_without_retry_on_exception(self):
        """Test read cache succeeds without retry on exception"""

        cache_specification = CacheSpecification(
            lambda: clients.get_sysinv_client().get_license(), retry_on_exception=False
        )
        self.shared_client_cache = SharedClientCache(
            REGION_ONE_LICENSE_CACHE_TYPE, cache_specification
        )

        self.mock_sysinv_client().get_license.return_value = "fake license"

        response = self.shared_client_cache.read()

        self.assertEqual(response, "fake license")
        self.mock_sysinv_client().get_license.assert_called_once()

    def test_read_fails_with_retry_on_exception(self):
        """Test read cache fails with retry on exception"""

        fetch_implementation = mock.MagicMock(side_effect=socket.timeout)

        shared_client_cache = SharedClientCache(
            REGION_ONE_LICENSE_CACHE_TYPE, CacheSpecification(fetch_implementation)
        )

        self.assertRaises(socket.timeout, shared_client_cache.read)
        self.assertEqual(
            fetch_implementation.call_count, shared_client_cache._max_attempts
        )
