#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import copy
import socket
import threading
import time

import mock

from dccommon.drivers.openstack.patching_v1 import PatchingClient
from dcmanager.common.exceptions import InvalidParameterValue
from dcmanager.orchestrator.states.upgrade.cache.cache_specifications import \
    REGION_ONE_PATCHING_CACHE_SPECIFICATION
from dcmanager.orchestrator.states.upgrade.cache.cache_specifications import \
    REGION_ONE_PATCHING_CACHE_TYPE
from dcmanager.orchestrator.states.upgrade.cache.shared_client_cache import \
    SharedClientCache
from dcmanager.tests import base

CACHE_CLASS_PATH = 'dcmanager.orchestrator.states.upgrade.cache.' \
                   'shared_client_cache.SharedClientCache'

CACHE_CLIENT_PATH = 'dcmanager.orchestrator.states.upgrade.cache.clients'

BLOCKING_TIME_SECONDS = 0.01
WAIT_TIME_SECONDS = 0.005

MOCK_REGION_ONE_PATCHES = {'committed_patch': {'sw_version': '17.07',
                                               'repostate': 'Committed',
                                               'patchstate': 'Committed'},

                           'applied_patch': {'sw_version': '17.07',
                                             'repostate': 'Applied',
                                             'patchstate': 'Applied'},

                           'available_patch': {'sw_version': '17.07',
                                               'repostate': 'Available',
                                               'patchstate': 'Available'}
                           }


class TestRegionOnePatchingCache(base.DCManagerTestCase):

    def setUp(self):
        super(TestRegionOnePatchingCache, self).setUp()

        # Mock patching client used by cache
        self.mock_client = mock.MagicMock(spec=PatchingClient)
        self.mock_client.query.side_effect = lambda timeout: MOCK_REGION_ONE_PATCHES
        self.region_one_client_patch = mock.patch(
            '%s.get_patching_client' % CACHE_CLIENT_PATH,
            return_value=self.mock_client)
        self.region_one_client_patch.start()

    def test_read_should_use_cache(self):
        # Retrieve patches from cache for the first time
        patching_cache = SharedClientCache(REGION_ONE_PATCHING_CACHE_TYPE,
                                           REGION_ONE_PATCHING_CACHE_SPECIFICATION)
        patches = patching_cache.read()

        # Check if mocked client was used to retrieve the patches
        assert set(patches.keys()) == set(MOCK_REGION_ONE_PATCHES.keys())
        assert self.mock_client.query.call_count == 1

        # Retrieve patches from cache another time
        patches = patching_cache.read()

        # Check if cached patches were used instead of the client (client is not
        # called again)
        assert set(patches.keys()) == set(MOCK_REGION_ONE_PATCHES.keys())
        assert self.mock_client.query.call_count == 1

    def test_read_should_block_concurrent_calls(self):
        # Alter mock client to block the query and hold the cache lock for a while
        self.mock_client.query.side_effect = \
            lambda timeout: self._blocking_mock_client_query()

        patching_cache = SharedClientCache(REGION_ONE_PATCHING_CACHE_TYPE,
                                           REGION_ONE_PATCHING_CACHE_SPECIFICATION)

        # Start thread to retrieve patches from cache for the first time
        # Call from a separate method to add the client mock to the thread context
        thread = threading.Thread(target=self._retrieve_patches_from_thread,
                                  args=(patching_cache,))
        thread.start()

        # Wait for a short while before second call, so that the first call acquires
        # lock
        time.sleep(WAIT_TIME_SECONDS)

        # By this point, the first call should have reached the blocking query
        assert self.mock_client.query.call_count == 1

        # Check that a second call retrieves patches directly (does not call client
        # again)
        patches = patching_cache.read()
        assert set(patches.keys()) == set(MOCK_REGION_ONE_PATCHES.keys())
        assert self.mock_client.query.call_count == 1

    def test_read_should_retry_if_specified(self):
        # First attempt to read from client should fail, second one should succeed
        attempt_sequence = [self._blocking_mock_client_error,
                            self._blocking_mock_client_query]

        self.mock_client.query.side_effect = \
            lambda timeout: attempt_sequence.pop(0)()

        # Specify two attempts for the patching client read
        cache_specification = copy.deepcopy(REGION_ONE_PATCHING_CACHE_SPECIFICATION)
        cache_specification.max_attempts = 2
        cache_specification.retry_sleep_msecs = WAIT_TIME_SECONDS * 1000
        patching_cache = SharedClientCache(REGION_ONE_PATCHING_CACHE_TYPE,
                                           cache_specification)

        # Start thread to retrieve patches from cache for the first time
        # Call from a separate method to add the client mock to the thread context
        thread = threading.Thread(target=self._retrieve_patches_from_thread,
                                  args=(patching_cache,))
        thread.start()

        # After a while, the first call should try to retrieve data for the first
        # time
        time.sleep(WAIT_TIME_SECONDS)
        assert self.mock_client.query.call_count == 1

        # After some more time, the first attempt should fail, and the call should
        # try a second time
        time.sleep(BLOCKING_TIME_SECONDS + WAIT_TIME_SECONDS)
        assert self.mock_client.query.call_count == 2

        # Start a second read while the first one is retrying
        patches = patching_cache.read()

        # Second read should retrieve data directly from the cache (client should
        # not be called)
        assert set(patches.keys()) == set(MOCK_REGION_ONE_PATCHES.keys())
        assert self.mock_client.query.call_count == 2

    def test_read_should_fail_concurrent_calls_if_client_fails(self):
        # Read from client should only succeed on third attempt
        attempt_sequence = [self._blocking_mock_client_error,
                            self._blocking_mock_client_error,
                            self._blocking_mock_client_query]

        self.mock_client.query.side_effect = \
            lambda timeout: attempt_sequence.pop(0)()

        # Specify only two attempts for the patching client read
        # Since client read should only succeed on third attempt, fetch should fail
        cache_specification = copy.deepcopy(REGION_ONE_PATCHING_CACHE_SPECIFICATION)
        cache_specification.max_attempts = 2
        cache_specification.retry_sleep_msecs = WAIT_TIME_SECONDS * 1000
        patching_cache = SharedClientCache(REGION_ONE_PATCHING_CACHE_TYPE,
                                           cache_specification)

        # Start thread to retrieve patches from cache for the first time
        # Call from a separate method to add the client mock to the thread context
        thread = threading.Thread(target=self._retrieve_patches_from_thread,
                                  args=(patching_cache,))
        thread.start()

        # Wait for first call to have the client lock
        time.sleep(WAIT_TIME_SECONDS)
        assert self.mock_client.query.call_count == 1

        # Start a second read while the first one is reading from client
        # Since client read should fail, reading from cache should fail too
        self.assertRaises(RuntimeError, patching_cache.read)

        # Check that second call did not read from client (number of calls did not
        # change)
        assert self.mock_client.query.call_count == 2

    def test_read_should_filter_by_given_state(self):
        patching_cache = SharedClientCache(REGION_ONE_PATCHING_CACHE_TYPE,
                                           REGION_ONE_PATCHING_CACHE_SPECIFICATION)

        # Retrieve available patches from cache and verify results
        assert set(patching_cache.read(state='Available').keys()) == {
            'available_patch'}
        assert self.mock_client.query.call_count == 1

        # Retrieve applied patches from cache and verify results
        assert set(patching_cache.read(state='Applied').keys()) == {'applied_patch'}
        assert self.mock_client.query.call_count == 1

        # Retrieve committed patches from cache and verify results
        assert set(patching_cache.read(state='Committed').keys()) == {
            'committed_patch'}
        assert self.mock_client.query.call_count == 1

    def test_read_should_reject_invalid_filter_parameter(self):
        patching_cache = SharedClientCache(REGION_ONE_PATCHING_CACHE_TYPE,
                                           REGION_ONE_PATCHING_CACHE_SPECIFICATION)
        self.assertRaises(InvalidParameterValue, patching_cache.read,
                          invalid_param='test')

    def _retrieve_patches_from_thread(self, patching_cache):
        patcher = mock.patch('%s.get_patching_client' % CACHE_CLIENT_PATH,
                             return_value=self.mock_client)
        patcher.start()
        patching_cache.read()
        patcher.stop()

    @staticmethod
    def _blocking_mock_client_query():
        time.sleep(BLOCKING_TIME_SECONDS)
        return MOCK_REGION_ONE_PATCHES

    @staticmethod
    def _blocking_mock_client_error():
        time.sleep(BLOCKING_TIME_SECONDS)
        raise socket.timeout

    def tearDown(self):
        super(TestRegionOnePatchingCache, self).tearDown()
        self.region_one_client_patch.stop()
