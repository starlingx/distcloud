#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import threading
import time

import mock

from dccommon.drivers.openstack.patching_v1 import PatchingClient
from dcmanager.common.exceptions import InUse
from dcmanager.orchestrator.states.upgrade.cache.region_one_patching_cache import \
    RegionOnePatchingCache
from dcmanager.tests import base

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
        self.mock_patching_client = mock.MagicMock(spec=PatchingClient)
        self.mock_patching_client.query.return_value = MOCK_REGION_ONE_PATCHES
        self.region_one_client_patch = mock.patch('dcmanager.orchestrator.states.upgrade.cache.'
                                                  'region_one_patching_cache.'
                                                  'RegionOnePatchingCache._get_patching_client',
                                                  return_value=self.mock_patching_client)
        self.region_one_client_patch.start()

    def test_get_patches_should_use_cache(self):
        # Retrieve patches from cache for the first time
        patching_cache = RegionOnePatchingCache()
        patches = patching_cache.get_patches()

        # Check if mocked client was used to retrieve the patches
        assert set(patches.keys()) == set(MOCK_REGION_ONE_PATCHES.keys())
        assert self.mock_patching_client.query.call_count == 1

        # Retrieve patches from cache another time
        patches = patching_cache.get_patches()

        # Check if cached patches were used instead of the client (client is not called again)
        assert set(patches.keys()) == set(MOCK_REGION_ONE_PATCHES.keys())
        assert self.mock_patching_client.query.call_count == 1

    def test_get_patches_should_block_concurrent_calls(self):
        # Alter mock client to block the query and hold the cache lock for a while
        self.mock_patching_client.query.side_effect = self._blocking_mock_client_query
        patching_cache = RegionOnePatchingCache()

        # Start thread to retrieve patches from cache for the first time
        # Call from a separate method to add the client mock to the thread context
        thread = threading.Thread(target=self._retrieve_patches_from_thread, args=(patching_cache,))
        thread.start()

        # Wait for a short while before calling assertRaises, so that the first call acquires lock
        time.sleep(WAIT_TIME_SECONDS)

        # By this point, the first call should have reached the blocking query
        assert self.mock_patching_client.query.call_count == 1

        # Check that a second call gets an exception due to the first one being in progress
        self.assertRaises(InUse, patching_cache.get_patches)

        # Wait for the first call to finish blocking query and try again
        time.sleep(BLOCKING_TIME_SECONDS)
        patches = patching_cache.get_patches()

        # This time, it should retrieve the cached patches
        assert set(patches.keys()) == set(MOCK_REGION_ONE_PATCHES.keys())
        assert self.mock_patching_client.query.call_count == 1

    def test_get_patches_should_filter_by_given_state(self):
        patching_cache = RegionOnePatchingCache()

        # Retrieve available patches from cache and verify results
        assert set(patching_cache.get_patches('Available').keys()) == {'available_patch'}
        assert self.mock_patching_client.query.call_count == 1

        # Retrieve applied patches from cache and verify results
        assert set(patching_cache.get_patches('Applied').keys()) == {'applied_patch'}
        assert self.mock_patching_client.query.call_count == 1

        # Retrieve committed patches from cache and verify results
        assert set(patching_cache.get_patches('Committed').keys()) == {'committed_patch'}
        assert self.mock_patching_client.query.call_count == 1

    def _retrieve_patches_from_thread(self, patching_cache):
        with mock.patch('dcmanager.orchestrator.states.upgrade.cache.'
                        'region_one_patching_cache.'
                        'RegionOnePatchingCache._get_patching_client',
                        return_value=self.mock_patching_client):
            patching_cache.get_patches()

    @staticmethod
    def _blocking_mock_client_query():
        time.sleep(BLOCKING_TIME_SECONDS)
        return MOCK_REGION_ONE_PATCHES

    def tearDown(self):
        super(TestRegionOnePatchingCache, self).tearDown()
        self.region_one_client_patch.stop()
