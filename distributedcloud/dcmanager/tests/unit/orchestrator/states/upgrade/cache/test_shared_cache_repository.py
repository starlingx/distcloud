#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.common.exceptions import InvalidParameterValue
from dcmanager.orchestrator.states.upgrade.cache.cache_specifications import \
    REGION_ONE_PATCHING_CACHE_TYPE
from dcmanager.orchestrator.states.upgrade.cache.shared_cache_repository import \
    SharedCacheRepository
from dcmanager.tests import base

CACHE_CLASS_PATH = 'dcmanager.orchestrator.states.upgrade.cache.' \
                   'shared_client_cache.SharedClientCache'

MOCK_REGION_ONE_PATCHES = {'applied_patch': {'sw_version': '17.07',
                                             'repostate': 'Applied',
                                             'patchstate': 'Applied'}
                           }


class TestSharedCacheRepo(base.DCManagerTestCase):
    def setUp(self):
        super(TestSharedCacheRepo, self).setUp()

        # Return the same mock patches when reading from cache and from client
        self.read_patch = mock.patch('%s.read' % CACHE_CLASS_PATH,
                                     return_value=MOCK_REGION_ONE_PATCHES)

        self.mock_read = self.read_patch.start()

        # Initialize repository and instantiate caches
        self.shared_cache = SharedCacheRepository(
            operation_type=consts.SW_UPDATE_TYPE_UPGRADE)
        self.shared_cache.initialize_caches()

    def test_read_from_cache_should_use_shared_cache_if_present(self):
        patches = self.shared_cache.read(REGION_ONE_PATCHING_CACHE_TYPE)

        # Verify that cache instance was used to retrieve patches
        assert set(patches.keys()) == set(MOCK_REGION_ONE_PATCHES.keys())
        assert self.mock_read.call_count == 1

    def test_read_from_cache_should_raise_exception_if_cache_type_invalid(self):
        # Verify that an exception is raised if cache type does not correspond
        # an existing one
        self.assertRaises(InvalidParameterValue, self.shared_cache.read,
                          "Invalid type")

    def tearDown(self):
        super(TestSharedCacheRepo, self).tearDown()
        self.read_patch.stop()
