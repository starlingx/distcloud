#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from oslotest import base


class DCAgentTestCase(base.BaseTestCase):
    """Test case base class for all unit tests."""

    def setUp(self):
        super().setUp()

    def _mock_sysinv_client(self, target):
        """Mock the target's SysinvClient"""

        mock_patch_object = mock.patch.object(target, "CachedSysinvClient")
        self.mock_sysinv_client = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_fm_client(self, target):
        """Mock the target's FmClient"""

        mock_patch_object = mock.patch.object(target, "CachedFmClient")
        self.mock_fm_client = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_software_client(self, target):
        """Mock the target's SoftwareClient"""

        mock_patch_object = mock.patch.object(target, "CachedSoftwareClient")
        self.mock_software_client = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)

    def _mock_keystone_cache(self, target):
        """Mock the target's KeystoneClient"""

        mock_patch_object = mock.patch.object(target, "KeystoneCache")
        self.mock_keystone_client = mock_patch_object.start()
        self.addCleanup(mock_patch_object.stop)
