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

    def _mock_object(self, target, attribute, wraps=None):
        """Mock a specified target's attribute and return the mock object"""

        mock_patch_object = mock.patch.object(target, attribute, wraps=wraps)
        self.addCleanup(mock_patch_object.stop)

        return mock_patch_object.start()
