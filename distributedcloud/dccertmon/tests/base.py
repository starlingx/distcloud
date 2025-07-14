#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from oslo_config import cfg
from oslotest import base

from dccertmon.common import config


class DCCertMonTestCase(base.BaseTestCase):
    """Test case base class for all unit tests."""

    def setUp(self):
        super().setUp()
        config.register_config_opts()
        cfg.CONF([], project="dccertmon", default_config_files=[])
        cfg.CONF.set_override("auth_uri", "http://fake:5000/v3", group="endpoint_cache")

    def _mock_object(self, target, attribute, wraps=None):
        """Mock a specified target's attribute and return the mock object"""

        mock_patch_object = mock.patch.object(target, attribute, wraps=wraps)
        self.addCleanup(mock_patch_object.stop)

        return mock_patch_object.start()
