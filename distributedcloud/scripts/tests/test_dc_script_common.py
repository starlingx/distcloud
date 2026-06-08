#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

import dc_script_common
from dccommon.tests import base


class TestGetSwVersion(base.DCCommonTestCase):
    """Test class for get_sw_version function."""

    def test_get_sw_version_returns_version(self):
        """Test get_sw_version returns version from platform.conf."""
        conf_content = "sw_version=m.n\nsystem_mode=simplex\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=conf_content)):
            result = dc_script_common.get_sw_version()
        self.assertEqual(result, "m.n")

    def test_get_sw_version_raises_when_not_found(self):
        """Test get_sw_version raises when sw_version not in file."""
        conf_content = "system_mode=simplex\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=conf_content)):
            self.assertRaises(RuntimeError, dc_script_common.get_sw_version)

    def test_get_sw_version_raises_when_empty_value(self):
        """Test get_sw_version raises when value is empty."""
        conf_content = "sw_version=\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=conf_content)):
            self.assertRaises(RuntimeError, dc_script_common.get_sw_version)

    def test_get_sw_version_raises_on_io_error(self):
        """Test get_sw_version raises on IOError."""
        with mock.patch("builtins.open", side_effect=IOError("No such file")):
            self.assertRaises(RuntimeError, dc_script_common.get_sw_version)
