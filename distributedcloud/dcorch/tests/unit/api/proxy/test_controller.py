# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import sys
import unittest
from unittest import mock

from oslo_config import cfg

# Mock modules that are unavailable in the tox environment.
sys.modules.setdefault("gi", mock.MagicMock())
sys.modules.setdefault("gi.repository", mock.MagicMock())
sys.modules.setdefault("software.ostree_utils", mock.MagicMock())

try:
    cfg.CONF.register_opt(cfg.StrOpt("type", default="usm"))
except cfg.DuplicateOptError:
    pass

# pylint: disable=wrong-import-position
from dcorch.api.proxy.apps.controller import USMAPIController  # noqa: E402

# pylint: enable=wrong-import-position


class TestUSMAPIControllerAuditDcvault(unittest.TestCase):
    """Test _audit_dcvault removes old files and metadata for deleted releases."""

    def setUp(self):
        self.controller = mock.MagicMock(spec=USMAPIController)
        self.controller.software_vault = "/opt/dc-vault/software"
        # pylint: disable=assignment-from-no-return,no-value-for-parameter
        self.controller._audit_dcvault = USMAPIController._audit_dcvault.__get__(
            self.controller
        )

    @mock.patch("pathlib.Path")
    def test_audit_removes_old_files_and_metadata(self, mock_path_cls):
        mock_path_instance = mock.MagicMock()
        mock_path_cls.return_value = mock_path_instance

        self.controller.read_metadata.return_value = {
            "starlingx-24.09.1": [
                "/opt/dc-vault/software/24.09/starlingx-24.09.1.iso",
                "/opt/dc-vault/software/24.09/starlingx-24.09.1.sig",
            ],
        }

        # Release no longer present in USM
        current_releases = {}

        self.controller._audit_dcvault(current_releases)

        self.controller.read_metadata.assert_called_once()
        self.assertEqual(mock_path_instance.unlink.call_count, 2)
        # remove_release_from_metadata is called once per file in the loop
        self.assertEqual(self.controller.remove_release_from_metadata.call_count, 2)
        self.controller.remove_release_from_metadata.assert_called_with(
            "starlingx-24.09.1"
        )
