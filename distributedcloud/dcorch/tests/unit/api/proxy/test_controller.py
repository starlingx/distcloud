# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import io
import json
import os
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


class TestUSMAPIControllerRemoveEmptyDirs(unittest.TestCase):
    """Test _remove_empty_dirs tolerates a missing vault directory."""

    @mock.patch("os.path.isdir", return_value=False)
    @mock.patch("pathlib.Path")
    def test_missing_directory_is_skipped(self, mock_path_cls, _mock_isdir):
        USMAPIController._remove_empty_dirs("/opt/dc-vault/software")
        mock_path_cls.assert_not_called()

    @mock.patch("os.path.isdir", return_value=True)
    @mock.patch("pathlib.Path")
    def test_existing_directory_is_iterated(self, mock_path_cls, _mock_isdir):
        empty_folder = mock.MagicMock()
        empty_folder.is_dir.return_value = True
        mock_path_cls.return_value.iterdir.return_value = [empty_folder]

        USMAPIController._remove_empty_dirs("/opt/dc-vault/software")

        empty_folder.rmdir.assert_called_once()


class TestUSMAPIControllerProcessResponse(unittest.TestCase):
    """Test _process_response does not mask the software API response."""

    def setUp(self):
        self.controller = mock.MagicMock(spec=USMAPIController)
        self.controller.OK_STATUS_CODE = USMAPIController.OK_STATUS_CODE
        # pylint: disable=assignment-from-no-return,no-value-for-parameter
        self.controller._process_response = USMAPIController._process_response.__get__(
            self.controller
        )

    @mock.patch("dcorch.api.proxy.apps.controller.proxy_utils")
    def test_audit_failure_returns_original_response(self, mock_proxy_utils):
        mock_proxy_utils.get_operation_type.return_value = "post"
        environ = {}
        request = mock.MagicMock()
        # Software API rejected the upload: the error response must reach the
        # client even if the dc-vault audit raises an exception afterwards.
        response = mock.MagicMock()
        self.controller.get_status_code.return_value = 500
        self.controller._get_releases.side_effect = OSError("vault is unreadable")

        ret = self.controller._process_response(environ, request, response)

        self.assertEqual(ret, response)
        self.controller._audit_dcvault.assert_not_called()
        mock_proxy_utils.cleanup.assert_called_once_with(environ)


class TestUSMAPIControllerMetadata(unittest.TestCase):
    """Test the metadata file is created and parsed sanely."""

    def test_empty_file_loads_as_no_releases(self):
        # The metadata file is created empty by the _open_create opener, so
        # the first write must not report it as invalid JSON.
        self.assertEqual(USMAPIController._load_metadata(io.StringIO("")), {})
        self.assertEqual(USMAPIController._load_metadata(io.StringIO("   ")), {})

    def test_valid_json_is_parsed(self):
        metadata = {"starlingx-24.09.1": ["/opt/dc-vault/software/24.09/a.iso"]}
        self.assertEqual(
            USMAPIController._load_metadata(io.StringIO(json.dumps(metadata))),
            metadata,
        )

    def test_invalid_json_still_raises(self):
        # Corrupted content should still raise
        with self.assertRaises(json.JSONDecodeError):
            USMAPIController._load_metadata(io.StringIO("{not json"))

    @mock.patch("os.open")
    def test_open_create_uses_non_executable_mode(self, mock_os_open):
        USMAPIController._open_create("/opt/dc-vault/software/.metadata", os.O_RDWR)

        mock_os_open.assert_called_once_with(
            "/opt/dc-vault/software/.metadata", os.O_RDWR | os.O_CREAT, 0o644
        )
