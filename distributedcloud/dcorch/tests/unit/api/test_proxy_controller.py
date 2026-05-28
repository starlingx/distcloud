# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import sys
import unittest
from unittest import mock

from oslo_config import cfg

# Mock modules that are unavailable in the tox environment.
# The controller imports usm_util -> software.utils -> software.ostree_utils
# -> gi.repository which is a system C library not available in tox.
sys.modules.setdefault("gi", mock.MagicMock())
sys.modules.setdefault("gi.repository", mock.MagicMock())
sys.modules.setdefault("software.ostree_utils", mock.MagicMock())

# Register the 'type' option required by dispatcher.py
try:
    cfg.CONF.register_opt(cfg.StrOpt("type", default="identity"))
except cfg.DuplicateOptError:
    pass

# pylint: disable=wrong-import-position
from dcorch.api.proxy.apps.controller import IdentityAPIController  # noqa: E402
from dcorch.common import consts  # noqa: E402

# pylint: enable=wrong-import-position


class TestIdentityAPIController(unittest.TestCase):
    """Test identity api controller for user password change requests."""

    def setUp(self):
        self.controller = mock.MagicMock(spec=IdentityAPIController)
        self.controller.get_resource_id_from_link = (
            IdentityAPIController.get_resource_id_from_link
        )
        self.controller._mask_sensitive_info.side_effect = lambda x: x
        self.controller.ctxt = mock.MagicMock()
        self.controller.sync_endpoint = "identity"
        # Bind the real _enqueue_work to the mock instance
        # pylint: disable=assignment-from-no-return,no-value-for-parameter
        self.controller._enqueue_work = IdentityAPIController._enqueue_work.__get__(
            self.controller
        )

    @mock.patch("dcorch.api.proxy.apps.controller.utils")
    def test_enqueue_work_password_change_removes_password_suffix(self, mock_utils):
        user_id = "05a1ee70b75a42a7ba71da2f72sword"
        request_header = f"/v3/users/{user_id}/password"
        self.controller.get_request_header.return_value = request_header
        self.controller._get_resource_type_from_environ.return_value = (
            consts.RESOURCE_TYPE_IDENTITY_USERS_PASSWORD
        )
        request_body = json.dumps(
            {"user": {"password": "new_pass", "original_password": "old_pass"}}
        )
        environ = {"REQUEST_METHOD": "POST"}

        # pylint: disable=no-value-for-parameter
        self.controller._enqueue_work(environ, request_body, None)

        mock_utils.enqueue_work.assert_called_once()
        call_args = mock_utils.enqueue_work.call_args[0]
        actual_resource_id = call_args[3]
        self.assertEqual(user_id, actual_resource_id)
