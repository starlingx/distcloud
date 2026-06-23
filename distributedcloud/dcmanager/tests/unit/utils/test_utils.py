# Copyright 2016 Ericsson AB
# Copyright (c) 2017, 2019, 2021, 2024 Wind River Systems, Inc.
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import os
import tempfile
from unittest import mock

from dcmanager.common import utils
from dcmanager.tests import base


class TestUtils(base.DCManagerTestCase):
    def setUp(self):
        super(TestUtils, self).setUp()

    def test_get_management_subnet(self):
        payload = {"management_subnet": "192.168.204.0/24"}
        self.assertEqual(
            utils.get_management_subnet(payload), payload["management_subnet"]
        )

    def test_get_management_subnet_return_admin(self):
        payload = {
            "admin_subnet": "192.168.205.0/24",
            "management_subnet": "192.168.204.0/24",
        }
        self.assertEqual(utils.get_management_subnet(payload), payload["admin_subnet"])

    def test_get_management_start_address(self):
        payload = {"management_start_address": "192.168.204.2"}
        self.assertEqual(
            utils.get_management_start_address(payload),
            payload["management_start_address"],
        )

    def test_get_management_start_address_return_admin(self):
        payload = {
            "admin_start_address": "192.168.205.2",
            "management_start_address": "192.168.204.2",
        }
        self.assertEqual(
            utils.get_management_start_address(payload),
            payload["admin_start_address"],
        )

    def test_get_management_end_address(self):
        payload = {"management_end_address": "192.168.204.50"}
        self.assertEqual(
            utils.get_management_end_address(payload),
            payload["management_end_address"],
        )

    def test_get_management_end_address_return_admin(self):
        payload = {
            "admin_end_address": "192.168.205.50",
            "management_end_address": "192.168.204.50",
        }
        self.assertEqual(
            utils.get_management_end_address(payload), payload["admin_end_address"]
        )

    def test_get_primary_management_gateway_address(self):
        payload = {"management_gateway_address": "192.168.204.1"}
        self.assertEqual(
            utils.get_primary_management_gateway_address(payload),
            payload["management_gateway_address"],
        )

    def test_get_primary_management_gateway_address_return_admin(self):
        payload = {
            "admin_gateway_address": "192.168.205.1",
            "management_gateway_address": "192.168.204.1",
        }
        self.assertEqual(
            utils.get_primary_management_gateway_address(payload),
            payload["admin_gateway_address"],
        )

    def _create_log_file(self, content):
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
        tmp.write(content)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    @mock.patch("dcmanager.common.utils.add_latest_rotated_file")
    def test_get_msg_output_info_double_quote_format(self, mock_rotated):
        log_file = self._create_log_file(
            "TASK [prestage/prepare-env : Some setup task] ***\n"
            'ok: [subcloud1] => {"msg": "some other output"}\n'
            "TASK [prestage/get-prestage-versions : Print prestage versions] ***\n"
            'ok: [subcloud1] => {"msg": "prestage_versions: '
            'for-install: None - for-sw-deploy: 26.09"}\n'
            "TASK [prestage/cleanup : Remove temp files] ***\n"
            'ok: [subcloud1] => {"msg": "cleanup done"}\n'
            "PLAY RECAP ***\n"
        )
        mock_rotated.return_value = [log_file]
        result = utils.get_msg_output_info(
            log_file,
            r"prestage\/get-prestage-versions : Print prestage versions",
            "prestage_versions: ",
        )
        self.assertEqual(result, "for-install: None - for-sw-deploy: 26.09")

    @mock.patch("dcmanager.common.utils.add_latest_rotated_file")
    def test_get_msg_output_info_single_quote_format(self, mock_rotated):
        log_file = self._create_log_file(
            "TASK [prestage/sync-software-metadata : debug] ***\n"
            "ok: [subcloud1] => {msg: 'some unrelated msg'}\n"
            "TASK [prestage/get-prestage-versions : Print prestage versions] ***\n"
            "ok: [subcloud1] => {msg: 'prestage_versions: "
            "for-install: None - for-sw-deploy: 26.09'}\n"
            "TASK [prestage/cleanup : Remove temp files] ***\n"
            "ok: [subcloud1] => {msg: 'cleanup done'}\n"
            "PLAY RECAP ***\n"
        )
        mock_rotated.return_value = [log_file]
        result = utils.get_msg_output_info(
            log_file,
            r"prestage\/get-prestage-versions : Print prestage versions",
            "prestage_versions: ",
        )
        self.assertEqual(result, "for-install: None - for-sw-deploy: 26.09")

    @mock.patch("dcmanager.common.utils.add_latest_rotated_file")
    def test_get_msg_output_info_not_found(self, mock_rotated):
        log_file = self._create_log_file(
            "TASK [other-task : Something] ***\nPLAY RECAP ***\n"
        )
        mock_rotated.return_value = [log_file]
        result = utils.get_msg_output_info(
            log_file,
            r"prestage\/get-prestage-versions : Print prestage versions",
            "prestage_versions: ",
        )
        self.assertFalse(result)

    @mock.patch("dcmanager.common.utils.add_latest_rotated_file")
    def test_get_msg_output_info_multiple_play_recaps(self, mock_rotated):
        log_file = self._create_log_file(
            "TASK [prestage/get-prestage-versions : Print prestage versions] ***\n"
            'ok: [subcloud1] => {"msg": "prestage_versions: '
            'for-install: None - for-sw-deploy: 25.09"}\n'
            "PLAY RECAP ***\n"
            "TASK [prestage/get-prestage-versions : Print prestage versions] ***\n"
            'ok: [subcloud1] => {"msg": "prestage_versions: '
            'for-install: None - for-sw-deploy: 26.09"}\n'
            "PLAY RECAP ***\n"
        )
        mock_rotated.return_value = [log_file]
        result = utils.get_msg_output_info(
            log_file,
            r"prestage\/get-prestage-versions : Print prestage versions",
            "prestage_versions: ",
        )
        self.assertEqual(result, "for-install: None - for-sw-deploy: 26.09")
