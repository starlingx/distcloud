# Copyright (c) 2017-2024 Wind River Systems, Inc.
# All Rights Reserved.
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

from keystoneauth1 import exceptions as keystone_exceptions
import mock

from dccommon import consts as dccommon_consts
from dcmanager.audit import patch_audit
from dcmanager.audit import rpcapi
from dcmanager.audit import subcloud_audit_manager
from dcmanager.tests import base
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


class TestPatchAudit(base.DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self._mock_object(rpcapi, "ManagerAuditWorkerClient")
        self.mock_subcloud_audit_manager_context = self._mock_object(
            subcloud_audit_manager, "context"
        )

        self.mock_subcloud_audit_manager_context.get_admin_context.return_value = (
            self.ctx
        )

        self.pm = patch_audit.PatchAudit(self.ctx)
        self.am = subcloud_audit_manager.SubcloudAuditManager()
        self.am.patch_audit = self.pm

        self.keystone_client = mock.MagicMock()

    def test_patch_audit_previous_release_usm_enabled(self):
        subcloud = create_fake_subcloud(self.ctx)
        patch_response = self.pm.subcloud_patch_audit(
            self.keystone_client,
            subcloud,
        )
        load_response = self.pm.subcloud_load_audit()

        expected_patch_response = dccommon_consts.SYNC_STATUS_NOT_AVAILABLE
        expected_load_response = dccommon_consts.SYNC_STATUS_NOT_AVAILABLE

        self.keystone_client.services.find.assert_called_once()
        self.assertEqual(patch_response, expected_patch_response)
        self.assertEqual(load_response, expected_load_response)

    def test_patch_audit_previous_release(self):
        subcloud = create_fake_subcloud(self.ctx)
        self.keystone_client.services.find.side_effect = keystone_exceptions.NotFound

        patch_response = self.pm.subcloud_patch_audit(
            self.keystone_client,
            subcloud,
        )
        load_response = self.pm.subcloud_load_audit()

        expected_patch_response = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        expected_load_response = dccommon_consts.SYNC_STATUS_NOT_AVAILABLE

        self.keystone_client.services.find.assert_called_once()
        self.assertEqual(patch_response, expected_patch_response)
        self.assertEqual(load_response, expected_load_response)

    def test_patch_audit_current_release(self):
        subcloud = create_fake_subcloud(self.ctx, software_version="TEST.SW.VERSION")
        patch_response = self.pm.subcloud_patch_audit(
            self.keystone_client,
            subcloud,
        )
        load_response = self.pm.subcloud_load_audit()

        expected_patch_response = dccommon_consts.SYNC_STATUS_NOT_AVAILABLE
        expected_load_response = dccommon_consts.SYNC_STATUS_NOT_AVAILABLE

        self.assertFalse(self.keystone_client.get_endpoint.called)
        self.assertEqual(patch_response, expected_patch_response)
        self.assertEqual(load_response, expected_load_response)
