# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import mock

import sys
sys.modules['fm_core'] = mock.Mock()

from dcmanager.manager import scheduler
from dcmanager.manager import service
from dcmanager.tests import base
from dcmanager.tests import utils
from oslo_config import cfg

CONF = cfg.CONF
FAKE_USER = utils.UUID1
FAKE_JOB = utils.UUID2


class TestDCManagerService(base.DCManagerTestCase):
    def setUp(self):
        super(TestDCManagerService, self).setUp()
        self.tenant_id = 'fake_admin'
        self.thm = scheduler.ThreadGroupManager()
        self.context = utils.dummy_context(user='test_user',
                                           tenant=self.tenant_id)
        self.service_obj = service.DCManagerService('dcmanager',
                                                    'dcmanager')
        self.payload = {}
        self.user_id = FAKE_USER
        self.job_id = FAKE_JOB

    def test_init(self):
        self.assertEqual(self.service_obj.host, 'localhost')
        self.assertEqual(self.service_obj.topic, 'dcmanager')
        self.assertEqual(self.service_obj.periodic_enable,
                         CONF.scheduler.periodic_enable)

    def test_init_tgm(self):
        self.service_obj.init_tgm()
        self.assertIsNotNone(self.service_obj.TG)

    @mock.patch.object(service, 'SubcloudAuditManager')
    def test_init_audit_managers(self, mock_audit_manager):
        self.service_obj.init_audit_managers()
        self.assertIsNotNone(self.service_obj.subcloud_audit_manager)
        self.assertIsNotNone(self.service_obj.patch_audit_manager)

    @mock.patch.object(service, 'SwUpdateManager')
    @mock.patch.object(service, 'SubcloudManager')
    def test_init_managers(self, mock_subcloud_manager,
                           mock_sw_update_manager):
        self.service_obj.init_managers()
        self.assertIsNotNone(self.service_obj.subcloud_manager)
        self.assertIsNotNone(self.service_obj.sw_update_manager)

    @mock.patch.object(service, 'SwUpdateManager')
    @mock.patch.object(service, 'SubcloudManager')
    @mock.patch.object(service, 'SubcloudAuditManager')
    @mock.patch.object(service, 'rpc_messaging')
    def test_start(self, mock_rpc, mock_audit_manager, mock_subcloud_manager,
                   mock_sw_update_manager):
        self.service_obj.start()
        mock_rpc.get_rpc_server.assert_called_once_with(
            self.service_obj.target, self.service_obj)
        mock_rpc.get_rpc_server().start.assert_called_once_with()

    @mock.patch.object(service, 'SubcloudAuditManager')
    @mock.patch.object(service, 'PatchAuditManager')
    def test_periodic_audit_subclouds(self, mock_patch_audit_manager,
                                      mock_subcloud_audit_manager):
        self.service_obj.init_tgm()
        self.service_obj.init_audit_managers()
        self.service_obj.subcloud_audit()
        mock_subcloud_audit_manager().periodic_subcloud_audit.\
            assert_called_once_with()

    @mock.patch.object(service, 'SubcloudAuditManager')
    @mock.patch.object(service, 'PatchAuditManager')
    def test_periodic_audit_patches(self, mock_patch_audit_manager,
                                    mock_subcloud_audit_manager):
        self.service_obj.init_tgm()
        self.service_obj.init_audit_managers()
        self.service_obj.patch_audit()
        mock_patch_audit_manager().periodic_patch_audit.\
            assert_called_once_with()

    @mock.patch.object(service, 'SwUpdateManager')
    @mock.patch.object(service, 'SubcloudManager')
    def test_add_subcloud(self, mock_subcloud_manager, mock_sw_update_manager):
        self.service_obj.init_tgm()
        self.service_obj.init_managers()
        self.service_obj.add_subcloud(
            self.context, payload={'name': 'testname'})
        mock_subcloud_manager().add_subcloud.\
            assert_called_once_with(self.context, mock.ANY)

    @mock.patch.object(service, 'SwUpdateManager')
    @mock.patch.object(service, 'SubcloudManager')
    def test_delete_subcloud(self, mock_subcloud_manager,
                             mock_sw_update_manager):
        self.service_obj.init_tgm()
        self.service_obj.init_managers()
        self.service_obj.delete_subcloud(
            self.context, subcloud_id=1)
        mock_subcloud_manager().delete_subcloud.\
            assert_called_once_with(self.context, mock.ANY)

    @mock.patch.object(service, 'SwUpdateManager')
    @mock.patch.object(service, 'SubcloudManager')
    def test_update_subcloud(self, mock_subcloud_manager,
                             mock_sw_update_manager):
        self.service_obj.init_tgm()
        self.service_obj.init_managers()
        self.service_obj.update_subcloud(
            self.context, subcloud_id=1, management_state='testmgmtstatus')
        mock_subcloud_manager().update_subcloud.\
            assert_called_once_with(self.context, mock.ANY,
                                    mock.ANY, mock.ANY,
                                    mock.ANY, mock.ANY)

    @mock.patch.object(service, 'SwUpdateManager')
    @mock.patch.object(service, 'SubcloudManager')
    @mock.patch.object(service, 'SubcloudAuditManager')
    @mock.patch.object(service, 'rpc_messaging')
    def test_stop_rpc_server(self, mock_rpc, mock_audit_manager,
                             mock_subcloud_manager, mock_sw_update_manager):
        self.service_obj.start()
        self.service_obj._stop_rpc_server()
        mock_rpc.get_rpc_server().stop.assert_called_once_with()

    @mock.patch.object(service, 'SwUpdateManager')
    @mock.patch.object(service, 'SubcloudManager')
    @mock.patch.object(service, 'SubcloudAuditManager')
    @mock.patch.object(service, 'rpc_messaging')
    def test_stop(self, mock_rpc, mock_audit_manager,
                  mock_subcloud_manager, mock_sw_update_manager):
        self.service_obj.start()
        self.service_obj.stop()
        mock_rpc.get_rpc_server().stop.assert_called_once_with()
