# Copyright (c) 2017-2023 Wind River Systems, Inc.
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

import mock
import os.path
import sys
sys.modules['fm_core'] = mock.Mock()

from dcmanager.common import scheduler
from dcmanager.manager import service
from dcmanager.tests import base
from dcmanager.tests import utils
from oslo_config import cfg

CONF = cfg.CONF
FAKE_USER = utils.UUID1
FAKE_JOB = utils.UUID2


class FakeDCManagerAuditAPI(object):

    def __init__(self):
        self.trigger_patch_audit = mock.MagicMock()


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

        os.path.isdir = mock.Mock(return_value=True)

        # Mock the DCManager Audit API
        self.fake_dcmanager_audit_api = FakeDCManagerAuditAPI()
        p = mock.patch('dcmanager.audit.rpcapi.ManagerAuditClient')
        self.mock_dcmanager_audit_api = p.start()
        self.mock_dcmanager_audit_api.return_value = \
            self.fake_dcmanager_audit_api
        self.addCleanup(p.stop)

    def test_init(self):
        self.assertEqual(self.service_obj.host, 'localhost')
        self.assertEqual(self.service_obj.topic, 'dcmanager')

    @mock.patch.object(service, 'SubcloudManager')
    def test_init_managers(self, mock_subcloud_manager):
        self.service_obj.init_managers()
        self.assertIsNotNone(self.service_obj.subcloud_manager)

    @mock.patch.object(service, 'SubcloudManager')
    @mock.patch.object(service, 'rpc_messaging')
    def test_start(self, mock_rpc, mock_subcloud_manager):
        self.service_obj.start()
        mock_rpc.get_rpc_server.assert_called_once_with(
            self.service_obj.target, self.service_obj)
        mock_rpc.get_rpc_server().start.assert_called_once_with()

    @mock.patch.object(service, 'SubcloudManager')
    def test_add_subcloud(self, mock_subcloud_manager):
        self.service_obj.init_managers()
        self.service_obj.add_subcloud(
            self.context, subcloud_id=1, payload={'name': 'testname'})
        mock_subcloud_manager().add_subcloud.\
            assert_called_once_with(self.context, 1, mock.ANY)

    @mock.patch.object(service, 'SubcloudManager')
    def test_delete_subcloud(self, mock_subcloud_manager):
        self.service_obj.init_managers()
        self.service_obj.delete_subcloud(
            self.context, subcloud_id=1)
        mock_subcloud_manager().delete_subcloud.\
            assert_called_once_with(self.context, mock.ANY)

    @mock.patch.object(service, 'SubcloudManager')
    def test_update_subcloud(self, mock_subcloud_manager):
        self.service_obj.init_managers()
        self.service_obj.update_subcloud(
            self.context, subcloud_id=1,
            management_state='testmgmtstatus')
        mock_subcloud_manager().update_subcloud.assert_called_once_with(
            self.context, 1, 'testmgmtstatus', None, None, None, None, None, None, None, None)

    @mock.patch.object(service, 'SubcloudManager')
    @mock.patch.object(service, 'rpc_messaging')
    def test_stop_rpc_server(self, mock_rpc, mock_subcloud_manager):
        self.service_obj.start()
        self.service_obj._stop_rpc_server()
        mock_rpc.get_rpc_server().stop.assert_called_once_with()

    @mock.patch.object(service, 'SubcloudManager')
    @mock.patch.object(service, 'rpc_messaging')
    def test_stop(self, mock_rpc, mock_subcloud_manager):
        self.service_obj.start()
        self.service_obj.stop()
        mock_rpc.get_rpc_server().stop.assert_called_once_with()
