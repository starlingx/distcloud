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

from oslo_config import cfg

from dcmanager.manager import subcloud_audit_manager
from dcmanager.manager import subcloud_manager
from dcmanager.tests import base
from dcmanager.tests import utils


from dcorch.common import messaging as dcorch_messaging


CONF = cfg.CONF
FAKE_PROJECT = 'fake_project'
FAKE_REGION = 'fake_region'
NOVA_USAGE = {'ram': 100, 'cores': '50'}
NEUTRON_USAGE = {'port': 10}
CINDER_USAGE = {'volumes': 18}
FAKE_REGION_DICT = {'region1': {'ram': 100},
                    'region2': {'ram': 200, 'volumes': 500}}
TOTAL_USAGE = {}
TOTAL_USAGE.update(NOVA_USAGE)
TOTAL_USAGE.update(NEUTRON_USAGE)
TOTAL_USAGE.update(CINDER_USAGE)
TASK_TYPE = 'quota_sync'


class TestAuditManager(base.DCManagerTestCase):
    def setUp(self):
        super(TestAuditManager, self).setUp()
        self.ctxt = utils.dummy_context()
        dcorch_messaging.setup("fake://", optional=True)

    @mock.patch.object(subcloud_audit_manager, 'SysinvClient')
    @mock.patch.object(subcloud_audit_manager, 'KeystoneClient')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_init(self, mock_context,
                  mock_keystone_client,
                  mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt

        sm = subcloud_manager.SubcloudManager()
        am = subcloud_audit_manager.SubcloudAuditManager(subcloud_manager=sm)
        self.assertIsNotNone(am)
        self.assertEqual('subcloud_audit_manager', am.service_name)
        self.assertEqual('localhost', am.host)
        self.assertEqual(self.ctxt, am.context)

    @mock.patch.object(subcloud_audit_manager, 'SysinvClient')
    @mock.patch.object(subcloud_audit_manager, 'KeystoneClient')
    @mock.patch.object(subcloud_audit_manager, 'context')
    def test_periodic_subcloud_audit(self, mock_context,
                                     mock_keystone_client,
                                     mock_sysinv_client):
        mock_context.get_admin_context.return_value = self.ctxt
        mock_sm = mock.Mock()
        am = subcloud_audit_manager.SubcloudAuditManager(
            subcloud_manager=mock_sm)
        am.periodic_subcloud_audit()
