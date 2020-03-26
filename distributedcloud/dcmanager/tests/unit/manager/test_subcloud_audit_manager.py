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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import copy
import mock

import sys
sys.modules['fm_core'] = mock.Mock()

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.manager import subcloud_audit_manager
from dcmanager.manager import subcloud_manager

from dcmanager.tests import base


class FakeDCOrchAPI(object):

    def __init__(self):
        self.update_subcloud_states = mock.MagicMock()
        self.add_subcloud_sync_endpoint_type = mock.MagicMock()


class FakeAlarmAggregation(object):

    def __init__(self):
        self.update_alarm_summary = mock.MagicMock()


class FakeServiceGroup(object):
    def __init__(self, status, desired_state, service_group_name, uuid,
                 node_name, state, condition, name):
        self.status = status
        self.desired_state = desired_state
        self.service_group_name = service_group_name
        self.uuid = uuid
        self.node_name = node_name
        self.state = state
        self.condition = condition
        self.name = name


class FakeApplication(object):
    def __init__(self, status, name, manifest_name, active, progress,
                 app_version, manifest_file):
        self.status = status
        self.name = name
        self.manifest_name = manifest_name
        self.active = active
        self.progress = progress
        self.app_version = app_version
        self.manifest_file = manifest_file


FAKE_SERVICE_GROUPS = [
    FakeServiceGroup("",
                     "active",
                     "distributed-cloud-services",
                     "b00fd252-5bd7-44b5-bbde-7d525e7125c7",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "storage-monitoring-services",
                     "5a14a1d1-dac1-48b0-9598-3702e0b0338a",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "storage-services",
                     "5cbfa903-379f-4329-81b4-2e88acdfa215",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "web-services",
                     "42829858-008f-4931-94e1-4b86fe31ce3c",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "directory-services",
                     "74225295-2601-4376-a52c-7cbd149146f6",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "patching-services",
                     "6870c079-e1c3-4402-b88b-63a5ef06a77a",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "vim-services",
                     "d8367a52-316e-418b-9211-a13331e073ef",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "cloud-services",
                     "12682dc0-cef5-427a-b1a6-145cf950b49c",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "controller-services",
                     "daac63fb-24b3-4cd1-b895-260a32e356ae",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
    FakeServiceGroup("",
                     "active",
                     "oam-services",
                     "4b66913d-98ba-4a4a-86c3-168625f629eb",
                     "controller-0",
                     "active",
                     "",
                     "controller"),
]

FAKE_APPLICATIONS = [
    FakeApplication("applied",
                    "platform-integ-apps",
                    "platform-integration-manifest",
                    True,
                    "completed",
                    "1.0-8",
                    "manifest.yaml"),
    FakeApplication("applied",
                    "stx-openstack",
                    "stx-openstack-manifest",
                    True,
                    "completed",
                    "1.0-8",
                    "manifest.yaml"),
]


class FakeSysinvClient(object):

    def __init__(self, region, session):
        self.get_service_groups_result = FAKE_SERVICE_GROUPS
        self.get_applications_result = FAKE_APPLICATIONS

    def get_service_groups(self):
        return self.get_service_groups_result

    def get_applications(self):
        return self.get_applications_result


class FakeFmClient(object):

    def get_alarm_summary(self):
        pass


class FakeOpenStackDriver(object):

    def __init__(self, region_name):
        self.sysinv_client = FakeSysinvClient('fake_region', 'fake_session')
        self.fm_client = FakeFmClient()


class TestAuditManager(base.DCManagerTestCase):
    def setUp(self):
        super(TestAuditManager, self).setUp()

        # Mock the DCOrch API
        self.fake_dcorch_api = FakeDCOrchAPI()
        p = mock.patch('dcorch.rpc.client.EngineClient')
        self.mock_dcorch_api = p.start()
        self.mock_dcorch_api.return_value = self.fake_dcorch_api
        self.addCleanup(p.stop)

        # Mock the OpenStackDriver
        self.fake_openstack_client = FakeOpenStackDriver('fake_region')
        p = mock.patch.object(subcloud_audit_manager, 'OpenStackDriver')
        self.mock_openstack_driver = p.start()
        self.mock_openstack_driver.return_value = self.fake_openstack_client
        self.addCleanup(p.stop)

        # Mock the context
        p = mock.patch.object(subcloud_audit_manager, 'context')
        self.mock_context = p.start()
        self.mock_context.get_admin_context.return_value = self.ctx
        self.addCleanup(p.stop)

        # Mock alarm aggregation
        self.fake_alarm_aggr = FakeAlarmAggregation()
        p = mock.patch.object(subcloud_audit_manager,
                              'alarm_aggregation')
        self.mock_alarm_aggr = p.start()
        self.mock_alarm_aggr.AlarmAggregation.return_value = \
            self.fake_alarm_aggr
        self.addCleanup(p.stop)

    @staticmethod
    def create_subcloud_static(ctxt, **kwargs):
        values = {
            'name': "subcloud1",
            'description': "This is a subcloud",
            'location': "This is the location of the subcloud",
            'software_version': "10.04",
            'management_subnet': "192.168.101.0/24",
            'management_gateway_ip': "192.168.101.1",
            'management_start_ip': "192.168.101.2",
            'management_end_ip': "192.168.101.50",
            'systemcontroller_gateway_ip': "192.168.204.101",
            'deploy_status': "not-deployed",
            'openstack_installed': False,
        }
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, **values)

    def test_init(self):
        sm = subcloud_manager.SubcloudManager()
        am = subcloud_audit_manager.SubcloudAuditManager(subcloud_manager=sm)
        self.assertIsNotNone(am)
        self.assertEqual('subcloud_audit_manager', am.service_name)
        self.assertEqual('localhost', am.host)
        self.assertEqual(self.ctx, am.context)

    def test_periodic_subcloud_audit(self):
        mock_sm = mock.Mock()
        am = subcloud_audit_manager.SubcloudAuditManager(
            subcloud_manager=mock_sm)
        am.periodic_subcloud_audit()

    def test_audit_subcloud_online(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        mock_sm = mock.Mock()
        am = subcloud_audit_manager.SubcloudAuditManager(
            subcloud_manager=mock_sm)

        # No stx-openstack application
        self.fake_openstack_client.sysinv_client.get_application_results = []

        # Audit the subcloud
        am._audit_subcloud(subcloud.name, update_subcloud_state=False,
                           audit_openstack=False)

        # Verify the subcloud was set to online
        self.fake_dcorch_api.update_subcloud_states.assert_called_with(
            mock.ANY, subcloud.name, consts.MANAGEMENT_UNMANAGED,
            consts.AVAILABILITY_ONLINE)

        # Verify the openstack endpoints were not added
        self.fake_dcorch_api.add_subcloud_sync_endpoint_type.\
            assert_not_called()

        # Verify the subcloud openstack_installed was not updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.openstack_installed, False)

        # Verify alarm update is called
        self.fake_alarm_aggr.update_alarm_summary.assert_called_with(
            'subcloud1', self.fake_openstack_client.fm_client)

    def test_audit_subcloud_online_no_change(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        mock_sm = mock.Mock()
        am = subcloud_audit_manager.SubcloudAuditManager(
            subcloud_manager=mock_sm)

        # No stx-openstack application
        self.fake_openstack_client.sysinv_client.get_application_results = []

        # Set the subcloud to online
        db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=consts.AVAILABILITY_ONLINE)

        # Audit the subcloud
        am._audit_subcloud(subcloud.name, update_subcloud_state=False,
                           audit_openstack=False)

        # Verify the subcloud state was not updated
        self.fake_dcorch_api.update_subcloud_states.assert_not_called()

        # Verify the openstack endpoints were not added
        self.fake_dcorch_api.add_subcloud_sync_endpoint_type.\
            assert_not_called()

        # Verify the subcloud openstack_installed was not updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.openstack_installed, False)

        # Verify alarm update is called
        self.fake_alarm_aggr.update_alarm_summary.assert_called_with(
            'subcloud1', self.fake_openstack_client.fm_client)

    def test_audit_subcloud_online_no_change_force_update(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        mock_sm = mock.Mock()
        am = subcloud_audit_manager.SubcloudAuditManager(
            subcloud_manager=mock_sm)

        # No stx-openstack application
        self.fake_openstack_client.sysinv_client.get_application_results = []

        # Set the subcloud to online
        db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=consts.AVAILABILITY_ONLINE)

        # Audit the subcloud and force a state update
        am._audit_subcloud(subcloud.name, update_subcloud_state=True,
                           audit_openstack=False)

        # Verify the subcloud state was updated even though no change
        self.fake_dcorch_api.update_subcloud_states.assert_called_with(
            mock.ANY, 'subcloud1', consts.MANAGEMENT_UNMANAGED,
            consts.AVAILABILITY_ONLINE)

        # Verify the openstack endpoints were not added
        self.fake_dcorch_api.add_subcloud_sync_endpoint_type.\
            assert_not_called()

        # Verify the subcloud openstack_installed was not updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.openstack_installed, False)

        # Verify alarm update is called
        self.fake_alarm_aggr.update_alarm_summary.assert_called_with(
            'subcloud1', self.fake_openstack_client.fm_client)

    def test_audit_subcloud_offline(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        mock_sm = mock.Mock()
        am = subcloud_audit_manager.SubcloudAuditManager(
            subcloud_manager=mock_sm)

        # Set the subcloud to online
        db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=consts.AVAILABILITY_ONLINE)

        # Mark a service group as inactive
        self.fake_openstack_client.sysinv_client.get_service_groups_result = \
            copy.deepcopy(FAKE_SERVICE_GROUPS)
        self.fake_openstack_client.sysinv_client. \
            get_service_groups_result[3].state = 'inactive'

        # Audit the subcloud
        am._audit_subcloud(subcloud.name, update_subcloud_state=False,
                           audit_openstack=False)

        # Verify the subcloud was not set to offline
        self.fake_dcorch_api.update_subcloud_states.assert_not_called()

        # Verify the audit_fail_count was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.audit_fail_count, 1)

        # Audit the subcloud again
        am._audit_subcloud(subcloud.name, update_subcloud_state=False,
                           audit_openstack=False)

        # Verify the subcloud was set to offline
        self.fake_dcorch_api.update_subcloud_states.assert_called_with(
            mock.ANY, 'subcloud1', consts.MANAGEMENT_UNMANAGED,
            consts.AVAILABILITY_OFFLINE)

        # Verify the sublcoud availability was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.availability_status,
                         consts.AVAILABILITY_OFFLINE)

        # Verify alarm update is called
        self.fake_alarm_aggr.update_alarm_summary.assert_called_once_with(
            'subcloud1', self.fake_openstack_client.fm_client)

    def test_audit_subcloud_online_with_openstack(self):

        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        mock_sm = mock.Mock()
        am = subcloud_audit_manager.SubcloudAuditManager(
            subcloud_manager=mock_sm)

        # Audit the subcloud
        am._audit_subcloud(subcloud.name, update_subcloud_state=False,
                           audit_openstack=True)

        # Verify the subcloud was set to online
        self.fake_dcorch_api.update_subcloud_states.assert_called_with(
            mock.ANY, 'subcloud1', consts.MANAGEMENT_UNMANAGED,
            consts.AVAILABILITY_ONLINE)

        # Verify the openstack endpoints were added
        self.fake_dcorch_api.add_subcloud_sync_endpoint_type.\
            assert_called_with(mock.ANY, 'subcloud1',
                               dccommon_consts.ENDPOINT_TYPES_LIST_OS)

        # Verify the subcloud openstack_installed was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.openstack_installed, True)
