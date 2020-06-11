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

import mock

from oslo_concurrency import lockutils
from oslo_utils import timeutils

import sys
sys.modules['fm_core'] = mock.Mock()

import threading

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.manager import subcloud_manager
from dcmanager.tests import base
from dcmanager.tests import utils
from dcorch.common import consts as dcorch_consts


class FakeDCOrchAPI(object):
    def __init__(self):
        self.update_subcloud_states = mock.MagicMock()
        self.add_subcloud_sync_endpoint_type = mock.MagicMock()
        self.remove_subcloud_sync_endpoint_type = mock.MagicMock()
        self.del_subcloud = mock.MagicMock()
        self.add_subcloud = mock.MagicMock()


class FakeService(object):
    def __init__(self, type, id):
        self.type = type
        self.id = id


FAKE_SERVICES = [
    FakeService(
        dcorch_consts.ENDPOINT_TYPE_PLATFORM,
        1
    ),
    FakeService(
        dcorch_consts.ENDPOINT_TYPE_IDENTITY,
        2
    ),
    FakeService(
        dcorch_consts.ENDPOINT_TYPE_PATCHING,
        3
    ),
    FakeService(
        dcorch_consts.ENDPOINT_TYPE_FM,
        4
    ),
    FakeService(
        dcorch_consts.ENDPOINT_TYPE_NFV,
        5
    ),
]


class FakeController(object):
    def __init__(self, hostname):
        self.hostname = hostname


FAKE_CONTROLLERS = [
    FakeController(
        'controller-0'
    ),
    FakeController(
        'controller-1'
    ),
]


class FakeException(Exception):
        pass


class Subcloud(object):
    def __init__(self, data, is_online):
        self.id = data['id']
        self.name = data['name']
        self.description = data['description']
        self.location = data['location']
        self.software_version = data['software-version']
        self.management_state = consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = consts.AVAILABILITY_OFFLINE
        self.deploy_status = data['deploy_status']
        self.management_subnet = data['management_subnet']
        self.management_gateway_ip = data['management_gateway_address']
        self.management_start_ip = data['management_start_address']
        self.management_end_ip = data['management_end_address']
        self.external_oam_subnet = data['external_oam_subnet']
        self.external_oam_gateway_address = \
            data['external_oam_gateway_address']
        self.external_oam_floating_address = \
            data['external_oam_floating_address']
        self.systemcontroller_gateway_ip = \
            data['systemcontroller_gateway_address']
        self.created_at = timeutils.utcnow()
        self.updated_at = timeutils.utcnow()


class TestSubcloudManager(base.DCManagerTestCase):
    def setUp(self):
        super(TestSubcloudManager, self).setUp()

        # Mock the DCOrch API
        self.fake_dcorch_api = FakeDCOrchAPI()
        p = mock.patch('dcorch.rpc.client.EngineClient')
        self.mock_dcorch_api = p.start()
        self.mock_dcorch_api.return_value = self.fake_dcorch_api
        self.addCleanup(p.stop)

        # Mock the context
        p = mock.patch.object(subcloud_manager, 'context')
        self.mock_context = p.start()
        self.mock_context.get_admin_context.return_value = self.ctx
        self.addCleanup(p.stop)

    @staticmethod
    def create_subcloud_static(ctxt, **kwargs):
        values = {
            "name": "subcloud1",
            "description": "subcloud1 description",
            "location": "subcloud1 location",
            'software_version': "18.03",
            "management_subnet": "192.168.101.0/24",
            "management_gateway_ip": "192.168.101.1",
            "management_start_ip": "192.168.101.3",
            "management_end_ip": "192.168.101.4",
            "systemcontroller_gateway_ip": "192.168.204.101",
            'deploy_status': "not-deployed",
            'openstack_installed': False,
            'group_id': 1,
        }
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, **values)

    def test_init(self):
        sm = subcloud_manager.SubcloudManager()
        self.assertIsNotNone(sm)
        self.assertEqual('subcloud_manager', sm.service_name)
        self.assertEqual('localhost', sm.host)
        self.assertEqual(self.ctx, sm.context)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_intermediate_ca_cert')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_delete_subcloud_inventory')
    @mock.patch.object(subcloud_manager, 'KeystoneClient')
    @mock.patch.object(subcloud_manager, 'db_api')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_addn_hosts_dc')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_subcloud_inventory')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_write_subcloud_ansible_config')
    @mock.patch.object(subcloud_manager,
                       'keyring')
    @mock.patch.object(threading.Thread,
                       'start')
    def test_add_subcloud(self, mock_thread_start, mock_keyring,
                          mock_write_subcloud_ansible_config,
                          mock_create_subcloud_inventory,
                          mock_create_addn_hosts, mock_sysinv_client,
                          mock_db_api, mock_keystone_client,
                          mock_delete_subcloud_inventory,
                          mock_create_intermediate_ca_cert):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        controllers = FAKE_CONTROLLERS
        services = FAKE_SERVICES

        # dcmanager add_subcloud queries the data from the db
        fake_subcloud = Subcloud(values, False)
        mock_db_api.subcloud_get_by_name.return_value = fake_subcloud

        mock_sysinv_client().get_controller_hosts.return_value = controllers
        mock_keystone_client().services_list = services
        mock_keyring.get_password.return_value = "testpassword"

        sm = subcloud_manager.SubcloudManager()
        sm.add_subcloud(self.ctx, payload=values)
        mock_db_api.subcloud_status_create.assert_called()
        mock_sysinv_client().create_route.assert_called()
        self.fake_dcorch_api.add_subcloud.assert_called_once()
        mock_create_addn_hosts.assert_called_once()
        mock_create_subcloud_inventory.assert_called_once()
        mock_write_subcloud_ansible_config.assert_called_once()
        mock_keyring.get_password.assert_called()
        mock_thread_start.assert_called_once()
        mock_create_intermediate_ca_cert.assert_called_once()

    @mock.patch.object(subcloud_manager, 'KeystoneClient')
    @mock.patch.object(subcloud_manager, 'db_api')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    def test_add_subcloud_deploy_prep_failed(self,
                                             mock_sysinv_client,
                                             mock_db_api,
                                             mock_keystone_client):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        controllers = FAKE_CONTROLLERS
        services = FAKE_SERVICES

        # dcmanager add_subcloud queries the data from the db
        fake_subcloud = Subcloud(values, False)
        mock_db_api.subcloud_get_by_name.return_value = fake_subcloud

        self.fake_dcorch_api.add_subcloud.side_effect = FakeException('boom')
        mock_sysinv_client().get_controller_hosts.return_value = controllers
        mock_keystone_client().services_list = services

        sm = subcloud_manager.SubcloudManager()
        sm.add_subcloud(self.ctx, payload=values)
        mock_db_api.subcloud_status_create.assert_called()
        mock_sysinv_client().create_route.assert_called()
        mock_db_api.subcloud_update.\
            assert_called_with(self.ctx,
                               mock_db_api.subcloud_get_by_name().id,
                               deploy_status=consts.DEPLOY_STATE_DEPLOY_PREP_FAILED)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_delete_subcloud_cert')
    @mock.patch.object(subcloud_manager, 'db_api')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager, 'KeystoneClient')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_addn_hosts_dc')
    def test_delete_subcloud(self, mock_create_addn_hosts,
                             mock_keystone_client,
                             mock_sysinv_client,
                             mock_db_api,
                             mock_delete_subcloud_cert):
        controllers = FAKE_CONTROLLERS
        data = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        fake_subcloud = Subcloud(data, False)
        mock_db_api.subcloud_get.return_value = fake_subcloud
        mock_sysinv_client().get_controller_hosts.return_value = controllers
        sm = subcloud_manager.SubcloudManager()
        sm.delete_subcloud(self.ctx, subcloud_id=data['id'])
        mock_sysinv_client().delete_route.assert_called()
        mock_keystone_client().delete_region.assert_called_once()
        mock_db_api.subcloud_destroy.assert_called_once()
        mock_create_addn_hosts.assert_called_once()
        mock_delete_subcloud_cert.assert_called_once()

    @mock.patch.object(subcloud_manager, 'db_api')
    def test_update_subcloud(self, mock_db_api):
        data = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud_result = Subcloud(data, True)
        mock_db_api.subcloud_get.return_value = subcloud_result
        mock_db_api.subcloud_update.return_value = subcloud_result
        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           data['id'],
                           management_state=consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location")
        mock_db_api.subcloud_update.assert_called_once_with(
            mock.ANY,
            data['id'],
            management_state=consts.MANAGEMENT_MANAGED,
            description="subcloud new description",
            location="subcloud new location",
            group_id=None)

    @mock.patch.object(subcloud_manager, 'db_api')
    def test_update_already_managed_subcloud(self, mock_db_api):
        data = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud_result = Subcloud(data, True)
        mock_db_api.subcloud_get.return_value = subcloud_result
        subcloud_result.management_state = consts.MANAGEMENT_MANAGED
        sm = subcloud_manager.SubcloudManager()
        self.assertRaises(exceptions.BadRequest,
                          sm.update_subcloud, self.ctx,
                          data['id'],
                          management_state=consts.MANAGEMENT_MANAGED)

    @mock.patch.object(subcloud_manager, 'db_api')
    def test_update_already_unmanaged_subcloud(self, mock_db_api):
        data = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud_result = Subcloud(data, True)
        mock_db_api.subcloud_get.return_value = subcloud_result
        sm = subcloud_manager.SubcloudManager()
        self.assertRaises(exceptions.BadRequest,
                          sm.update_subcloud, self.ctx,
                          data['id'],
                          management_state=consts.MANAGEMENT_UNMANAGED)

    @mock.patch.object(subcloud_manager, 'db_api')
    def test_manage_when_deploy_status_failed(self, mock_db_api):
        data = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud_result = Subcloud(data, True)
        mock_db_api.subcloud_get.return_value = subcloud_result
        subcloud_result.deploy_status = consts.DEPLOY_STATE_DEPLOY_FAILED
        sm = subcloud_manager.SubcloudManager()
        self.assertRaises(exceptions.BadRequest,
                          sm.update_subcloud, self.ctx,
                          data['id'],
                          management_state=consts.MANAGEMENT_MANAGED)

    @mock.patch.object(subcloud_manager, 'db_api')
    def test_update_subcloud_group_id(self, mock_db_api):
        data = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        subcloud_result = Subcloud(data, True)
        mock_db_api.subcloud_get.return_value = subcloud_result
        mock_db_api.subcloud_update.return_value = subcloud_result
        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           data['id'],
                           management_state=consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location",
                           group_id=2)
        mock_db_api.subcloud_update.assert_called_once_with(
            mock.ANY,
            data['id'],
            management_state=consts.MANAGEMENT_MANAGED,
            description="subcloud new description",
            location="subcloud new location",
            group_id=2)

    def test_update_subcloud_endpoint_status(self):
        # create a subcloud
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud.management_state,
                         consts.MANAGEMENT_UNMANAGED)
        self.assertEqual(subcloud.availability_status,
                         consts.AVAILABILITY_OFFLINE)

        # create sync statuses for endpoints
        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV]:
            status = db_api.subcloud_status_create(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(status)
            self.assertEqual(status.sync_status, consts.SYNC_STATUS_UNKNOWN)

        # Update/verify each status with the default sync state: out-of-sync
        sm = subcloud_manager.SubcloudManager()
        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV]:
            # Update
            sm.update_subcloud_endpoint_status(
                self.ctx, subcloud_name=subcloud.name,
                endpoint_type=endpoint)

            # Verify
            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(updated_subcloud_status.sync_status,
                             consts.SYNC_STATUS_OUT_OF_SYNC)

        # Attempt to update each status to be in-sync for an offline/unmanaged
        # subcloud. This is not allowed. Verify no change.
        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV]:
            sm.update_subcloud_endpoint_status(
                self.ctx, subcloud_name=subcloud.name,
                endpoint_type=endpoint,
                sync_status=consts.SYNC_STATUS_IN_SYNC)

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            # No change in status: Only online/managed clouds are updated
            self.assertEqual(updated_subcloud_status.sync_status,
                             consts.SYNC_STATUS_OUT_OF_SYNC)

        # Set/verify the subcloud is online/unmanaged
        db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=consts.AVAILABILITY_ONLINE)
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud.management_state,
                         consts.MANAGEMENT_UNMANAGED)
        self.assertEqual(subcloud.availability_status,
                         consts.AVAILABILITY_ONLINE)

        # Attempt to update each status to be in-sync for an online/unmanaged
        # subcloud. This is not allowed. Verify no change.
        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV]:
            sm.update_subcloud_endpoint_status(
                self.ctx, subcloud_name=subcloud.name,
                endpoint_type=endpoint,
                sync_status=consts.SYNC_STATUS_IN_SYNC)

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            # No change in status: Only online/managed clouds are updated
            self.assertEqual(updated_subcloud_status.sync_status,
                             consts.SYNC_STATUS_OUT_OF_SYNC)

        # Set/verify the subcloud is online/managed
        db_api.subcloud_update(
            self.ctx, subcloud.id,
            management_state=consts.MANAGEMENT_MANAGED)
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud.management_state,
                         consts.MANAGEMENT_MANAGED)
        self.assertEqual(subcloud.availability_status,
                         consts.AVAILABILITY_ONLINE)

        # Attempt to update each status to be in-sync for an online/managed
        # subcloud
        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV]:
            sm.update_subcloud_endpoint_status(
                self.ctx, subcloud_name=subcloud.name,
                endpoint_type=endpoint,
                sync_status=consts.SYNC_STATUS_IN_SYNC)

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(updated_subcloud_status.sync_status,
                             consts.SYNC_STATUS_IN_SYNC)

        # Change the sync status to 'out-of-sync' and verify fair lock access
        # based on subcloud name for each update
        with mock.patch.object(lockutils, 'internal_fair_lock') as mock_lock:
            for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                             dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                             dcorch_consts.ENDPOINT_TYPE_PATCHING,
                             dcorch_consts.ENDPOINT_TYPE_FM,
                             dcorch_consts.ENDPOINT_TYPE_NFV]:
                sm.update_subcloud_endpoint_status(
                    self.ctx, subcloud_name=subcloud.name,
                    endpoint_type=endpoint,
                    sync_status=consts.SYNC_STATUS_OUT_OF_SYNC)
                # Verify lock was called
                mock_lock.assert_called_with(subcloud.name)

                # Verify status was updated
                updated_subcloud_status = db_api.subcloud_status_get(
                    self.ctx, subcloud.id, endpoint)
                self.assertIsNotNone(updated_subcloud_status)
                self.assertEqual(updated_subcloud_status.sync_status,
                                 consts.SYNC_STATUS_OUT_OF_SYNC)

    def test_update_subcloud_availability_go_online(self):
        # create a subcloud
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud.availability_status,
                         consts.AVAILABILITY_OFFLINE)

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud_availability(self.ctx, subcloud.name,
                                        consts.AVAILABILITY_ONLINE)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        # Verify the subcloud was set to online
        self.assertEqual(updated_subcloud.availability_status,
                         consts.AVAILABILITY_ONLINE)
        # Verify notifying dcorch
        self.fake_dcorch_api.update_subcloud_states.assert_called_once_with(
            self.ctx, subcloud.name, updated_subcloud.management_state,
            consts.AVAILABILITY_ONLINE)

    def test_update_subcloud_availability_go_offline(self):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        # Set the subcloud to online/managed
        db_api.subcloud_update(self.ctx, subcloud.id,
                               management_state=consts.MANAGEMENT_MANAGED,
                               availability_status=consts.AVAILABILITY_ONLINE)

        sm = subcloud_manager.SubcloudManager()

        # create sync statuses for endpoints and set them to in-sync
        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV]:
            db_api.subcloud_status_create(
                self.ctx, subcloud.id, endpoint)
            sm.update_subcloud_endpoint_status(
                self.ctx, subcloud_name=subcloud.name,
                endpoint_type=endpoint,
                sync_status=consts.SYNC_STATUS_IN_SYNC)

        # Audit fails once
        audit_fail_count = 1
        sm.update_subcloud_availability(self.ctx, subcloud.name,
                                        availability_status=None,
                                        audit_fail_count=audit_fail_count)
        # Verify the subclcoud availability was not updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.availability_status,
                         consts.AVAILABILITY_ONLINE)
        # Verify dcorch was not notified
        self.fake_dcorch_api.update_subcloud_states.assert_not_called()
        # Verify the audit_fail_count was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.audit_fail_count, audit_fail_count)

        # Audit fails again
        audit_fail_count = audit_fail_count + 1
        sm.update_subcloud_availability(self.ctx, subcloud.name,
                                        consts.AVAILABILITY_OFFLINE,
                                        audit_fail_count=audit_fail_count)

        # Verify the subclcoud availability was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.availability_status,
                         consts.AVAILABILITY_OFFLINE)

        # Verify notifying dcorch
        self.fake_dcorch_api.update_subcloud_states.assert_called_once_with(
            self.ctx, subcloud.name, updated_subcloud.management_state,
            consts.AVAILABILITY_OFFLINE)

        # Verify all endpoint statuses set to unknown
        for subcloud, subcloud_status in db_api. \
                subcloud_get_with_status(self.ctx, subcloud.id):
            self.assertIsNotNone(subcloud_status)
            self.assertEqual(subcloud_status.sync_status,
                             consts.SYNC_STATUS_UNKNOWN)

    def test_update_subcloud_sync_endpoint_type(self):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        sm = subcloud_manager.SubcloudManager()

        endpoint_type_list = dccommon_consts.ENDPOINT_TYPES_LIST_OS

        # Test openstack app installed
        openstack_installed = True
        sm.update_subcloud_sync_endpoint_type(self.ctx, subcloud.name,
                                              endpoint_type_list,
                                              openstack_installed)

        # Verify notifying dcorch to add subcloud sync endpoint type
        self.fake_dcorch_api.add_subcloud_sync_endpoint_type.\
            assert_called_once_with(self.ctx, subcloud.name,
                                    endpoint_type_list)

        # Verify the subcloud status created for os endpoints
        for endpoint in endpoint_type_list:
            subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(subcloud_status)
            self.assertEqual(subcloud_status.sync_status,
                             consts.SYNC_STATUS_UNKNOWN)

        # Verify the subcloud openstack_installed was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(updated_subcloud.openstack_installed, True)

        # Test openstack app removed
        openstack_installed = False
        sm.update_subcloud_sync_endpoint_type(self.ctx, subcloud.name,
                                              endpoint_type_list,
                                              openstack_installed)
        # Verify notifying dcorch to remove subcloud sync endpoint type
        self.fake_dcorch_api.remove_subcloud_sync_endpoint_type.\
            assert_called_once_with(self.ctx, subcloud.name,
                                    endpoint_type_list)

        # Verify the subcloud status is deleted for os endpoints
        for endpoint in endpoint_type_list:
            self.assertRaises(exceptions.SubcloudStatusNotFound,
                              db_api.subcloud_status_get, self.ctx,
                              subcloud.id, endpoint)

        # Verify the subcloud openstack_installed was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(updated_subcloud.openstack_installed, False)

    @mock.patch.object(subcloud_manager, 'db_api')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_prepare_for_deployment')
    @mock.patch.object(threading.Thread,
                       'start')
    def test_reconfig_subcloud(self, mock_thread_start,
                               mock_prepare_for_deployment,
                               mock_db_api):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values['deploy_status'] = consts.DEPLOY_STATE_PRE_DEPLOY
        fake_subcloud_result = Subcloud(values, False)
        mock_db_api.subcloud_update.return_value = fake_subcloud_result
        fake_payload = {"sysadmin_password": "testpass",
                        "deploy_playbook": "test_playbook.yaml",
                        "deploy_overrides": "test_overrides.yaml",
                        "deploy_chart": "test_chart.yaml",
                        "deploy_config": "subcloud1.yaml"}
        sm = subcloud_manager.SubcloudManager()
        sm.reconfigure_subcloud(self.ctx,
                                values['id'],
                                payload=fake_payload)
        mock_thread_start.assert_called_once()
        mock_prepare_for_deployment.assert_called_once()
