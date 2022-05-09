# Copyright (c) 2017-2022 Wind River Systems, Inc.
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

import copy
import datetime
import mock

from os import path as os_path
from oslo_concurrency import lockutils
from oslo_utils import timeutils

import sys
sys.modules['fm_core'] = mock.Mock()

import threading

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import prestage
from dcmanager.common import utils as cutils
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.manager import subcloud_manager
from dcmanager.state import subcloud_state_manager
from dcmanager.tests import base
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests import utils
from dcorch.common import consts as dcorch_consts
from tsconfig.tsconfig import SW_VERSION


FAKE_ADMIN_USER_ID = 1
FAKE_SYSINV_USER_ID = 2
FAKE_DCMANAGER_USER_ID = 3
FAKE_ADMIN_PROJECT_ID = 1
FAKE_SERVICE_PROJECT_ID = 2


class FakeDCManagerAuditAPI(object):
    def __init__(self):
        self.trigger_subcloud_audits = mock.MagicMock()
        self.trigger_subcloud_patch_load_audits = mock.MagicMock()


class FakeDCManagerStateAPI(object):
    def __init__(self):
        self.update_subcloud_availability = mock.MagicMock()
        self.update_subcloud_endpoint_status = mock.MagicMock()


class FakeDCOrchAPI(object):
    def __init__(self):
        self.update_subcloud_states = mock.MagicMock()
        self.add_subcloud_sync_endpoint_type = mock.MagicMock()
        self.remove_subcloud_sync_endpoint_type = mock.MagicMock()
        self.del_subcloud = mock.MagicMock()
        self.add_subcloud = mock.MagicMock()
        self.update_subcloud_version = mock.MagicMock()


class FakeDCManagerNotifications(object):
    def __init__(self):
        self.subcloud_online = mock.MagicMock()
        self.subcloud_managed = mock.MagicMock()


class FakeUser(object):
    def __init__(self, username, userid):
        self.name = username
        self.id = userid


FAKE_USERS = [
    FakeUser(
        dccommon_consts.ADMIN_USER_NAME,
        FAKE_ADMIN_USER_ID),
    FakeUser(
        dccommon_consts.SYSINV_USER_NAME,
        FAKE_SYSINV_USER_ID),
    FakeUser(
        dccommon_consts.DCMANAGER_USER_NAME,
        FAKE_DCMANAGER_USER_ID)
]


class FakeProject(object):
    def __init__(self, projname, projid):
        self.name = projname
        self.id = projid

FAKE_PROJECTS = [
    FakeProject(
        dccommon_consts.ADMIN_PROJECT_NAME,
        FAKE_ADMIN_PROJECT_ID),
    FakeProject(
        dccommon_consts.SERVICES_USER_NAME,
        FAKE_SERVICE_PROJECT_ID)
]


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
    FakeService(
        dcorch_consts.ENDPOINT_TYPE_DC_CERT,
        6
    )
]


class FakeKeystoneClient(object):
    def __init__(self):
        self.user_list = FAKE_USERS
        self.project_list = FAKE_PROJECTS
        self.services_list = FAKE_SERVICES
        self.keystone_client = mock.MagicMock()
        self.session = mock.MagicMock()
        self.endpoint_cache = mock.MagicMock()

    def get_enabled_users(self, id_only):
        if not id_only:
            return self.user_list
        else:
            return None

    def get_enabled_projects(self, id_only):
        if not id_only:
            return self.project_list
        else:
            return None

    def delete_endpoints(self, region_name):
        pass

    def delete_region(self, region_name):
        pass


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


class FakeManagementInterface(object):
    def __init__(self, hostname):
        if hostname == 'controller-0':
            self.uuid = '47cb1222-21a9-4ee0-b1f9-0b37de345f65'
        else:
            self.uuid = '0106bdf0-1662-48cc-b6b3-664c91147843'


FAKE_MGMT_INTERFACES = [
    FakeManagementInterface(
        'controller-0'
    ),
    FakeManagementInterface(
        'controller-1'
    ),
]


class FakeSysinvClient(object):
    def __init__(self):
        self.hosts = FAKE_CONTROLLERS
        self.interfaces = FAKE_MGMT_INTERFACES

    def get_controller_hosts(self):
        return self.hosts

    def get_management_interface(self, hostname):
        if hostname == 'controller-0':
            return self.interfaces[0]
        else:
            return self.interfaces[1]


class FakeException(Exception):
        pass


FAKE_RESTORE_VALUES = {
    "backup_filename": "subcloud_platform_backup.tgz",
    "on_box_data": "false",
    "initial_backup_dir": "/home/sysadmin",
    "skip_patches_restore": "true"
}


FAKE_SUBCLOUD_RESTORE_PAYLOAD = {
    "install_values": fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES,
    "with_install": True,
    "bootstrap-address": "bootstrap_ip",
    "software_version": "20.12",
    "sysadmin_password": "testpasswd",
    "restore_values": FAKE_RESTORE_VALUES
}


FAKE_SUBCLOUD_PRESTAGE_PAYLOAD = {
    "install_values": fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES,
    "subcloud_name": 'subcloud1',
    "force": False,
    "oam_floating_ip": '10.10.10.12',
    "software_version": "20.12",
    "sysadmin_password": "testpasswd",
}

FAKE_PRESTAGE_PAYLOAD = {
    "subcloud_name": "subcloud1",
    "oam_floating_ip": "10.10.10.12",
    "sysadmin_password": 'testpassword',
    "force": False
}

FAKE_MGMT_IF_UUIDS = [
    '47cb1222-21a9-4ee0-b1f9-0b37de345f65',
    '0106bdf0-1662-48cc-b6b3-664c91147843'
]

FAKE_CACHED_REGIONONE_DATA = {
    "admin_user_id": FAKE_USERS[0].id,
    "sysinv_user_id": FAKE_USERS[1].id,
    "dcmanager_user_id": FAKE_USERS[2].id,
    "admin_project_id": FAKE_PROJECTS[0].id,
    "services_project_id": FAKE_PROJECTS[1].id,
    "mgmt_interface_uuids": FAKE_MGMT_IF_UUIDS,
    "expiry": datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)
}


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
        self.data_install = data['data_install']
        self.created_at = timeutils.utcnow()
        self.updated_at = timeutils.utcnow()


class TestSubcloudManager(base.DCManagerTestCase):
    def setUp(self):
        super(TestSubcloudManager, self).setUp()

        # Mock the DCManager Audit API
        self.fake_dcmanager_audit_api = FakeDCManagerAuditAPI()
        p = mock.patch('dcmanager.audit.rpcapi.ManagerAuditClient')
        self.mock_dcmanager_audit_api = p.start()
        self.mock_dcmanager_audit_api.return_value = \
            self.fake_dcmanager_audit_api
        self.addCleanup(p.stop)

        # Mock the DCManager subcloud state API
        self.fake_dcmanager_state_api = FakeDCManagerStateAPI()
        p = mock.patch('dcmanager.rpc.client.SubcloudStateClient')
        self.mock_dcmanager_state_api = p.start()
        self.mock_dcmanager_state_api.return_value = \
            self.fake_dcmanager_state_api
        self.addCleanup(p.stop)

        # Mock the DCOrch API
        self.fake_dcorch_api = FakeDCOrchAPI()
        p = mock.patch('dcorch.rpc.client.EngineClient')
        self.mock_dcorch_api = p.start()
        self.mock_dcorch_api.return_value = self.fake_dcorch_api
        self.addCleanup(p.stop)

        # Mock the context
        p = mock.patch.object(subcloud_manager, 'dcmanager_context')
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
            'data_install': 'data from install',
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
                       'compose_rehome_command')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_intermediate_ca_cert')
    @mock.patch.object(cutils, 'delete_subcloud_inventory')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_get_cached_regionone_data')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_addn_hosts_dc')
    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_write_subcloud_ansible_config')
    @mock.patch.object(subcloud_manager,
                       'keyring')
    @mock.patch.object(threading.Thread,
                       'start')
    def test_add_subcloud(self, mock_thread_start, mock_keyring,
                          mock_write_subcloud_ansible_config,
                          mock_create_subcloud_inventory,
                          mock_create_addn_hosts,
                          mock_get_cached_regionone_data,
                          mock_sysinv_client,
                          mock_keystone_client,
                          mock_delete_subcloud_inventory,
                          mock_create_intermediate_ca_cert,
                          mock_compose_rehome_command):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values['deploy_status'] = consts.DEPLOY_STATE_NONE

        # dcmanager add_subcloud queries the data from the db
        self.create_subcloud_static(self.ctx, name=values['name'])

        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_keyring.get_password.return_value = "testpassword"
        mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA

        sm = subcloud_manager.SubcloudManager()
        subcloud_dict = sm.add_subcloud(self.ctx, payload=values)
        mock_get_cached_regionone_data.assert_called_once()
        mock_sysinv_client().create_route.assert_called()
        self.fake_dcorch_api.add_subcloud.assert_called_once()
        mock_create_addn_hosts.assert_called_once()
        mock_create_subcloud_inventory.assert_called_once()
        mock_write_subcloud_ansible_config.assert_called_once()
        mock_keyring.get_password.assert_called()
        mock_thread_start.assert_called_once()
        mock_create_intermediate_ca_cert.assert_called_once()
        mock_compose_rehome_command.assert_not_called()

        # Verify subcloud was updated with correct values
        self.assertEqual(consts.DEPLOY_STATE_PRE_DEPLOY,
                         subcloud_dict['deploy-status'])

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, values['name'])
        self.assertEqual(consts.DEPLOY_STATE_PRE_DEPLOY,
                         updated_subcloud.deploy_status)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       'compose_rehome_command')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_intermediate_ca_cert')
    @mock.patch.object(cutils, 'delete_subcloud_inventory')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_get_cached_regionone_data')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_addn_hosts_dc')
    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_write_subcloud_ansible_config')
    @mock.patch.object(subcloud_manager,
                       'keyring')
    @mock.patch.object(threading.Thread,
                       'start')
    def test_add_subcloud_with_migration_option(
        self, mock_thread_start, mock_keyring,
        mock_write_subcloud_ansible_config,
        mock_create_subcloud_inventory,
        mock_create_addn_hosts,
        mock_get_cached_regionone_data,
        mock_sysinv_client,
        mock_keystone_client,
        mock_delete_subcloud_inventory,
        mock_create_intermediate_ca_cert,
        mock_compose_rehome_command):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values['deploy_status'] = consts.DEPLOY_STATE_NONE
        values['migrate'] = 'true'

        # dcmanager add_subcloud queries the data from the db
        self.create_subcloud_static(self.ctx, name=values['name'])

        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_keyring.get_password.return_value = "testpassword"
        mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA

        sm = subcloud_manager.SubcloudManager()
        subcloud_dict = sm.add_subcloud(self.ctx, payload=values)
        mock_get_cached_regionone_data.assert_called_once()
        mock_sysinv_client().create_route.assert_called()
        self.fake_dcorch_api.add_subcloud.assert_called_once()
        mock_create_addn_hosts.assert_called_once()
        mock_create_subcloud_inventory.assert_called_once()
        mock_write_subcloud_ansible_config.assert_called_once()
        mock_keyring.get_password.assert_called_with('smapi', 'services')
        mock_thread_start.assert_called_once()
        mock_create_intermediate_ca_cert.assert_called_once()
        mock_compose_rehome_command.assert_called_once()

        # Verify subcloud was updated with correct values
        self.assertEqual(consts.DEPLOY_STATE_PRE_REHOME,
                         subcloud_dict['deploy-status'])

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, values['name'])
        self.assertEqual(consts.DEPLOY_STATE_PRE_REHOME,
                         updated_subcloud.deploy_status)

    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager.SubcloudManager, '_get_cached_regionone_data')
    def test_add_subcloud_deploy_prep_failed(self,
                                             mock_get_cached_regionone_data,
                                             mock_sysinv_client,
                                             mock_keystone_client):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        services = FAKE_SERVICES

        # dcmanager add_subcloud queries the data from the db
        self.create_subcloud_static(self.ctx, name=values['name'])

        self.fake_dcorch_api.add_subcloud.side_effect = FakeException('boom')
        mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA
        mock_keystone_client().services_list = services

        sm = subcloud_manager.SubcloudManager()
        sm.add_subcloud(self.ctx, payload=values)
        mock_get_cached_regionone_data.assert_called_once()
        mock_sysinv_client().create_route.assert_called()

        # Verify subcloud was updated with correct values
        subcloud = db_api.subcloud_get_by_name(self.ctx, values['name'])
        self.assertEqual(consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
                         subcloud.deploy_status)

    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager.SubcloudManager, '_get_cached_regionone_data')
    def test_add_subcloud_with_migrate_option_prep_failed(
        self, mock_get_cached_regionone_data, mock_sysinv_client, mock_keystone_client):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values['migrate'] = 'true'
        services = FAKE_SERVICES

        # dcmanager add_subcloud queries the data from the db
        self.create_subcloud_static(self.ctx, name=values['name'])

        self.fake_dcorch_api.add_subcloud.side_effect = FakeException('boom')
        mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA
        mock_keystone_client().services_list = services

        sm = subcloud_manager.SubcloudManager()
        sm.add_subcloud(self.ctx, payload=values)
        mock_get_cached_regionone_data.assert_called_once()
        mock_sysinv_client().create_route.assert_called()

        # Verify subcloud was updated with correct values
        subcloud = db_api.subcloud_get_by_name(self.ctx, values['name'])
        self.assertEqual(consts.DEPLOY_STATE_REHOME_PREP_FAILED,
                         subcloud.deploy_status)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_delete_subcloud_cert')
    @mock.patch.object(subcloud_manager.SubcloudManager, '_get_cached_regionone_data')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_addn_hosts_dc')
    def test_delete_subcloud(self, mock_create_addn_hosts,
                             mock_keystone_client,
                             mock_sysinv_client,
                             mock_get_cached_regionone_data,
                             mock_delete_subcloud_cert):
        subcloud = self.create_subcloud_static(self.ctx)
        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA
        sm = subcloud_manager.SubcloudManager()
        sm.delete_subcloud(self.ctx, subcloud_id=subcloud.id)
        mock_get_cached_regionone_data.assert_called_once()
        mock_sysinv_client().delete_route.assert_called()
        mock_create_addn_hosts.assert_called_once()
        mock_delete_subcloud_cert.assert_called_once()

        # Verify subcloud was deleted
        self.assertRaises(exceptions.SubcloudNameNotFound,
                          db_api.subcloud_get_by_name,
                          self.ctx,
                          subcloud.name)

    def test_update_subcloud(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=consts.AVAILABILITY_ONLINE)

        fake_dcmanager_notification = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_notification

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           management_state=consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location")

        fake_dcmanager_notification.subcloud_managed.assert_called_once_with(
            self.ctx, subcloud.name)

        exclude_endpoints = [dcorch_consts.ENDPOINT_TYPE_PATCHING,
                             dcorch_consts.ENDPOINT_TYPE_LOAD]
        self.fake_dcmanager_audit_api.trigger_subcloud_audits.\
            assert_called_once_with(self.ctx, subcloud.id, exclude_endpoints)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.MANAGEMENT_MANAGED,
                         updated_subcloud.management_state)
        self.assertEqual("subcloud new description",
                         updated_subcloud.description)
        self.assertEqual("subcloud new location",
                         updated_subcloud.location)

    def test_update_subcloud_with_install_values(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=consts.AVAILABILITY_ONLINE)

        sm = subcloud_manager.SubcloudManager()
        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           management_state=consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location",
                           data_install="install values")

        fake_dcmanager_cermon_api.subcloud_managed.assert_called_once_with(
            self.ctx, subcloud.name)
        exclude_endpoints = [dcorch_consts.ENDPOINT_TYPE_PATCHING,
                             dcorch_consts.ENDPOINT_TYPE_LOAD]
        self.fake_dcmanager_audit_api.trigger_subcloud_audits.\
            assert_called_once_with(self.ctx, subcloud.id, exclude_endpoints)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.MANAGEMENT_MANAGED,
                         updated_subcloud.management_state)
        self.assertEqual("subcloud new description",
                         updated_subcloud.description)
        self.assertEqual("subcloud new location",
                         updated_subcloud.location)
        self.assertEqual("install values",
                         updated_subcloud.data_install)

    def test_update_already_managed_subcloud(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               management_state=consts.MANAGEMENT_MANAGED)

        sm = subcloud_manager.SubcloudManager()
        self.assertRaises(exceptions.BadRequest,
                          sm.update_subcloud, self.ctx,
                          subcloud.id,
                          management_state=consts.MANAGEMENT_MANAGED)
        self.fake_dcmanager_audit_api.trigger_subcloud_audits.assert_not_called()

    def test_update_already_unmanaged_subcloud(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)

        sm = subcloud_manager.SubcloudManager()
        self.assertRaises(exceptions.BadRequest,
                          sm.update_subcloud, self.ctx,
                          subcloud.id,
                          management_state=consts.MANAGEMENT_UNMANAGED)
        self.fake_dcmanager_audit_api.trigger_subcloud_audits.assert_not_called()

    def test_manage_when_deploy_status_failed(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DEPLOY_FAILED)

        sm = subcloud_manager.SubcloudManager()
        self.assertRaises(exceptions.BadRequest,
                          sm.update_subcloud, self.ctx,
                          subcloud.id,
                          management_state=consts.MANAGEMENT_MANAGED)

    def test_manage_when_offline_without_force(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=consts.AVAILABILITY_OFFLINE)

        sm = subcloud_manager.SubcloudManager()
        self.assertRaises(exceptions.SubcloudNotOnline,
                          sm.update_subcloud, self.ctx,
                          subcloud.id,
                          management_state=consts.MANAGEMENT_MANAGED)

    def test_manage_when_offline_with_force(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=consts.AVAILABILITY_OFFLINE)

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           management_state=consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location",
                           data_install="install values",
                           force=True)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.MANAGEMENT_MANAGED,
                         updated_subcloud.management_state)
        self.assertEqual("subcloud new description",
                         updated_subcloud.description)
        self.assertEqual("subcloud new location",
                         updated_subcloud.location)
        self.assertEqual("install values",
                         updated_subcloud.data_install)

    def test_update_subcloud_group_id(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=consts.AVAILABILITY_ONLINE)

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           management_state=consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location",
                           group_id=2)

        fake_dcmanager_cermon_api.subcloud_managed.assert_called_once_with(
            self.ctx, subcloud.name)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.MANAGEMENT_MANAGED,
                         updated_subcloud.management_state)
        self.assertEqual("subcloud new description",
                         updated_subcloud.description)
        self.assertEqual("subcloud new location",
                         updated_subcloud.location)
        self.assertEqual(2,
                         updated_subcloud.group_id)

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
                         dcorch_consts.ENDPOINT_TYPE_NFV,
                         dcorch_consts.ENDPOINT_TYPE_DC_CERT]:
            status = db_api.subcloud_status_create(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(status)
            self.assertEqual(status.sync_status, consts.SYNC_STATUS_UNKNOWN)

        # Update/verify each status with the default sync state: out-of-sync
        ssm = subcloud_state_manager.SubcloudStateManager()
        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV,
                         dcorch_consts.ENDPOINT_TYPE_DC_CERT]:
            # Update
            ssm.update_subcloud_endpoint_status(
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
                         dcorch_consts.ENDPOINT_TYPE_NFV,
                         dcorch_consts.ENDPOINT_TYPE_DC_CERT]:
            ssm.update_subcloud_endpoint_status(
                self.ctx, subcloud_name=subcloud.name,
                endpoint_type=endpoint,
                sync_status=consts.SYNC_STATUS_IN_SYNC)

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            # No change in status: Only online/managed clouds are updated
            self.assertEqual(updated_subcloud_status.sync_status,
                             consts.SYNC_STATUS_OUT_OF_SYNC)

        # Attempt to update each status to be unknown for an offline/unmanaged
        # subcloud. This is allowed.
        ssm.update_subcloud_endpoint_status(
            self.ctx, subcloud_name=subcloud.name,
            endpoint_type=None,
            sync_status=consts.SYNC_STATUS_UNKNOWN)

        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV,
                         dcorch_consts.ENDPOINT_TYPE_DC_CERT]:
            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(updated_subcloud_status.sync_status,
                             consts.SYNC_STATUS_UNKNOWN)

        # Attempt to update each status to be out-of-sync for an
        # offline/unmanaged subcloud. Exclude one endpoint. This is allowed.
        ssm.update_subcloud_endpoint_status(
            self.ctx, subcloud_name=subcloud.name,
            endpoint_type=None,
            sync_status=consts.SYNC_STATUS_OUT_OF_SYNC,
            ignore_endpoints=[dcorch_consts.ENDPOINT_TYPE_DC_CERT])

        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV]:
            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(updated_subcloud_status.sync_status,
                             consts.SYNC_STATUS_OUT_OF_SYNC)
        # Verify the dc-sync endpoint did not change
        endpoint = dcorch_consts.ENDPOINT_TYPE_DC_CERT
        updated_subcloud_status = db_api.subcloud_status_get(
            self.ctx, subcloud.id, endpoint)
        self.assertIsNotNone(updated_subcloud_status)
        self.assertEqual(updated_subcloud_status.sync_status,
                         consts.SYNC_STATUS_UNKNOWN)

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
            ssm.update_subcloud_endpoint_status(
                self.ctx, subcloud_name=subcloud.name,
                endpoint_type=endpoint,
                sync_status=consts.SYNC_STATUS_IN_SYNC)

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            # No change in status: Only online/managed clouds are updated
            self.assertEqual(updated_subcloud_status.sync_status,
                             consts.SYNC_STATUS_OUT_OF_SYNC)

        # Attempt to update dc-cert status to be in-sync for an
        # online/unmanaged subcloud. This is allowed. Verify the change.
        endpoint = dcorch_consts.ENDPOINT_TYPE_DC_CERT
        ssm.update_subcloud_endpoint_status(
            self.ctx, subcloud_name=subcloud.name,
            endpoint_type=endpoint,
            sync_status=consts.SYNC_STATUS_IN_SYNC)

        updated_subcloud_status = db_api.subcloud_status_get(
            self.ctx, subcloud.id, endpoint)
        self.assertIsNotNone(updated_subcloud_status)
        self.assertEqual(updated_subcloud_status.sync_status,
                         consts.SYNC_STATUS_IN_SYNC)

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
                         dcorch_consts.ENDPOINT_TYPE_NFV,
                         dcorch_consts.ENDPOINT_TYPE_DC_CERT]:
            ssm.update_subcloud_endpoint_status(
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
                             dcorch_consts.ENDPOINT_TYPE_NFV,
                             dcorch_consts.ENDPOINT_TYPE_DC_CERT]:
                ssm.update_subcloud_endpoint_status(
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

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        ssm = subcloud_state_manager.SubcloudStateManager()
        db_api.subcloud_update(self.ctx, subcloud.id,
                               management_state=consts.MANAGEMENT_MANAGED)

        # create sync statuses for endpoints
        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV,
                         dcorch_consts.ENDPOINT_TYPE_DC_CERT]:
            status = db_api.subcloud_status_create(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(status)
            self.assertEqual(status.sync_status, consts.SYNC_STATUS_UNKNOWN)

        ssm.update_subcloud_availability(self.ctx, subcloud.name,
                                         consts.AVAILABILITY_ONLINE)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        # Verify the subcloud was set to online
        self.assertEqual(updated_subcloud.availability_status,
                         consts.AVAILABILITY_ONLINE)
        # Verify notifying dcorch
        self.fake_dcorch_api.update_subcloud_states.assert_called_once_with(
            self.ctx, subcloud.name, updated_subcloud.management_state,
            consts.AVAILABILITY_ONLINE)
        # Verify triggering audits
        self.fake_dcmanager_audit_api.trigger_subcloud_audits.\
            assert_called_once_with(self.ctx, subcloud.id)

        fake_dcmanager_cermon_api.subcloud_online.assert_called_once_with(self.ctx, subcloud.name)

    def test_update_subcloud_availability_go_online_unmanaged(self):
        # create a subcloud
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')

        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud.availability_status,
                         consts.AVAILABILITY_OFFLINE)

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        ssm = subcloud_state_manager.SubcloudStateManager()

        # Note that we have intentionally left the subcloud as "unmanaged"

        # create sync statuses for endpoints
        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV,
                         dcorch_consts.ENDPOINT_TYPE_DC_CERT]:
            status = db_api.subcloud_status_create(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(status)
            self.assertEqual(status.sync_status, consts.SYNC_STATUS_UNKNOWN)

        ssm.update_subcloud_availability(self.ctx, subcloud.name,
                                         consts.AVAILABILITY_ONLINE)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        # Verify the subcloud was set to online
        self.assertEqual(updated_subcloud.availability_status,
                         consts.AVAILABILITY_ONLINE)
        # Verify notifying dcorch
        self.fake_dcorch_api.update_subcloud_states.assert_called_once_with(
            self.ctx, subcloud.name, updated_subcloud.management_state,
            consts.AVAILABILITY_ONLINE)
        # Verify triggering audits
        self.fake_dcmanager_audit_api.trigger_subcloud_audits.\
            assert_called_once_with(self.ctx, subcloud.id)

        fake_dcmanager_cermon_api.subcloud_online.assert_called_once_with(self.ctx, subcloud.name)

    def test_update_subcloud_availability_go_offline(self):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        # Set the subcloud to online/managed
        db_api.subcloud_update(self.ctx, subcloud.id,
                               management_state=consts.MANAGEMENT_MANAGED,
                               availability_status=consts.AVAILABILITY_ONLINE)

        ssm = subcloud_state_manager.SubcloudStateManager()

        # create sync statuses for endpoints and set them to in-sync
        for endpoint in [dcorch_consts.ENDPOINT_TYPE_PLATFORM,
                         dcorch_consts.ENDPOINT_TYPE_IDENTITY,
                         dcorch_consts.ENDPOINT_TYPE_PATCHING,
                         dcorch_consts.ENDPOINT_TYPE_FM,
                         dcorch_consts.ENDPOINT_TYPE_NFV]:
            db_api.subcloud_status_create(
                self.ctx, subcloud.id, endpoint)
            ssm.update_subcloud_endpoint_status(
                self.ctx, subcloud_name=subcloud.name,
                endpoint_type=endpoint,
                sync_status=consts.SYNC_STATUS_IN_SYNC)

        # We trigger a subcloud audits after updating the identity from unknown
        # to in-sync
        self.fake_dcmanager_audit_api.trigger_subcloud_patch_load_audits.\
            assert_called_once_with(self.ctx, subcloud.id)

        # Audit fails once
        audit_fail_count = 1
        ssm.update_subcloud_availability(self.ctx, subcloud.name,
                                         availability_status=None,
                                         audit_fail_count=audit_fail_count)
        # Verify the subcloud availability was not updated
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
        ssm.update_subcloud_availability(self.ctx, subcloud.name,
                                         consts.AVAILABILITY_OFFLINE,
                                         audit_fail_count=audit_fail_count)

        # Verify the subcloud availability was updated
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

    def test_update_subcloud_identity_endpoint(self):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        ssm = subcloud_state_manager.SubcloudStateManager()

        # Set the subcloud to online/managed
        db_api.subcloud_update(self.ctx, subcloud.id,
                               management_state=consts.MANAGEMENT_MANAGED,
                               availability_status=consts.AVAILABILITY_ONLINE)

        # Create identity endpoints statuses
        endpoint = dcorch_consts.ENDPOINT_TYPE_IDENTITY
        db_api.subcloud_status_create(
            self.ctx, subcloud.id, endpoint)

        for original_sync_status in [consts.SYNC_STATUS_IN_SYNC,
                                     consts.SYNC_STATUS_OUT_OF_SYNC,
                                     consts.SYNC_STATUS_UNKNOWN]:

            for new_sync_status in [consts.SYNC_STATUS_IN_SYNC,
                                    consts.SYNC_STATUS_OUT_OF_SYNC,
                                    consts.SYNC_STATUS_UNKNOWN]:

                # Update identity to the original status
                ssm.update_subcloud_endpoint_status(
                    self.ctx, subcloud_name=subcloud.name,
                    endpoint_type=endpoint,
                    sync_status=original_sync_status)

                # Get the count of the trigger already called
                original_trigger_subcloud_patch_load_audits_count = \
                    self.fake_dcmanager_audit_api.trigger_subcloud_patch_load_audits.call_count

                # Update identity to new status and get the count of the trigger again
                ssm.update_subcloud_endpoint_status(
                    self.ctx, subcloud_name=subcloud.name,
                    endpoint_type=endpoint,
                    sync_status=new_sync_status)
                new_trigger_subcloud_patch_load_audits_count = \
                    self.fake_dcmanager_audit_api.trigger_subcloud_patch_load_audits.call_count

                trigger_count = new_trigger_subcloud_patch_load_audits_count - \
                    original_trigger_subcloud_patch_load_audits_count

                if original_sync_status == consts.SYNC_STATUS_UNKNOWN and \
                   new_sync_status != consts.SYNC_STATUS_UNKNOWN:
                    # Verify the subcloud patch and load audit is triggered once
                    self.assertEqual(trigger_count, 1)
                else:
                    # Verify the subcloud patch and load audit is not triggered
                    self.assertEqual(trigger_count, 0)

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

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_prepare_for_deployment')
    @mock.patch.object(threading.Thread,
                       'start')
    def test_reconfig_subcloud(self, mock_thread_start,
                               mock_prepare_for_deployment):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_PRE_DEPLOY)

        fake_payload = {"sysadmin_password": "testpass",
                        "deploy_playbook": "test_playbook.yaml",
                        "deploy_overrides": "test_overrides.yaml",
                        "deploy_chart": "test_chart.yaml",
                        "deploy_config": "subcloud1.yaml"}
        sm = subcloud_manager.SubcloudManager()
        sm.reconfigure_subcloud(self.ctx,
                                subcloud.id,
                                payload=fake_payload)
        mock_thread_start.assert_called_once()
        mock_prepare_for_deployment.assert_called_once()

    def test_get_ansible_filename(self):
        sm = subcloud_manager.SubcloudManager()
        filename = sm._get_ansible_filename('subcloud1',
                                            consts.INVENTORY_FILE_POSTFIX)
        self.assertEqual(filename, '/opt/dc/ansible/subcloud1_inventory.yml')

    def test_compose_install_command(self):
        sm = subcloud_manager.SubcloudManager()
        install_command = sm.compose_install_command(
            'subcloud1', '/opt/dc/ansible/subcloud1_inventory.yml')
        self.assertEqual(
            install_command,
            [
                'ansible-playbook', subcloud_manager.ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK,
                '-i', '/opt/dc/ansible/subcloud1_inventory.yml', '--limit', 'subcloud1',
                '-e', "@/opt/dc/ansible/subcloud1/install_values.yml"
            ]
        )

    def test_compose_apply_command(self):
        sm = subcloud_manager.SubcloudManager()
        apply_command = sm.compose_apply_command(
            'subcloud1', '/opt/dc/ansible/subcloud1_inventory.yml')
        self.assertEqual(
            apply_command,
            [
                'ansible-playbook', subcloud_manager.ANSIBLE_SUBCLOUD_PLAYBOOK, '-i',
                '/opt/dc/ansible/subcloud1_inventory.yml', '--limit', 'subcloud1', '-e',
                "override_files_dir='/opt/dc/ansible' region_name=subcloud1"
            ]
        )

    def test_compose_deploy_command(self):
        sm = subcloud_manager.SubcloudManager()
        fake_payload = {"sysadmin_password": "testpass",
                        "deploy_playbook": "test_playbook.yaml",
                        "deploy_overrides": "test_overrides.yaml",
                        "deploy_chart": "test_chart.yaml",
                        "deploy_config": "subcloud1.yaml"}
        deploy_command = sm.compose_deploy_command(
            'subcloud1', '/opt/dc/ansible/subcloud1_inventory.yml', fake_payload)
        self.assertEqual(
            deploy_command,
            [
                'ansible-playbook', 'test_playbook.yaml', '-e',
                '@/opt/dc/ansible/subcloud1_deploy_values.yml', '-i',
                '/opt/dc/ansible/subcloud1_inventory.yml', '--limit', 'subcloud1'
            ]
        )

    def test_compose_rehome_command(self):
        sm = subcloud_manager.SubcloudManager()
        rehome_command = sm.compose_rehome_command(
            'subcloud1', '/opt/dc/ansible/subcloud1_inventory.yml')
        self.assertEqual(
            rehome_command,
            [
                'ansible-playbook', subcloud_manager.ANSIBLE_SUBCLOUD_REHOME_PLAYBOOK, '-i',
                '/opt/dc/ansible/subcloud1_inventory.yml', '--limit', 'subcloud1',
                '--timeout', subcloud_manager.REHOME_PLAYBOOK_TIMEOUT,
                '-e', "override_files_dir='/opt/dc/ansible' region_name=subcloud1"
            ]
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, '_write_subcloud_ansible_config')
    @mock.patch.object(
        subcloud_manager.SubcloudManager, '_create_intermediate_ca_cert')
    @mock.patch.object(
        subcloud_manager.SubcloudManager, 'compose_install_command')
    @mock.patch.object(
        subcloud_manager.SubcloudManager, 'compose_apply_command')
    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(subcloud_manager.SubcloudManager, '_get_cached_regionone_data')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(threading.Thread, 'start')
    @mock.patch.object(subcloud_manager, 'keyring')
    def test_reinstall_subcloud(
        self, mock_keyring, mock_thread_start,
        mock_keystone_client, mock_get_cached_regionone_data, mock_create_subcloud_inventory,
        mock_compose_apply_command, mock_compose_install_command,
        mock_create_intermediate_ca_cert, mock_write_subcloud_ansible_config):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_PRE_INSTALL)

        fake_install_values = \
            copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        fake_install_values['software_version'] = SW_VERSION
        fake_payload = copy.copy(fake_subcloud.FAKE_SUBCLOUD_BOOTSTRAP_PAYLOAD)
        fake_payload.update({
            'bmc_password': 'bmc_pass',
            'software_version': SW_VERSION,
            'install_values': fake_install_values})

        sm = subcloud_manager.SubcloudManager()
        mock_keyring.get_password.return_value = "testpassword"
        mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA

        sm.reinstall_subcloud(self.ctx, subcloud.id, payload=fake_payload)
        mock_keystone_client.assert_called_once()
        mock_get_cached_regionone_data.assert_called_once()
        mock_create_subcloud_inventory.assert_called_once()
        mock_create_intermediate_ca_cert.assert_called_once()
        mock_write_subcloud_ansible_config.assert_called_once()
        mock_compose_install_command.assert_called_once()
        mock_compose_apply_command.assert_called_once()
        mock_thread_start.assert_called_once()

    def test_handle_subcloud_operations_in_progress(self):
        subcloud1 = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_PRE_DEPLOY)
        subcloud2 = self.create_subcloud_static(
            self.ctx,
            name='subcloud2',
            deploy_status=consts.DEPLOY_STATE_PRE_INSTALL)
        subcloud3 = self.create_subcloud_static(
            self.ctx,
            name='subcloud3',
            deploy_status=consts.DEPLOY_STATE_INSTALLING)
        subcloud4 = self.create_subcloud_static(
            self.ctx,
            name='subcloud4',
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING)
        subcloud5 = self.create_subcloud_static(
            self.ctx,
            name='subcloud5',
            deploy_status=consts.DEPLOY_STATE_DEPLOYING)
        subcloud6 = self.create_subcloud_static(
            self.ctx,
            name='subcloud6',
            deploy_status=consts.DEPLOY_STATE_MIGRATING_DATA)
        subcloud7 = self.create_subcloud_static(
            self.ctx,
            name='subcloud7',
            deploy_status=consts.DEPLOY_STATE_PRE_RESTORE)
        subcloud8 = self.create_subcloud_static(
            self.ctx,
            name='subcloud8',
            deploy_status=consts.DEPLOY_STATE_RESTORING)
        subcloud9 = self.create_subcloud_static(
            self.ctx,
            name='subcloud9',
            deploy_status=consts.DEPLOY_STATE_NONE)

        sm = subcloud_manager.SubcloudManager()
        sm.handle_subcloud_operations_in_progress()

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud1.name)
        self.assertEqual(consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud2.name)
        self.assertEqual(consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud3.name)
        self.assertEqual(consts.DEPLOY_STATE_INSTALL_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud4.name)
        self.assertEqual(consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud5.name)
        self.assertEqual(consts.DEPLOY_STATE_DEPLOY_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud6.name)
        self.assertEqual(consts.DEPLOY_STATE_DATA_MIGRATION_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud7.name)
        self.assertEqual(consts.DEPLOY_STATE_RESTORE_PREP_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud8.name)
        self.assertEqual(consts.DEPLOY_STATE_RESTORE_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud9.name)
        self.assertEqual(consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
                         subcloud.deploy_status)

    def test_handle_completed_subcloud_operations(self):
        subcloud1 = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DEPLOY_PREP_FAILED)
        subcloud2 = self.create_subcloud_static(
            self.ctx,
            name='subcloud2',
            deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED)
        subcloud3 = self.create_subcloud_static(
            self.ctx,
            name='subcloud3',
            deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED)
        subcloud4 = self.create_subcloud_static(
            self.ctx,
            name='subcloud4',
            deploy_status=consts.DEPLOY_STATE_INSTALLED)
        subcloud5 = self.create_subcloud_static(
            self.ctx,
            name='subcloud5',
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED)
        subcloud6 = self.create_subcloud_static(
            self.ctx,
            name='subcloud6',
            deploy_status=consts.DEPLOY_STATE_DEPLOY_FAILED)
        subcloud7 = self.create_subcloud_static(
            self.ctx,
            name='subcloud7',
            deploy_status=consts.DEPLOY_STATE_DATA_MIGRATION_FAILED)
        subcloud8 = self.create_subcloud_static(
            self.ctx,
            name='subcloud8',
            deploy_status=consts.DEPLOY_STATE_MIGRATED)
        subcloud9 = self.create_subcloud_static(
            self.ctx,
            name='subcloud9',
            deploy_status=consts.DEPLOY_STATE_RESTORE_PREP_FAILED)
        subcloud10 = self.create_subcloud_static(
            self.ctx,
            name='subcloud10',
            deploy_status=consts.DEPLOY_STATE_RESTORE_FAILED)
        subcloud11 = self.create_subcloud_static(
            self.ctx,
            name='subcloud11',
            deploy_status=consts.DEPLOY_STATE_DONE)

        sm = subcloud_manager.SubcloudManager()
        sm.handle_subcloud_operations_in_progress()

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud1.name)
        self.assertEqual(consts.DEPLOY_STATE_DEPLOY_PREP_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud2.name)
        self.assertEqual(consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud3.name)
        self.assertEqual(consts.DEPLOY_STATE_INSTALL_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud4.name)
        self.assertEqual(consts.DEPLOY_STATE_INSTALLED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud5.name)
        self.assertEqual(consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud6.name)
        self.assertEqual(consts.DEPLOY_STATE_DEPLOY_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud7.name)
        self.assertEqual(consts.DEPLOY_STATE_DATA_MIGRATION_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud8.name)
        self.assertEqual(consts.DEPLOY_STATE_MIGRATED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud9.name)
        self.assertEqual(consts.DEPLOY_STATE_RESTORE_PREP_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud10.name)
        self.assertEqual(consts.DEPLOY_STATE_RESTORE_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud11.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE,
                         subcloud.deploy_status)

    def test_compose_check_target_command(self):
        sm = subcloud_manager.SubcloudManager()
        check_target_command = sm.compose_check_target_command(
            'subcloud1', '/opt/dc/ansible/subcloud1_inventory.yml',
            FAKE_SUBCLOUD_RESTORE_PAYLOAD)
        self.assertEqual(
            check_target_command,
            [
                'ansible-playbook', subcloud_manager.ANSIBLE_HOST_VALIDATION_PLAYBOOK,
                '-i', '/opt/dc/ansible/subcloud1_inventory.yml', '--limit', 'subcloud1',
                '-e', '@/opt/dc/ansible/subcloud1_check_target_values.yml'
            ]
        )

    def test_compose_restore_command(self):
        sm = subcloud_manager.SubcloudManager()
        restore_command = sm.compose_restore_command(
            'subcloud1', '/opt/dc/ansible/subcloud1_inventory.yml',
            FAKE_SUBCLOUD_RESTORE_PAYLOAD)
        self.assertEqual(
            restore_command,
            [
                'ansible-playbook', subcloud_manager.ANSIBLE_SUBCLOUD_RESTORE_PLAYBOOK,
                '-i', '/opt/dc/ansible/subcloud1_inventory.yml', '--limit', 'subcloud1',
                '-e', '@/opt/dc/ansible/subcloud1_restore_values.yml'
            ]
        )

    def test_restore_managed_subcloud(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               management_state=consts.MANAGEMENT_MANAGED)

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm = subcloud_manager.SubcloudManager()
        self.assertRaises(exceptions.SubcloudNotUnmanaged,
                          sm.restore_subcloud, self.ctx,
                          subcloud.id, FAKE_SUBCLOUD_RESTORE_PAYLOAD)

    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(
        subcloud_manager.SubcloudManager, 'compose_install_command')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_prepare_for_restore')
    @mock.patch.object(
        subcloud_manager.SubcloudManager, 'compose_check_target_command')
    @mock.patch.object(
        subcloud_manager.SubcloudManager, 'compose_restore_command')
    @mock.patch.object(threading.Thread, 'start')
    def test_restore_subcloud(
        self, mock_thread_start,
        mock_compose_restore_command, mock_compose_check_target_command,
        mock_prepare_for_restore, mock_compose_install_command,
        mock_create_subcloud_inventory, mock_get_vault_load_files):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_PRE_RESTORE)

        sm = subcloud_manager.SubcloudManager()
        mock_get_vault_load_files.return_value = ("iso file path", "sig file path")

        sm.restore_subcloud(self.ctx, subcloud.id, FAKE_SUBCLOUD_RESTORE_PAYLOAD)
        mock_get_vault_load_files.assert_called_once_with(SW_VERSION)
        mock_create_subcloud_inventory.assert_called_once_with(
            FAKE_SUBCLOUD_RESTORE_PAYLOAD, mock.ANY)
        mock_compose_install_command.assert_called_once_with(subcloud.name, mock.ANY)
        mock_compose_check_target_command.assert_called_once_with(
            subcloud.name, mock.ANY, FAKE_SUBCLOUD_RESTORE_PAYLOAD)
        mock_compose_restore_command.assert_called_once_with(
            subcloud.name, mock.ANY, FAKE_SUBCLOUD_RESTORE_PAYLOAD)
        mock_thread_start.assert_called_once()

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_PRE_RESTORE,
                         updated_subcloud.deploy_status)

    @mock.patch.object(threading.Thread, 'start')
    def test_prestage_subcloud_prepare(self, mock_thread_start):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_NONE)

        sm = subcloud_manager.SubcloudManager()
        sm.prestage_subcloud(self.ctx, payload=values)
        mock_thread_start.assert_called_once()

        # Verify that subcloud has the correct deploy status consts.PRESTAGE_STATE_PREPARE
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.PRESTAGE_STATE_PREPARE,
                         updated_subcloud.deploy_status)

    @mock.patch.object(threading.Thread, 'start')
    def test_prestage_subcloud_prepare_no_subcloud(self, mock_thread_start):
        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        values['subcloud_name'] = 'randomname'

        self.create_subcloud_static(self.ctx,
                                    name='subcloud1',
                                    deploy_status=consts.DEPLOY_STATE_NONE)
        sm = subcloud_manager.SubcloudManager()
        e = self.assertRaises(exceptions.PrestagePreCheckFailedException,
                              sm.prestage_subcloud, self.ctx, values)

        self.assertTrue('Subcloud does not exist'
                        in str(e))

    @mock.patch.object(os_path, 'exists')
    @mock.patch.object(cutils, 'get_filename_by_prefix')
    @mock.patch.object(prestage, '_run_ansible')
    def test_prestage_upgrade_pass(self, mock_run_ansible,
                                   mock_get_filename_by_prefix,
                                   mock_file_exists):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        subcloud = self.create_subcloud_static(self.ctx,
                                               name='subcloud1',
                                               deploy_status=consts.DEPLOY_STATE_NONE,
                                               software_version='18.02')

        prestage._prestage_standalone_thread(self.ctx, subcloud, payload=values)
        mock_run_ansible.return_value = None
        mock_get_filename_by_prefix.return_value = None
        mock_file_exists.return_value = False

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.PRESTAGE_STATE_COMPLETE,
                         updated_subcloud.deploy_status)

    @mock.patch.object(os_path, 'exists')
    @mock.patch.object(prestage, '_run_ansible')
    def test_prestage_ansible_failed(self, mock_run_ansible,
                                     mock_file_exists):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        subcloud = self.create_subcloud_static(self.ctx,
                                               name='subcloud1',
                                               deploy_status=consts.DEPLOY_STATE_NONE,
                                               software_version='18.02')

        mock_run_ansible.side_effect = FakeException('Test')
        mock_file_exists.return_value = False
        mock_open = mock.mock_open(read_data='test')
        with mock.patch('six.moves.builtins.open', mock_open):

            e = self.assertRaises(FakeException,
                                  prestage._sync_run_prestage_prepare_packages,
                                  context=self.ctx, subcloud=subcloud, payload=values)

            self.assertEqual('Test', str(e))

    @mock.patch.object(os_path, 'exists')
    @mock.patch.object(cutils, 'get_filename_by_prefix')
    @mock.patch.object(prestage, '_run_ansible')
    def test_prestage_reinstall_pass(self, mock_run_ansible,
                                     mock_get_filename_by_prefix,
                                     mock_file_exists):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        subcloud = self.create_subcloud_static(self.ctx,
                                               name='subcloud1',
                                               deploy_status=consts.DEPLOY_STATE_NONE,
                                               software_version=SW_VERSION)

        prestage._prestage_standalone_thread(self.ctx, subcloud, payload=values)
        mock_run_ansible.return_value = None
        mock_get_filename_by_prefix.return_value = None
        mock_file_exists.return_value = False

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.PRESTAGE_STATE_COMPLETE,
                         updated_subcloud.deploy_status)

    @mock.patch.object(prestage, 'prestage_complete')
    @mock.patch.object(prestage, 'prestage_images')
    @mock.patch.object(prestage, 'prestage_packages')
    @mock.patch.object(cutils, 'delete_subcloud_inventory')
    @mock.patch.object(prestage, '_run_ansible')
    def test_prestage_subcloud_prestage_prepare(self,
                                                mock_run_ansible,
                                                mock_delete_subcloud_inventory,
                                                mock_prestage_packages,
                                                mock_prestage_images,
                                                mock_prestage_complete):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        subcloud = self.create_subcloud_static(self.ctx,
                                               name='subcloud1',
                                               deploy_status=consts.DEPLOY_STATE_NONE)

        prestage._prestage_standalone_thread(self.ctx, subcloud, payload=values)

        mock_run_ansible.return_value = None
        mock_prestage_packages.assert_called_once_with(self.ctx, subcloud, values)
        mock_prestage_images.assert_called_once_with(self.ctx, subcloud, values)
        mock_prestage_complete.assert_called_once_with(self.ctx, subcloud.id)
        mock_delete_subcloud_inventory.return_value = None

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.PRESTAGE_STATE_PREPARE,
                         updated_subcloud.deploy_status)

    def test_get_cached_regionone_data(self):
        mock_keystone_client = FakeKeystoneClient()
        mock_sysinv_client = FakeSysinvClient()
        sm = subcloud_manager.SubcloudManager()
        cached_regionone_data = sm._get_cached_regionone_data(
            mock_keystone_client, mock_sysinv_client)
        expiry1 = cached_regionone_data['expiry']
        self.assertEqual(cached_regionone_data['dcmanager_user_id'],
                         FAKE_DCMANAGER_USER_ID)
        self.assertEqual(cached_regionone_data['admin_project_id'],
                         FAKE_ADMIN_PROJECT_ID)
        self.assertEqual(cached_regionone_data['mgmt_interface_uuids'],
                         FAKE_MGMT_IF_UUIDS)
        # The expiry timestamp is likely a couple of seconds less than the time
        # the cache is set when it gets here so check if the expiry is greater than
        # 59m55s from now.
        self.assertGreater(cached_regionone_data['expiry'],
                           datetime.datetime.utcnow() + datetime.timedelta(seconds=3595))
        cached_regionone_data = sm._get_cached_regionone_data(
            mock_keystone_client, mock_sysinv_client)
        expiry2 = cached_regionone_data['expiry']
        self.assertEqual(expiry1, expiry2)
