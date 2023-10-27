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
import base64
import collections
import copy
import datetime
import os

import mock

from os import path as os_path
from oslo_concurrency import lockutils
from oslo_utils import timeutils

import sys

sys.modules['fm_core'] = mock.Mock()

import threading

from dccommon import consts as dccommon_consts
from dccommon import subcloud_install
from dccommon.utils import AnsiblePlaybook
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
from tsconfig.tsconfig import SW_VERSION

FAKE_PREVIOUS_SW_VERSION = '21.12'


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
        dccommon_consts.ENDPOINT_TYPE_PLATFORM,
        1
    ),
    FakeService(
        dccommon_consts.ENDPOINT_TYPE_IDENTITY,
        2
    ),
    FakeService(
        dccommon_consts.ENDPOINT_TYPE_PATCHING,
        3
    ),
    FakeService(
        dccommon_consts.ENDPOINT_TYPE_FM,
        4
    ),
    FakeService(
        dccommon_consts.ENDPOINT_TYPE_NFV,
        5
    ),
    FakeService(
        dccommon_consts.ENDPOINT_TYPE_DC_CERT,
        6
    ),
    FakeService(
        dccommon_consts.ENDPOINT_TYPE_SOFTWARE,
        7
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

FAKE_MGMT_FLOATING_ADDRESS = 'fdff:719a:bf60:233::2'
FAKE_MGMT_NETWORK = 'fdff:719a:bf60:233::'


class FakeManagementPool(object):
    def __init__(self):
        self.floating_address = FAKE_MGMT_FLOATING_ADDRESS
        self.network = FAKE_MGMT_NETWORK
        self.prefix = 64


FAKE_OAM_FLOATING_IP = '2620:10a:a001:d41::260'
FAKE_OAM_SUBNET = '2620:10a:a001:d41::/64'


class FakeOamAddresses(object):
    def __init__(self):
        self.oam_floating_ip = FAKE_OAM_FLOATING_IP
        self.oam_subnet = FAKE_OAM_SUBNET


class FakeSysinvClient(object):
    def __init__(self):
        self.hosts = FAKE_CONTROLLERS
        self.interfaces = FAKE_MGMT_INTERFACES
        self.mgmt_pool = FakeManagementPool()
        self.oam_addresses = FakeOamAddresses()

    def get_controller_hosts(self):
        return self.hosts

    def get_management_interface(self, hostname):
        if hostname == 'controller-0':
            return self.interfaces[0]
        else:
            return self.interfaces[1]

    def get_management_address_pool(self):
        return self.mgmt_pool

    def get_oam_addresses(self):
        return self.oam_addresses


class FakeException(Exception):
    pass


FAKE_SUBCLOUD_PRESTAGE_PAYLOAD = {
    "install_values": fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES,
    "subcloud_name": 'subcloud1',
    "force": False,
    "oam_floating_ip": '10.10.10.12',
    "software_version": "20.12",
    "sysadmin_password": "testpasswd",
}

FAKE_PRESTAGE_RELEASE = '22.12'
FAKE_SUBCLOUD_SW_VERSION = '21.12'
FAKE_PASSWORD = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
FAKE_PRESTAGE_PAYLOAD = {
    "subcloud_name": "subcloud1",
    "oam_floating_ip": "10.10.10.12",
    "sysadmin_password": FAKE_PASSWORD,
    "force": False,
    "release": FAKE_PRESTAGE_RELEASE
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

FAKE_BACKUP_DELETE_LOAD = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1,
    "software_version": "22.12"
}

FAKE_BACKUP_DELETE_LOCAL_LOAD = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1,
    "software_version": "22.12",
    "local_only": True
}

FAKE_BACKUP_DELETE_LOAD_1 = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1,
    "software_version": "22.12",
    "local_only": False
}

FAKE_BACKUP_CREATE_LOAD = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1,
}

FAKE_BACKUP_CREATE_LOAD_1 = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1,
    "local_only": False,
    "registry_images": False,
}

FAKE_BACKUP_RESTORE_LOAD = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1
}

FAKE_BACKUP_RESTORE_LOAD_WITH_INSTALL = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1,
    "install_values": fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES
}


class Subcloud(object):
    def __init__(self, data, is_online):
        self.id = data['id']
        self.name = data['name']
        self.description = data['description']
        self.location = data['location']
        self.software_version = data['software-version']
        self.management_state = dccommon_consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = dccommon_consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = dccommon_consts.AVAILABILITY_OFFLINE
        self.deploy_status = data['deploy_status']
        self.error_description = data['error_description']
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

        # Reset the regionone_data cache between tests
        subcloud_manager.SubcloudManager.regionone_data = \
            collections.defaultdict(dict)

    @staticmethod
    def create_subcloud_static(ctxt, **kwargs):
        values = {
            "name": "subcloud1",
            "description": "subcloud1 description",
            "location": "subcloud1 location",
            'software_version': "18.03",
            "management_subnet": "192.168.101.0/24",
            "management_gateway_ip": "192.168.101.1",
            "management_start_ip": "192.168.101.2",
            "management_end_ip": "192.168.101.50",
            "systemcontroller_gateway_ip": "192.168.204.101",
            'deploy_status': "not-deployed",
            'error_description': "No errors present",
            'region_name': base.SUBCLOUD_1['region_name'],
            'openstack_installed': False,
            'group_id': 1,
            'data_install': 'data from install',
        }
        values.update(kwargs)
        return db_api.subcloud_create(ctxt, **values)

    @staticmethod
    def create_subcloud_peer_group_static(ctxt, **kwargs):
        values = {
            "peer_group_name": "pgname",
            "system_leader_id": "12e0cb13-2c5c-480e-b0ea-9161fc03f3ef",
            "system_leader_name": "DC0",
            "group_priority": 0,
            "group_state": "enabled",
            "max_subcloud_rehoming": 50
        }
        values.update(kwargs)
        return db_api.subcloud_peer_group_create(ctxt, **values)

    def test_init(self):
        sm = subcloud_manager.SubcloudManager()
        self.assertIsNotNone(sm)
        self.assertEqual('subcloud_manager', sm.service_name)
        self.assertEqual('localhost', sm.host)
        self.assertEqual(self.ctx, sm.context)

    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(
        subcloud_manager.SubcloudManager, 'compose_install_command')
    @mock.patch.object(
        subcloud_manager.SubcloudManager, '_run_subcloud_install')
    def test_subcloud_deploy_install(self,
                                     mock_run_subcloud_install,
                                     mock_compose_install_command,
                                     mock_create_subcloud_inventory):
        mock_run_subcloud_install.return_value = True

        subcloud_name = 'subcloud1'
        subcloud = self.create_subcloud_static(
            self.ctx,
            name=subcloud_name,
            deploy_status=consts.DEPLOY_STATE_PRE_INSTALL)

        fake_install_values = \
            copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        fake_install_values['software_version'] = SW_VERSION
        fake_payload = {'bmc_password': 'bmc_pass',
                        'install_values': fake_install_values,
                        'software_version': FAKE_PREVIOUS_SW_VERSION,
                        'sysadmin_password': 'sys_pass'}

        sm = subcloud_manager.SubcloudManager()

        sm.subcloud_deploy_install(self.ctx, subcloud.id, payload=fake_payload)
        mock_compose_install_command.assert_called_once_with(
            subcloud_name,
            cutils.get_ansible_filename(subcloud_name, consts.INVENTORY_FILE_POSTFIX),
            FAKE_PREVIOUS_SW_VERSION)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx,
                                                       subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_INSTALLED,
                         updated_subcloud.deploy_status)

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
    def test_subcloud_deploy_create(self, mock_keyring,
                                    mock_write_subcloud_ansible_config,
                                    mock_create_subcloud_inventory,
                                    mock_create_addn_hosts,
                                    mock_get_cached_regionone_data,
                                    mock_sysinv_client,
                                    mock_keystone_client,
                                    mock_delete_subcloud_inventory,
                                    mock_create_intermediate_ca_cert):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values['deploy_status'] = consts.DEPLOY_STATE_NONE

        # dcmanager add_subcloud queries the data from the db
        subcloud = self.create_subcloud_static(self.ctx, name=values['name'],
                                               region_name=values['region_name'])
        values['id'] = subcloud.id

        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_keyring.get_password.return_value = "testpassword"
        mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA

        sm = subcloud_manager.SubcloudManager()
        subcloud_dict = sm.subcloud_deploy_create(self.ctx, subcloud.id,
                                                  payload=values)
        mock_get_cached_regionone_data.assert_called_once()
        mock_sysinv_client().create_route.assert_called()
        self.fake_dcorch_api.add_subcloud.assert_called_once()
        mock_create_addn_hosts.assert_called_once()
        mock_create_subcloud_inventory.assert_called_once()
        mock_write_subcloud_ansible_config.assert_called_once()
        mock_keyring.get_password.assert_called()
        mock_create_intermediate_ca_cert.assert_called_once()

        # Verify subcloud was updated with correct values
        self.assertEqual(consts.DEPLOY_STATE_CREATED,
                         subcloud_dict['deploy-status'])

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, values['name'])
        self.assertEqual(consts.DEPLOY_STATE_CREATED,
                         updated_subcloud.deploy_status)

    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    def test_subcloud_deploy_create_failed(self, mock_keystone_client):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values['deploy_status'] = consts.DEPLOY_STATE_NONE

        # dcmanager add_subcloud queries the data from the db
        subcloud = self.create_subcloud_static(self.ctx, name=values['name'],
                                               region_name=values['region_name'])
        values['id'] = subcloud.id

        mock_keystone_client.side_effect = FakeException('boom')

        sm = subcloud_manager.SubcloudManager()
        subcloud_dict = sm.subcloud_deploy_create(self.ctx, subcloud.id,
                                                  payload=values)

        # Verify subcloud was updated with correct values
        self.assertEqual(consts.DEPLOY_STATE_CREATE_FAILED,
                         subcloud_dict['deploy-status'])

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, values['name'])
        self.assertEqual(consts.DEPLOY_STATE_CREATE_FAILED,
                         updated_subcloud.deploy_status)

    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(subcloud_manager, 'keyring')
    @mock.patch.object(cutils, 'get_playbook_for_software_version')
    @mock.patch.object(cutils, 'update_values_on_yaml_file')
    @mock.patch.object(AnsiblePlaybook, 'run_playbook')
    def test_subcloud_deploy_bootstrap(self, mock_run_playbook, mock_update_yml,
                                       mock_get_playbook_for_software_version,
                                       mock_keyring, mock_create_subcloud_inventory):
        mock_get_playbook_for_software_version.return_value = "22.12"
        mock_keyring.get_password.return_value = "testpass"
        mock_run_playbook.return_value = False

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED)

        payload = {**fake_subcloud.FAKE_BOOTSTRAP_VALUE,
                   **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA}
        payload["sysadmin_password"] = "testpass"

        sm = subcloud_manager.SubcloudManager()
        sm.subcloud_deploy_bootstrap(self.ctx, subcloud.id, payload)

        mock_run_playbook.assert_called_once()

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx,
                                                       payload['name'])
        self.assertEqual(consts.DEPLOY_STATE_BOOTSTRAPPED,
                         updated_subcloud.deploy_status)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_deploy_bootstrap_prep')
    def test_subcloud_deploy_bootstrap_failed(self, mock_bootstrap_prep):
        mock_bootstrap_prep.side_effect = FakeException('boom')

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED)

        payload = {**fake_subcloud.FAKE_BOOTSTRAP_VALUE,
                   **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA}
        payload["sysadmin_password"] = "testpass"

        sm = subcloud_manager.SubcloudManager()
        sm.subcloud_deploy_bootstrap(self.ctx, subcloud.id, payload)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx,
                                                       payload['name'])
        self.assertEqual(consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED,
                         updated_subcloud.deploy_status)

    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_prepare_for_deployment')
    def test_configure_subcloud(self, mock_prepare_for_deployment,
                                mock_create_subcloud_inventory):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_PRE_CONFIG)

        fake_payload = {"sysadmin_password": "testpass",
                        "deploy_playbook": "test_playbook.yaml",
                        "deploy_overrides": "test_overrides.yaml",
                        "deploy_chart": "test_chart.yaml",
                        "deploy_config": "subcloud1.yaml",
                        consts.BOOTSTRAP_ADDRESS:
                            fake_subcloud.FAKE_BOOTSTRAP_VALUE[consts.BOOTSTRAP_ADDRESS]}
        sm = subcloud_manager.SubcloudManager()
        sm.subcloud_deploy_config(self.ctx,
                                  subcloud.id,
                                  payload=fake_payload)
        mock_prepare_for_deployment.assert_called_once()
        mock_create_subcloud_inventory.assert_called_once()

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_subcloud_install')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_prepare_for_deployment')
    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(subcloud_manager, 'keyring')
    @mock.patch.object(cutils, 'update_values_on_yaml_file')
    @mock.patch.object(cutils, 'get_playbook_for_software_version')
    @mock.patch.object(AnsiblePlaybook, 'run_playbook')
    def test_subcloud_deploy_resume(
        self, mock_run_playbook, mock_get_playbook_for_software_version,
        mock_update_yml, mock_keyring, mock_create_subcloud_inventory,
        mock_prepare_for_deployment, mock_run_subcloud_install):

        mock_get_playbook_for_software_version.return_value = "22.12"
        mock_keyring.get_password.return_value = "testpass"
        mock_run_playbook.return_value = False
        mock_run_subcloud_install.return_value = True

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_CREATED)

        deploy_states_to_run = [consts.DEPLOY_PHASE_INSTALL,
                                consts.DEPLOY_PHASE_BOOTSTRAP,
                                consts.DEPLOY_PHASE_CONFIG]

        fake_install_values = \
            copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        fake_install_values['software_version'] = SW_VERSION
        fake_payload_install = {'bmc_password': 'bmc_pass',
                                'install_values': fake_install_values,
                                'software_version': SW_VERSION,
                                'sysadmin_password': 'sys_pass'}

        fake_payload_bootstrap = {**fake_subcloud.FAKE_BOOTSTRAP_VALUE,
                                  **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA}
        fake_payload_bootstrap["sysadmin_password"] = "testpass"

        fake_payload_config = {"sysadmin_password": "testpass",
                               "deploy_playbook": "test_playbook.yaml",
                               "deploy_overrides": "test_overrides.yaml",
                               "deploy_chart": "test_chart.yaml",
                               "deploy_config": "subcloud1.yaml"}

        fake_payload = {**fake_payload_install,
                        **fake_payload_bootstrap,
                        **fake_payload_config}

        sm = subcloud_manager.SubcloudManager()
        sm.subcloud_deploy_resume(self.ctx, subcloud.id, subcloud.name,
                                  fake_payload, deploy_states_to_run)
        mock_prepare_for_deployment.assert_called_once()

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx,
                                                       subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE,
                         updated_subcloud.deploy_status)

    @mock.patch.object(cutils, 'get_oam_addresses')
    @mock.patch.object(subcloud_install.SubcloudInstall, 'prep')
    @mock.patch.object(subcloud_install, 'KeystoneClient')
    @mock.patch.object(subcloud_install, 'SysinvClient')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_write_subcloud_ansible_config')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_intermediate_ca_cert')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_addn_hosts_dc')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_write_deploy_files')
    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(subcloud_manager, 'keyring')
    @mock.patch.object(cutils, 'get_playbook_for_software_version')
    @mock.patch.object(cutils, 'update_values_on_yaml_file')
    @mock.patch.object(AnsiblePlaybook, 'run_playbook')
    def test_add_subcloud(self, mock_run_playbook, mock_update_yml,
                          mock_get_playbook_for_software_version,
                          mock_keyring, mock_create_subcloud_inventory,
                          mock_write_deploy_files, mock_sysinv_client,
                          mock_openstack_driver, mock_create_addn_hosts,
                          mock_create_intermediate_ca_cert,
                          mock_write_subcloud_ansible_config,
                          mock_install_ks_client, mock_install_sysinvclient,
                          mock_install_prep, mock_oam_address):
        # Prepare the payload
        install_values = copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        install_values['software_version'] = SW_VERSION
        payload = {**fake_subcloud.FAKE_BOOTSTRAP_VALUE,
                   **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA,
                   "sysadmin_password": "testpass",
                   'bmc_password': 'bmc_pass',
                   'install_values': install_values,
                   'software_version': FAKE_PREVIOUS_SW_VERSION,
                   "deploy_playbook": "test_playbook.yaml",
                   "deploy_overrides": "test_overrides.yaml",
                   "deploy_chart": "test_chart.yaml",
                   "deploy_config": "subcloud1.yaml",
                   "user_uploaded_artifacts": True}

        # Create subcloud in DB
        subcloud = self.create_subcloud_static(self.ctx, name=payload['name'])
        payload['region_name'] = subcloud.region_name

        # Mock return values
        mock_get_playbook_for_software_version.return_value = SW_VERSION
        mock_keyring.get_password.return_value = payload['sysadmin_password']
        mock_run_playbook.return_value = False
        mock_openstack_driver().keystone_client = FakeKeystoneClient()

        # Call the add method
        sm = subcloud_manager.SubcloudManager()
        sm.add_subcloud(self.ctx, subcloud.id, payload)

        # Verify results
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE,
                         updated_subcloud.deploy_status)

        mock_write_deploy_files.assert_called()
        mock_keyring.get_password.assert_called()
        mock_update_yml.assert_called()
        mock_create_subcloud_inventory.assert_called()
        mock_get_playbook_for_software_version.assert_called_once()
        self.assertEqual(mock_run_playbook.call_count, 3)

    @mock.patch.object(subcloud_manager.AnsiblePlaybook,
                       'run_playbook')
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
    def test_add_subcloud_with_migration_option(
        self, mock_keyring,
        mock_write_subcloud_ansible_config,
        mock_create_subcloud_inventory,
        mock_create_addn_hosts,
        mock_get_cached_regionone_data,
        mock_sysinv_client,
        mock_keystone_client,
        mock_delete_subcloud_inventory,
        mock_create_intermediate_ca_cert,
        mock_compose_rehome_command,
        mock_run_playbook):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values['deploy_status'] = consts.DEPLOY_STATE_NONE
        values['migrate'] = 'true'
        sysadmin_password = values['sysadmin_password']

        # dcmanager add_subcloud queries the data from the db
        subcloud = self.create_subcloud_static(self.ctx, name=values['name'],
                                               region_name=values['region_name'])

        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_keyring.get_password.return_value = sysadmin_password
        mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA

        sm = subcloud_manager.SubcloudManager()
        sm.add_subcloud(self.ctx, subcloud.id, payload=values)

        mock_get_cached_regionone_data.assert_called_once()
        mock_sysinv_client().create_route.assert_called()
        self.fake_dcorch_api.add_subcloud.assert_called_once()
        mock_create_addn_hosts.assert_called_once()
        mock_create_subcloud_inventory.assert_called_once()
        mock_write_subcloud_ansible_config.assert_called_once()
        mock_create_intermediate_ca_cert.assert_called_once()
        mock_compose_rehome_command.assert_called_once_with(
            values['name'],
            values['region_name'],
            sm._get_ansible_filename(values['name'], consts.INVENTORY_FILE_POSTFIX),
            subcloud['software_version'])

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, values['name'])
        self.assertEqual(consts.DEPLOY_STATE_DONE,
                         updated_subcloud.deploy_status)

        # Verify that the password fields are present
        written_payload = mock_write_subcloud_ansible_config.call_args.args[1]
        expected_subset = {'ansible_become_pass': sysadmin_password,
                           'ansible_ssh_pass': sysadmin_password,
                           'admin_password': sysadmin_password}
        # Check that expected_subset is a subset of written_payload
        self.assertTrue(expected_subset.items() <= written_payload.items())

    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager.SubcloudManager, '_get_cached_regionone_data')
    def test_add_subcloud_create_failed(self,
                                        mock_get_cached_regionone_data,
                                        mock_sysinv_client,
                                        mock_keystone_client):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        services = FAKE_SERVICES

        # dcmanager add_subcloud queries the data from the db
        subcloud = self.create_subcloud_static(self.ctx, name=values['name'],
                                               region_name=values['region_name'])

        self.fake_dcorch_api.add_subcloud.side_effect = FakeException('boom')
        mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA
        mock_keystone_client().services_list = services

        sm = subcloud_manager.SubcloudManager()
        sm.add_subcloud(self.ctx, subcloud.id, payload=values)
        mock_get_cached_regionone_data.assert_called_once()
        mock_sysinv_client().create_route.assert_called()

        # Verify subcloud was updated with correct values
        subcloud = db_api.subcloud_get_by_name(self.ctx, values['name'])
        self.assertEqual(consts.DEPLOY_STATE_CREATE_FAILED,
                         subcloud.deploy_status)

    @mock.patch.object(subcloud_manager, 'keyring')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(subcloud_manager, 'SysinvClient')
    @mock.patch.object(subcloud_manager.SubcloudManager, '_get_cached_regionone_data')
    def test_add_subcloud_with_migrate_option_prep_failed(
        self, mock_get_cached_regionone_data, mock_sysinv_client,
        mock_keystone_client, mock_keyring):

        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values['migrate'] = 'true'
        services = FAKE_SERVICES

        # dcmanager add_subcloud queries the data from the db
        subcloud = self.create_subcloud_static(self.ctx, name=values['name'],
                                               region_name=values['region_name'])

        self.fake_dcorch_api.add_subcloud.side_effect = FakeException('boom')
        mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA
        mock_keystone_client().services_list = services
        mock_keyring.get_password.return_vaue = "testpass"

        sm = subcloud_manager.SubcloudManager()
        sm.add_subcloud(self.ctx, subcloud.id, payload=values)
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
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        fake_dcmanager_notification = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_notification

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           management_state=dccommon_consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location")

        fake_dcmanager_notification.subcloud_managed.assert_called_once_with(
            self.ctx, subcloud.region_name)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(dccommon_consts.MANAGEMENT_MANAGED,
                         updated_subcloud.management_state)
        self.assertEqual("subcloud new description",
                         updated_subcloud.description)
        self.assertEqual("subcloud new location",
                         updated_subcloud.location)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_addn_hosts_dc')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_delete_subcloud_routes')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_update_services_endpoint')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_subcloud_route')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(subcloud_manager.AnsiblePlaybook, 'run_playbook')
    def test_update_subcloud_network_reconfiguration(
            self, mock_run_playbook, mock_keystone_client, mock_create_route,
            mock_update_endpoints, mock_delete_route, mock_addn_hosts_dc):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        payload = {'name': subcloud.name,
                   'description': "subcloud description",
                   'location': "subcloud location",
                   'management_subnet': "192.168.102.0/24",
                   'management_start_ip': "192.168.102.5",
                   'management_end_ip': "192.168.102.49",
                   'management_gateway_ip': "192.168.102.1"}

        fake_dcmanager_notification = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_notification

        sm = subcloud_manager.SubcloudManager()
        sm._run_network_reconfiguration(
            subcloud.name, mock.ANY, None, payload, self.ctx, subcloud)

        mock_run_playbook.assert_called_once()
        mock_keystone_client.assert_called_once()
        mock_create_route.assert_called_once()
        mock_update_endpoints.assert_called_once()
        mock_delete_route.assert_called_once()
        mock_addn_hosts_dc.assert_called_once()

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(payload['description'],
                         updated_subcloud.description)
        self.assertEqual(payload['location'],
                         updated_subcloud.location)
        self.assertEqual(payload['management_subnet'],
                         updated_subcloud.management_subnet)
        self.assertEqual(payload['management_gateway_ip'],
                         updated_subcloud.management_gateway_ip)
        self.assertEqual(payload['management_start_ip'],
                         updated_subcloud.management_start_ip)
        self.assertEqual(payload['management_end_ip'],
                         updated_subcloud.management_end_ip)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_delete_subcloud_routes')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_update_services_endpoint')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_subcloud_route')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    def test_network_reconf_same_subnet(
            self, mock_keystone_client, mock_create_route,
            mock_update_endpoints, mock_delete_route):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        payload = {'name': "subcloud1",
                   'description': "subcloud description",
                   'location': "subcloud location",
                   'management_subnet': "192.168.101.0/24",
                   'management_start_ip': "192.168.101.3",
                   'management_end_ip': "192.168.101.49",
                   'management_gateway_ip': "192.168.101.1"}

        sm = subcloud_manager.SubcloudManager()
        sm._configure_system_controller_network(self.ctx, payload, subcloud)

        mock_keystone_client.assert_called_once()
        mock_create_route.assert_called_once()
        mock_update_endpoints.assert_called_once()
        self.assertFalse(mock_delete_route.called)

    def test_update_subcloud_with_install_values(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        sm = subcloud_manager.SubcloudManager()
        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           management_state=dccommon_consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location",
                           data_install="install values")

        fake_dcmanager_cermon_api.subcloud_managed.assert_called_once_with(
            self.ctx, subcloud.region_name)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(dccommon_consts.MANAGEMENT_MANAGED,
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
                               management_state=dccommon_consts.MANAGEMENT_MANAGED)

        sm = subcloud_manager.SubcloudManager()
        self.assertRaises(exceptions.BadRequest,
                          sm.update_subcloud, self.ctx,
                          subcloud.id,
                          management_state=dccommon_consts.MANAGEMENT_MANAGED)
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
                          management_state=dccommon_consts.MANAGEMENT_UNMANAGED)
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
                          management_state=dccommon_consts.MANAGEMENT_MANAGED)

    def test_manage_when_offline_without_force(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE)
        sm = subcloud_manager.SubcloudManager()
        self.assertRaises(exceptions.SubcloudNotOnline,
                          sm.update_subcloud, self.ctx,
                          subcloud.id,
                          management_state=dccommon_consts.MANAGEMENT_MANAGED)

    def test_manage_when_offline_with_force(self):
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE)

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           management_state=dccommon_consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location",
                           data_install="install values",
                           force=True)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(dccommon_consts.MANAGEMENT_MANAGED,
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
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           management_state=dccommon_consts.MANAGEMENT_MANAGED,
                           description="subcloud new description",
                           location="subcloud new location",
                           group_id=2)

        fake_dcmanager_cermon_api.subcloud_managed.assert_called_once_with(
            self.ctx, subcloud.region_name)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(dccommon_consts.MANAGEMENT_MANAGED,
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
                         dccommon_consts.MANAGEMENT_UNMANAGED)
        self.assertEqual(subcloud.availability_status,
                         dccommon_consts.AVAILABILITY_OFFLINE)

        # create sync statuses for endpoints
        for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                         dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                         dccommon_consts.ENDPOINT_TYPE_PATCHING,
                         dccommon_consts.ENDPOINT_TYPE_FM,
                         dccommon_consts.ENDPOINT_TYPE_NFV,
                         dccommon_consts.ENDPOINT_TYPE_DC_CERT]:
            status = db_api.subcloud_status_create(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(status)
            self.assertEqual(status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN)

        # Update/verify each status with the default sync state: out-of-sync
        ssm = subcloud_state_manager.SubcloudStateManager()
        for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                         dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                         dccommon_consts.ENDPOINT_TYPE_PATCHING,
                         dccommon_consts.ENDPOINT_TYPE_FM,
                         dccommon_consts.ENDPOINT_TYPE_NFV,
                         dccommon_consts.ENDPOINT_TYPE_DC_CERT]:
            # Update
            ssm.update_subcloud_endpoint_status(
                self.ctx, subcloud_region=subcloud.region_name,
                endpoint_type=endpoint)

            # Verify
            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(updated_subcloud_status.sync_status,
                             dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

        # Attempt to update each status to be in-sync for an offline/unmanaged
        # subcloud. This is not allowed. Verify no change.
        for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                         dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                         dccommon_consts.ENDPOINT_TYPE_PATCHING,
                         dccommon_consts.ENDPOINT_TYPE_FM,
                         dccommon_consts.ENDPOINT_TYPE_NFV,
                         dccommon_consts.ENDPOINT_TYPE_DC_CERT]:
            ssm.update_subcloud_endpoint_status(
                self.ctx, subcloud_region=subcloud.region_name,
                endpoint_type=endpoint,
                sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            # No change in status: Only online/managed clouds are updated
            self.assertEqual(updated_subcloud_status.sync_status,
                             dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

        # Attempt to update each status to be unknown for an offline/unmanaged
        # subcloud. This is allowed.
        ssm.update_subcloud_endpoint_status(
            self.ctx, subcloud_region=subcloud.region_name,
            endpoint_type=None,
            sync_status=dccommon_consts.SYNC_STATUS_UNKNOWN)

        for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                         dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                         dccommon_consts.ENDPOINT_TYPE_PATCHING,
                         dccommon_consts.ENDPOINT_TYPE_FM,
                         dccommon_consts.ENDPOINT_TYPE_NFV,
                         dccommon_consts.ENDPOINT_TYPE_DC_CERT]:
            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(updated_subcloud_status.sync_status,
                             dccommon_consts.SYNC_STATUS_UNKNOWN)

        # Attempt to update each status to be out-of-sync for an
        # offline/unmanaged subcloud. Exclude one endpoint. This is allowed.
        ssm.update_subcloud_endpoint_status(
            self.ctx, subcloud_region=subcloud.region_name,
            endpoint_type=None,
            sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            ignore_endpoints=[dccommon_consts.ENDPOINT_TYPE_DC_CERT])

        for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                         dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                         dccommon_consts.ENDPOINT_TYPE_PATCHING,
                         dccommon_consts.ENDPOINT_TYPE_FM,
                         dccommon_consts.ENDPOINT_TYPE_NFV]:
            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(updated_subcloud_status.sync_status,
                             dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
        # Verify the dc-sync endpoint did not change
        endpoint = dccommon_consts.ENDPOINT_TYPE_DC_CERT
        updated_subcloud_status = db_api.subcloud_status_get(
            self.ctx, subcloud.id, endpoint)
        self.assertIsNotNone(updated_subcloud_status)
        self.assertEqual(updated_subcloud_status.sync_status,
                         dccommon_consts.SYNC_STATUS_UNKNOWN)

        # Set/verify the subcloud is online/unmanaged
        db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud.management_state,
                         dccommon_consts.MANAGEMENT_UNMANAGED)
        self.assertEqual(subcloud.availability_status,
                         dccommon_consts.AVAILABILITY_ONLINE)

        # Attempt to update each status to be in-sync for an online/unmanaged
        # subcloud. This is not allowed. Verify no change.
        for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                         dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                         dccommon_consts.ENDPOINT_TYPE_PATCHING,
                         dccommon_consts.ENDPOINT_TYPE_FM,
                         dccommon_consts.ENDPOINT_TYPE_NFV]:
            ssm.update_subcloud_endpoint_status(
                self.ctx, subcloud_region=subcloud.region_name,
                endpoint_type=endpoint,
                sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            # No change in status: Only online/managed clouds are updated
            self.assertEqual(updated_subcloud_status.sync_status,
                             dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

        # Attempt to update dc-cert status to be in-sync for an
        # online/unmanaged subcloud. This is allowed. Verify the change.
        endpoint = dccommon_consts.ENDPOINT_TYPE_DC_CERT
        ssm.update_subcloud_endpoint_status(
            self.ctx, subcloud_region=subcloud.region_name,
            endpoint_type=endpoint,
            sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)

        updated_subcloud_status = db_api.subcloud_status_get(
            self.ctx, subcloud.id, endpoint)
        self.assertIsNotNone(updated_subcloud_status)
        self.assertEqual(updated_subcloud_status.sync_status,
                         dccommon_consts.SYNC_STATUS_IN_SYNC)

        # Set/verify the subcloud is online/managed
        db_api.subcloud_update(
            self.ctx, subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED)
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud.management_state,
                         dccommon_consts.MANAGEMENT_MANAGED)
        self.assertEqual(subcloud.availability_status,
                         dccommon_consts.AVAILABILITY_ONLINE)

        # Attempt to update each status to be in-sync for an online/managed
        # subcloud
        for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                         dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                         dccommon_consts.ENDPOINT_TYPE_PATCHING,
                         dccommon_consts.ENDPOINT_TYPE_FM,
                         dccommon_consts.ENDPOINT_TYPE_NFV,
                         dccommon_consts.ENDPOINT_TYPE_DC_CERT]:
            ssm.update_subcloud_endpoint_status(
                self.ctx, subcloud_region=subcloud.region_name,
                endpoint_type=endpoint,
                sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(updated_subcloud_status.sync_status,
                             dccommon_consts.SYNC_STATUS_IN_SYNC)

        # Change the sync status to 'out-of-sync' and verify fair lock access
        # based on subcloud name for each update
        with mock.patch.object(lockutils, 'internal_fair_lock') as mock_lock:
            for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                             dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                             dccommon_consts.ENDPOINT_TYPE_PATCHING,
                             dccommon_consts.ENDPOINT_TYPE_FM,
                             dccommon_consts.ENDPOINT_TYPE_NFV,
                             dccommon_consts.ENDPOINT_TYPE_DC_CERT]:
                ssm.update_subcloud_endpoint_status(
                    self.ctx, subcloud_region=subcloud.region_name,
                    endpoint_type=endpoint,
                    sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
                # Verify lock was called
                mock_lock.assert_called_with(subcloud.region_name)

                # Verify status was updated
                updated_subcloud_status = db_api.subcloud_status_get(
                    self.ctx, subcloud.id, endpoint)
                self.assertIsNotNone(updated_subcloud_status)
                self.assertEqual(updated_subcloud_status.sync_status,
                                 dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)

    def test_update_subcloud_availability_go_online(self):
        # create a subcloud
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')

        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud.availability_status,
                         dccommon_consts.AVAILABILITY_OFFLINE)

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        ssm = subcloud_state_manager.SubcloudStateManager()
        db_api.subcloud_update(self.ctx, subcloud.id,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED)

        # create sync statuses for endpoints
        for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                         dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                         dccommon_consts.ENDPOINT_TYPE_PATCHING,
                         dccommon_consts.ENDPOINT_TYPE_FM,
                         dccommon_consts.ENDPOINT_TYPE_NFV,
                         dccommon_consts.ENDPOINT_TYPE_DC_CERT]:
            status = db_api.subcloud_status_create(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(status)
            self.assertEqual(status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN)

        ssm.update_subcloud_availability(self.ctx, subcloud.region_name,
                                         dccommon_consts.AVAILABILITY_ONLINE)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        # Verify the subcloud was set to online
        self.assertEqual(updated_subcloud.availability_status,
                         dccommon_consts.AVAILABILITY_ONLINE)
        # Verify notifying dcorch
        self.fake_dcorch_api.update_subcloud_states.assert_called_once_with(
            self.ctx, subcloud.region_name, updated_subcloud.management_state,
            dccommon_consts.AVAILABILITY_ONLINE)
        # Verify triggering audits
        self.fake_dcmanager_audit_api.trigger_subcloud_audits.\
            assert_called_once_with(self.ctx, subcloud.id)

        fake_dcmanager_cermon_api.subcloud_online.\
            assert_called_once_with(self.ctx, subcloud.region_name)

    @mock.patch.object(subcloud_state_manager.SubcloudStateManager,
                       '_raise_or_clear_subcloud_status_alarm')
    def test_update_state_only(self, mock_update_status_alarm):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        # Set the subcloud to online/managed
        db_api.subcloud_update(self.ctx, subcloud.id,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        ssm = subcloud_state_manager.SubcloudStateManager()

        with mock.patch.object(db_api, "subcloud_update") as subcloud_update_mock:
            ssm.update_subcloud_availability(self.ctx, subcloud.region_name,
                                             availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                                             update_state_only=True)
            # Verify that the subcloud was not updated
            subcloud_update_mock.assert_not_called()

        # Verify alarm status update was attempted
        mock_update_status_alarm.assert_called_once()

        # Verify dcorch was notified
        self.fake_dcorch_api.update_subcloud_states.assert_called_once_with(
            self.ctx, subcloud.region_name, subcloud.management_state,
            dccommon_consts.AVAILABILITY_ONLINE)

        # Verify audits were not triggered
        self.fake_dcmanager_audit_api.trigger_subcloud_audits.assert_not_called()

    def test_update_subcloud_availability_go_online_unmanaged(self):
        # create a subcloud
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')

        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud.availability_status,
                         dccommon_consts.AVAILABILITY_OFFLINE)

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        ssm = subcloud_state_manager.SubcloudStateManager()

        # Note that we have intentionally left the subcloud as "unmanaged"

        # create sync statuses for endpoints
        for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                         dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                         dccommon_consts.ENDPOINT_TYPE_PATCHING,
                         dccommon_consts.ENDPOINT_TYPE_FM,
                         dccommon_consts.ENDPOINT_TYPE_NFV,
                         dccommon_consts.ENDPOINT_TYPE_DC_CERT]:
            status = db_api.subcloud_status_create(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(status)
            self.assertEqual(status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN)

        ssm.update_subcloud_availability(self.ctx, subcloud.region_name,
                                         dccommon_consts.AVAILABILITY_ONLINE)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        # Verify the subcloud was set to online
        self.assertEqual(updated_subcloud.availability_status,
                         dccommon_consts.AVAILABILITY_ONLINE)
        # Verify notifying dcorch
        self.fake_dcorch_api.update_subcloud_states.assert_called_once_with(
            self.ctx, subcloud.region_name, updated_subcloud.management_state,
            dccommon_consts.AVAILABILITY_ONLINE)
        # Verify triggering audits
        self.fake_dcmanager_audit_api.trigger_subcloud_audits.\
            assert_called_once_with(self.ctx, subcloud.id)

        fake_dcmanager_cermon_api.subcloud_online.\
            assert_called_once_with(self.ctx, subcloud.region_name)

    def test_update_subcloud_availability_go_offline(self):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)

        # Set the subcloud to online/managed
        db_api.subcloud_update(self.ctx, subcloud.id,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        ssm = subcloud_state_manager.SubcloudStateManager()

        # create sync statuses for endpoints and set them to in-sync
        for endpoint in [dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                         dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                         dccommon_consts.ENDPOINT_TYPE_PATCHING,
                         dccommon_consts.ENDPOINT_TYPE_FM,
                         dccommon_consts.ENDPOINT_TYPE_NFV]:
            db_api.subcloud_status_create(
                self.ctx, subcloud.id, endpoint)
            ssm.update_subcloud_endpoint_status(
                self.ctx, subcloud_region=subcloud.region_name,
                endpoint_type=endpoint,
                sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC)

        # We trigger a subcloud audits after updating the identity from unknown
        # to in-sync
        self.fake_dcmanager_audit_api.trigger_subcloud_audits.\
            assert_called_once_with(self.ctx, subcloud.id)

        # Audit fails once
        audit_fail_count = 1
        ssm.update_subcloud_availability(self.ctx, subcloud.region_name,
                                         availability_status=None,
                                         audit_fail_count=audit_fail_count)
        # Verify the subcloud availability was not updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.availability_status,
                         dccommon_consts.AVAILABILITY_ONLINE)
        # Verify dcorch was not notified
        self.fake_dcorch_api.update_subcloud_states.assert_not_called()
        # Verify the audit_fail_count was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.audit_fail_count, audit_fail_count)

        # Audit fails again
        audit_fail_count = audit_fail_count + 1
        ssm.update_subcloud_availability(self.ctx, subcloud.region_name,
                                         dccommon_consts.AVAILABILITY_OFFLINE,
                                         audit_fail_count=audit_fail_count)

        # Verify the subcloud availability was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, 'subcloud1')
        self.assertEqual(updated_subcloud.availability_status,
                         dccommon_consts.AVAILABILITY_OFFLINE)

        # Verify notifying dcorch
        self.fake_dcorch_api.update_subcloud_states.assert_called_once_with(
            self.ctx, subcloud.region_name, updated_subcloud.management_state,
            dccommon_consts.AVAILABILITY_OFFLINE)

        # Verify all endpoint statuses set to unknown
        for subcloud, subcloud_status in db_api. \
                subcloud_get_with_status(self.ctx, subcloud.id):
            self.assertIsNotNone(subcloud_status)
            self.assertEqual(subcloud_status.sync_status,
                             dccommon_consts.SYNC_STATUS_UNKNOWN)

    def test_update_subcloud_identity_endpoint(self):
        subcloud = self.create_subcloud_static(self.ctx, name='subcloud1')
        self.assertIsNotNone(subcloud)
        for endpoint_type in dccommon_consts.ENDPOINT_TYPES_LIST:
            subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint_type)
            self.assertIsNotNone(subcloud_status)
            self.assertEqual(subcloud_status.sync_status,
                             dccommon_consts.SYNC_STATUS_UNKNOWN)

        ssm = subcloud_state_manager.SubcloudStateManager()

        # Set the subcloud to online/managed
        db_api.subcloud_update(self.ctx, subcloud.id,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               first_identity_sync_complete=True,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        # Update identity endpoints statuses
        endpoint = dccommon_consts.ENDPOINT_TYPE_IDENTITY
        for original_sync_status in [dccommon_consts.SYNC_STATUS_IN_SYNC,
                                     dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
                                     dccommon_consts.SYNC_STATUS_UNKNOWN]:

            for new_sync_status in [dccommon_consts.SYNC_STATUS_IN_SYNC,
                                    dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
                                    dccommon_consts.SYNC_STATUS_UNKNOWN]:

                # Update identity to the original status
                ssm.update_subcloud_endpoint_status(
                    self.ctx, subcloud_region=subcloud.region_name,
                    endpoint_type=endpoint,
                    sync_status=original_sync_status)

                # Get the count of the trigger already called
                trigger_subcloud_audits = \
                    self.fake_dcmanager_audit_api.trigger_subcloud_audits.call_count

                # Update identity to new status and get the count of the trigger again
                ssm.update_subcloud_endpoint_status(
                    self.ctx, subcloud_region=subcloud.region_name,
                    endpoint_type=endpoint,
                    sync_status=new_sync_status)
                new_trigger_subcloud_audits = \
                    self.fake_dcmanager_audit_api.trigger_subcloud_audits.call_count

                trigger_count = new_trigger_subcloud_audits - \
                    trigger_subcloud_audits

                if original_sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN and \
                   new_sync_status != dccommon_consts.SYNC_STATUS_UNKNOWN:
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
        sm.update_subcloud_sync_endpoint_type(self.ctx, subcloud.region_name,
                                              endpoint_type_list,
                                              openstack_installed)

        # Verify notifying dcorch to add subcloud sync endpoint type
        self.fake_dcorch_api.add_subcloud_sync_endpoint_type.\
            assert_called_once_with(self.ctx, subcloud.region_name,
                                    endpoint_type_list)

        # Verify the subcloud status created for os endpoints
        for endpoint in endpoint_type_list:
            subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint)
            self.assertIsNotNone(subcloud_status)
            self.assertEqual(subcloud_status.sync_status,
                             dccommon_consts.SYNC_STATUS_UNKNOWN)

        # Verify the subcloud openstack_installed was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(updated_subcloud.openstack_installed, True)

        # Test openstack app removed
        openstack_installed = False
        sm.update_subcloud_sync_endpoint_type(self.ctx, subcloud.region_name,
                                              endpoint_type_list,
                                              openstack_installed)
        # Verify notifying dcorch to remove subcloud sync endpoint type
        self.fake_dcorch_api.remove_subcloud_sync_endpoint_type.\
            assert_called_once_with(self.ctx, subcloud.region_name,
                                    endpoint_type_list)

        # Verify the subcloud status is deleted for os endpoints
        for endpoint in endpoint_type_list:
            self.assertRaises(exceptions.SubcloudStatusNotFound,
                              db_api.subcloud_status_get, self.ctx,
                              subcloud.id, endpoint)

        # Verify the subcloud openstack_installed was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(updated_subcloud.openstack_installed, False)

    def test_get_ansible_filename(self):
        filename = cutils.get_ansible_filename('subcloud1',
                                               consts.INVENTORY_FILE_POSTFIX)
        self.assertEqual(filename,
                         f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml')

    def test_compose_install_command(self):
        sm = subcloud_manager.SubcloudManager()
        install_command = sm.compose_install_command(
            'subcloud1',
            f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml',
            FAKE_PREVIOUS_SW_VERSION)
        self.assertEqual(
            install_command,
            [
                'ansible-playbook',
                dccommon_consts.ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK,
                '-i', f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml',
                '--limit', 'subcloud1',
                '-e', f"@{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1/install_values.yml",
                '-e', "install_release_version=%s" % FAKE_PREVIOUS_SW_VERSION
            ]
        )

    @mock.patch('os.path.isfile')
    def test_compose_bootstrap_command(self, mock_isfile):
        mock_isfile.return_value = True
        sm = subcloud_manager.SubcloudManager()
        subcloud_name = base.SUBCLOUD_1['name']
        subcloud_region = base.SUBCLOUD_1['region_name']
        bootstrap_command = sm.compose_bootstrap_command(
            subcloud_name,
            subcloud_region,
            f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml',
            FAKE_PREVIOUS_SW_VERSION)
        self.assertEqual(
            bootstrap_command,
            [
                'ansible-playbook',
                cutils.get_playbook_for_software_version(
                    subcloud_manager.ANSIBLE_SUBCLOUD_PLAYBOOK,
                    FAKE_PREVIOUS_SW_VERSION),
                '-i', f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml',
                '--limit', '%s' % subcloud_name, '-e',
                str("override_files_dir='%s' region_name=%s") %
                (dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_region),
                '-e', "install_release_version=%s" % FAKE_PREVIOUS_SW_VERSION
            ]
        )

    def test_compose_config_command(self):
        sm = subcloud_manager.SubcloudManager()
        fake_payload = {"sysadmin_password": "testpass",
                        "deploy_playbook": "test_playbook.yaml",
                        "deploy_overrides": "test_overrides.yaml",
                        "deploy_chart": "test_chart.yaml",
                        "deploy_config": "subcloud1.yaml"}
        config_command = sm.compose_config_command(
            'subcloud1',
            f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml',
            fake_payload)
        self.assertEqual(
            config_command,
            [
                'ansible-playbook', 'test_playbook.yaml', '-e',
                f'@{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_deploy_values.yml', '-i',
                f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml',
                '--limit', 'subcloud1'
            ]
        )

    @mock.patch('os.path.isfile')
    def test_compose_rehome_command_with_previous_sw_version(self, mock_isfile):
        mock_isfile.return_value = True
        sm = subcloud_manager.SubcloudManager()
        subcloud_name = base.SUBCLOUD_1['name']
        subcloud_region = base.SUBCLOUD_1['region_name']

        rehome_command = sm.compose_rehome_command(
            subcloud_name,
            subcloud_region,
            f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml',
            FAKE_PREVIOUS_SW_VERSION)

        extra_vars = "override_files_dir='%s' region_name=%s" % (
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_region)
        extra_vars += (" validate_keystone_passwords_script='%s'" %
                       subcloud_manager.ANSIBLE_VALIDATE_KEYSTONE_PASSWORD_SCRIPT)

        self.assertEqual(
            rehome_command,
            [
                'ansible-playbook',
                cutils.get_playbook_for_software_version(
                    subcloud_manager.ANSIBLE_SUBCLOUD_REHOME_PLAYBOOK,
                    FAKE_PREVIOUS_SW_VERSION),
                '-i', f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml',
                '--limit', subcloud_name,
                '--timeout', subcloud_manager.REHOME_PLAYBOOK_TIMEOUT,
                '-e', extra_vars
            ]
        )

    @mock.patch('os.path.isfile')
    def test_compose_rehome_command(self, mock_isfile):
        mock_isfile.return_value = True
        sm = subcloud_manager.SubcloudManager()
        subcloud_name = base.SUBCLOUD_1['name']
        subcloud_region = base.SUBCLOUD_1['region_name']

        rehome_command = sm.compose_rehome_command(
            subcloud_name,
            subcloud_region,
            f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml',
            SW_VERSION)

        self.assertEqual(
            rehome_command,
            [
                'ansible-playbook',
                cutils.get_playbook_for_software_version(
                    subcloud_manager.ANSIBLE_SUBCLOUD_REHOME_PLAYBOOK,
                    SW_VERSION),
                '-i', f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_inventory.yml',
                '--limit', subcloud_name,
                '--timeout', subcloud_manager.REHOME_PLAYBOOK_TIMEOUT,
                '-e', str("override_files_dir='%s' region_name=%s") %
                (dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud_region)
            ]
        )

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_addn_hosts_dc')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(cutils, 'get_oam_addresses')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_subcloud_install')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_prepare_for_deployment')
    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(subcloud_manager, 'keyring')
    @mock.patch.object(cutils, 'get_playbook_for_software_version')
    @mock.patch.object(cutils, 'update_values_on_yaml_file')
    @mock.patch.object(AnsiblePlaybook, 'run_playbook')
    def test_subcloud_redeploy(self, mock_run_playbook, mock_update_yml,
                               mock_get_playbook_for_software_version,
                               mock_keyring, create_subcloud_inventory,
                               mock_prepare_for_deployment,
                               mock_run_subcloud_install,
                               mock_oam_address, mock_keystone_client,
                               mock_create_addn_hosts):

        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_get_playbook_for_software_version.return_value = "22.12"
        mock_keyring.get_password.return_value = "testpass"
        mock_run_playbook.return_value = False
        mock_run_subcloud_install.return_value = True

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_CREATED)

        fake_install_values = \
            copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        fake_install_values['software_version'] = SW_VERSION
        fake_payload_install = {'bmc_password': 'bmc_pass',
                                'install_values': fake_install_values,
                                'software_version': SW_VERSION,
                                'sysadmin_password': 'sys_pass'}

        fake_payload_bootstrap = {**fake_subcloud.FAKE_BOOTSTRAP_VALUE,
                                  **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA}
        fake_payload_bootstrap["sysadmin_password"] = "testpass"

        fake_payload_config = {"sysadmin_password": "testpass",
                               "deploy_playbook": "test_playbook.yaml",
                               "deploy_overrides": "test_overrides.yaml",
                               "deploy_chart": "test_chart.yaml",
                               "deploy_config": "subcloud1.yaml"}

        fake_payload = {**fake_payload_install,
                        **fake_payload_bootstrap,
                        **fake_payload_config}

        sm = subcloud_manager.SubcloudManager()
        sm.redeploy_subcloud(self.ctx, subcloud.id, fake_payload)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx,
                                                       subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE,
                         updated_subcloud.deploy_status)

    def test_handle_subcloud_operations_in_progress(self):
        subcloud1 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_1['name'],
            region_name=base.SUBCLOUD_1['region_name'],
            deploy_status=consts.DEPLOY_STATE_PRE_DEPLOY)
        subcloud2 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_2['name'],
            region_name=base.SUBCLOUD_2['region_name'],
            deploy_status=consts.DEPLOY_STATE_PRE_INSTALL)
        subcloud3 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_3['name'],
            region_name=base.SUBCLOUD_3['region_name'],
            deploy_status=consts.DEPLOY_STATE_INSTALLING)
        subcloud4 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_4['name'],
            region_name=base.SUBCLOUD_4['region_name'],
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING)
        subcloud5 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_5['name'],
            region_name=base.SUBCLOUD_5['region_name'],
            deploy_status=consts.DEPLOY_STATE_DEPLOYING)
        subcloud6 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_6['name'],
            region_name=base.SUBCLOUD_6['region_name'],
            deploy_status=consts.DEPLOY_STATE_MIGRATING_DATA)
        subcloud7 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_7['name'],
            region_name=base.SUBCLOUD_7['region_name'],
            deploy_status=consts.DEPLOY_STATE_PRE_RESTORE)
        subcloud8 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_8['name'],
            region_name=base.SUBCLOUD_8['region_name'],
            deploy_status=consts.DEPLOY_STATE_RESTORING)
        subcloud9 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_9['name'],
            region_name=base.SUBCLOUD_9['region_name'],
            deploy_status=consts.DEPLOY_STATE_NONE)
        subcloud10 = self.create_subcloud_static(
            self.ctx,
            name='subcloud10',
            deploy_status=consts.DEPLOY_STATE_CREATING)
        subcloud11 = self.create_subcloud_static(
            self.ctx,
            name='subcloud11',
            deploy_status=consts.DEPLOY_STATE_PRE_BOOTSTRAP)
        subcloud12 = self.create_subcloud_static(
            self.ctx,
            name='subcloud12',
            deploy_status=consts.DEPLOY_STATE_ABORTING_INSTALL)
        subcloud13 = self.create_subcloud_static(
            self.ctx,
            name='subcloud13',
            deploy_status=consts.DEPLOY_STATE_ABORTING_BOOTSTRAP)
        subcloud14 = self.create_subcloud_static(
            self.ctx,
            name='subcloud14',
            deploy_status=consts.DEPLOY_STATE_ABORTING_CONFIG)

        sm = subcloud_manager.SubcloudManager()
        sm.handle_subcloud_operations_in_progress()

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud1.name)
        self.assertEqual(consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
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
        self.assertEqual(consts.DEPLOY_STATE_CONFIG_FAILED,
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
        self.assertEqual(consts.DEPLOY_STATE_CREATE_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud10.name)
        self.assertEqual(consts.DEPLOY_STATE_CREATE_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud11.name)
        self.assertEqual(consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud12.name)
        self.assertEqual(consts.DEPLOY_STATE_INSTALL_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud13.name)
        self.assertEqual(consts.DEPLOY_STATE_BOOTSTRAP_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud14.name)
        self.assertEqual(consts.DEPLOY_STATE_CONFIG_FAILED,
                         subcloud.deploy_status)

    def test_handle_completed_subcloud_operations(self):
        subcloud1 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_1['name'],
            region_name=base.SUBCLOUD_1['region_name'],
            deploy_status=consts.DEPLOY_STATE_CREATE_FAILED)
        subcloud2 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_2['name'],
            region_name=base.SUBCLOUD_2['region_name'],
            deploy_status=consts.DEPLOY_STATE_PRE_INSTALL_FAILED)
        subcloud3 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_3['name'],
            region_name=base.SUBCLOUD_3['region_name'],
            deploy_status=consts.DEPLOY_STATE_INSTALL_FAILED)
        subcloud4 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_4['name'],
            region_name=base.SUBCLOUD_4['region_name'],
            deploy_status=consts.DEPLOY_STATE_INSTALLED)
        subcloud5 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_5['name'],
            region_name=base.SUBCLOUD_5['region_name'],
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED)
        subcloud6 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_6['name'],
            region_name=base.SUBCLOUD_6['region_name'],
            deploy_status=consts.DEPLOY_STATE_CONFIG_FAILED)
        subcloud7 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_7['name'],
            region_name=base.SUBCLOUD_7['region_name'],
            deploy_status=consts.DEPLOY_STATE_DATA_MIGRATION_FAILED)
        subcloud8 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_8['name'],
            region_name=base.SUBCLOUD_8['region_name'],
            deploy_status=consts.DEPLOY_STATE_MIGRATED)
        subcloud9 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_9['name'],
            region_name=base.SUBCLOUD_9['region_name'],
            deploy_status=consts.DEPLOY_STATE_RESTORE_PREP_FAILED)
        subcloud10 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_10['name'],
            region_name=base.SUBCLOUD_10['region_name'],
            deploy_status=consts.DEPLOY_STATE_RESTORE_FAILED)
        subcloud11 = self.create_subcloud_static(
            self.ctx,
            name=base.SUBCLOUD_11['name'],
            region_name=base.SUBCLOUD_11['region_name'],
            deploy_status=consts.DEPLOY_STATE_DONE)
        subcloud12 = self.create_subcloud_static(
            self.ctx,
            name='subcloud12',
            deploy_status=consts.DEPLOY_STATE_CREATE_FAILED)
        subcloud13 = self.create_subcloud_static(
            self.ctx,
            name='subcloud13',
            deploy_status=consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED)
        subcloud14 = self.create_subcloud_static(
            self.ctx,
            name='subcloud14',
            deploy_status=consts.DEPLOY_STATE_PRE_CONFIG_FAILED)

        sm = subcloud_manager.SubcloudManager()
        sm.handle_subcloud_operations_in_progress()

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud1.name)
        self.assertEqual(consts.DEPLOY_STATE_CREATE_FAILED,
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
        self.assertEqual(consts.DEPLOY_STATE_CONFIG_FAILED,
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

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud12.name)
        self.assertEqual(consts.DEPLOY_STATE_CREATE_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud13.name)
        self.assertEqual(consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED,
                         subcloud.deploy_status)

        subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud14.name)
        self.assertEqual(consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
                         subcloud.deploy_status)

    @mock.patch.object(cutils, 'is_subcloud_healthy', return_value=True)
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_subcloud_backup_create_playbook')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_set_subcloud_backup_failure_alarm')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_clear_subcloud_backup_failure_alarm_if_exists')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_overrides_for_backup_or_restore')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_subcloud_inventory_file')
    def test_backup_create_managed_online(
        self, mock_create_inventory_file, mock_create_overrides,
        mock_clear_alarm, mock_set_alarm, mock_run_playbook, mock_is_healthy,
    ):
        mock_create_inventory_file.return_value = 'inventory_file.yml'
        mock_create_overrides.return_value = 'overrides_file.yml'

        values = copy.copy(FAKE_BACKUP_CREATE_LOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        sm = subcloud_manager.SubcloudManager()
        sm.create_subcloud_backups(self.ctx, payload=values)

        mock_create_inventory_file.assert_called_once()
        mock_create_overrides.assert_called_once()
        mock_clear_alarm.assert_called_once()
        mock_set_alarm.assert_not_called()
        mock_run_playbook.assert_called_once()
        mock_is_healthy.assert_called_once()

        # Verify that subcloud has the correct deploy status consts.PRESTAGE_STATE_PACKAGES
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_PRE_BACKUP,
                         updated_subcloud.backup_status)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_parallel_group_operation')
    def test_backup_create_unmanaged_online(self, mock_parallel_group_operation):

        values = copy.copy(FAKE_BACKUP_CREATE_LOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_NONE)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        sm = subcloud_manager.SubcloudManager()
        sm.create_subcloud_backups(self.ctx, payload=values)

        mock_parallel_group_operation.assert_called_once()

        # Verify that subcloud has the correct deploy status consts.PRESTAGE_STATE_PACKAGES
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_VALIDATE_FAILED,
                         updated_subcloud.backup_status)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_parallel_group_operation')
    def test_backup_create_unmanaged_offline(self, mock_parallel_group_operation):

        values = copy.copy(FAKE_BACKUP_CREATE_LOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_NONE)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        sm = subcloud_manager.SubcloudManager()
        sm.create_subcloud_backups(self.ctx, payload=values)

        mock_parallel_group_operation.assert_called_once()

        # Verify that subcloud has the correct deploy status consts.PRESTAGE_STATE_PACKAGES
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_VALIDATE_FAILED,
                         updated_subcloud.backup_status)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_parallel_group_operation')
    def test_backup_create_managed_offline(self, mock_parallel_group_operation):

        values = copy.copy(FAKE_BACKUP_CREATE_LOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_NONE)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        sm = subcloud_manager.SubcloudManager()
        sm.create_subcloud_backups(self.ctx, payload=values)

        mock_parallel_group_operation.assert_called_once()

        # Verify that subcloud has the correct deploy status consts.PRESTAGE_STATE_PACKAGES
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_VALIDATE_FAILED,
                         updated_subcloud.backup_status)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_parallel_group_operation')
    def test_backup_delete_managed_online(self, mock_parallel_group_operation):

        release_version = '22.12'
        values = copy.copy(FAKE_BACKUP_DELETE_LOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_NONE)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        sm = subcloud_manager.SubcloudManager()
        sm.delete_subcloud_backups(self.ctx, payload=values, release_version=release_version)

        mock_parallel_group_operation.assert_called_once()

        # Verify that subcloud has the correct deploy status consts.PRESTAGE_STATE_PACKAGES
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_UNKNOWN,
                         updated_subcloud.backup_status)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_parallel_group_operation')
    def test_backup_delete_managed_local_online(self, mock_parallel_group_operation):

        release_version = '22.12'
        values = copy.copy(FAKE_BACKUP_DELETE_LOCAL_LOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_NONE)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        sm = subcloud_manager.SubcloudManager()
        sm.delete_subcloud_backups(self.ctx, payload=values, release_version=release_version)

        mock_parallel_group_operation.assert_called_once()

        # Verify that subcloud has the correct deploy status consts.PRESTAGE_STATE_PACKAGES
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_UNKNOWN,
                         updated_subcloud.backup_status)

    @mock.patch.object(cutils, 'is_subcloud_healthy', return_value=True)
    @mock.patch.object(cutils, 'delete_subcloud_inventory')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_backup_overrides_file')
    @mock.patch.object(subcloud_manager, 'keyring')
    @mock.patch.object(cutils, 'get_oam_addresses')
    @mock.patch.object(subcloud_manager.AnsiblePlaybook, 'run_playbook')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_clear_subcloud_backup_failure_alarm_if_exists')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       'compose_backup_command')
    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    def test_backup_create_subcloud(
        self, mock_keystone_client,
        mock_create_subcloud_inventory, mock_compose_backup_command,
        mock_clear_subcloud_failure_alarm, mock_run_playbook,
        mock_oam_address, mock_keyring, mock_create_backup_file,
        mock_delete_subcloud_inventory, mock_is_healthy):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.BACKUP_STATE_UNKNOWN)

        values = copy.copy(FAKE_BACKUP_CREATE_LOAD_1)

        override_file = os_path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud.name + "_backup_create_values.yml"
        )
        mock_create_backup_file.return_value = override_file

        sm = subcloud_manager.SubcloudManager()
        sm._backup_subcloud(self.ctx, payload=values, subcloud=subcloud)

        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_create_subcloud_inventory.assert_called_once()
        mock_oam_address.return_value = FAKE_OAM_FLOATING_IP
        mock_keyring.get_password.return_value = "testpassword"
        mock_keyring.get_password.assert_called()

        mock_create_backup_file.assert_called_once()
        mock_run_playbook.assert_called_once()
        mock_is_healthy.assert_called_once()

        mock_compose_backup_command.assert_called_once()
        mock_clear_subcloud_failure_alarm.assert_called_once()

        mock_delete_subcloud_inventory.assert_called_once_with(override_file)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_COMPLETE_CENTRAL,
                         updated_subcloud.backup_status)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_subcloud_inventory_file')
    def test_backup_create_subcloud_fail_to_create(
        self, mock_create_subcloud_inventory_file):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.BACKUP_STATE_UNKNOWN)

        values = copy.copy(FAKE_BACKUP_CREATE_LOAD_1)

        sm = subcloud_manager.SubcloudManager()
        sm._backup_subcloud(self.ctx, payload=values, subcloud=subcloud)

        mock_create_subcloud_inventory_file.side_effect = Exception(
            'FakeFailure')

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_PREP_FAILED,
                         updated_subcloud.backup_status)

    @mock.patch.object(cutils, 'delete_subcloud_inventory')
    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(cutils, 'get_oam_addresses')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(subcloud_manager.AnsiblePlaybook, 'run_playbook')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       'compose_backup_delete_command')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_backup_overrides_file')
    def test_delete_subcloud_backup(
        self, mock_create_backup_overrides_file,
        mock_compose_backup_delete_command,
        mock_run_playbook, mock_keystone_client,
        mock_oam_address, mock_create_subcloud_inventory,
        mock_delete_subcloud_inventory):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.BACKUP_STATE_COMPLETE_CENTRAL)

        values = copy.copy(FAKE_BACKUP_DELETE_LOAD_1)
        RELEASE_VERSION = '22.12'

        override_file = os_path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud.name + "_backup_delete_values.yml"
        )
        mock_create_backup_overrides_file.return_value = override_file

        sm = subcloud_manager.SubcloudManager()
        sm._delete_subcloud_backup(
            self.ctx, payload=values, release_version=RELEASE_VERSION, subcloud=subcloud)

        mock_create_backup_overrides_file.assert_called_once()
        mock_compose_backup_delete_command.assert_called_once()
        mock_run_playbook.assert_called_once()
        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_oam_address.return_value = FAKE_OAM_FLOATING_IP
        mock_create_subcloud_inventory.assert_not_called()
        mock_delete_subcloud_inventory.assert_called_once_with(override_file)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_UNKNOWN,
                         updated_subcloud.backup_status)

    @mock.patch.object(cutils, 'delete_subcloud_inventory')
    @mock.patch.object(cutils, 'create_subcloud_inventory')
    @mock.patch.object(cutils, 'get_oam_addresses')
    @mock.patch.object(subcloud_manager, 'OpenStackDriver')
    @mock.patch.object(AnsiblePlaybook, 'run_playbook')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       'compose_backup_delete_command')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_backup_overrides_file')
    def test_delete_subcloud_backup_local_only(
            self, mock_create_subcloud_inventory_file,
            mock_compose_backup_delete_command,
            mock_run_playbook, mock_keystone_client,
            mock_oam_address, mock_create_subcloud_inventory,
            mock_delete_subcloud_inventory):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.BACKUP_STATE_COMPLETE_LOCAL)

        values = copy.copy(FAKE_BACKUP_DELETE_LOAD_1)
        values['local_only'] = True

        RELEASE_VERSION = '22.12'

        override_file = os_path.join(
            dccommon_consts.ANSIBLE_OVERRIDES_PATH, subcloud.name + "_backup_delete_values.yml"
        )
        mock_create_subcloud_inventory_file.return_value = override_file

        sm = subcloud_manager.SubcloudManager()
        sm._delete_subcloud_backup(
            self.ctx, payload=values, release_version=RELEASE_VERSION, subcloud=subcloud)

        mock_create_subcloud_inventory_file.assert_called_once()
        mock_compose_backup_delete_command.assert_called_once()
        mock_run_playbook.assert_called_once()
        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_oam_address.return_value = FAKE_OAM_FLOATING_IP
        mock_create_subcloud_inventory.assert_called_once()
        mock_delete_subcloud_inventory.assert_called_once_with(override_file)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_UNKNOWN,
                         updated_subcloud.backup_status)

    @mock.patch.object(threading.Thread, 'start')
    def test_prestage_no_subcloud(self, mock_thread_start):
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

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(cutils, 'get_filename_by_prefix')
    @mock.patch.object(prestage, '_run_ansible')
    def test_prestage_remote_pass_with_img_list(self, mock_run_ansible,
                                                mock_get_filename_by_prefix,
                                                mock_isdir):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        subcloud = self.create_subcloud_static(self.ctx,
                                               name='subcloud1',
                                               deploy_status=consts.DEPLOY_STATE_NONE,
                                               software_version=FAKE_SUBCLOUD_SW_VERSION)

        mock_run_ansible.return_value = None
        mock_get_filename_by_prefix.return_value = 'prestage_images_list.txt'
        mock_isdir.return_value = True
        prestage._prestage_standalone_thread(self.ctx, subcloud, payload=values)

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.PRESTAGE_STATE_COMPLETE,
                         updated_subcloud.deploy_status)

        # Verify both of prestage package and image ansible playbooks were called
        self.assertEqual(mock_run_ansible.call_count, 2)
        # Verify the "image_list_file" was passed to the prestage image playbook
        # for the remote prestage
        self.assertIn('image_list_file', mock_run_ansible.call_args_list[1].args[1][5])
        # Verify the prestage request release was passed to the playbooks
        self.assertIn(FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[0].args[1][5])
        self.assertIn(FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[1].args[1][5])

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(cutils, 'get_filename_by_prefix')
    @mock.patch.object(prestage, '_run_ansible')
    def test_prestage_remote_pass_without_img_list(self, mock_run_ansible,
                                                   mock_get_filename_by_prefix,
                                                   mock_isdir):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        subcloud = self.create_subcloud_static(self.ctx,
                                               name='subcloud1',
                                               deploy_status=consts.DEPLOY_STATE_NONE,
                                               software_version=FAKE_SUBCLOUD_SW_VERSION)

        mock_run_ansible.return_value = None
        mock_get_filename_by_prefix.return_value = None
        mock_isdir.return_value = True
        prestage._prestage_standalone_thread(self.ctx, subcloud, payload=values)

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.PRESTAGE_STATE_COMPLETE,
                         updated_subcloud.deploy_status)

        # Verify that only prestage package playbook is called
        self.assertEqual(mock_run_ansible.call_count, 1)

        # Verify the prestage request release was passed to the playbooks
        self.assertTrue(
            FAKE_PRESTAGE_RELEASE in mock_run_ansible.call_args_list[0].args[1][5])

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(cutils, 'get_filename_by_prefix')
    @mock.patch.object(prestage, '_run_ansible')
    def test_prestage_local_pass_with_img_list(self, mock_run_ansible,
                                               mock_get_filename_by_prefix,
                                               mock_isdir):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        subcloud = self.create_subcloud_static(self.ctx,
                                               name='subcloud1',
                                               deploy_status=consts.DEPLOY_STATE_NONE,
                                               software_version=FAKE_PRESTAGE_RELEASE)

        mock_run_ansible.return_value = None
        mock_get_filename_by_prefix.return_value = 'prestage_images_list.txt'
        mock_isdir.return_value = True
        prestage._prestage_standalone_thread(self.ctx, subcloud, payload=values)

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.PRESTAGE_STATE_COMPLETE,
                         updated_subcloud.deploy_status)

        # Verify both of prestage package and image ansible playbooks were called
        self.assertEqual(mock_run_ansible.call_count, 2)
        # Verify the "image_list_file" was passed to the prestage image playbook
        # for the local prestage
        self.assertTrue(
            'image_list_file' in mock_run_ansible.call_args_list[1].args[1][5])
        # Verify the prestage request release was passed to the playbooks
        self.assertTrue(
            FAKE_PRESTAGE_RELEASE in mock_run_ansible.call_args_list[0].args[1][5])
        self.assertTrue(
            FAKE_PRESTAGE_RELEASE in mock_run_ansible.call_args_list[1].args[1][5])

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(cutils, 'get_filename_by_prefix')
    @mock.patch.object(prestage, '_run_ansible')
    def test_prestage_local_pass_without_img_list(self, mock_run_ansible,
                                                  mock_get_filename_by_prefix,
                                                  mock_isdir):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        subcloud = self.create_subcloud_static(self.ctx,
                                               name='subcloud1',
                                               deploy_status=consts.DEPLOY_STATE_NONE,
                                               software_version=FAKE_PRESTAGE_RELEASE)

        mock_run_ansible.return_value = None
        mock_get_filename_by_prefix.return_value = None
        mock_isdir.return_value = True
        prestage._prestage_standalone_thread(self.ctx, subcloud, payload=values)

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.PRESTAGE_STATE_COMPLETE,
                         updated_subcloud.deploy_status)

        # Verify both of prestage package and image ansible playbooks were called
        self.assertEqual(mock_run_ansible.call_count, 2)
        # Verify the "image_list_file" was not passed to the prestage image playbook
        # for the local prestage
        self.assertTrue(
            'image_list_file' not in mock_run_ansible.call_args_list[1].args[1][5])
        # Verify the prestage request release was passed to the playbooks
        self.assertIn(FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[0].args[1][5])
        self.assertIn(FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[1].args[1][5])

    @mock.patch.object(prestage, 'prestage_images')
    @mock.patch.object(prestage, 'prestage_packages')
    @mock.patch.object(cutils, 'delete_subcloud_inventory')
    @mock.patch.object(prestage, '_run_ansible')
    def test_prestage_subcloud_complete(self,
                                        mock_run_ansible,
                                        mock_delete_subcloud_inventory,
                                        mock_prestage_packages,
                                        mock_prestage_images):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        subcloud = self.create_subcloud_static(self.ctx,
                                               name='subcloud1',
                                               deploy_status=consts.DEPLOY_STATE_NONE)
        prestage._prestage_standalone_thread(self.ctx, subcloud, payload=values)
        mock_run_ansible.return_value = None
        mock_prestage_packages.assert_called_once_with(self.ctx, subcloud, values)
        mock_prestage_images.assert_called_once_with(self.ctx, subcloud, values)
        mock_delete_subcloud_inventory.return_value = None

        # Verify that subcloud has the "prestage-complete" deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.PRESTAGE_STATE_COMPLETE,
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
        self.assertEqual(cached_regionone_data['mgmt_pool'].floating_address,
                         FAKE_MGMT_FLOATING_ADDRESS)
        self.assertEqual(cached_regionone_data['oam_addresses'].oam_floating_ip,
                         FAKE_OAM_FLOATING_IP)
        # The expiry timestamp is likely a couple of seconds less than the time
        # the cache is set when it gets here so check if the expiry is greater than
        # 59m55s from now.
        self.assertGreater(cached_regionone_data['expiry'],
                           datetime.datetime.utcnow() + datetime.timedelta(seconds=3595))
        cached_regionone_data = sm._get_cached_regionone_data(
            mock_keystone_client, mock_sysinv_client)
        expiry2 = cached_regionone_data['expiry']
        self.assertEqual(expiry1, expiry2)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_subcloud_backup_restore_playbook')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_overrides_for_backup_or_restore')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_subcloud_inventory_file')
    def test_backup_restore_unmanaged_online(self,
                                             mock_create_inventory_file,
                                             mock_create_overrides,
                                             mock_run_playbook
                                             ):
        mock_create_inventory_file.return_value = 'inventory_file.yml'
        mock_create_overrides.return_value = 'overrides_file.yml'

        values = copy.copy(FAKE_BACKUP_RESTORE_LOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)

        data_install = str(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES).replace('\'', '"')

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               data_install=data_install)

        sm = subcloud_manager.SubcloudManager()
        sm.restore_subcloud_backups(self.ctx, payload=values)

        mock_create_inventory_file.assert_called_once()
        mock_create_overrides.assert_called_once()
        mock_run_playbook.assert_called_once()

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_PRE_RESTORE,
                         updated_subcloud.deploy_status)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_subcloud_backup_restore_playbook')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_overrides_for_backup_or_restore')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_subcloud_inventory_file')
    def test_backup_restore_managed_online(self,
                                           mock_create_inventory_file,
                                           mock_create_overrides,
                                           mock_run_playbook
                                           ):

        values = copy.copy(FAKE_BACKUP_RESTORE_LOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_NONE)

        data_install = str(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES).replace('\'', '"')

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               data_install=data_install)

        sm = subcloud_manager.SubcloudManager()
        return_log = sm.restore_subcloud_backups(self.ctx, payload=values)

        expected_log = 'skipped for local backup restore operation'

        self.assertIn(expected_log, return_log)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_subcloud_backup_restore_playbook')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_overrides_for_backup_or_restore')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_subcloud_inventory_file')
    def test_backup_restore_unmanaged_offline(self,
                                              mock_create_inventory_file,
                                              mock_create_overrides,
                                              mock_run_playbook
                                              ):

        values = copy.copy(FAKE_BACKUP_RESTORE_LOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_NONE)

        data_install = str(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES).replace('\'', '"')

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               data_install=data_install)

        sm = subcloud_manager.SubcloudManager()
        sm.restore_subcloud_backups(self.ctx, payload=values)

        mock_create_inventory_file.assert_called_once()
        mock_create_overrides.assert_called_once()
        mock_run_playbook.assert_called_once()

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_PRE_RESTORE,
                         updated_subcloud.deploy_status)

    def test_backup_restore_managed_offline(self):

        values = copy.copy(FAKE_BACKUP_RESTORE_LOAD)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_NONE)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED)

        sm = subcloud_manager.SubcloudManager()
        return_log = sm.restore_subcloud_backups(self.ctx, payload=values)

        expected_log = 'skipped for local backup restore operation'

        self.assertIn(expected_log, return_log)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_subcloud_backup_restore_playbook')
    @mock.patch.object(subcloud_manager.SubcloudManager, '_run_subcloud_install')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_overrides_for_backup_or_restore')
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_create_subcloud_inventory_file')
    @mock.patch('os.path.isdir')
    @mock.patch('os.listdir')
    def test_backup_restore_with_install(self,
                                         mock_listdir,
                                         mock_isdir,
                                         mock_create_inventory_file,
                                         mock_create_overrides,
                                         mock_subcloud_install,
                                         mock_run_restore_playbook
                                         ):
        mock_isdir.return_value = True
        mock_listdir.return_value = ['test.iso', 'test.sig']
        mock_create_inventory_file.return_value = 'inventory_file.yml'
        mock_create_overrides.return_value = 'overrides_file.yml'
        mock_subcloud_install.return_value = True
        mock_run_restore_playbook.return_value = True

        data_install = str(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES).replace('\'', '"')

        values = copy.copy(FAKE_BACKUP_RESTORE_LOAD_WITH_INSTALL)
        values['with_install'] = True
        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            data_install=data_install,
            deploy_status=consts.DEPLOY_STATE_DONE)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED)

        sm = subcloud_manager.SubcloudManager()
        sm.restore_subcloud_backups(self.ctx, payload=values)

        mock_create_inventory_file.assert_called_once()
        mock_create_overrides.assert_called_once()

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_PRE_RESTORE,
                         updated_subcloud.deploy_status)

    @mock.patch.object(subcloud_manager, 'db_api', side_effect=db_api)
    @mock.patch.object(subcloud_manager.SubcloudManager,
                       'subcloud_migrate_generate_ansible_config')
    @mock.patch.object(subcloud_manager.SubcloudManager, 'rehome_subcloud')
    def test_migrate_subcloud(self, mock_rehome_subcloud,
                              mock_subcloud_migrate_generate_ansible_config,
                              mock_db_api):
        # Prepare the test data
        subcloud = self.create_subcloud_static(self.ctx)
        saved_payload = {
            "name": subcloud.name,
            "deploy_status": "secondary",
            "rehome_data": '{"saved_payload": {"system_mode": "simplex",\
            "name": "testsub", "bootstrap-address": "128.224.119.56"}}',
        }
        payload = {
            "sysadmin_password": "TGk2OW51eA=="
        }
        payload_result = {
            "name": subcloud.name,
            "deploy_status": "secondary",
            "rehome_data": {
                "saved_payload": {
                    "system_mode": "simplex",
                    "name": "testsub",
                    "bootstrap-address": "128.224.119.56",
                    "sysadmin_password": "Li69nux"
                }
            },
        }
        sm = subcloud_manager.SubcloudManager()
        db_api.subcloud_update(self.ctx, subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_SECONDARY,
                               rehome_data=saved_payload['rehome_data'])
        sm.migrate_subcloud(self.ctx, subcloud.id, payload)

        mock_subcloud_migrate_generate_ansible_config.assert_called_once_with(
            mock.ANY, mock.ANY, payload_result['rehome_data']['saved_payload'])
        mock_rehome_subcloud.assert_called_once_with(mock.ANY, mock.ANY)

        self.assertFalse(mock_db_api.subcloud_update.called)

    @mock.patch.object(subcloud_manager.SubcloudManager,
                       '_run_parallel_group_operation')
    def test_batch_migrate_subcloud(self, mock_run_parallel_group_operation):
        # Prepare the test data
        subcloud_pg = self.create_subcloud_peer_group_static(self.ctx)
        rehome_data = '{"saved_payload": {"system_mode": "simplex",\
            "name": "test_sub_migrate", "bootstrap-address": "128.224.119.56"}}'
        payload = {
            "sysadmin_password": "TGk2OW51eA==",
            "peer_group": subcloud_pg.peer_group_name
        }
        sm = subcloud_manager.SubcloudManager()
        subcloud = self.create_subcloud_static(
            self.ctx,
            name="sub_migrateable",
            deploy_status=consts.DEPLOY_STATE_SECONDARY
            )
        db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            peer_group_id=subcloud_pg.id,
            rehome_data=rehome_data,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name="sub_no_rehome_data",
            deploy_status=consts.DEPLOY_STATE_SECONDARY
            )
        db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            peer_group_id=subcloud_pg.id,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name="sub_no_secondary"
            )
        db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            peer_group_id=subcloud_pg.id,
            rehome_data=rehome_data,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED)
        subcloud = self.create_subcloud_static(
            self.ctx,
            name="sub_no_saved_payload"
            )
        db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            peer_group_id=subcloud_pg.id,
            rehome_data="{}",
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED)

        sm.batch_migrate_subcloud(self.ctx, payload)
        mock_run_parallel_group_operation.assert_called_with(
            "migrate", mock.ANY, mock.ANY, mock.ANY)
        actual_args, _ = mock_run_parallel_group_operation.call_args
        expect_subclouds = actual_args[3]
        self.assertEqual(1, len(expect_subclouds))
        self.assertEqual("sub_migrateable", expect_subclouds[0].name)

    @mock.patch.object(subcloud_manager.SubcloudManager, 'subcloud_deploy_create')
    @mock.patch.object(subcloud_manager.SubcloudManager, 'rehome_subcloud')
    @mock.patch.object(subcloud_manager.SubcloudManager, 'run_deploy_phases')
    @mock.patch.object(subcloud_manager, 'db_api')
    def test_add_subcloud_with_secondary_option(self, mock_db_api,
                                                mock_run_deploy_phases,
                                                mock_rehome_subcloud,
                                                mock_subcloud_deploy_create):
        # Prepare the test data
        values = {
            'name': 'TestSubcloud',
            'sysadmin_password': '123',
            'secondary': 'true',
            'region_name': '2ec93dfb654846909efe61d1b39dd2ce'
        }

        # Create an instance of SubcloudManager
        sm = subcloud_manager.SubcloudManager()

        # Call add_subcloud method with the test data
        sm.add_subcloud(mock.MagicMock(), 1, values)

        # Assert that the rehome_subcloud and run_deploy_phases methods were not called
        mock_rehome_subcloud.assert_not_called()
        mock_run_deploy_phases.assert_not_called()

        mock_subcloud_deploy_create.assert_called_once()

        # Assert that db_api.subcloud_update was not called for secondary subcloud
        self.assertFalse(mock_db_api.subcloud_update.called)

    def test_update_subcloud_bootstrap_values(self):

        fake_bootstrap_values = "{'name': 'TestSubcloud', 'system_mode': 'simplex'}"
        fake_result = '{"saved_payload": {"name": "TestSubcloud", "system_mode": "simplex"}}'

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           bootstrap_values=fake_bootstrap_values)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(fake_result,
                         updated_subcloud.rehome_data)

    def test_update_subcloud_bootstrap_address(self):
        fake_bootstrap_values = '{"name": "TestSubcloud", "system_mode": "simplex"}'
        fake_result = ('{"saved_payload": {"name": "TestSubcloud", '
                       '"system_mode": "simplex", '
                       '"bootstrap-address": "123.123.123.123"}}')

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           bootstrap_values=fake_bootstrap_values)
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           bootstrap_address="123.123.123.123")

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(fake_result,
                         updated_subcloud.rehome_data)

    @mock.patch('os.remove')
    @mock.patch('shutil.rmtree')
    @mock.patch.object(os_path, 'exists')
    def test_cleanup_ansible_files(self, moch_path_exists, mock_rmtree, mock_remove):
        moch_path_exists.return_value = True

        sm = subcloud_manager.SubcloudManager()
        sm._cleanup_ansible_files('subcloud1')

        files = ('subcloud1.yml',
                 'subcloud1_deploy_values.yml',
                 'subcloud1_deploy_config.yml')

        calls = []
        for f in files:
            filepath = os.path.join(dccommon_consts.ANSIBLE_OVERRIDES_PATH, f)
            calls.append(mock.call(filepath))

        install_dir = os.path.join(dccommon_consts.ANSIBLE_OVERRIDES_PATH,
                                   'subcloud1')

        mock_remove.assert_has_calls(calls, any_order=True)
        mock_rmtree.assert_called_with(install_dir)

    def test_update_subcloud_peer_group_id(self):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        fake_peer_group_id = 123

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           peer_group_id=fake_peer_group_id)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(fake_peer_group_id,
                         updated_subcloud.peer_group_id)

    def test_update_subcloud_peer_group_id_to_none(self):

        subcloud = self.create_subcloud_static(
            self.ctx,
            name='subcloud1',
            deploy_status=consts.DEPLOY_STATE_DONE)
        fake_peer_group_id = 123

        fake_dcmanager_cermon_api = FakeDCManagerNotifications()

        p = mock.patch('dcmanager.rpc.client.DCManagerNotifications')
        mock_dcmanager_api = p.start()
        mock_dcmanager_api.return_value = fake_dcmanager_cermon_api

        sm = subcloud_manager.SubcloudManager()
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           peer_group_id=fake_peer_group_id)
        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(fake_peer_group_id,
                         updated_subcloud.peer_group_id)
        sm.update_subcloud(self.ctx,
                           subcloud.id,
                           peer_group_id='NoNe')
        # Verify subcloud was updated to None
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(None,
                         updated_subcloud.peer_group_id)
