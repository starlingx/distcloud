# Copyright (c) 2017-2025 Wind River Systems, Inc.
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

import base64
import builtins
import collections
import copy
import datetime
import filecmp
import json
import os
from os import path as os_path
import shutil
import sys
import tempfile
import threading
import time
from urllib import request
import uuid
import yaml

from eventlet.green import subprocess
import mock
import netaddr
from oslo_concurrency import lockutils
from oslo_utils import timeutils
from oslo_utils import uuidutils
from tsconfig.tsconfig import SW_VERSION

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import dcmanager_v1
from dccommon.endpoint_cache import EndpointCache
from dccommon.exceptions import PlaybookExecutionFailed
from dccommon.exceptions import PlaybookExecutionTimeout
from dccommon import kubeoperator
from dccommon import ostree_mount
from dccommon import subcloud_enrollment
from dccommon import subcloud_install
from dccommon.utils import AnsiblePlaybook
from dcmanager.audit import rpcapi
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import prestage
from dcmanager.common import utils as cutils
from dcmanager.db import api as db_api
from dcmanager.manager import subcloud_manager
from dcmanager.manager import system_peer_manager
from dcmanager.rpc import client as rpc_client
from dcmanager.state import subcloud_state_manager
from dcmanager.tests import base
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests.unit.db import test_subcloud_alarms
from dcmanager.tests.unit.manager import test_system_peer_manager
from dcmanager.tests import utils
from dcorch.rpc import client as dcorch_rpc_client

sys.modules["fm_core"] = mock.Mock()

ANS_PATH = dccommon_consts.ANSIBLE_OVERRIDES_PATH
FAKE_PREVIOUS_SW_VERSION = "21.12"
FAKE_SW_VERSION = "22.12"
FAKE_ADMIN_USER_ID = 1
FAKE_SYSINV_USER_ID = 2
FAKE_DCMANAGER_USER_ID = 3
FAKE_ADMIN_PROJECT_ID = 1
FAKE_SERVICE_PROJECT_ID = 2


class FakeEndpoint(object):
    def __init__(self, endpoint_name, region, service_id):
        self.endpoint_name = endpoint_name
        self.region = region
        self.service_id = service_id


class FakeUser(object):
    def __init__(self, name, id):
        self.name = name
        self.id = id


FAKE_USERS = [
    FakeUser(dccommon_consts.ADMIN_USER_NAME, FAKE_ADMIN_USER_ID),
    FakeUser(dccommon_consts.SYSINV_USER_NAME, FAKE_SYSINV_USER_ID),
    FakeUser(dccommon_consts.DCMANAGER_USER_NAME, FAKE_DCMANAGER_USER_ID),
]


class FakeProject(object):
    def __init__(self, name, id):
        self.name = name
        self.id = id


FAKE_PROJECTS = [
    FakeProject(dccommon_consts.ADMIN_PROJECT_NAME, FAKE_ADMIN_PROJECT_ID),
    FakeProject(dccommon_consts.SERVICES_USER_NAME, FAKE_SERVICE_PROJECT_ID),
]


class FakeService(object):
    def __init__(self, name, type, id):
        self.name = name
        self.type = type
        self.id = id


FAKE_SERVICES = [
    FakeService(
        dccommon_consts.ENDPOINT_NAME_SYSINV, dccommon_consts.ENDPOINT_TYPE_PLATFORM, 1
    ),
    FakeService(
        dccommon_consts.ENDPOINT_NAME_KEYSTONE,
        dccommon_consts.ENDPOINT_TYPE_IDENTITY,
        2,
    ),
    FakeService(dccommon_consts.ENDPOINT_NAME_FM, dccommon_consts.ENDPOINT_TYPE_FM, 4),
    FakeService(
        dccommon_consts.ENDPOINT_NAME_VIM, dccommon_consts.ENDPOINT_TYPE_NFV, 5
    ),
    FakeService(
        dccommon_consts.ENDPOINT_NAME_USM, dccommon_consts.ENDPOINT_TYPE_USM, 6
    ),
]


class FakeKeystoneClient(object):
    def __init__(self):
        self.user_list = FAKE_USERS
        self.project_list = FAKE_PROJECTS
        self.keystone_client = mock.MagicMock()
        self.session = mock.MagicMock()
        self.endpoint_cache = mock.MagicMock()
        self.region_name = uuidutils.generate_uuid().replace("-", "")

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


class FakeSystem(object):
    def __init__(self, uuid):
        self.uuid = uuid
        self.name = "fake_name"


class FakeController(object):
    def __init__(self, hostname):
        self.hostname = hostname


FAKE_CONTROLLERS = [
    FakeController("controller-0"),
    FakeController("controller-1"),
]


class FakeManagementInterface(object):
    def __init__(self, uuid):
        self.uuid = uuid


FAKE_MGMT_INTERFACES = [
    FakeManagementInterface("47cb1222-21a9-4ee0-b1f9-0b37de345f65"),
    FakeManagementInterface("0106bdf0-1662-48cc-b6b3-664c91147843"),
]


class FakeAddressPool(object):
    def __init__(self, floating_address, network, prefix):
        self.floating_address = floating_address
        self.network = network
        self.prefix = prefix
        self.family = netaddr.IPAddress(network).version


FAKE_MGMT_POOLS = [
    FakeAddressPool("fdff:719a:bf60:233::2", "fdff:719a:bf60:233::", 64),
]


FAKE_OAM_POOLS = [
    FakeAddressPool("2620:10a:a001:d41::260", "2620:10a:a001:d41::", 64),
]


class FakeSysinvClient(object):
    def __init__(self):
        self.hosts = FAKE_CONTROLLERS
        self.interfaces = FAKE_MGMT_INTERFACES
        self.mgmt_pools = FAKE_MGMT_POOLS
        self.oam_pools = FAKE_OAM_POOLS

    def get_controller_hosts(self):
        return self.hosts

    def get_management_interface(self, hostname):
        if hostname == "controller-0":
            return self.interfaces[0]
        else:
            return self.interfaces[1]

    def get_management_address_pools(self):
        return self.mgmt_pools

    def get_oam_address_pools(self):
        return self.oam_pools

    def get_system(self):
        return FakeSystem(str(uuid.uuid4()))


FAKE_SUBCLOUD_PRESTAGE_PAYLOAD = {
    "install_values": fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES,
    "subcloud_name": "subcloud1",
    "force": False,
    "oam_floating_ip": "10.10.10.12",
    "software_version": "20.12",
    "sysadmin_password": "testpasswd",
}

FAKE_PRESTAGE_RELEASE = "22.12"
FAKE_SUBCLOUD_SW_VERSION = "21.12"
FAKE_PRESTAGE_PAYLOAD = {
    "subcloud_name": "subcloud1",
    "oam_floating_ip": "10.10.10.12",
    "sysadmin_password": (base64.b64encode("testpass".encode("utf-8"))).decode("ascii"),
    "force": False,
    "release": FAKE_PRESTAGE_RELEASE,
}

FAKE_MGMT_IF_UUIDS = [
    "47cb1222-21a9-4ee0-b1f9-0b37de345f65",
    "0106bdf0-1662-48cc-b6b3-664c91147843",
]

FAKE_CACHED_REGIONONE_DATA = {
    "admin_user_id": FAKE_USERS[0].id,
    "sysinv_user_id": FAKE_USERS[1].id,
    "dcmanager_user_id": FAKE_USERS[2].id,
    "admin_project_id": FAKE_PROJECTS[0].id,
    "services_project_id": FAKE_PROJECTS[1].id,
    "mgmt_interface_uuids": FAKE_MGMT_IF_UUIDS,
    "expiry": timeutils.utcnow() + datetime.timedelta(seconds=3600),
    "mgmt_pools": FAKE_MGMT_POOLS,
    "oam_pools": FAKE_OAM_POOLS,
}

FAKE_BACKUP_DELETE_LOAD = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1,
    "software_version": "22.12",
}

FAKE_BACKUP_DELETE_LOCAL_LOAD = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1,
    "software_version": "22.12",
    "local_only": True,
}

FAKE_BACKUP_DELETE_LOAD_1 = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1,
    "software_version": "22.12",
    "local_only": False,
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

FAKE_BACKUP_RESTORE_LOAD = {"sysadmin_password": "testpasswd", "subcloud": 1}

FAKE_BACKUP_RESTORE_LOAD_WITH_INSTALL = {
    "sysadmin_password": "testpasswd",
    "subcloud": 1,
    "install_values": fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES,
}

SERVICE_ENDPOINTS = [
    dccommon_consts.ENDPOINT_TYPE_PLATFORM,
    dccommon_consts.ENDPOINT_TYPE_IDENTITY,
    dccommon_consts.ENDPOINT_TYPE_FM,
    dccommon_consts.ENDPOINT_TYPE_NFV,
    dccommon_consts.AUDIT_TYPE_SOFTWARE,
]


class Subcloud(object):
    def __init__(self, data, is_online):
        self.id = data["id"]
        self.name = data["name"]
        self.description = data["description"]
        self.location = data["location"]
        self.software_version = data["software-version"]
        self.management_state = dccommon_consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = dccommon_consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = dccommon_consts.AVAILABILITY_OFFLINE
        self.deploy_status = data["deploy_status"]
        self.error_description = data["error_description"]
        self.management_subnet = data["management_subnet"]
        self.management_gateway_ip = data["management_gateway_address"]
        self.management_start_ip = data["management_start_address"]
        self.management_end_ip = data["management_end_address"]
        self.external_oam_subnet = data["external_oam_subnet"]
        self.external_oam_gateway_address = data["external_oam_gateway_address"]
        self.external_oam_floating_address = data["external_oam_floating_address"]
        self.systemcontroller_gateway_ip = data["systemcontroller_gateway_address"]
        self.data_install = data["data_install"]
        self.created_at = timeutils.utcnow()
        self.updated_at = timeutils.utcnow()


class BaseTestSubcloudManager(base.DCManagerTestCase):
    """Base class for testing subcloud Manager"""

    def setUp(self):
        super().setUp()

        self.mock_audit_rpc_client = self._mock_object(rpcapi, "ManagerAuditClient")
        self._mock_object(rpc_client, "SubcloudStateClient")
        self._mock_object(EndpointCache, "get_admin_session")
        self.mock_subcloud_install_sysinv_client = self._mock_object(
            subcloud_install, "SysinvClient"
        )
        self.mock_openstack_driver = self._mock_object(
            subcloud_manager, "OpenStackDriver"
        )
        self.mock_sysinv_client = self._mock_object(subcloud_manager, "SysinvClient")
        self.mock_dcorch_api = self._mock_object(
            dcorch_rpc_client, "EngineWorkerClient"
        )
        self.mock_dcmanager_api = self._mock_object(
            rpc_client, "DCManagerNotifications"
        )
        mock_context = self._mock_object(subcloud_manager, "dcmanager_context")
        mock_context.get_admin_context.return_value = self.ctx
        self.mock_log_subcloud_manager = self._mock_object(subcloud_manager, "LOG")
        self.mock_keyring = self._mock_object(subcloud_manager, "keyring")
        self.mock_create_subcloud_inventory = self._mock_object(
            cutils, "create_subcloud_inventory"
        )
        self.mock_delete_subcloud_inventory = self._mock_object(
            cutils, "delete_subcloud_inventory"
        )
        self.mock_get_playbook_for_software_version = self._mock_object(
            cutils, "get_playbook_for_software_version"
        )
        self.mock_get_local_system = self._mock_object(cutils, "get_local_system")
        self._mock_object(cutils, "get_pool_by_ip_family")
        self.mock_subprocess_run = self._mock_object(subprocess, "run")
        self.mock_ansible_run_playbook = self._mock_object(
            AnsiblePlaybook, "run_playbook"
        )
        self.original_builtins_open = builtins.open
        self.mock_builtins_open = self._mock_object(builtins, "open")
        self._mock_object(os, "mkdir")
        self.mock_os_listdir = self._mock_object(os, "listdir")
        self.mock_os_path_isdir = self._mock_object(os.path, "isdir")
        self.mock_os_path_exists = self._mock_object(os.path, "exists")
        self.mock_os_remove = self._mock_object(os, "remove")
        self._mock_object(ostree_mount, "validate_ostree_iso_mount")
        self.sm = subcloud_manager.SubcloudManager()

        self.subcloud = self.create_subcloud_static(self.ctx)
        self.test_system_peer_manager = test_system_peer_manager.TestSystemPeerManager
        self.system_peer = self.test_system_peer_manager.create_system_peer_static(
            self.ctx, peer_name="SystemPeer1"
        )
        self.peer_group = self.create_subcloud_peer_group_static(self.ctx)

        self.mock_keyring.get_password.return_value = "testpassword"
        self.fake_install_values = copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        self.fake_bootstrap_values = copy.copy(
            fake_subcloud.FAKE_SUBCLOUD_BOOTSTRAP_PAYLOAD
        )

        self.fake_payload = {
            "sysadmin_password": "testpass",
            "deploy_playbook": "test_playbook.yaml",
            "deploy_overrides": "test_overrides.yaml",
            "deploy_chart": "test_chart.yaml",
            "deploy_config": "subcloud1.yaml",
        }
        self.fake_payload_install = {
            "bmc_password": "bmc_pass",
            "install_values": self.fake_install_values,
            "software_version": SW_VERSION,
            "sysadmin_password": "sys_pass",
        }
        self.fake_payload_enroll = {
            "bmc_password": "bmc_pass",
            "install_values": self.fake_install_values,
            "software_version": SW_VERSION,
            "sysadmin_password": "sys_pass",
            "admin_password": "sys_pass",
        }
        self.fake_payload_enroll = dict(
            self.fake_payload_enroll,
            **self.fake_bootstrap_values,
            **self.fake_install_values,
        )

        rel_version = self.fake_payload_enroll.get("software_version")

        self.iso_dir = f"/opt/platform/iso/{rel_version}/nodes/{self.subcloud.name}"
        self.iso_file = f"{self.iso_dir}/seed.iso"

        # Reset the regionone_data cache between tests
        subcloud_manager.SubcloudManager.regionone_data = collections.defaultdict(dict)

    def patched_isdir(self, path):
        return path != self.iso_dir

    @staticmethod
    def create_subcloud_static(ctxt, **kwargs):
        values = {
            "name": "subcloud1",
            "description": "subcloud1 description",
            "location": "subcloud1 location",
            "software_version": "18.03",
            "management_subnet": "192.168.101.0/24",
            "management_gateway_ip": "192.168.101.1",
            "management_start_ip": "192.168.101.2",
            "management_end_ip": "192.168.101.50",
            "systemcontroller_gateway_ip": "192.168.204.101",
            "external_oam_subnet_ip_family": "4",
            "deploy_status": "not-deployed",
            "error_description": "No errors present",
            "region_name": base.SUBCLOUD_1["region_name"],
            "openstack_installed": False,
            "group_id": 1,
            "data_install": "data from install",
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
            "max_subcloud_rehoming": 50,
            "migration_status": None,
        }
        values.update(kwargs)
        return db_api.subcloud_peer_group_create(ctxt, **values)

    def test_init(self):
        self.assertIsNotNone(self.sm)
        self.assertEqual("subcloud_manager", self.sm.service_name)
        self.assertEqual("localhost", self.sm.host)
        self.assertEqual(self.ctx, self.sm.context)


class TestSubcloudManager(BaseTestSubcloudManager):
    """Test class for testing subcloud Manager"""

    def setUp(self):
        super().setUp()
        self._mock_object(netaddr, "IPAddress")
        self.values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        self.test_system_peer_manager.create_peer_group_association_static(
            self.ctx,
            system_peer_id=self.system_peer.id,
            peer_group_id=self.peer_group.id,
        )
        self.payload = {
            "name": self.subcloud.name,
            "description": "subcloud description",
            "location": "subcloud location",
            "management_subnet": "192.168.102.0/24",
            "management_start_ip": "192.168.102.5",
            "management_end_ip": "192.168.102.49",
            "management_gateway_ip": "192.168.102.1",
        }

    def test_network_reconf_same_subnet_endpoint_type_platform(self):
        self.payload.update(
            {
                "management_subnet": "192.168.101.0/24",
                "management_start_address": "192.168.101.3",
                "management_end_ip": "192.168.101.49",
                "management_gateway_ip": "192.168.101.1",
            }
        )
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        endpoint_1 = FakeEndpoint("endpoint1", "regionOne", "1")
        keystone_client = self.mock_openstack_driver().keystone_client
        keystone_client.endpoints.list.return_value = [endpoint_1]
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        for endpoint_type in SERVICE_ENDPOINTS:
            keystone_client.services.get.return_value.type = endpoint_type
            self.sm._update_services_endpoint(
                self.ctx,
                self.payload,
                self.subcloud.region_name,
                self.mock_openstack_driver,
            )
            self.mock_log_subcloud_manager.info.assert_called_with(
                "Update services endpoint to 192.168.101.3 in subcloud region "
                f'{base.SUBCLOUD_1["region_name"]}'
            )
        self.assertEqual(
            self.mock_dcmanager_api().subcloud_sysinv_endpoint_update.call_count,
            len(FAKE_SERVICES),
        )

    @mock.patch.object(kubeoperator, "KubeOperator")
    @mock.patch.object(json, "dumps")
    def test_generate_subcloud_ansible_config_initial_deployment(
        self, mock_dumps, mock_kubeoperator
    ):
        self.subcloud["region_name"] = self.values["region_name"]
        self.sm.generate_subcloud_ansible_config(self.subcloud, self.values, True)
        self.mock_keyring.get_password.assert_called()
        self.mock_create_subcloud_inventory.assert_called_once()
        mock_kubeoperator.assert_called_once()

    def test_generate_subcloud_ansible_config(self):
        self.mock_write_subcloud_ansible_config = self._mock_object(
            subcloud_manager.SubcloudManager, "_write_subcloud_ansible_config"
        )
        self.mock_create_intermediate_ca_cert = self._mock_object(
            subcloud_manager.SubcloudManager, "_create_intermediate_ca_cert"
        )
        self.subcloud["region_name"] = self.values["region_name"]
        initial_deployment = False
        self.sm.generate_subcloud_ansible_config(
            self.subcloud, self.values, initial_deployment
        )
        self.mock_keyring.get_password.assert_called()
        self.mock_create_subcloud_inventory.assert_called_once()
        self.mock_create_intermediate_ca_cert.assert_called_once()
        self.mock_write_subcloud_ansible_config.assert_called_once()

    def test_generate_subcloud_ansible_config_failed(self):
        self.mock_create_subcloud_inventory.side_effect = base.FakeException("boom")
        self.subcloud["region_name"] = self.values["region_name"]
        self.assertRaises(
            base.FakeException,
            self.sm.generate_subcloud_ansible_config,
            self.subcloud,
            self.values,
        )

    def test_get_subcloud_name_by_region_name(self):
        self.subcloud.update(
            {
                "name": fake_subcloud.FAKE_SUBCLOUD_DATA["name"],
                "region_name": fake_subcloud.FAKE_SUBCLOUD_DATA["region_name"],
            }
        )
        self.sm.get_subcloud_name_by_region_name(self.ctx, self.subcloud.region_name)

        ret = db_api.subcloud_get_by_region_name(self.ctx, self.subcloud.region_name)
        self.assertEqual(self.subcloud.name, ret.name)

    def test_get_peer_system_list_with_unavailable_peer(self):
        db_api.system_peer_update(
            self.ctx,
            self.system_peer.id,
            availability_state=consts.SYSTEM_PEER_AVAILABILITY_STATE_UNAVAILABLE,
        )
        self.sm._get_peer_system_list(self.peer_group)
        self.mock_log_subcloud_manager.warning.assert_called_once_with(
            "Peer system %s offline, skip checking" % self.system_peer.peer_name
        )

    def test_get_peer_system_list_availability_state(self):
        db_api.system_peer_update(
            self.ctx,
            self.system_peer.id,
            availability_state=consts.SYSTEM_PEER_AVAILABILITY_STATE_AVAILABLE,
        )
        return_peer = self.sm._get_peer_system_list(self.peer_group)
        self.assertEqual(len(return_peer), 1)

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "subcloud_deploy_install", return_value=True
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "subcloud_deploy_bootstrap", return_value=True
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "subcloud_deploy_config", return_value=True
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "subcloud_deploy_complete", return_value=True
    )
    def test_run_deploy_phases(
        self,
        mock_subcloud_deploy_complete,
        mock_subcloud_deploy_config,
        mock_subcloud_deploy_bootstrap,
        mock_subcloud_deploy_install,
    ):
        deploy_phases_to_run = [
            consts.DEPLOY_PHASE_COMPLETE,
            consts.DEPLOY_PHASE_CONFIG,
            consts.DEPLOY_PHASE_INSTALL,
            consts.DEPLOY_PHASE_BOOTSTRAP,
        ]
        manager = mock.Mock()
        manager.attach_mock(
            mock_subcloud_deploy_install, "mock_subcloud_deploy_install"
        )
        manager.attach_mock(
            mock_subcloud_deploy_bootstrap, "mock_subcloud_deploy_bootstrap"
        )
        manager.attach_mock(mock_subcloud_deploy_config, "mock_subcloud_deploy_config")
        manager.attach_mock(
            mock_subcloud_deploy_complete, "mock_subcloud_deploy_complete"
        )
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        self.sm.run_deploy_phases(
            self.ctx, self.subcloud.id, values, deploy_phases_to_run
        )
        expected_calls = [
            mock.call.mock_subcloud_deploy_install(
                self.ctx, self.subcloud.id, values, False, None
            ),
            mock.call.mock_subcloud_deploy_bootstrap(
                self.ctx, self.subcloud.id, values, False
            ),
            mock.call.mock_subcloud_deploy_config(
                self.ctx, self.subcloud.id, values, False
            ),
            mock.call.mock_subcloud_deploy_complete(self.ctx, self.subcloud.id),
        ]
        self.assertEqual(expected_calls, manager.mock_calls)

    @mock.patch.object(subcloud_manager.SubcloudManager, "subcloud_deploy_install")
    @mock.patch.object(subcloud_manager.SubcloudManager, "subcloud_deploy_bootstrap")
    @mock.patch.object(subcloud_manager.SubcloudManager, "subcloud_deploy_config")
    @mock.patch.object(subcloud_manager.SubcloudManager, "subcloud_deploy_complete")
    def test_run_deploy_phases_failed(
        self,
        mock_subcloud_deploy_complete,
        mock_subcloud_deploy_config,
        mock_subcloud_deploy_bootstrap,
        mock_subcloud_deploy_install,
    ):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        mock_subcloud_deploy_config.return_value = False
        deploy_phases_to_run = [
            consts.DEPLOY_PHASE_COMPLETE,
            consts.DEPLOY_PHASE_CONFIG,
            consts.DEPLOY_PHASE_INSTALL,
            consts.DEPLOY_PHASE_BOOTSTRAP,
        ]
        ret = self.sm.run_deploy_phases(
            self.ctx, self.subcloud.id, values, deploy_phases_to_run
        )
        self.assertEqual(ret, False)

    @mock.patch.object(subcloud_manager.SubcloudManager, "_update_backup_status_by_ids")
    def test_mark_invalid_subclouds_for_backup_validation_failed(
        self, mock_update_backup_status_by_ids
    ):
        mock_update_backup_status_by_ids.side_effect = exceptions.DCManagerException
        self.assertRaises(
            exceptions.DCManagerException,
            self.sm._mark_invalid_subclouds_for_backup,
            self.ctx,
            [self.subcloud],
        )
        self.mock_log_subcloud_manager.exception.assert_called_once_with(
            "Subcloud backup validation failed"
        )

    def test_mark_invalid_subclouds_for_backup_validation_success(self):
        self.sm._mark_invalid_subclouds_for_backup(self.ctx, [self.subcloud])
        self.mock_log_subcloud_manager.warn.assert_called_once_with(
            "The following subclouds are not online and/or managed "
            "and/or in a valid deploy state, and will not be backed up: %s",
            self.subcloud.name,
        )
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.BACKUP_STATE_VALIDATE_FAILED, updated_subcloud.backup_status
        )

    @mock.patch.object(subcloud_manager.SubcloudManager, "_delete_subcloud_routes")
    @mock.patch.object(subcloud_manager.SubcloudManager, "_update_services_endpoint")
    @mock.patch.object(subcloud_manager.SubcloudManager, "_create_subcloud_route")
    def test_update_subcloud_network_reconfiguration(
        self, mock_create_route, mock_update_endpoints, mock_delete_route
    ):
        self.mock_create_addn_hosts = self._mock_object(
            subcloud_manager.SubcloudManager, "_create_addn_hosts_dc"
        )
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_RECONFIGURING_NETWORK
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        self.sm._run_network_reconfiguration(
            self.subcloud.name, mock.ANY, None, self.payload, self.ctx, self.subcloud
        )

        self.mock_ansible_run_playbook.assert_called_once()
        self.mock_openstack_driver.assert_called_once()
        mock_create_route.assert_called_once()
        mock_update_endpoints.assert_called_once()
        mock_delete_route.assert_called_once()
        self.mock_create_addn_hosts.assert_called_once()

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        for key, value in self.payload.items():
            self.assertEqual(value, updated_subcloud[key])
        self.assertEqual(consts.DEPLOY_STATE_DONE, updated_subcloud.deploy_status)

    @mock.patch.object(kubeoperator, "KubeOperator")
    def test_run_network_reconfiguration_fail(self, mock_kube_operator):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_RECONFIGURING_NETWORK

        self.sm._run_network_reconfiguration(
            self.subcloud.name, mock.ANY, None, self.payload, self.ctx, self.subcloud
        )
        self.mock_log_subcloud_manager.error.assert_called_once_with(
            "FAILED reconfiguring-network playbook of (subcloud1).\n"
            "check individual log at /var/log/dcmanager/ansible"
            "/subcloud1_playbook_output.log for detailed output"
        )
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
            updated_subcloud.deploy_status,
        )

    @mock.patch.object(
        cutils, "find_ansible_error_msg", return_value="Fake playbook error"
    )
    def test_run_network_reconfiguration_find_and_save_playbook_error(
        self, mock_find_msg
    ):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_RECONFIGURING_NETWORK

        self.sm._run_network_reconfiguration(
            self.subcloud.name, mock.ANY, None, self.payload, self.ctx, self.subcloud
        )

        mock_find_msg.assert_called_once_with(
            self.subcloud.name, mock.ANY, consts.DEPLOY_STATE_RECONFIGURING_NETWORK
        )

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual("Fake playbook error", updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
            updated_subcloud.deploy_status,
        )

    def test_run_network_reconfiguration_find_and_save_playbook_timeout(self):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionTimeout()

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_RECONFIGURING_NETWORK

        self.sm._run_network_reconfiguration(
            self.subcloud.name, mock.ANY, None, self.payload, self.ctx, self.subcloud
        )

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertIn("Timeout", updated_subcloud.error_description)
        self.assertIn(self.subcloud.name, updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
            updated_subcloud.deploy_status,
        )

    @mock.patch.object(subcloud_manager.SubcloudManager, "_delete_subcloud_routes")
    @mock.patch.object(subcloud_manager.SubcloudManager, "_update_services_endpoint")
    @mock.patch.object(subcloud_manager.SubcloudManager, "_create_subcloud_route")
    def test_configure_system_controller_network(
        self, mock_create_route, mock_update_endpoints, mock_delete_route
    ):
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_RECONFIGURING_NETWORK
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        self.payload.update(
            {
                "management_subnet": "192.168.101.0/24",
                "management_start_ip": "192.168.101.3",
                "management_end_ip": "192.168.101.49",
                "management_gateway_ip": "192.168.101.1",
            }
        )

        self.sm._configure_system_controller_network(
            self.ctx, self.payload, self.subcloud
        )

        self.mock_openstack_driver.assert_called_once()
        mock_create_route.assert_called_once()
        mock_update_endpoints.assert_called_once()
        mock_delete_route.assert_not_called()

    @mock.patch.object(subcloud_manager.SubcloudManager, "_delete_subcloud_routes")
    @mock.patch.object(subcloud_manager.SubcloudManager, "_update_services_endpoint")
    @mock.patch.object(subcloud_manager.SubcloudManager, "_create_subcloud_route")
    def test_configure_system_controller_network_failed_to_update_endpoints(
        self, mock_create_route, mock_update_endpoints, mock_delete_route
    ):
        mock_update_endpoints.side_effect = Exception("boom")
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_RECONFIGURING_NETWORK
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        self.sm._configure_system_controller_network(
            self.ctx, self.payload, self.subcloud
        )

        self.mock_openstack_driver.assert_called_once()
        mock_create_route.assert_called_once()
        mock_update_endpoints.assert_called_once()
        self.assertFalse(mock_delete_route.called)
        self.mock_log_subcloud_manager.exception.assert_called_once_with(
            f"Failed to update subcloud {self.subcloud.name} endpoints"
        )
        mock_delete_route.assert_not_called()
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
            updated_subcloud.deploy_status,
        )

    @mock.patch.object(subcloud_manager.SubcloudManager, "_delete_subcloud_routes")
    def test_configure_system_controller_network_failed(self, mock_delete_route):
        self.mock_sysinv_client.side_effect = Exception("boom")
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_RECONFIGURING_NETWORK
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        self.sm._configure_system_controller_network(
            self.ctx, self.payload, self.subcloud
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
            updated_subcloud.deploy_status,
        )
        self.mock_openstack_driver.assert_called_once()
        self.assertFalse(mock_delete_route.called)
        self.mock_log_subcloud_manager.exception.assert_called_once_with(
            f"Failed to create route to subcloud {self.subcloud.name}."
        )
        self.assertEqual(
            consts.DEPLOY_STATE_RECONFIGURING_NETWORK_FAILED,
            updated_subcloud.deploy_status,
        )


class TestSubcloudDeploy(BaseTestSubcloudManager):
    """Test class for testing subcloud deploy"""

    def setUp(self):
        super().setUp()

        self.mock_create_addn_hosts = self._mock_object(
            subcloud_manager.SubcloudManager, "_create_addn_hosts_dc"
        )
        self.mock_run_subcloud_install = self._mock_object(
            subcloud_manager.SubcloudManager, "_run_subcloud_install"
        )
        self.mock_create_intermediate_ca_cert = self._mock_object(
            subcloud_manager.SubcloudManager, "_create_intermediate_ca_cert"
        )
        self.mock_openstack_driver().keystone_client = FakeKeystoneClient()
        self.mock_get_cached_regionone_data = self._mock_object(
            subcloud_manager.SubcloudManager, "_get_cached_regionone_data"
        )
        self.mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA

        self.payload = {
            **fake_subcloud.FAKE_BOOTSTRAP_VALUE,
            **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA,
            "sysadmin_password": "testpass",
        }

    def test_subcloud_deploy_install(self):
        self.mock_compose_install_command = self._mock_object(
            subcloud_manager.SubcloudManager, "compose_install_command"
        )
        self.mock_run_subcloud_install.return_value = True
        self.fake_payload_install["software_version"] = FAKE_PREVIOUS_SW_VERSION
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_PRE_INSTALL
        self.fake_install_values["software_version"] = SW_VERSION

        self.sm.subcloud_deploy_install(
            self.ctx, self.subcloud.id, payload=self.fake_payload_install
        )

        self.mock_compose_install_command.assert_called_once_with(
            self.subcloud.name,
            cutils.get_ansible_filename(
                self.subcloud.name, consts.INVENTORY_FILE_POSTFIX
            ),
            FAKE_PREVIOUS_SW_VERSION,
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_INSTALLED, updated_subcloud.deploy_status)

    def test_subcloud_deploy_install_failed(self):
        self.mock_run_subcloud_install.side_effect = Exception("boom")
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_PRE_INSTALL
        self.fake_install_values["software_version"] = SW_VERSION

        self.sm.subcloud_deploy_install(
            self.ctx, self.subcloud.id, payload=self.fake_payload_install
        )

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_PRE_INSTALL_FAILED, updated_subcloud.deploy_status
        )

    def test_subcloud_deploy_create(self):
        self.mock_write_subcloud_ansible_config = self._mock_object(
            subcloud_manager.SubcloudManager, "_write_subcloud_ansible_config"
        )
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values["deploy_status"] = consts.DEPLOY_STATE_NONE

        # dcmanager add_subcloud queries the data from the db
        subcloud = self.create_subcloud_static(
            self.ctx, name=values["name"], region_name=values["region_name"]
        )
        values["id"] = subcloud.id

        subcloud_dict = self.sm.subcloud_deploy_create(
            self.ctx, subcloud.id, payload=values
        )

        self.mock_get_cached_regionone_data.assert_called_once()
        self.mock_sysinv_client().create_route.assert_called()
        self.mock_dcorch_api().add_subcloud.assert_called_once()
        self.mock_create_addn_hosts.assert_called_once()
        self.mock_create_subcloud_inventory.assert_called_once()
        self.mock_write_subcloud_ansible_config.assert_called_once()
        self.mock_keyring.get_password.assert_called()
        self.mock_create_intermediate_ca_cert.assert_called_once()

        # Verify subcloud was updated with correct values
        self.assertEqual(consts.DEPLOY_STATE_CREATED, subcloud_dict["deploy-status"])

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, values["name"])
        self.assertEqual(consts.DEPLOY_STATE_CREATED, updated_subcloud.deploy_status)

    def test_subcloud_deploy_create_failed(self):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values["deploy_status"] = consts.DEPLOY_STATE_NONE

        # dcmanager add_subcloud queries the data from the db
        subcloud = self.create_subcloud_static(
            self.ctx, name=values["name"], region_name=values["region_name"]
        )
        values["id"] = subcloud.id

        self.mock_openstack_driver.side_effect = Exception("boom")

        subcloud_dict = self.sm.subcloud_deploy_create(
            self.ctx, subcloud.id, payload=values
        )

        # Verify subcloud was updated with correct values
        self.assertEqual(
            consts.DEPLOY_STATE_CREATE_FAILED, subcloud_dict["deploy-status"]
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, values["name"])
        self.assertEqual(
            consts.DEPLOY_STATE_CREATE_FAILED, updated_subcloud.deploy_status
        )

    def test_deploy_create_secondary(self):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values["deploy_status"] = consts.DEPLOY_STATE_NONE
        sysadmin_password = values["sysadmin_password"]
        subcloud = self.create_subcloud_static(
            self.ctx, name=values["name"], region_name=values["region_name"]
        )
        values.update(
            {
                "id": subcloud.id,
                "secondary": "true",
                "ansible_ssh_pass": sysadmin_password,
                "ansible_become_pass": sysadmin_password,
                "admin_password": sysadmin_password,
            }
        )

        subcloud_dict = self.sm.subcloud_deploy_create(
            self.ctx, subcloud.id, payload=values
        )

        self.assertEqual(consts.DEPLOY_STATE_SECONDARY, subcloud_dict["deploy-status"])

    def test_deploy_create_secondary_without_additional_values(self):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values["deploy_status"] = consts.DEPLOY_STATE_NONE
        subcloud = self.create_subcloud_static(
            self.ctx, name=values["name"], region_name=values["region_name"]
        )
        values["id"] = subcloud.id
        values["secondary"] = "true"

        subcloud_dict = self.sm.subcloud_deploy_create(
            self.ctx, subcloud.id, payload=values
        )

        self.assertEqual(consts.DEPLOY_STATE_SECONDARY, subcloud_dict["deploy-status"])

    def test_deploy_create_secondary_failed(self):
        self.mock_openstack_driver.side_effect = Exception("boom")
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values["deploy_status"] = consts.DEPLOY_STATE_NONE
        subcloud = self.create_subcloud_static(
            self.ctx, name=values["name"], region_name=values["region_name"]
        )
        values["id"] = subcloud.id
        values["secondary"] = "true"
        subcloud_dict = self.sm.subcloud_deploy_create(
            self.ctx, subcloud.id, payload=values
        )
        self.assertEqual(
            consts.DEPLOY_STATE_SECONDARY_FAILED, subcloud_dict["deploy-status"]
        )

    @mock.patch.object(cutils, "update_values_on_yaml_file")
    def test_subcloud_deploy_bootstrap(self, mock_update_yml):
        self.mock_get_playbook_for_software_version.return_value = SW_VERSION
        self.mock_keyring.get_password.return_value = "testpass"
        self.mock_ansible_run_playbook.return_value = False
        self.fake_install_values["software_version"] = SW_VERSION

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED,
            data_install=json.dumps(self.fake_install_values),
        )
        self.payload["bootstrap-address"] = "10.10.10.12"

        self.sm.subcloud_deploy_bootstrap(self.ctx, subcloud.id, self.payload)

        self.mock_ansible_run_playbook.assert_called_once()

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.payload["name"])
        self.assertEqual(
            consts.DEPLOY_STATE_BOOTSTRAPPED, updated_subcloud.deploy_status
        )
        # Verify the subcloud rehomed flag is False after bootstrapped
        self.assertFalse(updated_subcloud.rehomed)

    def test_subcloud_deploy_bootstrap_run_playbook_failed(self):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED,
            data_install=json.dumps(self.fake_install_values),
        )

        self.sm.subcloud_deploy_bootstrap(self.ctx, subcloud.id, self.payload)

        self.mock_ansible_run_playbook.assert_called_once()

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.payload["name"])
        self.assertEqual(
            consts.DEPLOY_STATE_BOOTSTRAP_FAILED, updated_subcloud.deploy_status
        )
        # Verify the subcloud rehomed flag is False after bootstrapped
        self.assertFalse(updated_subcloud.rehomed)
        self.mock_log_subcloud_manager.error.assert_called_once_with(
            "FAILED bootstrapping playbook of (fake_subcloud1).\n"
            "check individual log at /var/log/dcmanager/ansible/"
            "fake_subcloud1_playbook_output.log for detailed output"
        )

    @mock.patch.object(
        cutils, "find_ansible_error_msg", return_value="Fake playbook error"
    )
    def test_subcloud_deploy_bootstrap_find_and_save_playbook_error(
        self, mock_find_msg
    ):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED,
            data_install=json.dumps(self.fake_install_values),
        )

        self.sm.subcloud_deploy_bootstrap(self.ctx, subcloud.id, self.payload)

        self.mock_ansible_run_playbook.assert_called_once()

        mock_find_msg.assert_called_once_with(
            subcloud.name, mock.ANY, consts.DEPLOY_STATE_BOOTSTRAPPING
        )

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual("Fake playbook error", updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_BOOTSTRAP_FAILED, updated_subcloud.deploy_status
        )

    def test_subcloud_deploy_bootstrap_find_and_save_playbook_timeout(self):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionTimeout()

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED,
            data_install=json.dumps(self.fake_install_values),
        )

        self.sm.subcloud_deploy_bootstrap(self.ctx, subcloud.id, self.payload)

        self.mock_ansible_run_playbook.assert_called_once()

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertIn("Timeout", updated_subcloud.error_description)
        self.assertIn(subcloud.name, updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_BOOTSTRAP_FAILED, updated_subcloud.deploy_status
        )

    @mock.patch.object(subcloud_manager.SubcloudManager, "_deploy_bootstrap_prep")
    def test_subcloud_deploy_bootstrap_failed(self, mock_bootstrap_prep):
        mock_bootstrap_prep.side_effect = Exception("boom")

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED,
        )

        self.sm.subcloud_deploy_bootstrap(self.ctx, subcloud.id, self.payload)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.payload["name"])
        self.assertEqual(
            consts.DEPLOY_STATE_PRE_BOOTSTRAP_FAILED, updated_subcloud.deploy_status
        )

    @mock.patch.object(subcloud_manager.SubcloudManager, "_prepare_for_deployment")
    def test_configure_subcloud(self, mock_prepare_for_deployment):

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_PRE_CONFIG

        self.fake_payload[consts.BOOTSTRAP_ADDRESS] = (
            fake_subcloud.FAKE_BOOTSTRAP_VALUE[consts.BOOTSTRAP_ADDRESS]
        )

        self.sm.subcloud_deploy_config(
            self.ctx, self.subcloud.id, payload=self.fake_payload
        )
        mock_prepare_for_deployment.assert_called_once()
        self.mock_create_subcloud_inventory.assert_called_once()

    def test_configure_subcloud_failed(self):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_PRE_CONFIG
        self.fake_payload.update(
            {
                "user_uploaded_artifacts": "fake_files",
                consts.BOOTSTRAP_ADDRESS: fake_subcloud.FAKE_BOOTSTRAP_VALUE[
                    consts.BOOTSTRAP_ADDRESS
                ],
            }
        )
        self.sm.subcloud_deploy_config(
            self.ctx, self.subcloud.id, payload=self.fake_payload
        )
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_CONFIG_FAILED, updated_subcloud.deploy_status
        )
        self.mock_create_subcloud_inventory.assert_called_once()

    @mock.patch.object(
        cutils, "find_ansible_error_msg", return_value="Fake playbook error"
    )
    def test_configure_subcloud_find_and_save_playbook_error(self, mock_find_msg):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_PRE_CONFIG,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        self.fake_payload.update(
            {
                "user_uploaded_artifacts": "fake_files",
                consts.BOOTSTRAP_ADDRESS: fake_subcloud.FAKE_BOOTSTRAP_VALUE[
                    consts.BOOTSTRAP_ADDRESS
                ],
            }
        )

        self.sm.subcloud_deploy_config(
            self.ctx, self.subcloud.id, payload=self.fake_payload
        )

        self.mock_ansible_run_playbook.assert_called_once()

        mock_find_msg.assert_called_once_with(
            self.subcloud["name"], mock.ANY, consts.DEPLOY_STATE_CONFIGURING
        )

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud["name"])
        self.assertEqual("Fake playbook error", updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_CONFIG_FAILED, updated_subcloud.deploy_status
        )
        self.mock_create_subcloud_inventory.assert_called_once()

    def test_configure_subcloud_find_and_save_playbook_timeout(self):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionTimeout()

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_PRE_CONFIG
        self.fake_payload.update(
            {
                "user_uploaded_artifacts": "fake_files",
                consts.BOOTSTRAP_ADDRESS: fake_subcloud.FAKE_BOOTSTRAP_VALUE[
                    consts.BOOTSTRAP_ADDRESS
                ],
            }
        )

        self.sm.subcloud_deploy_config(
            self.ctx, self.subcloud.id, payload=self.fake_payload
        )

        self.mock_ansible_run_playbook.assert_called_once()

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud["name"])
        self.assertIn("Timeout", updated_subcloud.error_description)
        self.assertIn(self.subcloud["name"], updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_CONFIG_FAILED, updated_subcloud.deploy_status
        )

    def test_configure_subcloud_pre_config_failed(self):

        ret = self.sm.subcloud_deploy_config(
            self.ctx, self.subcloud.id, payload=self.fake_payload
        )
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_PRE_CONFIG_FAILED, updated_subcloud.deploy_status
        )
        self.mock_log_subcloud_manager.exception.assert_called_once_with(
            f"Failed to configure {self.subcloud.name}"
        )
        self.assertFalse(ret)

    @mock.patch.object(subcloud_manager.SubcloudManager, "_prepare_for_deployment")
    @mock.patch.object(cutils, "update_values_on_yaml_file")
    def test_subcloud_deploy_resume(self, mock_update_yml, mock_prepare_for_deployment):
        self.mock_get_playbook_for_software_version.return_value = FAKE_SW_VERSION
        self.mock_ansible_run_playbook.return_value = False
        self.mock_run_subcloud_install.return_value = True

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_CREATED

        deploy_states_to_run = [
            consts.DEPLOY_PHASE_INSTALL,
            consts.DEPLOY_PHASE_BOOTSTRAP,
            consts.DEPLOY_PHASE_CONFIG,
        ]

        fake_payload_bootstrap = {
            **fake_subcloud.FAKE_BOOTSTRAP_VALUE,
            **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA,
        }
        fake_payload_bootstrap["sysadmin_password"] = "testpass"
        fake_payload = {
            **self.fake_payload_install,
            **fake_payload_bootstrap,
            **self.fake_payload,
        }

        self.sm.subcloud_deploy_resume(
            self.ctx,
            self.subcloud.id,
            self.subcloud.name,
            fake_payload,
            deploy_states_to_run,
        )
        mock_prepare_for_deployment.assert_called_once()

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE, updated_subcloud.deploy_status)

    @mock.patch.object(AnsiblePlaybook, "run_abort")
    def test_subcloud_deploy_abort_failed(self, mock_run_abort):
        self.subcloud.update(
            {
                "name": fake_subcloud.FAKE_SUBCLOUD_DATA["name"],
                "deploy_status": consts.DEPLOY_STATE_INSTALLING,
            }
        )
        mock_run_abort.side_effect = base.FakeException("boom")
        self.assertRaises(
            base.FakeException,
            self.sm.subcloud_deploy_abort,
            self.ctx,
            self.subcloud.id,
            self.subcloud.deploy_status,
        )
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_INSTALL_FAILED, updated_subcloud.deploy_status
        )

    @mock.patch.object(AnsiblePlaybook, "run_abort")
    def test_subprocessors_terminated_before_abort(self, mock_run_abort):
        self.subcloud.update(
            {
                "name": fake_subcloud.FAKE_SUBCLOUD_DATA["name"],
                "deploy_status": consts.DEPLOY_STATE_INSTALLING,
            }
        )
        mock_run_abort.return_value = False

        self.sm.subcloud_deploy_abort(
            self.ctx, self.subcloud.id, self.subcloud.deploy_status
        )
        ret = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_ABORTING_INSTALL, ret.deploy_status)
        mock_run_abort.assert_called_once()

    def test_subcloud_deploy_complete(self):
        self.subcloud.update(
            {
                "name": fake_subcloud.FAKE_SUBCLOUD_DATA["name"],
                "deploy_status": consts.DEPLOY_STATE_INSTALLING,
            }
        )
        self.sm.subcloud_deploy_complete(self.ctx, self.subcloud.id)
        ret = db_api.subcloud_get_by_region_name(self.ctx, self.subcloud.region_name)
        self.assertEqual(consts.DEPLOY_STATE_DONE, ret.deploy_status)

    @mock.patch.object(cutils, "get_region_name")
    @mock.patch.object(subcloud_enrollment.SubcloudEnrollmentInit, "prep")
    def test_deploy_subcloud_enroll(
        self, mock_subcloud_enrollment_prep, mock_get_region_name
    ):
        mock_mkdtemp = self._mock_object(tempfile, "mkdtemp")
        self._mock_object(os, "makedirs")
        self._mock_object(shutil, "rmtree")

        self.seed_data_dir = "/temp/seed_data"
        mock_get_region_name.return_value = "11111"

        self.mock_os_path_exists.return_value = True
        mock_mkdtemp.return_value = self.seed_data_dir
        self.mock_os_path_isdir.return_value = True
        self.mock_subprocess_run.return_value = mock.MagicMock(
            returncode=0, stdout=b"Success"
        )

        self.mock_compose_enroll_command = self._mock_object(
            subcloud_manager.SubcloudManager, "compose_enroll_command"
        )
        self.fake_payload_enroll["software_version"] = FAKE_PREVIOUS_SW_VERSION
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_PRE_INIT_ENROLL
        self.fake_payload_enroll["software_version"] = SW_VERSION

        with mock.patch("os.path.isdir", side_effect=self.patched_isdir):
            self.sm.subcloud_deploy_enroll(
                self.ctx, self.subcloud.id, payload=self.fake_payload_enroll
            )

    @mock.patch.object(subcloud_enrollment.SubcloudEnrollmentInit, "prep")
    @mock.patch.object(subcloud_manager.SubcloudManager, "_deploy_install_prep")
    def test_subcloud_deploy_pre_init_enroll_failed(
        self, mock_deploy_install_prep, mock_subcloud_enrollment_prep
    ):

        mock_deploy_install_prep.side_effect = base.FakeException("boom")

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_CREATED,
            data_install=json.dumps(self.fake_payload_enroll["install_values"]),
        )

        self.sm.subcloud_init_enroll(self.ctx, subcloud.id, self.fake_payload_enroll)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.payload["name"])

        self.assertEqual(
            consts.DEPLOY_STATE_PRE_INIT_ENROLL_FAILED, updated_subcloud.deploy_status
        )

    @mock.patch.object(subcloud_enrollment.SubcloudEnrollmentInit, "prep")
    def test_subcloud_deploy_enroll_failed(self, mock_subcloud_enrollment_prep):

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INIT_ENROLL_COMPLETE,
            data_install=json.dumps(self.fake_payload_enroll["install_values"]),
        )

        self.sm.subcloud_deploy_enroll(self.ctx, subcloud.id, self.fake_payload_enroll)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.payload["name"])

        self.assertEqual(
            consts.DEPLOY_STATE_PRE_ENROLL_FAILED, updated_subcloud.deploy_status
        )

    @mock.patch.object(subcloud_enrollment.SubcloudEnrollmentInit, "prep")
    @mock.patch.object(subcloud_enrollment.SubcloudEnrollmentInit, "enroll_init")
    @mock.patch.object(cutils, "get_region_name")
    def test_subcloud_deploy_enroll_run_playbook_failed(
        self,
        mock_get_region_name,
        mock_subcloud_enrollment_prep,
        mock_subcloud_enrollment_enroll_init,
    ):

        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()
        mock_get_region_name.return_value = "11111"

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_PRE_ENROLL_COMPLETE,
            data_install=json.dumps(self.fake_payload_enroll["install_values"]),
        )

        self.sm.subcloud_deploy_enroll(self.ctx, subcloud.id, self.fake_payload_enroll)

        self.mock_ansible_run_playbook.assert_called_once()

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.payload["name"])
        self.assertEqual(
            consts.DEPLOY_STATE_ENROLL_FAILED, updated_subcloud.deploy_status
        )
        # Verify the subcloud rehomed flag is False after bootstrapped
        self.assertFalse(updated_subcloud.rehomed)
        self.mock_log_subcloud_manager.error.assert_called_once_with(
            "Enroll failed for subcloud fake_subcloud1: FAILED enrolling playbook of "
            "(fake_subcloud1).\ncheck individual log at /var/log/dcmanager/ansible/"
            "fake_subcloud1_playbook_output.log for detailed output"
        )

    @mock.patch.object(
        cutils, "find_ansible_error_msg", return_value="Fake playbook error"
    )
    @mock.patch.object(subcloud_enrollment.SubcloudEnrollmentInit, "prep")
    @mock.patch.object(subcloud_enrollment.SubcloudEnrollmentInit, "enroll_init")
    @mock.patch.object(cutils, "get_region_name")
    def test_subcloud_deploy_enroll_find_and_save_ansible_error(
        self,
        mock_get_region_name,
        mock_subcloud_enrollment_enroll_init,
        mock_subcloud_enrollment_prep,
        mock_find_msg,
    ):

        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()
        mock_get_region_name.return_value = "11111"

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_PRE_ENROLL_COMPLETE,
            data_install=json.dumps(self.fake_payload_enroll["install_values"]),
        )

        self.sm.subcloud_deploy_enroll(self.ctx, subcloud.id, self.fake_payload_enroll)

        self.mock_ansible_run_playbook.assert_called_once()

        mock_find_msg.assert_called_once_with(
            subcloud.name, mock.ANY, consts.DEPLOY_STATE_ENROLLING
        )

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.payload["name"])
        self.assertEqual("Fake playbook error", updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_ENROLL_FAILED, updated_subcloud.deploy_status
        )
        self.assertFalse(updated_subcloud.rehomed)

    @mock.patch.object(cutils, "get_region_name")
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "subcloud_init_enroll", return_value=True
    )
    def test_subcloud_deploy_enroll_find_and_save_ansible_timeout(
        self, mock_init_enroll, mock_get_region_name
    ):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionTimeout()
        mock_get_region_name.return_value = "11111"

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_PRE_ENROLL_COMPLETE,
            data_install=json.dumps(self.fake_payload_enroll["install_values"]),
        )

        self.sm.subcloud_deploy_enroll(self.ctx, subcloud.id, self.fake_payload_enroll)

        self.mock_ansible_run_playbook.assert_called_once()

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertIn("Timeout", updated_subcloud.error_description)
        self.assertIn(subcloud.name, updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_ENROLL_FAILED, updated_subcloud.deploy_status
        )
        self.assertFalse(updated_subcloud.rehomed)


class TestSubcloudAdd(BaseTestSubcloudManager):
    """Test class for testing subcloud add"""

    def setUp(self):
        super().setUp()
        self.mock_write_subcloud_ansible_config = self._mock_object(
            subcloud_manager.SubcloudManager, "_write_subcloud_ansible_config"
        )
        self.mock_create_addn_hosts = self._mock_object(
            subcloud_manager.SubcloudManager, "_create_addn_hosts_dc"
        )
        self.mock_create_intermediate_ca_cert = self._mock_object(
            subcloud_manager.SubcloudManager, "_create_intermediate_ca_cert"
        )
        self.mock_openstack_driver().keystone_client = FakeKeystoneClient()
        self.mock_get_cached_regionone_data = self._mock_object(
            subcloud_manager.SubcloudManager, "_get_cached_regionone_data"
        )
        self.mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA
        self.mock_subcloud_init_enroll = self._mock_object(
            subcloud_manager.SubcloudManager, "subcloud_init_enroll"
        )
        self.mock_get_region_name = self._mock_object(cutils, "get_region_name")
        self.mock_run_subcloud_enroll = self._mock_object(
            subcloud_manager.SubcloudManager, "_run_subcloud_enroll"
        )
        self.mock_subcloud_deploy_complete = self._mock_object(
            subcloud_manager.SubcloudManager, "subcloud_deploy_complete"
        )
        self.fake_install_values = copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        self.fake_install_values["software_version"] = SW_VERSION

    @mock.patch.object(cutils, "get_oam_floating_ip_primary")
    @mock.patch.object(subcloud_install.SubcloudInstall, "prep")
    @mock.patch.object(subcloud_manager.SubcloudManager, "_write_deploy_files")
    @mock.patch.object(cutils, "update_values_on_yaml_file")
    def test_add_subcloud(
        self,
        mock_update_yml,
        mock_write_deploy_files,
        mock_install_prep,
        mock_oam_address,
    ):
        # Prepare the payload
        install_values = copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        install_values["software_version"] = SW_VERSION
        payload = {
            **fake_subcloud.FAKE_BOOTSTRAP_VALUE,
            **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA,
            "sysadmin_password": "testpass",
            "bmc_password": "bmc_pass",
            "install_values": install_values,
            "software_version": FAKE_PREVIOUS_SW_VERSION,
            "deploy_playbook": "test_playbook.yaml",
            "deploy_overrides": "test_overrides.yaml",
            "deploy_chart": "test_chart.yaml",
            "deploy_config": "subcloud1.yaml",
            "user_uploaded_artifacts": True,
        }

        # Create subcloud in DB
        subcloud = self.create_subcloud_static(self.ctx, name=payload["name"])
        payload["region_name"] = subcloud.region_name

        # Mock return values
        self.mock_get_playbook_for_software_version.return_value = SW_VERSION
        self.mock_keyring.get_password.return_value = payload["sysadmin_password"]
        self.mock_ansible_run_playbook.return_value = False

        # Call the add method
        self.sm.add_subcloud(self.ctx, subcloud.id, payload)

        # Verify results
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE, updated_subcloud.deploy_status)

        mock_write_deploy_files.assert_called()
        self.mock_keyring.get_password.assert_called()
        mock_update_yml.assert_called()
        self.mock_create_subcloud_inventory.assert_called()
        self.mock_get_playbook_for_software_version.assert_called_once()
        self.assertEqual(self.mock_ansible_run_playbook.call_count, 3)

    @mock.patch.object(subcloud_manager.SubcloudManager, "compose_rehome_command")
    def test_add_subcloud_with_migration_option(self, mock_compose_rehome_command):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values["deploy_status"] = consts.DEPLOY_STATE_NONE
        values["migrate"] = "true"
        sysadmin_password = values["sysadmin_password"]

        # dcmanager add_subcloud queries the data from the db
        subcloud = self.create_subcloud_static(
            self.ctx, name=values["name"], region_name=values["region_name"]
        )

        self.mock_keyring.get_password.return_value = sysadmin_password

        self.sm.add_subcloud(self.ctx, subcloud.id, payload=values)

        self.mock_get_cached_regionone_data.assert_called_once()
        self.mock_sysinv_client().create_route.assert_called()
        self.mock_dcorch_api().add_subcloud.assert_called_once()
        self.mock_create_addn_hosts.assert_called_once()
        self.mock_create_subcloud_inventory.assert_called_once()
        self.mock_write_subcloud_ansible_config.assert_called_once()
        self.mock_create_intermediate_ca_cert.assert_called_once()
        mock_compose_rehome_command.assert_called_once_with(
            values["name"],
            values["region_name"],
            self.sm._get_ansible_filename(
                values["name"], consts.INVENTORY_FILE_POSTFIX
            ),
            subcloud["software_version"],
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, values["name"])
        self.assertEqual(consts.DEPLOY_STATE_DONE, updated_subcloud.deploy_status)
        # Verify subcloud rehomed flag is true
        self.assertTrue(updated_subcloud.rehomed)

        # Verify that the password fields are present
        written_payload = self.mock_write_subcloud_ansible_config.call_args.args[1]
        expected_subset = {
            "ansible_become_pass": sysadmin_password,
            "ansible_ssh_pass": sysadmin_password,
            "admin_password": sysadmin_password,
        }
        # Check that expected_subset is a subset of written_payload
        self.assertTrue(expected_subset.items() <= written_payload.items())

    def test_add_subcloud_create_failed(self):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)

        # dcmanager add_subcloud queries the data from the db
        subcloud = self.create_subcloud_static(
            self.ctx, name=values["name"], region_name=values["region_name"]
        )

        self.mock_dcorch_api().add_subcloud.side_effect = Exception("boom")

        self.sm.add_subcloud(self.ctx, subcloud.id, payload=values)
        self.mock_get_cached_regionone_data.assert_called_once()
        self.mock_sysinv_client().create_route.assert_called()

        # Verify subcloud was updated with correct values
        subcloud = db_api.subcloud_get_by_name(self.ctx, values["name"])
        self.assertEqual(consts.DEPLOY_STATE_CREATE_FAILED, subcloud.deploy_status)

    def test_add_subcloud_with_migrate_option_prep_failed(self):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values["migrate"] = "true"

        # dcmanager add_subcloud queries the data from the db
        subcloud = self.create_subcloud_static(
            self.ctx, name=values["name"], region_name=values["region_name"]
        )

        self.mock_dcorch_api().add_subcloud.side_effect = Exception("boom")
        self.mock_keyring.get_password.return_vaue = "testpass"

        self.sm.add_subcloud(self.ctx, subcloud.id, payload=values)
        self.mock_get_cached_regionone_data.assert_called_once()
        self.mock_sysinv_client().create_route.assert_called()

        # Verify subcloud was updated with correct values
        subcloud = db_api.subcloud_get_by_name(self.ctx, values["name"])
        self.assertEqual(consts.DEPLOY_STATE_REHOME_PREP_FAILED, subcloud.deploy_status)

    def test_add_subcloud_with_enroll_option(self):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values["deploy_status"] = consts.DEPLOY_STATE_NONE
        values["enroll"] = "true"
        values["install_values"] = self.fake_install_values
        values["deploy_config"] = self.fake_payload
        sysadmin_password = values["sysadmin_password"]

        subcloud = self.create_subcloud_static(
            self.ctx, name=values["name"], region_name=values["region_name"]
        )

        self.mock_keyring.get_password.return_value = sysadmin_password
        self.mock_subcloud_init_enroll.return_value = True
        self.mock_get_region_name.return_value = values["region_name"]
        self.mock_run_subcloud_enroll.return_value = True

        self.sm.add_subcloud(self.ctx, subcloud.id, payload=values)

        self.mock_subcloud_init_enroll.assert_called_once()
        self.mock_get_region_name.assert_called_once()
        self.mock_get_cached_regionone_data.assert_called()
        self.mock_sysinv_client().create_route.assert_called()
        self.mock_dcorch_api().add_subcloud.assert_called_once()
        self.mock_create_addn_hosts.assert_called()
        self.mock_create_subcloud_inventory.assert_called()
        self.mock_write_subcloud_ansible_config.assert_called()
        self.mock_create_intermediate_ca_cert.assert_called_once()

    def test_add_subcloud_with_init_enroll_fail(self):
        """Test subcloud add with init enroll fail"""

        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values["deploy_status"] = consts.DEPLOY_STATE_NONE
        values["enroll"] = "true"
        values["install_values"] = self.fake_install_values
        sysadmin_password = values["sysadmin_password"]

        subcloud = self.create_subcloud_static(
            self.ctx, name=values["name"], region_name=values["region_name"]
        )

        self.sm.add_subcloud(self.ctx, subcloud.id, payload=values)

        self.mock_keyring.get_password.return_value = sysadmin_password
        self.mock_subcloud_init_enroll.return_value = False

        self.mock_subcloud_init_enroll.assert_called_once()
        self.mock_subcloud_deploy_complete.assert_not_called()


class TestSubcloudDelete(BaseTestSubcloudManager):
    """Test class for testing subcloud delete"""

    def setUp(self):
        super().setUp()
        self.mock_openstack_driver().keystone_client = FakeKeystoneClient()
        self.mock_get_cached_regionone_data = self._mock_object(
            subcloud_manager.SubcloudManager, "_get_cached_regionone_data"
        )
        self.mock_get_cached_regionone_data.return_value = FAKE_CACHED_REGIONONE_DATA
        self.mock_is_system_controller_deploying = self._mock_object(
            cutils, "is_system_controller_deploying"
        )

    @mock.patch.object(kubeoperator, "KubeOperator")
    def test_delete_subcloud(self, mock_kubeoperator):
        self.mock_create_addn_hosts = self._mock_object(
            subcloud_manager.SubcloudManager, "_create_addn_hosts_dc"
        )
        self.mock_is_system_controller_deploying.return_value = False
        self.sm.delete_subcloud(self.ctx, subcloud_id=self.subcloud.id)
        self.mock_get_cached_regionone_data.assert_called_once()
        self.mock_sysinv_client().delete_route.assert_called()
        self.mock_create_addn_hosts.assert_called_once()
        mock_kubeoperator().delete_cert_manager_certificate.assert_called_once()

        # Verify subcloud was deleted
        self.assertRaises(
            exceptions.SubcloudNameNotFound,
            db_api.subcloud_get_by_name,
            self.ctx,
            self.subcloud.name,
        )

    def test_delete_subcloud_failed(self):
        # Semantic checking
        db_api.subcloud_update(self.ctx, self.subcloud.id, management_state="managed")
        self.assertRaises(
            exceptions.SubcloudNotUnmanaged,
            self.sm.delete_subcloud,
            self.ctx,
            self.subcloud.id,
        )
        subcloud2 = self.create_subcloud_static(self.ctx, name="subcloud2")
        db_api.subcloud_update(self.ctx, subcloud2.id, availability_status="online")
        self.assertRaises(
            exceptions.SubcloudNotOffline,
            self.sm.delete_subcloud,
            self.ctx,
            subcloud2.id,
        )

    @mock.patch("shutil.rmtree")
    def test_cleanup_ansible_files(self, mock_rmtree):
        self.sm._cleanup_ansible_files("subcloud1")

        files = (
            "subcloud1.yml",
            "subcloud1_deploy_values.yml",
            "subcloud1_deploy_config.yml",
        )

        calls = []
        for f in files:
            filepath = os.path.join(ANS_PATH, f)
            calls.append(mock.call(filepath))

        install_dir = os.path.join(ANS_PATH, "subcloud1")

        self.mock_os_remove.assert_has_calls(calls, any_order=True)
        mock_rmtree.assert_called_with(install_dir)

    @mock.patch("shutil.rmtree")
    def test_cleanup_ansible_files_exception(self, mock_rmtree):
        self.mock_os_remove.side_effect = FileNotFoundError()
        self.sm._cleanup_ansible_files("subcloud1")
        self.mock_log_subcloud_manager.exception.assert_called_once_with(
            "Unable to cleanup subcloud ansible files for subcloud: subcloud1"
        )


class TestSubcloudUpdate(BaseTestSubcloudManager):
    """Test class for testing subcloud update"""

    def setUp(self):
        super().setUp()
        # Revert the mock to the original method to enable the usage of lock files
        self.mock_builtins_open.side_effect = self.original_builtins_open
        self.fake_bootstrap_values = (
            '{"name": "TestSubcloud", "system_mode": "simplex"}'
        )
        self._test_values()

    def _test_values(self):
        values = utils.create_subcloud_dict(base.SUBCLOUD_SAMPLE_DATA_0)
        values["management_gateway_ip"] = "192.168.101.1"
        values["management_start_ip"] = "192.168.101.2"
        values["system_controller_network"] = "fdff:719a:bf60:233::"
        values["system_controller_network_prefix"] = 64
        values["dc_root_ca_cert"] = "fake_dc_root_ca_cert"
        values["sc_ca_cert"] = "fake_sc_ca_cert"
        values["sc_ca_key"] = "fake_sc_ca_key"
        return values

    def test_update_subcloud(self):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        self.sm.update_subcloud(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            description="subcloud new description",
            location="subcloud new location",
        )

        self.mock_dcmanager_api().subcloud_managed.assert_called_once_with(
            self.ctx, self.subcloud.region_name
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            dccommon_consts.MANAGEMENT_MANAGED, updated_subcloud.management_state
        )
        self.assertEqual("subcloud new description", updated_subcloud.description)
        self.assertEqual("subcloud new location", updated_subcloud.location)

    def test_update_subcloud_managed_rehome_pending(self):
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_REHOME_PENDING,
        )

        self.sm.update_subcloud(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )

        self.mock_dcmanager_api().subcloud_managed.assert_called_once_with(
            self.ctx, self.subcloud.region_name
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE, updated_subcloud.deploy_status)

    def test_update_subcloud_bootstrap_address_failed(self):
        """Failed updating bootstrap-address because bootstrap_values are missing."""

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        fake_bootstrap_address = "10.10.20.12"
        self.assertRaisesRegex(
            exceptions.BadRequest,
            (
                "Cannot update bootstrap_address into rehome data, need to "
                "import bootstrap_values first"
            ),
            self.sm.update_subcloud,
            self.ctx,
            self.subcloud.id,
            bootstrap_address=fake_bootstrap_address,
        )

    def test_update_subcloud_deploy_state_secondary(self):
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )
        self.sm.update_subcloud(
            self.ctx, self.subcloud.id, deploy_status=consts.DEPLOY_STATE_SECONDARY
        )
        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_SECONDARY, updated_subcloud.deploy_status)

    def test_update_subcloud_bootstrap_values(self):
        fake_result = f'{{"saved_payload": {self.fake_bootstrap_values}}}'
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        self.sm.update_subcloud(
            self.ctx, self.subcloud.id, bootstrap_values=self.fake_bootstrap_values
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(fake_result, updated_subcloud.rehome_data)

    def test_update_subcloud_bootstrap_address(self):
        fake_result = (
            '{"saved_payload": {"name": "TestSubcloud", '
            '"system_mode": "simplex", '
            '"bootstrap-address": "123.123.123.123"}}'
        )
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        self.sm.update_subcloud(
            self.ctx,
            self.subcloud.id,
            bootstrap_values=self.fake_bootstrap_values,
            bootstrap_address="123.123.123.123",
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(fake_result, updated_subcloud.rehome_data)

    def test_update_subcloud_management_state_failed(self):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_REHOME_PENDING,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        self.mock_dcorch_api().update_subcloud_states.side_effect = Exception("boom")

        self.sm.update_subcloud(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            dccommon_consts.MANAGEMENT_UNMANAGED, updated_subcloud.management_state
        )
        self.assertEqual(
            consts.DEPLOY_STATE_REHOME_PENDING, updated_subcloud.deploy_status
        )

    def test_update_subcloud_deploy_state_rehome_pending(self):
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )
        for state in (
            consts.DEPLOY_STATE_REHOME_PENDING,
            consts.DEPLOY_STATE_SECONDARY,
        ):
            self.assertRaisesRegex(
                exceptions.BadRequest,
                "Unable to update deploy_status of subcloud "
                f"{self.subcloud.name} to {state}",
                self.sm.update_subcloud,
                self.ctx,
                self.subcloud.id,
                deploy_status=state,
            )

    def test_update_subcloud_manage_with_invalid_deploy_status_failed(self):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        for state in (
            consts.DEPLOY_STATE_REHOME_PENDING,
            consts.DEPLOY_STATE_SECONDARY,
        ):
            self.assertRaisesRegex(
                exceptions.BadRequest,
                f"Unable to manage {self.subcloud.name} while also updating "
                f"its deploy_status to {state}: not allowed",
                self.sm.update_subcloud,
                self.ctx,
                self.subcloud.id,
                management_state=dccommon_consts.MANAGEMENT_MANAGED,
                deploy_status=state,
            )

    def test_update_subcloud_rehome_data(self):
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        fake_result = (
            '{"saved_payload": {"name": "TestSubcloud", '
            '"system_mode": "simplex", '
            '"admin_password": "dGVzdHBhc3M=", '
            '"bootstrap-address": "123.123.123.123"}}'
        )
        fake_bootstrap_values = (
            '{"name": "TestSubcloud",'
            '"system_mode": "simplex", "sysadmin_password": "testpass",'
            '"ansible_ssh_pass": "fakepass", "ansible_become_pass": "fakepass",'
            '"admin_password": "testpass"}'
        )
        fake_bootstrap_address = "123.123.123.123"

        self.sm.update_subcloud(
            self.ctx,
            self.subcloud.id,
            bootstrap_values=fake_bootstrap_values,
            bootstrap_address=fake_bootstrap_address,
        )
        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(fake_result, updated_subcloud.rehome_data)

    def test_update_subcloud_with_install_values(self):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        self.sm.update_subcloud(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            description="subcloud new description",
            location="subcloud new location",
            data_install="install values",
        )

        self.mock_dcmanager_api().subcloud_managed.assert_called_once_with(
            self.ctx, self.subcloud.region_name
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            dccommon_consts.MANAGEMENT_MANAGED, updated_subcloud.management_state
        )
        self.assertEqual("subcloud new description", updated_subcloud.description)
        self.assertEqual("subcloud new location", updated_subcloud.location)
        self.assertEqual("install values", updated_subcloud.data_install)

    def test_update_already_managed_subcloud(self):
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )

        self.assertRaisesRegex(
            exceptions.BadRequest,
            f"Subcloud {self.subcloud.name} already managed",
            self.sm.update_subcloud,
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )
        self.mock_audit_rpc_client().trigger_subcloud_audits.assert_not_called()

    def test_update_already_unmanaged_subcloud(self):
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        self.assertRaisesRegex(
            exceptions.BadRequest,
            f"Subcloud {self.subcloud.name} already unmanaged",
            self.sm.update_subcloud,
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )
        self.mock_audit_rpc_client().trigger_subcloud_audits.assert_not_called()

    def test_update_management_unmanaged(self):
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )
        self.sm.update_subcloud(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )
        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            dccommon_consts.MANAGEMENT_UNMANAGED, updated_subcloud.management_state
        )

    def test_manage_when_deploy_status_failed(self):
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DEPLOY_FAILED
        self.assertRaisesRegex(
            exceptions.BadRequest,
            (
                f"Unable to manage {self.subcloud.name}: its deploy_status "
                f"must be either '{consts.DEPLOY_STATE_DONE}' or "
                f"'{consts.DEPLOY_STATE_REHOME_PENDING}'"
            ),
            self.sm.update_subcloud,
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )

    def test_manage_when_offline_without_force(self):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
        )
        self.assertRaises(
            exceptions.SubcloudNotOnline,
            self.sm.update_subcloud,
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )

    def test_manage_when_offline_with_force(self):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
        )

        self.sm.update_subcloud(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            description="subcloud new description",
            location="subcloud new location",
            data_install="install values",
            force=True,
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            dccommon_consts.MANAGEMENT_MANAGED, updated_subcloud.management_state
        )
        self.assertEqual("subcloud new description", updated_subcloud.description)
        self.assertEqual("subcloud new location", updated_subcloud.location)
        self.assertEqual("install values", updated_subcloud.data_install)

    def test_update_subcloud_group_id(self):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        self.sm.update_subcloud(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            description="subcloud new description",
            location="subcloud new location",
            group_id=2,
        )
        self.mock_dcmanager_api().subcloud_managed.assert_called_once_with(
            self.ctx, self.subcloud.region_name
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            dccommon_consts.MANAGEMENT_MANAGED, updated_subcloud.management_state
        )
        self.assertEqual("subcloud new description", updated_subcloud.description)
        self.assertEqual("subcloud new location", updated_subcloud.location)
        self.assertEqual(2, updated_subcloud.group_id)

    def test_update_subcloud_endpoint_status(self):
        self.assertIsNotNone(self.subcloud)
        self.assertEqual(
            self.subcloud.management_state, dccommon_consts.MANAGEMENT_UNMANAGED
        )
        self.assertEqual(
            self.subcloud.availability_status, dccommon_consts.AVAILABILITY_OFFLINE
        )

        # create sync statuses for endpoints
        for endpoint in [
            dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            dccommon_consts.ENDPOINT_TYPE_FM,
            dccommon_consts.ENDPOINT_TYPE_NFV,
            dccommon_consts.ENDPOINT_TYPE_DC_CERT,
        ]:
            status = db_api.subcloud_status_create(self.ctx, self.subcloud.id, endpoint)
            self.assertIsNotNone(status)
            self.assertEqual(status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN)

        # Update/verify each status with the default sync state: out-of-sync
        ssm = subcloud_state_manager.SubcloudStateManager()
        for endpoint in [
            dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            dccommon_consts.ENDPOINT_TYPE_FM,
            dccommon_consts.ENDPOINT_TYPE_NFV,
            dccommon_consts.ENDPOINT_TYPE_DC_CERT,
        ]:
            # Update
            ssm.update_subcloud_endpoint_status(
                self.ctx,
                subcloud_region=self.subcloud.region_name,
                endpoint_type=endpoint,
            )

            # Verify
            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, self.subcloud.id, endpoint
            )
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(
                updated_subcloud_status.sync_status,
                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            )

        # Attempt to update each status to be in-sync for an offline/unmanaged
        # subcloud. This is not allowed. Verify no change.
        for endpoint in [
            dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            dccommon_consts.ENDPOINT_TYPE_FM,
            dccommon_consts.ENDPOINT_TYPE_NFV,
            dccommon_consts.ENDPOINT_TYPE_DC_CERT,
        ]:
            ssm.update_subcloud_endpoint_status(
                self.ctx,
                subcloud_region=self.subcloud.region_name,
                endpoint_type=endpoint,
                sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC,
            )

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, self.subcloud.id, endpoint
            )
            self.assertIsNotNone(updated_subcloud_status)
            # No change in status: Only online/managed clouds are updated
            self.assertEqual(
                updated_subcloud_status.sync_status,
                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            )

        # Attempt to update each status to be unknown for an offline/unmanaged
        # subcloud. This is allowed.
        ssm.update_subcloud_endpoint_status(
            self.ctx,
            subcloud_region=self.subcloud.region_name,
            endpoint_type=None,
            sync_status=dccommon_consts.SYNC_STATUS_UNKNOWN,
        )

        for endpoint in [
            dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            dccommon_consts.ENDPOINT_TYPE_FM,
            dccommon_consts.ENDPOINT_TYPE_NFV,
            dccommon_consts.ENDPOINT_TYPE_DC_CERT,
        ]:
            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, self.subcloud.id, endpoint
            )
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(
                updated_subcloud_status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN
            )

        # Attempt to update each status to be out-of-sync for an
        # offline/unmanaged subcloud. Exclude one endpoint. This is allowed.
        ssm.update_subcloud_endpoint_status(
            self.ctx,
            subcloud_region=self.subcloud.region_name,
            endpoint_type=None,
            sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            ignore_endpoints=[dccommon_consts.ENDPOINT_TYPE_DC_CERT],
        )

        for endpoint in [
            dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            dccommon_consts.ENDPOINT_TYPE_FM,
            dccommon_consts.ENDPOINT_TYPE_NFV,
        ]:
            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, self.subcloud.id, endpoint
            )
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(
                updated_subcloud_status.sync_status,
                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            )
        # Verify the dc-sync endpoint did not change
        endpoint = dccommon_consts.ENDPOINT_TYPE_DC_CERT
        updated_subcloud_status = db_api.subcloud_status_get(
            self.ctx, self.subcloud.id, endpoint
        )
        self.assertIsNotNone(updated_subcloud_status)
        self.assertEqual(
            updated_subcloud_status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN
        )

        # Set/verify the subcloud is online/unmanaged
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )
        subcloud = db_api.subcloud_get(self.ctx, self.subcloud.id)
        self.assertIsNotNone(subcloud)
        self.assertEqual(
            subcloud.management_state, dccommon_consts.MANAGEMENT_UNMANAGED
        )
        self.assertEqual(
            subcloud.availability_status, dccommon_consts.AVAILABILITY_ONLINE
        )

        # Attempt to update each status to be in-sync for an online/unmanaged
        # subcloud. This is not allowed. Verify no change.
        for endpoint in [
            dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            dccommon_consts.ENDPOINT_TYPE_FM,
            dccommon_consts.ENDPOINT_TYPE_NFV,
        ]:
            ssm.update_subcloud_endpoint_status(
                self.ctx,
                subcloud_region=subcloud.region_name,
                endpoint_type=endpoint,
                sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC,
            )

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint
            )
            self.assertIsNotNone(updated_subcloud_status)
            # No change in status: Only online/managed clouds are updated
            self.assertEqual(
                updated_subcloud_status.sync_status,
                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            )

        # Attempt to update dc-cert status to be in-sync for an
        # online/unmanaged subcloud. This is allowed. Verify the change.
        endpoint = dccommon_consts.ENDPOINT_TYPE_DC_CERT
        ssm.update_subcloud_endpoint_status(
            self.ctx,
            subcloud_region=subcloud.region_name,
            endpoint_type=endpoint,
            sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC,
        )

        updated_subcloud_status = db_api.subcloud_status_get(
            self.ctx, subcloud.id, endpoint
        )
        self.assertIsNotNone(updated_subcloud_status)
        self.assertEqual(
            updated_subcloud_status.sync_status, dccommon_consts.SYNC_STATUS_IN_SYNC
        )

        # Set/verify the subcloud is online/managed
        db_api.subcloud_update(
            self.ctx, subcloud.id, management_state=dccommon_consts.MANAGEMENT_MANAGED
        )
        subcloud = db_api.subcloud_get(self.ctx, subcloud.id)
        self.assertIsNotNone(subcloud)
        self.assertEqual(subcloud.management_state, dccommon_consts.MANAGEMENT_MANAGED)
        self.assertEqual(
            subcloud.availability_status, dccommon_consts.AVAILABILITY_ONLINE
        )

        # Attempt to update each status to be in-sync for an online/managed
        # subcloud
        for endpoint in [
            dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            dccommon_consts.ENDPOINT_TYPE_FM,
            dccommon_consts.ENDPOINT_TYPE_NFV,
            dccommon_consts.ENDPOINT_TYPE_DC_CERT,
        ]:
            ssm.update_subcloud_endpoint_status(
                self.ctx,
                subcloud_region=subcloud.region_name,
                endpoint_type=endpoint,
                sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC,
            )

            updated_subcloud_status = db_api.subcloud_status_get(
                self.ctx, subcloud.id, endpoint
            )
            self.assertIsNotNone(updated_subcloud_status)
            self.assertEqual(
                updated_subcloud_status.sync_status, dccommon_consts.SYNC_STATUS_IN_SYNC
            )

        # Change the sync status to 'out-of-sync' and verify fair lock access
        # based on subcloud name for each update
        with mock.patch.object(lockutils, "internal_fair_lock") as mock_lock:
            for endpoint in [
                dccommon_consts.ENDPOINT_TYPE_PLATFORM,
                dccommon_consts.ENDPOINT_TYPE_IDENTITY,
                dccommon_consts.ENDPOINT_TYPE_FM,
                dccommon_consts.ENDPOINT_TYPE_NFV,
                dccommon_consts.ENDPOINT_TYPE_DC_CERT,
            ]:
                ssm.update_subcloud_endpoint_status(
                    self.ctx,
                    subcloud_region=subcloud.region_name,
                    endpoint_type=endpoint,
                    sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
                )
                # Verify lock was called
                mock_lock.assert_called_with(subcloud.region_name)

                # Verify status was updated
                updated_subcloud_status = db_api.subcloud_status_get(
                    self.ctx, subcloud.id, endpoint
                )
                self.assertIsNotNone(updated_subcloud_status)
                self.assertEqual(
                    updated_subcloud_status.sync_status,
                    dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
                )

    def test_update_subcloud_availability_go_online(self):
        self.assertIsNotNone(self.subcloud)
        self.assertEqual(
            self.subcloud.availability_status, dccommon_consts.AVAILABILITY_OFFLINE
        )

        ssm = subcloud_state_manager.SubcloudStateManager()
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )

        # create sync statuses for endpoints
        for endpoint in [
            dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            dccommon_consts.ENDPOINT_TYPE_FM,
            dccommon_consts.ENDPOINT_TYPE_NFV,
            dccommon_consts.ENDPOINT_TYPE_DC_CERT,
        ]:
            status = db_api.subcloud_status_create(self.ctx, self.subcloud.id, endpoint)
            self.assertIsNotNone(status)
            self.assertEqual(status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN)

        ssm.update_subcloud_availability(
            self.ctx,
            self.subcloud.name,
            self.subcloud.region_name,
            dccommon_consts.AVAILABILITY_ONLINE,
        )

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, "subcloud1")
        # Verify the subcloud was set to online
        self.assertEqual(
            updated_subcloud.availability_status, dccommon_consts.AVAILABILITY_ONLINE
        )
        # Verify notifying dcorch
        self.mock_dcorch_api().update_subcloud_states.assert_called_once_with(
            self.ctx,
            self.subcloud.region_name,
            updated_subcloud.management_state,
            dccommon_consts.AVAILABILITY_ONLINE,
        )
        # Verify triggering audits
        self.mock_audit_rpc_client().trigger_subcloud_audits.assert_called_once_with(
            self.ctx, self.subcloud.id
        )

        self.mock_dcmanager_api().subcloud_online.assert_called_once_with(
            self.ctx, self.subcloud.region_name
        )

    def test_bulk_update_subcloud_availability_and_endpoint_status(self):
        availability_data = {
            "availability_status": dccommon_consts.AVAILABILITY_OFFLINE,
            "update_state_only": False,
            "audit_fail_count": 1,
        }
        FIRMWARE = dccommon_consts.ENDPOINT_TYPE_FIRMWARE
        endpoint_data = {
            FIRMWARE: dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        }
        endpoints = db_api.subcloud_status_get_all(self.ctx, self.subcloud.id)

        self.subcloud = db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )

        ssm = subcloud_state_manager.SubcloudStateManager()
        ssm.bulk_update_subcloud_availability_and_endpoint_status(
            self.ctx,
            self.subcloud.id,
            self.subcloud.name,
            availability_data,
            endpoint_data,
        )

        updated_subcloud = db_api.subcloud_get(self.ctx, self.subcloud.id)
        self.assertEqual(
            updated_subcloud.availability_status,
            availability_data["availability_status"],
        )

        new_endpoints = db_api.subcloud_status_get_all(self.ctx, self.subcloud.id)
        for index, endpoint in enumerate(endpoints):
            self.assertEqual(endpoint.endpoint_type, new_endpoints[index].endpoint_type)
            if endpoint.endpoint_type in endpoint_data:
                self.assertEqual(
                    new_endpoints[index].sync_status,
                    endpoint_data[endpoint.endpoint_type],
                )
            else:
                self.assertEqual(endpoint.sync_status, new_endpoints[index].sync_status)

    @mock.patch.object(
        db_api,
        "subcloud_status_bulk_update_endpoints",
        wraps=db_api.subcloud_status_bulk_update_endpoints,
    )
    def test_bulk_update_endpoint_status_when_endpoint_status_is_the_same(
        self, mock_db
    ):
        """Test bulk_update_endpoint_status updates the endpoint with same status

        When the endpoint's status in the database is the same as the one it'll be
        updated to, ensure that, instead of validating, bulk_update_endpoint_status
        just skip it
        """

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )

        FIRMWARE = dccommon_consts.ENDPOINT_TYPE_FIRMWARE
        endpoint_data = {
            FIRMWARE: dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        }

        ssm = subcloud_state_manager.SubcloudStateManager()
        ssm.bulk_update_subcloud_availability_and_endpoint_status(
            self.ctx,
            self.subcloud.id,
            self.subcloud.name,
            None,
            endpoint_data,
        )

        self.assertEqual(mock_db.call_count, 1)

        # Re-executing the method should result in no extra calls
        # for the database query since there are no updates
        ssm.bulk_update_subcloud_availability_and_endpoint_status(
            self.ctx,
            self.subcloud.id,
            self.subcloud.name,
            None,
            endpoint_data,
        )

        self.assertEqual(mock_db.call_count, 1)

    @mock.patch.object(
        subcloud_state_manager.SubcloudStateManager,
        "_raise_or_clear_subcloud_status_alarm",
    )
    def test_update_state_only(self, mock_update_status_alarm):
        self.assertIsNotNone(self.subcloud)

        # Set the subcloud to online/managed
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        ssm = subcloud_state_manager.SubcloudStateManager()

        with mock.patch.object(db_api, "subcloud_update") as subcloud_update_mock:
            ssm.update_subcloud_availability(
                self.ctx,
                self.subcloud.name,
                self.subcloud.region_name,
                availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                update_state_only=True,
            )
            # Verify that the subcloud was not updated
            subcloud_update_mock.assert_not_called()

        # Verify alarm status update was attempted
        mock_update_status_alarm.assert_called_once()

        # Verify dcorch was notified
        self.mock_dcorch_api().update_subcloud_states.assert_called_once_with(
            self.ctx,
            self.subcloud.region_name,
            self.subcloud.management_state,
            dccommon_consts.AVAILABILITY_ONLINE,
        )

        # Verify audits were not triggered
        self.mock_audit_rpc_client.trigger_subcloud_audits.assert_not_called()

    def test_update_subcloud_availability_go_online_unmanaged(self):
        self.assertIsNotNone(self.subcloud)
        self.assertEqual(
            self.subcloud.availability_status, dccommon_consts.AVAILABILITY_OFFLINE
        )

        ssm = subcloud_state_manager.SubcloudStateManager()

        # Note that we have intentionally left the subcloud as "unmanaged"

        # create sync statuses for endpoints
        for endpoint in [
            dccommon_consts.ENDPOINT_TYPE_PLATFORM,
            dccommon_consts.ENDPOINT_TYPE_IDENTITY,
            dccommon_consts.ENDPOINT_TYPE_FM,
            dccommon_consts.ENDPOINT_TYPE_NFV,
            dccommon_consts.ENDPOINT_TYPE_DC_CERT,
        ]:
            status = db_api.subcloud_status_create(self.ctx, self.subcloud.id, endpoint)
            self.assertIsNotNone(status)
            self.assertEqual(status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN)

        ssm.update_subcloud_availability(
            self.ctx,
            self.subcloud.name,
            self.subcloud.region_name,
            dccommon_consts.AVAILABILITY_ONLINE,
        )

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, "subcloud1")
        # Verify the subcloud was set to online
        self.assertEqual(
            updated_subcloud.availability_status, dccommon_consts.AVAILABILITY_ONLINE
        )
        # Verify notifying dcorch
        self.mock_dcorch_api().update_subcloud_states.assert_called_once_with(
            self.ctx,
            self.subcloud.region_name,
            updated_subcloud.management_state,
            dccommon_consts.AVAILABILITY_ONLINE,
        )
        # Verify triggering audits
        self.mock_audit_rpc_client().trigger_subcloud_audits.assert_called_once_with(
            self.ctx, self.subcloud.id
        )

        self.mock_dcmanager_api().subcloud_online.assert_called_once_with(
            self.ctx, self.subcloud.region_name
        )

    def test_update_subcloud_availability_go_offline(self):
        self.assertIsNotNone(self.subcloud)

        # Set the subcloud to online/managed
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        ssm = subcloud_state_manager.SubcloudStateManager()

        # create sync statuses for endpoints and set them to in-sync
        for endpoint in dccommon_consts.AUDIT_TYPES_LIST:
            db_api.subcloud_status_create(self.ctx, self.subcloud.id, endpoint)
            ssm.update_subcloud_endpoint_status(
                self.ctx,
                subcloud_region=self.subcloud.region_name,
                endpoint_type=endpoint,
                sync_status=dccommon_consts.SYNC_STATUS_IN_SYNC,
            )

        # We trigger a subcloud audits after updating the identity from unknown
        # to in-sync
        self.mock_audit_rpc_client().trigger_subcloud_audits.assert_called_once_with(
            self.ctx, self.subcloud.id
        )

        # Audit fails once
        audit_fail_count = 1
        ssm.update_subcloud_availability(
            self.ctx,
            self.subcloud.name,
            self.subcloud.region_name,
            availability_status=None,
            audit_fail_count=audit_fail_count,
        )
        # Verify the subcloud availability was not updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, "subcloud1")
        self.assertEqual(
            updated_subcloud.availability_status, dccommon_consts.AVAILABILITY_ONLINE
        )
        # Verify dcorch was not notified
        self.mock_dcorch_api().update_subcloud_states.assert_not_called()
        # Verify the audit_fail_count was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, "subcloud1")
        self.assertEqual(updated_subcloud.audit_fail_count, audit_fail_count)

        # Audit fails again
        audit_fail_count = audit_fail_count + 1
        ssm.update_subcloud_availability(
            self.ctx,
            self.subcloud.name,
            self.subcloud.region_name,
            dccommon_consts.AVAILABILITY_OFFLINE,
            audit_fail_count=audit_fail_count,
        )

        # Verify the subcloud availability was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, "subcloud1")
        self.assertEqual(
            updated_subcloud.availability_status, dccommon_consts.AVAILABILITY_OFFLINE
        )

        # Verify notifying dcorch
        self.mock_dcorch_api().update_subcloud_states.assert_called_once_with(
            self.ctx,
            self.subcloud.region_name,
            updated_subcloud.management_state,
            dccommon_consts.AVAILABILITY_OFFLINE,
        )

        # Verify all endpoint statuses set to unknown
        for self.subcloud, subcloud_status in db_api.subcloud_get_with_status(
            self.ctx, self.subcloud.id
        ):
            self.assertIsNotNone(subcloud_status)
            self.assertEqual(
                subcloud_status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN
            )

    def test_update_subcloud_identity_endpoint(self):
        self.assertIsNotNone(self.subcloud)
        for endpoint_type in dccommon_consts.AUDIT_TYPES_LIST:
            subcloud_status = db_api.subcloud_status_get(
                self.ctx, self.subcloud.id, endpoint_type
            )
            self.assertIsNotNone(subcloud_status)
            self.assertEqual(
                subcloud_status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN
            )

        ssm = subcloud_state_manager.SubcloudStateManager()

        # Set the subcloud to online/managed
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            first_identity_sync_complete=True,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        # Update identity endpoints statuses
        endpoint = dccommon_consts.ENDPOINT_TYPE_IDENTITY
        for original_sync_status in [
            dccommon_consts.SYNC_STATUS_IN_SYNC,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            dccommon_consts.SYNC_STATUS_UNKNOWN,
        ]:

            for new_sync_status in [
                dccommon_consts.SYNC_STATUS_IN_SYNC,
                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
                dccommon_consts.SYNC_STATUS_UNKNOWN,
            ]:

                # Update identity to the original status
                ssm.update_subcloud_endpoint_status(
                    self.ctx,
                    subcloud_region=self.subcloud.region_name,
                    endpoint_type=endpoint,
                    sync_status=original_sync_status,
                )

                # Get the count of the trigger already called
                trigger_subcloud_audits = (
                    self.mock_audit_rpc_client().trigger_subcloud_audits.call_count
                )

                # Update identity to new status and get the count of the trigger
                # again
                ssm.update_subcloud_endpoint_status(
                    self.ctx,
                    subcloud_region=self.subcloud.region_name,
                    endpoint_type=endpoint,
                    sync_status=new_sync_status,
                )
                new_trigger_subcloud_audits = (
                    self.mock_audit_rpc_client().trigger_subcloud_audits.call_count
                )

                trigger_count = new_trigger_subcloud_audits - trigger_subcloud_audits

                if (
                    original_sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN
                    and new_sync_status != dccommon_consts.SYNC_STATUS_UNKNOWN
                ):
                    # Verify the subcloud patch and load audit is triggered once
                    self.assertEqual(trigger_count, 1)
                else:
                    # Verify the subcloud patch and load audit is not triggered
                    self.assertEqual(trigger_count, 0)

    def test_update_subcloud_sync_endpoint_type(self):
        self.assertIsNotNone(self.subcloud)

        endpoint_type_list = dccommon_consts.ENDPOINT_TYPES_LIST_OS

        # Test openstack app installed
        openstack_installed = True
        self.sm.update_subcloud_sync_endpoint_type(
            self.ctx, self.subcloud.region_name, endpoint_type_list, openstack_installed
        )

        # Verify notifying dcorch to add subcloud sync endpoint type
        self.mock_dcorch_api().add_subcloud_sync_endpoint_type.assert_called_once_with(
            self.ctx, self.subcloud.region_name, endpoint_type_list
        )

        # Verify the subcloud status created for os endpoints
        for endpoint in endpoint_type_list:
            subcloud_status = db_api.subcloud_status_get(
                self.ctx, self.subcloud.id, endpoint
            )
            self.assertIsNotNone(subcloud_status)
            self.assertEqual(
                subcloud_status.sync_status, dccommon_consts.SYNC_STATUS_UNKNOWN
            )

        # Verify the subcloud openstack_installed was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(updated_subcloud.openstack_installed, True)

        # Test openstack app removed
        openstack_installed = False
        self.sm.update_subcloud_sync_endpoint_type(
            self.ctx, self.subcloud.region_name, endpoint_type_list, openstack_installed
        )
        # Verify notifying dcorch to remove subcloud sync endpoint type
        remove_endpoint_type = self.mock_dcorch_api().remove_subcloud_sync_endpoint_type
        remove_endpoint_type.assert_called_once_with(
            self.ctx, self.subcloud.region_name, endpoint_type_list
        )

        # Verify the subcloud status is deleted for os endpoints
        for endpoint in endpoint_type_list:
            self.assertRaises(
                exceptions.SubcloudStatusNotFound,
                db_api.subcloud_status_get,
                self.ctx,
                self.subcloud.id,
                endpoint,
            )

        # Verify the subcloud openstack_installed was updated
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(updated_subcloud.openstack_installed, False)

    def test_get_ansible_filename(self):
        filename = cutils.get_ansible_filename(
            "subcloud1", consts.INVENTORY_FILE_POSTFIX
        )
        self.assertEqual(filename, f"{ANS_PATH}/subcloud1_inventory.yml")

    def test_update_subcloud_peer_group_id(self):
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        fake_peer_group_id = 123

        self.sm.update_subcloud(
            self.ctx, self.subcloud.id, peer_group_id=fake_peer_group_id
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(fake_peer_group_id, updated_subcloud.peer_group_id)

    def test_update_subcloud_peer_group_id_to_none(self):

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_DONE
        fake_peer_group_id = 123

        self.sm.update_subcloud(
            self.ctx, self.subcloud.id, peer_group_id=fake_peer_group_id
        )
        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(fake_peer_group_id, updated_subcloud.peer_group_id)
        self.sm.update_subcloud(self.ctx, self.subcloud.id, peer_group_id="NoNe")
        # Verify subcloud was updated to None
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(None, updated_subcloud.peer_group_id)

    @mock.patch.object(threading.Thread, "start")
    def test_update_subcloud_with_network_reconfig_failed(self, mock_start):
        # In this test, the mocking is required
        self.mock_builtins_open.side_effect = mock.mock_open()
        self.mock_create_intermediate_ca_cert = self._mock_object(
            subcloud_manager.SubcloudManager, "_create_intermediate_ca_cert"
        )
        self.mock_os_listdir.return_value = ["testfile1", "testfile2"]
        mock_start.side_effect = Exception("boom")

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_PRE_INSTALL

        self.sm.update_subcloud_with_network_reconfig(
            self.ctx, self.subcloud.id, self._test_values()
        )

        self.assertEqual(self.mock_builtins_open.call_count, 1)
        self.mock_log_subcloud_manager.exception.assert_called_once_with(
            "Failed to update subcloud subcloud-4"
        )

    @mock.patch.object(time, "sleep")
    @mock.patch.object(kubeoperator, "KubeOperator")
    def test_update_subcloud_with_network_reconfig(
        self, mock_kube_operator, mock_time_sleep
    ):
        self.mock_os_listdir.return_value = ["testfile1", "testfile2"]

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_PRE_INSTALL
        self.sm.update_subcloud_with_network_reconfig(
            self.ctx, self.subcloud.id, self._test_values()
        )
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_RECONFIGURING_NETWORK, updated_subcloud.deploy_status
        )

    def test_compose_update_command(self):
        subcloud_update_command = self.sm.compose_update_command(
            "subcloud1", f"{ANS_PATH}/subcloud1_inventory.yml"
        )
        self.assertEqual(
            subcloud_update_command,
            [
                "ansible-playbook",
                subcloud_manager.ANSIBLE_SUBCLOUD_UPDATE_PLAYBOOK,
                "-i",
                f"{ANS_PATH}/subcloud1_inventory.yml",
                "--limit",
                "subcloud1",
                "--timeout",
                "180",
                "-e",
                "TEST.SW.VERSION",
                "-e",
                "subcloud_update_overrides={}/subcloud1_update_values.yml".format(
                    ANS_PATH
                ),
            ],
        )

    def test_update_subcloud_sync_endpoint_type_region_name_not_found(self):
        # Test openstack app installed
        openstack_installed = True
        self.assertRaises(
            exceptions.SubcloudRegionNameNotFound,
            self.sm.update_subcloud_sync_endpoint_type,
            self.ctx,
            "test_region",
            dccommon_consts.ENDPOINT_TYPES_LIST_OS,
            openstack_installed,
        )

    def test_update_subcloud_sync_endpoint_type_failed(self):
        endpoint_type_list = None
        # Test openstack app installed
        openstack_installed = True
        self.sm.update_subcloud_sync_endpoint_type(
            self.ctx, self.subcloud.region_name, endpoint_type_list, openstack_installed
        )
        self.mock_log_subcloud_manager.exception.assert_called_once_with(
            "Problem informing dcorch of subcloud sync endpoint type change,"
            f' subcloud region: {base.SUBCLOUD_1["region_name"]}'
        )


class TestSubcloudCompose(BaseTestSubcloudManager):
    """Test class for testing subcloud compose command"""

    def setUp(self):
        super().setUp()

    def test_compose_install_command(self):
        install_command = self.sm.compose_install_command(
            "subcloud1", f"{ANS_PATH}/subcloud1_inventory.yml", FAKE_PREVIOUS_SW_VERSION
        )
        self.assertEqual(
            install_command,
            [
                "ansible-playbook",
                dccommon_consts.ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK,
                "-i",
                f"{ANS_PATH}/subcloud1_inventory.yml",
                "--limit",
                "subcloud1",
                "-e",
                f"@{ANS_PATH}/subcloud1/install_values.yml",
                "-e",
                "install_release_version=%s" % FAKE_PREVIOUS_SW_VERSION,
                "-e",
                "rvmc_config_file=%s"
                % os.path.join(
                    ANS_PATH, "subcloud1", dccommon_consts.RVMC_CONFIG_FILE_NAME
                ),
            ],
        )

    def test_compose_install_command_with_bmc_access_only(self):
        install_command = self.sm.compose_install_command(
            "subcloud1",
            f"{ANS_PATH}/subcloud1_inventory.yml",
            FAKE_PREVIOUS_SW_VERSION,
            bmc_access_only=True,
        )
        self.assertIn("bmc_access_only=True", install_command)

    @mock.patch("os.path.isfile")
    def test_compose_bootstrap_command(self, mock_isfile):
        mock_isfile.return_value = True
        subcloud_name = base.SUBCLOUD_1["name"]
        subcloud_region = base.SUBCLOUD_1["region_name"]
        bootstrap_command = self.sm.compose_bootstrap_command(
            subcloud_name,
            subcloud_region,
            f"{ANS_PATH}/subcloud1_inventory.yml",
            FAKE_PREVIOUS_SW_VERSION,
        )
        self.assertEqual(
            bootstrap_command,
            [
                "ansible-playbook",
                cutils.get_playbook_for_software_version(
                    subcloud_manager.ANSIBLE_SUBCLOUD_PLAYBOOK, FAKE_PREVIOUS_SW_VERSION
                ),
                "-i",
                f"{ANS_PATH}/subcloud1_inventory.yml",
                "--limit",
                "%s" % subcloud_name,
                "-e",
                str("override_files_dir='%s' region_name=%s")
                % (ANS_PATH, subcloud_region),
                "-e",
                "install_release_version=%s" % FAKE_PREVIOUS_SW_VERSION,
            ],
        )

    def test_compose_config_command(self):

        config_command = self.sm.compose_config_command(
            "subcloud1", f"{ANS_PATH}/subcloud1_inventory.yml", self.fake_payload
        )
        self.assertEqual(
            config_command,
            [
                "ansible-playbook",
                "test_playbook.yaml",
                "-e",
                f"@{ANS_PATH}/subcloud1_deploy_values.yml",
                "-i",
                f"{ANS_PATH}/subcloud1_inventory.yml",
                "--limit",
                "subcloud1",
            ],
        )

    @mock.patch("os.path.isfile")
    def test_compose_rehome_command(self, mock_isfile):
        mock_isfile.return_value = True
        subcloud_name = base.SUBCLOUD_1["name"]
        subcloud_region = base.SUBCLOUD_1["region_name"]

        rehome_command = self.sm.compose_rehome_command(
            subcloud_name,
            subcloud_region,
            f"{ANS_PATH}/subcloud1_inventory.yml",
            SW_VERSION,
        )

        self.assertEqual(
            rehome_command,
            [
                "ansible-playbook",
                subcloud_manager.ANSIBLE_SUBCLOUD_REHOME_PLAYBOOK,
                "-i",
                f"{ANS_PATH}/subcloud1_inventory.yml",
                "--limit",
                subcloud_name,
                "--timeout",
                subcloud_manager.REHOME_PLAYBOOK_TIMEOUT,
                "-e",
                f"install_release_version={SW_VERSION}",
                "-e",
                str("override_files_dir='%s' region_name=%s")
                % (ANS_PATH, subcloud_region),
            ],
        )

    def test_compose_backup_command(self):
        backup_command = self.sm.compose_backup_command(
            "subcloud1", f"{ANS_PATH}/subcloud1_inventory.yml"
        )
        self.assertEqual(
            backup_command,
            [
                "ansible-playbook",
                subcloud_manager.ANSIBLE_SUBCLOUD_BACKUP_CREATE_PLAYBOOK,
                "-i",
                f"{ANS_PATH}/subcloud1_inventory.yml",
                "--limit",
                "subcloud1",
                "-e",
                "subcloud_bnr_overrides={}/subcloud1_backup_create_values.yml".format(
                    ANS_PATH
                ),
            ],
        )

    def test_compose_backup_delete_command(self):
        backup_delete_command = self.sm.compose_backup_delete_command(
            "subcloud1", f"{ANS_PATH}/subcloud1_inventory.yml"
        )
        self.assertEqual(
            backup_delete_command,
            [
                "ansible-playbook",
                "/usr/share/ansible/stx-ansible/playbooks/delete_subcloud_backup.yml",
                "-e",
                "subcloud_bnr_overrides={}/subcloud1_backup_delete_values.yml".format(
                    ANS_PATH
                ),
                "-i",
                "/opt/dc-vault/ansible/subcloud1_inventory.yml",
                "--limit",
                "subcloud1",
            ],
        )


class TestSubcloudRedeploy(BaseTestSubcloudManager):
    """Test class for testing subcloud redeploy"""

    def setUp(self):
        super().setUp()

    @mock.patch.object(cutils, "get_oam_floating_ip_primary")
    @mock.patch.object(subcloud_manager.SubcloudManager, "_prepare_for_deployment")
    @mock.patch.object(cutils, "update_values_on_yaml_file")
    def test_subcloud_redeploy(
        self, mock_update_yml, mock_prepare_for_deployment, mock_oam_address
    ):
        self.mock_run_subcloud_install = self._mock_object(
            subcloud_manager.SubcloudManager, "_run_subcloud_install"
        )
        self.mock_get_playbook_for_software_version.return_value = FAKE_SW_VERSION
        self.mock_ansible_run_playbook.return_value = False
        self.mock_run_subcloud_install.return_value = True

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_CREATED
        self.fake_install_values["software_version"] = SW_VERSION
        # Change management start and end addresses to be the same as in self.subcloud
        # to avoid network reconfiguration.
        bootstrap_file_data = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        bootstrap_file_data["management_start_address"] = "192.168.101.2"
        bootstrap_file_data["management_end_address"] = "192.168.101.50"
        fake_payload_bootstrap = {
            **fake_subcloud.FAKE_BOOTSTRAP_VALUE,
            **bootstrap_file_data,
        }
        fake_payload_bootstrap["sysadmin_password"] = "testpass"
        fake_payload = {
            **self.fake_payload_install,
            **fake_payload_bootstrap,
            **self.fake_payload,
        }

        self.sm.redeploy_subcloud(self.ctx, self.subcloud.id, fake_payload, "22.12")

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE, updated_subcloud.deploy_status)
        # Verify subcloud rehomed flag is False after re-deploy
        self.assertFalse(updated_subcloud.rehomed)

    @mock.patch.object(subcloud_manager.SubcloudManager, "subcloud_deploy_config")
    @mock.patch.object(subcloud_install.SubcloudInstall, "prep")
    @mock.patch.object(cutils, "get_oam_floating_ip_primary")
    @mock.patch.object(cutils, "update_values_on_yaml_file")
    @mock.patch.object(subprocess, "check_call")
    def test_subcloud_redeploy_skip_deploy_config(
        self,
        mock_check_call,
        mock_update_yml,
        mock_oam_address,
        mock_prep,
        mock_subcloud_deploy_config,
    ):
        self.mock_get_playbook_for_software_version.return_value = FAKE_SW_VERSION
        self.mock_ansible_run_playbook.return_value = False
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_CREATED
        self.fake_install_values["software_version"] = SW_VERSION

        # Change management start and end addresses to be the same as in self.subcloud
        # to avoid network reconfiguration.
        bootstrap_file_data = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        bootstrap_file_data["management_start_address"] = "192.168.101.2"
        bootstrap_file_data["management_end_address"] = "192.168.101.50"
        fake_payload_bootstrap = {
            **fake_subcloud.FAKE_BOOTSTRAP_VALUE,
            **bootstrap_file_data,
        }
        fake_payload_bootstrap["sysadmin_password"] = "testpass"
        fake_payload = {**self.fake_payload_install, **fake_payload_bootstrap}

        self.sm.redeploy_subcloud(self.ctx, self.subcloud.id, fake_payload, "22.12")

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE, updated_subcloud.deploy_status)
        # Verify subcloud rehomed flag is False after re-deploy
        self.assertFalse(updated_subcloud.rehomed)
        mock_subcloud_deploy_config.assert_not_called()

    def test_handle_subcloud_operations_in_progress(self):
        # There are three types of transitory states
        state_map = {
            "deploy_status": subcloud_manager.TRANSITORY_STATES.copy(),
            "backup_status": subcloud_manager.TRANSITORY_BACKUP_STATES.copy(),
            "prestage_status": subcloud_manager.TRANSITORY_PRESTAGE_STATES.copy(),
        }

        # Any state not defined in the transitory states should not be modified
        # NOTE: this should cover the test_handle_completed_subcloud_operations test
        for states in state_map.values():
            states["undefined state"] = "undefined state"

        # Create subclouds
        expected_states = {}
        for state_type, states in state_map.items():
            for initial_state, expected_state in states.items():
                uid = str(uuid.uuid4())
                self.subcloud["name"] = uid
                self.subcloud["region_name"] = uid
                db_api.subcloud_update(
                    self.ctx, self.subcloud.id, **{state_type: initial_state}
                )
                expected_states[uid] = (state_type, expected_state)

        # Run the handle_subcloud_operations_in_progress function
        self.sm.handle_subcloud_operations_in_progress()

        # Verify the expected states
        for subcloud in db_api.subcloud_get_all(self.ctx):
            state_type, expected_state = expected_states[self.subcloud.name]
            self.assertEqual(expected_state, subcloud.get(state_type))


class TestSubcloudBackup(BaseTestSubcloudManager):
    """Test class for testing subcloud backup"""

    def setUp(self):
        super().setUp()
        self.mock_openstack_driver().keystone_client = FakeKeystoneClient()
        self.values = copy.copy(FAKE_BACKUP_DELETE_LOAD_1)
        self.backup_values = copy.copy(FAKE_BACKUP_CREATE_LOAD)

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            backup_datetime=None,
            backup_status=consts.BACKUP_STATE_UNKNOWN,
        )

    @mock.patch.object(cutils, "is_subcloud_healthy", return_value=True)
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_subcloud_backup_create_playbook"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_set_subcloud_backup_failure_alarm"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager,
        "_clear_subcloud_backup_failure_alarm_if_exists",
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_overrides_for_backup_or_restore"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    def test_backup_create_managed_online(
        self,
        mock_create_inventory_file,
        mock_create_overrides,
        mock_clear_alarm,
        mock_set_alarm,
        mock_run_playbook,
        mock_is_healthy,
    ):
        mock_create_inventory_file.return_value = "inventory_file.yml"
        mock_create_overrides.return_value = "overrides_file.yml"

        self.sm.create_subcloud_backups(self.ctx, payload=self.backup_values)

        mock_create_inventory_file.assert_called_once()
        mock_create_overrides.assert_called_once()
        mock_clear_alarm.assert_called_once()
        mock_set_alarm.assert_not_called()
        mock_run_playbook.assert_called_once()
        mock_is_healthy.assert_called_once()

        # Verify that subcloud has the correct backup status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_PRE_BACKUP, updated_subcloud.backup_status)

    @mock.patch.object(cutils, "is_subcloud_healthy", return_value=False)
    def test_backup_create_managed_online_not_healthy(self, mock_is_healthy):
        self.backup_values["local_only"] = False
        self.backup_values["registry_images"] = True

        self.sm.create_subcloud_backups(self.ctx, payload=self.backup_values)
        mock_is_healthy.assert_called_once()
        # Verify that subcloud has the correct backup status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.BACKUP_STATE_VALIDATE_FAILED, updated_subcloud.backup_status
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_backup_overrides_file"
    )
    def test_delete_subcloud_backup_failed(self, mock_create_backup_overrides_file):
        mock_create_backup_overrides_file.side_effect = Exception("boom")
        self.subcloud["deploy_status"] = consts.BACKUP_STATE_COMPLETE_CENTRAL
        self.sm._delete_subcloud_backup(
            self.ctx,
            payload=self.values,
            release_version=FAKE_SW_VERSION,
            subcloud=self.subcloud,
        )
        self.mock_log_subcloud_manager.exception.assert_called_once_with(
            f"Failed to prepare subcloud {self.subcloud.name} for backup delete"
        )

    @mock.patch.object(cutils, "is_subcloud_healthy", return_value=True)
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    @mock.patch.object(os.path, "join")
    def test_backup_create_failed(
        self, mock_os_path_join, mock_create_inventory_file, mock_is_healthy
    ):
        mock_os_path_join.return_value = "subcloud1_fake_file.yml"
        mock_create_inventory_file.return_value = "inventory_file.yml"
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()
        self.backup_values["local_only"] = True
        self.backup_values["registry_images"] = True

        self.sm.create_subcloud_backups(self.ctx, payload=self.backup_values)

        mock_create_inventory_file.assert_called_once()
        mock_is_healthy.assert_called_once()

        # Verify that subcloud has the correct backup status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_FAILED, updated_subcloud.backup_status)
        self.mock_log_subcloud_manager.error.assert_called_once_with(
            f"FAILED backing-up playbook of ({self.subcloud.name}).\ncheck individual "
            "log at subcloud1_fake_file.yml_playbook_output.log for detailed output"
        )

    @mock.patch.object(
        cutils, "find_ansible_error_msg", return_value="Fake playbook error"
    )
    @mock.patch.object(cutils, "is_subcloud_healthy", return_value=True)
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    @mock.patch.object(os.path, "join")
    def test_backup_create_find_and_save_playbook_error(
        self,
        mock_os_path_join,
        mock_create_inventory_file,
        mock_is_healthy,
        mock_find_msg,
    ):
        mock_os_path_join.return_value = "subcloud1_fake_file.yml"
        mock_create_inventory_file.return_value = "inventory_file.yml"

        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()

        self.backup_values["local_only"] = True
        self.backup_values["registry_images"] = True

        self.sm.create_subcloud_backups(self.ctx, payload=self.backup_values)

        mock_create_inventory_file.assert_called_once()
        mock_is_healthy.assert_called_once()

        mock_find_msg.assert_called_once_with(
            self.subcloud.name, mock.ANY, consts.BACKUP_STATE_IN_PROGRESS
        )

        # Verify that subcloud has the correct backup status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual("Fake playbook error", updated_subcloud.error_description)
        self.assertEqual(consts.BACKUP_STATE_FAILED, updated_subcloud.backup_status)

    @mock.patch.object(cutils, "is_subcloud_healthy", return_value=True)
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    @mock.patch.object(os.path, "join")
    def test_backup_create_find_and_save_playbook_timeout(
        self, mock_os_path_join, mock_create_inventory_file, mock_is_healthy
    ):
        mock_os_path_join.return_value = "subcloud1_fake_file.yml"
        mock_create_inventory_file.return_value = "inventory_file.yml"

        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionTimeout()

        self.backup_values["local_only"] = True
        self.backup_values["registry_images"] = True

        self.sm.create_subcloud_backups(self.ctx, payload=self.backup_values)

        mock_create_inventory_file.assert_called_once()
        mock_is_healthy.assert_called_once()

        # Verify that subcloud has the correct backup status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertIn("Timeout", updated_subcloud.error_description)
        self.assertIn(self.subcloud.name, updated_subcloud.error_description)
        self.assertEqual(consts.BACKUP_STATE_FAILED, updated_subcloud.backup_status)

    def test_backup_create_managed_online_backup_state_in_progess(self):
        self.backup_values["local_only"] = False
        self.backup_values["registry_images"] = True
        db_api.subcloud_update(
            self.ctx, self.subcloud.id, backup_status=consts.BACKUP_STATE_IN_PROGRESS
        )
        self.sm.create_subcloud_backups(self.ctx, payload=self.backup_values)
        # Verify that subcloud has the correct backup status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.BACKUP_STATE_IN_PROGRESS, updated_subcloud.backup_status
        )
        Calls = [
            mock.call.debug("SubcloudManager initialization..."),
            mock.call.info(
                "Subcloud subcloud1 already has a backup operation in progress"
            ),
            mock.call.info("Subcloud backup operation finished"),
        ]
        self.mock_log_subcloud_manager.assert_has_calls(Calls)

    @mock.patch.object(cutils, "get_oam_floating_ip_primary")
    @mock.patch.object(cutils, "is_subcloud_healthy", return_value=True)
    def backup_create_managed_online_local_only(
        self, mock_is_healthy, mock_get_oam_floating_ip_primary
    ):
        self.sm.create_subcloud_backups(self.ctx, payload=self.backup_values)

        mock_is_healthy.assert_called_once()

        # Verify that subcloud has the correct backup status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.BACKUP_STATE_COMPLETE_LOCAL, updated_subcloud.backup_status
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_parallel_group_operation"
    )
    def test_backup_create_unmanaged_online(self, mock_parallel_group_operation):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_NONE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )

        self.sm.create_subcloud_backups(self.ctx, payload=self.backup_values)

        mock_parallel_group_operation.assert_called_once()

        # Verify that subcloud has the correct backup status
        # consts.BACKUP_STATE_VALIDATE_FAILED
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.BACKUP_STATE_VALIDATE_FAILED, updated_subcloud.backup_status
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_parallel_group_operation"
    )
    def test_backup_create_unmanaged_offline(self, mock_parallel_group_operation):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_NONE,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )

        self.sm.create_subcloud_backups(self.ctx, payload=self.backup_values)
        mock_parallel_group_operation.assert_called_once()

        # Verify that subcloud has the correct backup status
        # consts.BACKUP_STATE_VALIDATE_FAILED
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.BACKUP_STATE_VALIDATE_FAILED, updated_subcloud.backup_status
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_parallel_group_operation"
    )
    def test_backup_create_managed_offline(self, mock_parallel_group_operation):

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_NONE,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
        )

        self.sm.create_subcloud_backups(self.ctx, payload=self.backup_values)
        mock_parallel_group_operation.assert_called_once()

        # Verify that subcloud has the correct backup status
        # consts.BACKUP_STATE_VALIDATE_FAILED
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.BACKUP_STATE_VALIDATE_FAILED, updated_subcloud.backup_status
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_parallel_group_operation"
    )
    def test_backup_delete_managed_online(self, mock_parallel_group_operation):
        values = copy.copy(FAKE_BACKUP_DELETE_LOAD)
        values["local_only"] = False

        db_api.subcloud_update(
            self.ctx, self.subcloud.id, deploy_status=consts.DEPLOY_STATE_NONE
        )

        self.sm.delete_subcloud_backups(
            self.ctx, payload=values, release_version=FAKE_SW_VERSION
        )

        mock_parallel_group_operation.assert_called_once()

        # Verify that subcloud has the correct backup status
        # consts.BACKUP_STATE_UNKNOWN
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_UNKNOWN, updated_subcloud.backup_status)

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_parallel_group_operation"
    )
    def test_backup_delete_managed_local_online(self, mock_parallel_group_operation):

        values = copy.copy(FAKE_BACKUP_DELETE_LOCAL_LOAD)
        db_api.subcloud_update(
            self.ctx, self.subcloud.id, deploy_status=consts.DEPLOY_STATE_NONE
        )

        self.sm.delete_subcloud_backups(
            self.ctx, payload=values, release_version=FAKE_SW_VERSION
        )

        mock_parallel_group_operation.assert_called_once()

        # Verify that subcloud has the correct backup status
        # consts.BACKUP_STATE_UNKNOWN
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_UNKNOWN, updated_subcloud.backup_status)

    @mock.patch.object(cutils, "is_subcloud_healthy", return_value=True)
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_backup_overrides_file"
    )
    @mock.patch.object(cutils, "get_oam_floating_ip_primary")
    @mock.patch.object(
        subcloud_manager.SubcloudManager,
        "_clear_subcloud_backup_failure_alarm_if_exists",
    )
    @mock.patch.object(subcloud_manager.SubcloudManager, "compose_backup_command")
    def test_backup_create_subcloud(
        self,
        mock_compose_backup_command,
        mock_clear_subcloud_failure_alarm,
        mock_oam_address,
        mock_create_backup_file,
        mock_is_healthy,
    ):
        db_api.subcloud_update(
            self.ctx, self.subcloud.id, backup_status=consts.BACKUP_STATE_UNKNOWN
        )
        values = copy.copy(FAKE_BACKUP_CREATE_LOAD_1)
        override_file = os_path.join(
            ANS_PATH, self.subcloud.name + "_backup_create_values.yml"
        )
        mock_create_backup_file.return_value = override_file

        self.sm._backup_subcloud(self.ctx, payload=values, subcloud=self.subcloud)
        self.mock_create_subcloud_inventory.assert_called_once()
        mock_oam_address.return_value = "2620:10a:a001:d41::260"
        self.mock_keyring.get_password.assert_called()

        mock_create_backup_file.assert_called_once()
        self.mock_ansible_run_playbook.assert_called_once()
        mock_is_healthy.assert_called_once()

        mock_compose_backup_command.assert_called_once()
        mock_clear_subcloud_failure_alarm.assert_called_once()

        self.mock_delete_subcloud_inventory.assert_called_once_with(override_file)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.BACKUP_STATE_COMPLETE_CENTRAL, updated_subcloud.backup_status
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    def test_backup_create_subcloud_fail_to_create(
        self, mock_create_subcloud_inventory_file
    ):
        db_api.subcloud_update(
            self.ctx, self.subcloud.id, backup_status=consts.BACKUP_STATE_UNKNOWN
        )

        values = copy.copy(FAKE_BACKUP_CREATE_LOAD_1)
        self.sm._backup_subcloud(self.ctx, payload=values, subcloud=self.subcloud)

        mock_create_subcloud_inventory_file.side_effect = Exception("FakeFailure")

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.BACKUP_STATE_PREP_FAILED, updated_subcloud.backup_status
        )

    @mock.patch.object(cutils, "get_oam_floating_ip_primary")
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "compose_backup_delete_command"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_backup_overrides_file"
    )
    def test_delete_subcloud_backup(
        self,
        mock_create_backup_overrides_file,
        mock_compose_backup_delete_command,
        mock_oam_address,
    ):
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            backup_status=consts.BACKUP_STATE_COMPLETE_CENTRAL,
        )

        override_file = os_path.join(
            ANS_PATH, self.subcloud.name + "_backup_delete_values.yml"
        )
        mock_create_backup_overrides_file.return_value = override_file

        self.sm._delete_subcloud_backup(
            self.ctx,
            payload=self.values,
            release_version=FAKE_SW_VERSION,
            subcloud=self.subcloud,
        )

        mock_create_backup_overrides_file.assert_called_once()
        mock_compose_backup_delete_command.assert_called_once()
        self.mock_ansible_run_playbook.assert_called_once()
        mock_oam_address.return_value = "2620:10a:a001:d41::260"
        self.mock_create_subcloud_inventory.assert_not_called()
        self.mock_delete_subcloud_inventory.assert_called_once_with(override_file)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_UNKNOWN, updated_subcloud.backup_status)

    @mock.patch.object(cutils, "get_oam_floating_ip_primary")
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "compose_backup_delete_command"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_backup_overrides_file"
    )
    def test_delete_subcloud_backup_local_only(
        self,
        mock_create_subcloud_inventory_file,
        mock_compose_backup_delete_command,
        mock_oam_address,
    ):
        db_api.subcloud_update(
            self.ctx, self.subcloud.id, backup_status=consts.BACKUP_STATE_COMPLETE_LOCAL
        )

        self.values["local_only"] = True

        override_file = os_path.join(
            ANS_PATH, self.subcloud.name + "_backup_delete_values.yml"
        )
        mock_create_subcloud_inventory_file.return_value = override_file

        self.sm._delete_subcloud_backup(
            self.ctx,
            payload=self.values,
            release_version=FAKE_SW_VERSION,
            subcloud=self.subcloud,
        )

        mock_create_subcloud_inventory_file.assert_called_once()
        mock_compose_backup_delete_command.assert_called_once()
        self.mock_ansible_run_playbook.assert_called_once()
        mock_oam_address.return_value = "2620:10a:a001:d41::260"
        self.mock_create_subcloud_inventory.assert_called_once()
        self.mock_delete_subcloud_inventory.assert_called_once_with(override_file)

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.BACKUP_STATE_UNKNOWN, updated_subcloud.backup_status)

    def test_compose_backup_delete_command_backup_stored_in_central_storage(self):
        backup_delete_command = self.sm.compose_backup_delete_command("subcloud1")
        self.assertEqual(
            backup_delete_command,
            [
                "ansible-playbook",
                "/usr/share/ansible/stx-ansible/playbooks/delete_subcloud_backup.yml",
                "-e",
                "subcloud_bnr_overrides={}/subcloud1_backup_delete_values.yml".format(
                    ANS_PATH
                ),
                "-e",
                "inventory_hostname=subcloud1",
            ],
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "compose_backup_delete_command"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_backup_overrides_file"
    )
    def test_delete_subcloud_backup_playbook_execution_failed(
        self, mock_create_backup_overrides_file, mock_compose_backup_delete_command
    ):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            backup_status=consts.BACKUP_STATE_COMPLETE_CENTRAL,
        )

        self.sm._delete_subcloud_backup(
            self.ctx,
            payload=self.values,
            release_version=FAKE_SW_VERSION,
            subcloud=self.subcloud,
        )
        Calls = [
            mock.call(
                "Failed to delete backup for subcloud subcloud1, check individual "
                "log at /var/log/dcmanager/ansible/subcloud1_playbook_output.log "
                "for detailed output."
            ),
            mock.call(
                "FAILED failed playbook of (subcloud1).\ncheck individual "
                "log at /var/log/dcmanager/ansible/subcloud1_playbook_output.log "
                "for detailed output"
            ),
        ]
        self.mock_log_subcloud_manager.error.assert_has_calls(Calls)
        mock_create_backup_overrides_file.assert_called_once()
        mock_compose_backup_delete_command.assert_called_once()
        self.mock_ansible_run_playbook.assert_called_once()
        self.mock_create_subcloud_inventory.assert_not_called()

    @mock.patch.object(
        cutils, "find_ansible_error_msg", return_value="Fake playbook error"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "compose_backup_delete_command"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_backup_overrides_file"
    )
    def test_delete_subcloud_backup_find_and_save_ansible_error(
        self,
        mock_create_backup_overrides_file,
        mock_compose_backup_delete_command,
        mock_find_msg,
    ):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            backup_status=consts.BACKUP_STATE_COMPLETE_CENTRAL,
        )

        self.sm._delete_subcloud_backup(
            self.ctx,
            payload=self.values,
            release_version=FAKE_SW_VERSION,
            subcloud=self.subcloud,
        )

        mock_find_msg.assert_called_once_with(
            self.subcloud.name, mock.ANY, consts.BACKUP_STATE_FAILED
        )

        # Verify that subcloud has the correct backup status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual("Fake playbook error", updated_subcloud.error_description)

        mock_create_backup_overrides_file.assert_called_once()
        mock_compose_backup_delete_command.assert_called_once()
        self.mock_ansible_run_playbook.assert_called_once()
        self.mock_create_subcloud_inventory.assert_not_called()

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "compose_backup_delete_command"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_backup_overrides_file"
    )
    def test_delete_subcloud_backup_find_and_save_ansible_timeout(
        self, mock_create_backup_overrides_file, mock_compose_backup_delete_command
    ):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionTimeout()

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            backup_status=consts.BACKUP_STATE_COMPLETE_CENTRAL,
        )

        self.sm._delete_subcloud_backup(
            self.ctx,
            payload=self.values,
            release_version=FAKE_SW_VERSION,
            subcloud=self.subcloud,
        )

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertIn("Timeout", updated_subcloud.error_description)

        mock_create_backup_overrides_file.assert_called_once()
        mock_compose_backup_delete_command.assert_called_once()
        self.mock_ansible_run_playbook.assert_called_once()
        self.mock_create_subcloud_inventory.assert_not_called()


class TestSubcloudPrestage(BaseTestSubcloudManager):
    """Test class for testing subcloud prestage"""

    def setUp(self):
        super().setUp()

    @mock.patch.object(threading.Thread, "start")
    def test_prestage_no_subcloud(self, mock_thread_start):
        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        values["subcloud_name"] = "randomname"

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_NONE
        e = self.assertRaises(
            exceptions.PrestagePreCheckFailedException,
            self.sm.prestage_subcloud,
            self.ctx,
            values,
        )

        self.assertTrue("Subcloud does not exist" in str(e))

    @mock.patch.object(cutils, "get_filename_by_prefix")
    @mock.patch.object(prestage, "_run_ansible")
    def test_prestage_remote_pass_with_img_list(
        self, mock_run_ansible, mock_get_filename_by_prefix
    ):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        self.subcloud.update(
            {
                "deploy_status": consts.DEPLOY_STATE_NONE,
                "software_version": FAKE_SUBCLOUD_SW_VERSION,
            }
        )

        mock_run_ansible.return_value = None
        mock_get_filename_by_prefix.return_value = "prestage_images_list.txt"
        self.mock_os_path_isdir.return_value = True
        prestage._prestage_standalone_thread(self.ctx, self.subcloud, payload=values)

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.PRESTAGE_STATE_COMPLETE, updated_subcloud.prestage_status
        )

        # Verify both of prestage package and image ansible playbooks were called
        self.assertEqual(mock_run_ansible.call_count, 2)
        # Verify the "image_list_file" was passed to the prestage image playbook
        # for the remote prestage
        self.assertIn("image_list_file", mock_run_ansible.call_args_list[1].args[1][5])
        # Verify the prestage request release was passed to the playbooks
        self.assertIn(
            FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[0].args[1][5]
        )
        self.assertIn(
            FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[1].args[1][5]
        )

    @mock.patch.object(cutils, "get_filename_by_prefix")
    @mock.patch.object(prestage, "_run_ansible")
    def test_prestage_remote_pass_without_img_list(
        self, mock_run_ansible, mock_get_filename_by_prefix
    ):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        self.subcloud.update(
            {
                "deploy_status": consts.DEPLOY_STATE_NONE,
                "software_version": FAKE_SUBCLOUD_SW_VERSION,
            }
        )

        mock_run_ansible.return_value = None
        mock_get_filename_by_prefix.return_value = None
        self.mock_os_path_isdir.return_value = True
        prestage._prestage_standalone_thread(self.ctx, self.subcloud, payload=values)

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.PRESTAGE_STATE_COMPLETE, updated_subcloud.prestage_status
        )

        # Verify that only prestage package playbook is called
        self.assertEqual(mock_run_ansible.call_count, 1)

        # Verify the prestage request release was passed to the playbooks
        self.assertIn(
            FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[0].args[1][5]
        )

    @mock.patch.object(cutils, "get_filename_by_prefix")
    @mock.patch.object(prestage, "_run_ansible")
    def test_prestage_local_pass_with_img_list(
        self, mock_run_ansible, mock_get_filename_by_prefix
    ):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        self.subcloud.update(
            {
                "deploy_status": consts.DEPLOY_STATE_NONE,
                "software_version": FAKE_PRESTAGE_RELEASE,
            }
        )

        mock_run_ansible.return_value = None
        mock_get_filename_by_prefix.return_value = "prestage_images_list.txt"
        self.mock_os_path_isdir.return_value = True
        prestage._prestage_standalone_thread(self.ctx, self.subcloud, payload=values)

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.PRESTAGE_STATE_COMPLETE, updated_subcloud.prestage_status
        )

        # Verify both of prestage package and image ansible playbooks were called
        self.assertEqual(mock_run_ansible.call_count, 2)
        # Verify the "image_list_file" was passed to the prestage image playbook
        # for the local prestage
        self.assertIn("image_list_file", mock_run_ansible.call_args_list[1].args[1][5])
        # Verify the prestage request release was passed to the playbooks
        self.assertIn(
            FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[0].args[1][5]
        )
        self.assertIn(
            FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[1].args[1][5]
        )

    @mock.patch.object(cutils, "get_filename_by_prefix")
    @mock.patch.object(prestage, "_run_ansible")
    def test_prestage_local_pass_without_img_list(
        self, mock_run_ansible, mock_get_filename_by_prefix
    ):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        self.subcloud.update(
            {
                "deploy_status": consts.DEPLOY_STATE_NONE,
                "software_version": FAKE_PRESTAGE_RELEASE,
            }
        )

        mock_run_ansible.return_value = None
        mock_get_filename_by_prefix.return_value = None
        self.mock_os_path_isdir.return_value = True
        prestage._prestage_standalone_thread(self.ctx, self.subcloud, payload=values)

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.PRESTAGE_STATE_COMPLETE, updated_subcloud.prestage_status
        )

        # Verify both of prestage package and image ansible playbooks were called
        self.assertEqual(mock_run_ansible.call_count, 2)
        # Verify the "image_list_file" was not passed to the prestage image playbook
        # for the local prestage
        self.assertNotIn(
            "image_list_file", mock_run_ansible.call_args_list[1].args[1][5]
        )
        # Verify the prestage request release was passed to the playbooks
        self.assertIn(
            FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[0].args[1][5]
        )
        self.assertIn(
            FAKE_PRESTAGE_RELEASE, mock_run_ansible.call_args_list[1].args[1][5]
        )

    @mock.patch.object(prestage, "prestage_images")
    @mock.patch.object(prestage, "prestage_packages")
    @mock.patch.object(prestage, "_run_ansible")
    def test_prestage_subcloud_complete(
        self, mock_run_ansible, mock_prestage_packages, mock_prestage_images
    ):

        values = copy.copy(FAKE_PRESTAGE_PAYLOAD)
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_NONE
        prestage._prestage_standalone_thread(self.ctx, self.subcloud, payload=values)
        mock_run_ansible.return_value = None
        mock_prestage_packages.assert_called_once_with(
            self.ctx, self.subcloud, values, consts.PRESTAGE_FOR_INSTALL
        )
        mock_prestage_images.assert_called_once_with(
            self.ctx, self.subcloud, values, consts.PRESTAGE_FOR_INSTALL
        )
        self.mock_delete_subcloud_inventory.return_value = None

        # Verify that subcloud has the "prestage-complete" deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.PRESTAGE_STATE_COMPLETE, updated_subcloud.prestage_status
        )

    def test_get_cached_regionone_data(self):
        mock_keystone_client = FakeKeystoneClient()
        mock_sysinv_client = FakeSysinvClient()
        cached_regionone_data = self.sm._get_cached_regionone_data(
            mock_keystone_client, mock_sysinv_client
        )
        expiry1 = cached_regionone_data["expiry"]
        self.assertEqual(
            cached_regionone_data["dcmanager_user_id"], FAKE_DCMANAGER_USER_ID
        )
        self.assertEqual(
            cached_regionone_data["admin_project_id"], FAKE_ADMIN_PROJECT_ID
        )
        self.assertEqual(
            cached_regionone_data["mgmt_interface_uuids"], FAKE_MGMT_IF_UUIDS
        )
        self.assertEqual(
            cached_regionone_data["mgmt_pools"][0].floating_address,
            "fdff:719a:bf60:233::2",
        )
        self.assertEqual(
            cached_regionone_data["oam_pools"][0].floating_address,
            "2620:10a:a001:d41::260",
        )
        # The expiry timestamp is likely a couple of seconds less than the time
        # the cache is set when it gets here so check if the expiry is greater than
        # 59m55s from now.
        self.assertGreater(
            cached_regionone_data["expiry"],
            timeutils.utcnow() + datetime.timedelta(seconds=3595),
        )
        cached_regionone_data = self.sm._get_cached_regionone_data(
            mock_keystone_client, mock_sysinv_client
        )
        expiry2 = cached_regionone_data["expiry"]
        self.assertEqual(expiry1, expiry2)


class TestSubcloudBackupRestore(BaseTestSubcloudManager):
    """Test class for testing subcloud backup restore"""

    def setUp(self):
        super().setUp()
        self.values = copy.copy(FAKE_BACKUP_RESTORE_LOAD)
        self.data_install = str(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES).replace(
            "'", '"'
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_subcloud_backup_restore_playbook"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_overrides_for_backup_or_restore"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    def test_backup_restore_unmanaged_online(
        self, mock_create_inventory_file, mock_create_overrides, mock_run_playbook
    ):
        mock_create_inventory_file.return_value = "inventory_file.yml"
        mock_create_overrides.return_value = "overrides_file.yml"
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=self.data_install,
        )

        self.sm.restore_subcloud_backups(self.ctx, payload=self.values)

        mock_create_inventory_file.assert_called_once()
        mock_create_overrides.assert_called_once()
        mock_run_playbook.assert_called_once()

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_PRE_RESTORE, updated_subcloud.deploy_status
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_subcloud_backup_restore_playbook"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_overrides_for_backup_or_restore"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    def test_backup_restore_unmanaged_offline(
        self, mock_create_inventory_file, mock_create_overrides, mock_run_playbook
    ):

        values = copy.copy(FAKE_BACKUP_RESTORE_LOAD)
        values["local_only"] = False
        values["registry_images"] = False

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_NONE,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=self.data_install,
        )

        self.sm.restore_subcloud_backups(self.ctx, payload=values)

        mock_create_inventory_file.assert_called_once()
        mock_create_overrides.assert_called_once()
        mock_run_playbook.assert_called_once()

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_PRE_RESTORE, updated_subcloud.deploy_status
        )

    def test_backup_restore_managed_offline(self):
        """Subcloud must be unmanaged for backup restore operation."""

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
        )

        return_log = self.sm.restore_subcloud_backups(self.ctx, payload=self.values)
        expected_log = "skipped for local backup restore operation"

        self.assertIn(expected_log, return_log)
        self.mock_log_subcloud_manager.info.assert_called_with(
            "Subcloud restore backup operation finished.\nRestored subclouds: 0. "
            "Invalid subclouds: 1. Failed subclouds: 0."
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_subcloud_backup_restore_playbook"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_overrides_for_backup_or_restore"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    def test_backup_restore_with_install(
        self,
        mock_create_inventory_file,
        mock_create_overrides,
        mock_run_restore_playbook,
    ):
        self.mock_run_subcloud_install = self._mock_object(
            subcloud_manager.SubcloudManager, "_run_subcloud_install"
        )
        self.mock_os_path_isdir.return_value = True
        self.mock_os_listdir.return_value = ["test.iso", "test.sig"]
        mock_create_inventory_file.return_value = "inventory_file.yml"
        mock_create_overrides.return_value = "overrides_file.yml"
        self.mock_run_subcloud_install.return_value = True
        mock_run_restore_playbook.return_value = True

        values = copy.copy(FAKE_BACKUP_RESTORE_LOAD_WITH_INSTALL)
        values["with_install"] = True

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            data_install=self.data_install,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )

        self.sm.restore_subcloud_backups(self.ctx, payload=values)

        mock_create_inventory_file.assert_called_once()
        mock_create_overrides.assert_called_once()

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_PRE_RESTORE, updated_subcloud.deploy_status
        )

    @mock.patch.object(subcloud_manager.SubcloudManager, "_stage_auto_restore_files")
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_subcloud_backup_restore_playbook"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_overrides_for_backup_or_restore"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    def test_backup_restore_with_auto_and_factory_restore(
        self,
        mock_create_inventory_file,
        mock_create_overrides,
        mock_run_restore_playbook,
        mock_stage_auto_restore_files,
    ):
        self.mock_run_subcloud_install = self._mock_object(
            subcloud_manager.SubcloudManager, "_run_subcloud_install"
        )
        self.mock_os_path_isdir.return_value = True
        self.mock_os_listdir.return_value = ["test.iso", "test.sig"]
        mock_create_inventory_file.return_value = "inventory_file.yml"
        mock_create_overrides.return_value = "overrides_file.yml"
        self.mock_run_subcloud_install.return_value = True
        mock_run_restore_playbook.return_value = True

        values = copy.copy(FAKE_BACKUP_RESTORE_LOAD_WITH_INSTALL)
        values["factory"] = True
        values["auto"] = True
        values["with_install"] = True

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            data_install=self.data_install,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )

        self.sm.restore_subcloud_backups(self.ctx, payload=values)

        # Assert that we called the _create_overrides_for_backup_or_restore and
        # compose_install_command with auto_restore_mode = "factory"
        mock_create_overrides.assert_called_once_with(
            "restore",
            values,
            self.subcloud.name,
            "factory",
            mock.ANY,
            subcloud_region_name=self.subcloud.region_name,
        )

        mock_stage_auto_restore_files.assert_called_once()

        mock_run_restore_playbook.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY, mock.ANY, "factory"
        )

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_PRE_RESTORE, updated_subcloud.deploy_status
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_subcloud_backup_restore_playbook"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_overrides_for_backup_or_restore"
    )
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    def test_backup_restore_with_install_wipe_osds(
        self,
        mock_create_inventory_file,
        mock_create_overrides,
        mock_run_restore_playbook,
    ):
        self.mock_run_subcloud_install = self._mock_object(
            subcloud_manager.SubcloudManager, "_run_subcloud_install"
        )
        self.mock_os_path_isdir.return_value = True
        self.mock_os_listdir.return_value = ["test.iso", "test.sig"]
        mock_create_inventory_file.return_value = "inventory_file.yml"
        mock_create_overrides.return_value = "overrides_file.yml"
        self.mock_run_subcloud_install.return_value = True
        mock_run_restore_playbook.return_value = True

        # Set the wipe_osds to True in the install data
        data_install = copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        data_install["wipe_osds"] = True

        # Set the values for the restore operation
        # to include the with_install flag
        values = copy.copy(FAKE_BACKUP_RESTORE_LOAD_WITH_INSTALL)
        values["with_install"] = True

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            data_install=json.dumps(data_install),
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )

        self.sm.restore_subcloud_backups(self.ctx, payload=values)

        mock_create_overrides.assert_called_once_with(
            "restore",
            values,
            self.subcloud.name,
            None,
            True,
            subcloud_region_name=self.subcloud.region_name,
        )

        mock_run_restore_playbook.assert_called_once_with(
            mock.ANY, mock.ANY, mock.ANY, mock.ANY, mock.ANY
        )

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_PRE_RESTORE, updated_subcloud.deploy_status
        )

    @mock.patch.object(subcloud_install.SubcloudInstall, "prep")
    def test_backup_restore_with_install_failed(self, mock_prep):
        # FAILED installing playbook of (subcloud1).
        # Backup restore failed for all applied subclouds.
        self.mock_os_path_isdir.return_value = True
        self.mock_os_listdir.return_value = ["test.iso", "test.sig"]
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()
        values = copy.copy(FAKE_BACKUP_RESTORE_LOAD_WITH_INSTALL)
        values["with_install"] = True
        values["local_only"] = False
        values["registry_images"] = True

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            data_install=self.data_install,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )

        self.assertRaises(
            exceptions.SubcloudBackupOperationFailed,
            self.sm.restore_subcloud_backups,
            self.ctx,
            payload=values,
        )
        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_INSTALL_FAILED, updated_subcloud.deploy_status
        )

    def test_backup_restore_unmanage_online_complete_restore_val(self):
        self.values["local_only"] = True
        self.values["registry_images"] = True
        self.values["restore_values"] = {
            "bootstrap_address": {"subcloud1": "10.10.20.12"}
        }
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=self.data_install,
        )

        self.sm.restore_subcloud_backups(self.ctx, payload=self.values)
        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE, updated_subcloud.deploy_status)
        Calls = [
            mock.call("Backup restore: Received restore_values for subcloud subcloud1"),
            mock.call("Successfully restore subcloud subcloud1"),
            mock.call(
                "Processed subcloud subcloud1 for backup restore "
                "(operation 100% complete, 0 subcloud(s) remaining)"
            ),
            mock.call(
                "Subcloud restore backup operation finished.\n"
                "Restored subclouds: 1. Invalid subclouds: 0. Failed subclouds: 0."
            ),
        ]
        self.mock_log_subcloud_manager.info.assert_has_calls(Calls)

    def test_backup_restore_unmanage_online_complete_backup_val(self):
        self.values["local_only"] = True
        self.values["registry_images"] = True
        self.values["backup_values"] = copy.copy(FAKE_BACKUP_CREATE_LOAD)
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=self.data_install,
        )

        self.sm.restore_subcloud_backups(self.ctx, payload=self.values)

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_DONE, updated_subcloud.deploy_status)
        Calls = [
            mock.call("Successfully restore subcloud subcloud1"),
            mock.call(
                "Processed subcloud subcloud1 for backup restore "
                "(operation 100% complete, 0 subcloud(s) remaining)"
            ),
            mock.call(
                "Subcloud restore backup operation finished.\n"
                "Restored subclouds: 1. Invalid subclouds: 0. Failed subclouds: 0."
            ),
        ]
        self.mock_log_subcloud_manager.info.assert_has_calls(Calls)

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_create_subcloud_inventory_file"
    )
    def test_backup_restore_failed(self, mock_create_inventory_file):
        mock_create_inventory_file.side_effect = Exception("boom")
        self.values["local_only"] = True
        self.values["registry_images"] = True

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=self.data_install,
        )
        self.assertRaises(
            exceptions.SubcloudBackupOperationFailed,
            self.sm.restore_subcloud_backups,
            self.ctx,
            payload=self.values,
        )

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_RESTORE_PREP_FAILED, updated_subcloud.deploy_status
        )
        self.mock_log_subcloud_manager.exception.assert_called_once_with(
            f"Failed to prepare subcloud {self.subcloud.name} for backup restore"
        )

    def test_backup_restore_playbook_execution_failed(self):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()
        self.values["local_only"] = True
        self.values["registry_images"] = True

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=self.data_install,
        )
        self.assertRaises(
            exceptions.SubcloudBackupOperationFailed,
            self.sm.restore_subcloud_backups,
            self.ctx,
            payload=self.values,
        )
        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_RESTORE_FAILED, updated_subcloud.deploy_status
        )

    @mock.patch.object(
        cutils, "find_ansible_error_msg", return_value="Fake playbook error"
    )
    def test_backup_restore_find_and_save_ansible_error(self, mock_find_msg):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()

        self.values["local_only"] = True
        self.values["registry_images"] = True

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=self.data_install,
        )

        self.assertRaises(
            exceptions.SubcloudBackupOperationFailed,
            self.sm.restore_subcloud_backups,
            self.ctx,
            payload=self.values,
        )

        mock_find_msg.assert_called_once_with(
            self.subcloud.name, mock.ANY, consts.DEPLOY_STATE_RESTORING
        )

        # Verify that subcloud has the correct backup status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual("Fake playbook error", updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_RESTORE_FAILED, updated_subcloud.deploy_status
        )

    def test_backup_restore_find_and_save_ansible_timeout(self):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionTimeout()

        self.values["local_only"] = True
        self.values["registry_images"] = True

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            data_install=self.data_install,
        )

        self.assertRaises(
            exceptions.SubcloudBackupOperationFailed,
            self.sm.restore_subcloud_backups,
            self.ctx,
            payload=self.values,
        )

        # Verify that subcloud has the correct backup status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertIn("Timeout", updated_subcloud.error_description)
        self.assertIn(self.subcloud.name, updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_RESTORE_FAILED, updated_subcloud.deploy_status
        )


class TestSubcloudMigrate(BaseTestSubcloudManager):
    """Test class for testing subcloud migrate"""

    def setUp(self):
        super().setUp()

        self.fake_bootstrap_values = (
            "{'name': 'TestSubcloud', 'system_mode': 'simplex'}"
        )
        self.saved_payload = {
            "deploy_status": consts.DEPLOY_STATE_DONE,
            "rehome_data": (
                '{"saved_payload": {"system_mode": "simplex",\
                "name": "testsub", "bootstrap-address": "128.224.119.56",\
                "admin_password": "TGk2OW51eA=="}}'
            ),
        }

    @mock.patch.object(subcloud_manager, "db_api", side_effect=db_api)
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "generate_subcloud_ansible_config"
    )
    @mock.patch.object(subcloud_manager.SubcloudManager, "rehome_subcloud")
    def test_migrate_subcloud(
        self, mock_rehome_subcloud, mock_generate_subcloud_ansible_config, mock_db_api
    ):
        # Prepare the test data
        payload = {"sysadmin_password": "TGk2OW51eA=="}
        payload_result = {
            "name": self.subcloud.name,
            "deploy_status": "secondary",
            "rehome_data": {
                "saved_payload": {
                    "system_mode": "simplex",
                    "name": "testsub",
                    "bootstrap-address": "128.224.119.56",
                    "sysadmin_password": "Li69nux",
                    "admin_password": "Li69nux",
                }
            },
        }
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_SECONDARY,
            rehome_data=self.saved_payload["rehome_data"],
        )
        self.sm.migrate_subcloud(self.ctx, self.subcloud.id, payload)

        mock_generate_subcloud_ansible_config.assert_called_once_with(
            mock.ANY, payload_result["rehome_data"]["saved_payload"]
        )
        mock_rehome_subcloud.assert_called_once_with(mock.ANY, mock.ANY)
        mock_db_api.subcloud_update.assert_called_once_with(
            mock.ANY,
            mock.ANY,
            deploy_status=consts.DEPLOY_STATE_PRE_REHOME,
            error_description=consts.ERROR_DESC_EMPTY,
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_parallel_group_operation"
    )
    def test_batch_migrate_subcloud(self, mock_run_parallel_group_operation):
        # Prepare the test data
        rehome_data = '{"saved_payload": {"system_mode": "simplex",\
            "name": "test_sub_migrate", "bootstrap-address": "128.224.119.56"}}'
        payload = {
            "sysadmin_password": self._create_password(),
            "peer_group": self.peer_group.peer_group_name,
        }
        subcloud = self.create_subcloud_static(
            self.ctx,
            name="sub_migrateable",
            deploy_status=consts.DEPLOY_STATE_SECONDARY,
        )
        db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            peer_group_id=self.peer_group.id,
            rehome_data=rehome_data,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )
        subcloud = self.create_subcloud_static(
            self.ctx,
            name="sub_no_rehome_data",
            deploy_status=consts.DEPLOY_STATE_SECONDARY,
        )
        db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            peer_group_id=self.peer_group.id,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )
        subcloud = self.create_subcloud_static(self.ctx, name="sub_no_secondary")
        db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            peer_group_id=self.peer_group.id,
            rehome_data=rehome_data,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )
        subcloud = self.create_subcloud_static(self.ctx, name="sub_no_saved_payload")
        db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            peer_group_id=self.peer_group.id,
            rehome_data="{}",
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )

        self.sm.batch_migrate_subcloud(self.ctx, payload)
        mock_run_parallel_group_operation.assert_called_with(
            "migrate", mock.ANY, mock.ANY, mock.ANY
        )
        actual_args, _ = mock_run_parallel_group_operation.call_args
        expect_subclouds = actual_args[3]
        self.assertEqual(1, len(expect_subclouds))
        self.assertEqual("sub_migrateable", expect_subclouds[0].name)

    def test_batch_migrate_subcloud_failed(self):
        # Prepare the test data
        payload = {}
        self.sm.batch_migrate_subcloud(self.ctx, payload)
        self.mock_log_subcloud_manager.error.assert_called_once_with(
            "Failed to migrate subcloud peer group, missing peer_group"
        )

    def test_batch_migrate_subcloud_failed_password(self):
        # Prepare the test data
        payload = {"peer_group": self.peer_group.peer_group_name}
        self.sm.batch_migrate_subcloud(self.ctx, payload)
        self.mock_log_subcloud_manager.error.assert_called_once_with(
            "Failed to migrate subcloud peer group, missing sysadmin_password"
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_unmanage_system_peer_subcloud"
    )
    def test_migrate_manage_subcloud_called_unmanage_peer_subcloud(
        self, mock_unmanage_system_peer_subcloud
    ):
        self.sm._migrate_manage_subcloud(
            self.ctx, mock.ANY, [self.system_peer], self.subcloud
        )
        mock_unmanage_system_peer_subcloud.assert_called()

    @mock.patch.object(system_peer_manager.SystemPeerManager, "get_peer_dc_client")
    @mock.patch.object(dcmanager_v1.DcmanagerClient, "update_subcloud")
    def test_unmanage_system_peer_subcloud_failed(
        self, mock_update_subcloud, mock_peer_dc_client
    ):
        mock_peer_dc_client.return_value = mock.MagicMock
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )
        ret = self.sm._unmanage_system_peer_subcloud([self.system_peer], self.subcloud)
        self.assertEqual(ret, False)
        self.mock_log_subcloud_manager.exception.assert_called_with(
            f"Failed to set unmanged for subcloud: {self.subcloud.region_name} "
            f"on system {self.system_peer.peer_name} attempt: 2"
        )

    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_unmanage_system_peer_subcloud"
    )
    def test_migrate_manage_subcloud_not_called_unmanage_peer_subcloud(
        self, mock_unmanage_system_peer_subcloud
    ):
        # Give empty system peers
        system_peers = []
        self.sm._migrate_manage_subcloud(
            self.ctx, mock.ANY, system_peers, self.subcloud
        )
        mock_unmanage_system_peer_subcloud.assert_not_called()

    @mock.patch.object(system_peer_manager.SystemPeerManager, "get_peer_dc_client")
    def test_unmanage_system_peer_subcloud_ret_false(self, mock_get_peer_dc_client):
        mock_get_peer_dc_client.update_subcloud.return_value = None
        ret = self.sm._unmanage_system_peer_subcloud([self.system_peer], self.subcloud)
        self.assertEqual(ret, False)
        mock_get_peer_dc_client().update_subcloud.assert_called()

    @mock.patch.object(system_peer_manager.SystemPeerManager, "get_peer_dc_client")
    @mock.patch.object(dcmanager_v1.DcmanagerClient, "update_subcloud")
    def test_unmanage_system_peer_subcloud_ret_true(
        self, mock_update_subcloud, mock_get_peer_dc_client
    ):
        mock_update_subcloud.return_value = mock.MagicMock()
        mock_get_peer_dc_client().get_subcloud.side_effect = (
            exceptions.SubcloudNotUnmanaged()
        )
        ret = self.sm._unmanage_system_peer_subcloud([self.system_peer], self.subcloud)
        self.assertEqual(ret, True)
        mock_get_peer_dc_client().update_subcloud.assert_not_called()

    @mock.patch.object(system_peer_manager.SystemPeerManager, "get_peer_dc_client")
    @mock.patch.object(dcmanager_v1.DcmanagerClient, "update_subcloud")
    def test_unmanage_system_peer_subcloud_update_subcloud(
        self, mock_update_subcloud, mock_get_peer_dc_client
    ):
        mock_get_peer_dc_client.return_value = mock.MagicMock()
        ret = self.sm._unmanage_system_peer_subcloud([self.system_peer], self.subcloud)
        self.assertEqual(ret, False)
        mock_get_peer_dc_client().update_subcloud.assert_called_once()

    @mock.patch.object(subcloud_manager.SubcloudManager, "subcloud_deploy_create")
    @mock.patch.object(subcloud_manager.SubcloudManager, "rehome_subcloud")
    @mock.patch.object(subcloud_manager.SubcloudManager, "run_deploy_phases")
    @mock.patch.object(subcloud_manager, "db_api")
    def test_add_subcloud_with_secondary_option(
        self,
        mock_db_api,
        mock_run_deploy_phases,
        mock_rehome_subcloud,
        mock_subcloud_deploy_create,
    ):
        # Prepare the test data
        values = {
            "name": "TestSubcloud",
            "sysadmin_password": "123",
            "secondary": "true",
            "region_name": "2ec93dfb654846909efe61d1b39dd2ce",
        }

        # Call add_subcloud method with the test data
        self.sm.add_subcloud(mock.MagicMock(), 1, values)

        # Assert that the rehome_subcloud and run_deploy_phases methods were not
        # called
        mock_rehome_subcloud.assert_not_called()
        mock_run_deploy_phases.assert_not_called()

        mock_subcloud_deploy_create.assert_called_once()

        # Assert that db_api.subcloud_update was not called for secondary subcloud
        self.assertFalse(mock_db_api.subcloud_update.called)

    def test_update_subcloud_bootstrap_address(self):
        fake_result = (
            '{"saved_payload": {"name": "TestSubcloud", '
            '"system_mode": "simplex", '
            '"bootstrap-address": "123.123.123.123"}}'
        )

        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
        )

        self.sm.update_subcloud(
            self.ctx, self.subcloud.id, bootstrap_values=self.fake_bootstrap_values
        )
        self.sm.update_subcloud(
            self.ctx, self.subcloud.id, bootstrap_address="123.123.123.123"
        )

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(fake_result, updated_subcloud.rehome_data)

    @mock.patch.object(db_api, "subcloud_peer_group_update")
    @mock.patch.object(
        subcloud_manager.SubcloudManager, "_run_parallel_group_operation"
    )
    def test_run_batch_migrate(
        self, mock_run_parallel_group_operation, mock_subcloud_peer_group_update
    ):
        self.mock_get_local_system.return_value = FakeSysinvClient.get_system(self)
        self.mock_openstack_driver.keystone_client = FakeKeystoneClient()
        db_api.subcloud_peer_group_update(
            self.ctx,
            group_id=1,
            peer_group_name="dc1-pg",
            group_priority=0,
            group_state="enabled",
            system_leader_id="ac62f555-9386-42f1-b3a1-51ecb709409d",
            system_leader_name="dc1-name",
            migration_status=None,
        )
        self.saved_payload.update(
            {
                "name": self.subcloud.name,
                "deploy_status": "secondary",
                "admin_password": self._create_password(),
            }
        )
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_SECONDARY,
            peer_group_id=self.peer_group.id,
            rehome_data=self.saved_payload["rehome_data"],
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )

        self.sm.run_batch_migrate(self.ctx, self.peer_group, "TGk2OW51eA==")
        Calls = [
            mock.call("No association found for peer group pgname"),
            mock.call("Batch migrate operation finished"),
        ]
        self.mock_log_subcloud_manager.info.assert_has_calls(Calls)

    @mock.patch.object(db_api, "subcloud_peer_group_update")
    def test_run_batch_migrate_no_secondary_subclouds(
        self, mock_subcloud_peer_group_update
    ):
        self.mock_sysinv_client().return_value = FakeSysinvClient()
        db_api.subcloud_peer_group_update(
            self.ctx,
            group_id=1,
            peer_group_name="dc1-pg",
            group_priority=0,
            group_state="enabled",
            system_leader_id="ac62f555-9386-42f1-b3a1-51ecb709409d",
            system_leader_name="dc1-name",
            migration_status=None,
        )
        self.saved_payload.update(
            {
                "name": self.subcloud.name,
                "deploy_status": "secondary",
                "admin_password": self._create_password(),
            }
        )
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            peer_group_id=self.peer_group.id,
            rehome_data=self.saved_payload["rehome_data"],
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
        )

        sysadmin_password = self._create_password()

        self.sm.run_batch_migrate(self.ctx, self.peer_group, sysadmin_password)
        Calls = [
            mock.call(
                "Skipping subcloud subcloud1 from batch migration: subcloud "
                "deploy_status is not in secondary, rehome-failed or rehome-prep-failed"
            ),
            mock.call(
                "No subclouds to be migrated in peer group: "
                "pgname ending migration attempt"
            ),
        ]
        self.mock_log_subcloud_manager.info.assert_has_calls(Calls)

    def test_migrate_subcloud_failed_non_existent_subcloud(self):
        payload = {}
        self.sm.migrate_subcloud(self.ctx, "subcloud2", payload)
        self.mock_log_subcloud_manager.error.assert_called_once_with(
            "Failed to migrate, non-existent subcloud subcloud2"
        )

    def test_migrate_subcloud_failed_sysadmin_pswd_not_provided(self):
        self.saved_payload["name"] = self.subcloud.name
        payload = {}
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            rehome_data=self.saved_payload["rehome_data"],
        )
        self.sm.migrate_subcloud(self.ctx, self.subcloud.id, payload)
        self.mock_log_subcloud_manager.error.assert_called_once_with(
            "Failed to migrate subcloud: subcloud1, must provide sysadmin_password"
        )

    def test_migrate_subcloud_failed_due_to_deploy_state(self):
        self.saved_payload["name"] = self.subcloud.name
        payload = {"sysadmin_password": self._create_password()}
        db_api.subcloud_update(
            self.ctx,
            self.subcloud.id,
            deploy_status=consts.DEPLOY_STATE_DONE,
            rehome_data=self.saved_payload["rehome_data"],
        )
        self.sm.migrate_subcloud(self.ctx, self.subcloud.id, payload)
        self.mock_log_subcloud_manager.error.assert_called_once_with(
            f"Failed to migrate subcloud: {self.subcloud.name}, "
            "must be in secondary or rehome failure state"
        )

    def test_rehome_subcloud_failed(self):
        self.mock_get_playbook_for_software_version = self._mock_object(
            cutils, "get_playbook_for_software_version"
        )
        self.mock_get_playbook_for_software_version.return_value = SW_VERSION
        self.mock_subprocess_run.return_value.returncode = 0
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_NONE

        self.sm.rehome_subcloud(self.ctx, self.subcloud)
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_REHOME_FAILED, updated_subcloud.deploy_status
        )

    @mock.patch.object(
        cutils, "find_ansible_error_msg", return_value="Fake playbook error"
    )
    def test_rehome_subcloud_find_and_save_ansible_error(self, mock_find_msg):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionFailed()

        self.mock_get_playbook_for_software_version = self._mock_object(
            cutils, "get_playbook_for_software_version"
        )
        self.mock_get_playbook_for_software_version.return_value = SW_VERSION

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_NONE

        self.sm.rehome_subcloud(self.ctx, self.subcloud)

        self.mock_ansible_run_playbook.assert_called_once()

        mock_find_msg.assert_called_once_with(
            self.subcloud["name"], mock.ANY, consts.DEPLOY_STATE_REHOMING
        )

        # Verify that subcloud has the correct deploy status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud["name"])
        self.assertEqual("Fake playbook error", updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_REHOME_FAILED, updated_subcloud.deploy_status
        )

    def test_rehome_subcloud_find_and_save_ansible_timeout(self):
        self.mock_ansible_run_playbook.side_effect = PlaybookExecutionTimeout()

        self.mock_get_playbook_for_software_version = self._mock_object(
            cutils, "get_playbook_for_software_version"
        )
        self.mock_get_playbook_for_software_version.return_value = SW_VERSION

        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_NONE

        self.sm.rehome_subcloud(self.ctx, self.subcloud)

        self.mock_ansible_run_playbook.assert_called_once()

        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud["name"])
        self.assertIn("Timeout", updated_subcloud.error_description)
        self.assertEqual(
            consts.DEPLOY_STATE_REHOME_FAILED, updated_subcloud.deploy_status
        )


class TestSubcloudInstall(BaseTestSubcloudManager):
    """Test class for testing subcloud install"""

    def setUp(self):
        super().setUp()
        self.mock_netaddr_ipaddress = self._mock_object(netaddr, "IPAddress")
        self.mock_compose_install_command = self._mock_object(
            subcloud_manager.SubcloudManager, "compose_install_command"
        )
        self.fake_install_values = copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        self.fake_install_values["software_version"] = SW_VERSION
        self.fake_log_file = (
            os.path.join(
                consts.DC_ANSIBLE_LOG_DIR, fake_subcloud.FAKE_SUBCLOUD_DATA["name"]
            )
            + "_playbook_output.log"
        )
        get_oam_address_pools = (
            self.mock_subcloud_install_sysinv_client().get_oam_address_pools
        )
        get_oam_address_pools.return_value = FAKE_OAM_POOLS
        self.mock_subprocess_run.return_value.returncode = 0
        self.subcloud.update(
            {
                "name": fake_subcloud.FAKE_SUBCLOUD_DATA["name"],
                "deploy_status": consts.DEPLOY_STATE_PRE_INSTALL,
            }
        )

    @mock.patch.object(request, "urlretrieve")
    def test_subcloud_install(self, mock_request_urlretrieve):
        mock_request_urlretrieve.return_value = "fake_path", "empty"
        self.mock_ansible_run_playbook.return_value = False

        install_success = self.sm._run_subcloud_install(
            self.ctx,
            self.subcloud,
            self.mock_compose_install_command,
            self.fake_log_file,
            self.fake_install_values,
        )
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_INSTALLING, updated_subcloud.deploy_status)
        self.mock_ansible_run_playbook.assert_called_once()
        self.assertTrue(install_success)
        Calls = [
            mock.call(
                "Preparing remote install of %s, version: %s",
                self.subcloud.name,
                SW_VERSION,
            ),
            mock.call(f"Starting remote install of {self.subcloud.name}"),
            mock.call(f"Successfully installed {self.subcloud.name}"),
        ]
        self.mock_log_subcloud_manager.info.assert_has_calls(Calls)

    @mock.patch.object(request, "urlretrieve")
    def test_subcloud_install_with_include_path(self, mock_request_urlretrieve):
        mock_request_urlretrieve.return_value = "fake_path", "empty"
        self.mock_ansible_run_playbook.return_value = False

        self.sm._run_subcloud_install(
            self.ctx,
            self.subcloud,
            self.mock_compose_install_command,
            self.fake_log_file,
            self.fake_install_values,
            include_paths=["/fake/include/path"],
        )

        # Assert that at least one gen-bootloader-iso.sh call was made
        script_calls = [
            call
            for call in self.mock_subprocess_run.call_args_list
            if "/usr/local/bin/gen-bootloader-iso.sh" in call[0][0]
        ]
        self.assertTrue(script_calls, "No call to gen-bootloader-iso.sh was found")

        # Assert that the --include-path and path are present
        script_args = [arg for call in script_calls for arg in call[0][0]]
        self.assertIn("--include-path", script_args)
        self.assertIn("/fake/include/path", script_args)

    @mock.patch.object(request, "urlretrieve")
    def test_subcloud_install_prep_failed(self, mock_request_urlretrieve):
        mock_request_urlretrieve.side_effect = Exception()

        install_success = self.sm._run_subcloud_install(
            self.ctx,
            self.subcloud,
            self.mock_compose_install_command,
            self.fake_log_file,
            self.fake_install_values,
        )
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_PRE_INSTALL_FAILED, updated_subcloud.deploy_status
        )
        self.assertFalse(install_success)

    @mock.patch.object(request, "urlretrieve")
    def test_subcloud_install_with_aborted_install(self, mock_request_urlretrieve):
        mock_request_urlretrieve.return_value = "fake_path", "empty"
        self.mock_ansible_run_playbook.return_value = True
        self.subcloud["deploy_status"] = consts.DEPLOY_STATE_PRE_INSTALL_FAILED

        install_success = self.sm._run_subcloud_install(
            self.ctx,
            self.subcloud,
            self.mock_compose_install_command,
            self.fake_log_file,
            self.fake_install_values,
        )
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(consts.DEPLOY_STATE_INSTALLING, updated_subcloud.deploy_status)
        self.mock_ansible_run_playbook.assert_called_once()
        self.assertFalse(install_success)

    @mock.patch.object(
        cutils, "find_ansible_error_msg", return_value="Fake playbook error"
    )
    @mock.patch.object(request, "urlretrieve")
    @mock.patch("dcmanager.manager.subcloud_manager.SubcloudInstall")
    def test_subcloud_install_find_and_save_playbook_error(
        self, mock_subcloud_install_cls, mock_request_urlretrieve, mock_find_msg
    ):

        mock_request_urlretrieve.return_value = "fake_path", "empty"

        mock_install_instance = mock_subcloud_install_cls.return_value
        mock_install_instance.install.side_effect = PlaybookExecutionFailed()

        payload = {
            "software_version": SW_VERSION,
            "install_values": self.fake_install_values,
        }

        install_success = self.sm._run_subcloud_install(
            self.ctx,
            self.subcloud,
            self.mock_compose_install_command,
            self.fake_log_file,
            payload,
        )

        self.assertFalse(install_success)

        mock_find_msg.assert_called_once_with(
            self.subcloud.name, self.fake_log_file, consts.DEPLOY_STATE_INSTALLING
        )

        mock_install_instance.cleanup.assert_called_once_with(
            payload["software_version"]
        )

        # Verify that subcloud has the correct enroll status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_INSTALL_FAILED, updated_subcloud.deploy_status
        )
        self.assertEqual("Fake playbook error", updated_subcloud.error_description)

    @mock.patch.object(request, "urlretrieve")
    @mock.patch("dcmanager.manager.subcloud_manager.SubcloudInstall")
    def test_subcloud_install_find_and_save_playbook_timeout(
        self, mock_subcloud_install_cls, mock_request_urlretrieve
    ):

        mock_request_urlretrieve.return_value = "fake_path", "empty"
        mock_install_instance = mock_subcloud_install_cls.return_value
        mock_install_instance.install.side_effect = PlaybookExecutionTimeout()

        payload = {
            "software_version": SW_VERSION,
            "install_values": self.fake_install_values,
        }

        install_success = self.sm._run_subcloud_install(
            self.ctx,
            self.subcloud,
            self.mock_compose_install_command,
            self.fake_log_file,
            payload,
        )

        self.assertFalse(install_success)
        mock_install_instance.cleanup.assert_called_once_with(
            payload["software_version"]
        )

        # Verify that subcloud has the correct enroll status
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, self.subcloud.name)
        self.assertEqual(
            consts.DEPLOY_STATE_INSTALL_FAILED, updated_subcloud.deploy_status
        )
        self.assertIn("Timeout", updated_subcloud.error_description)


class TestSubcloudRename(BaseTestSubcloudManager):
    """Test class for testing rename subcloud"""

    def setUp(self):
        super().setUp()
        self.new_subcloud_name = "testsubcloud"
        self.alarms = test_subcloud_alarms.DBAPISubcloudAlarm
        self.alarms.create_subcloud_alarms(self.ctx, self.subcloud.name)

    @mock.patch.object(yaml, "safe_load")
    @mock.patch.object(filecmp, "cmp")
    @mock.patch.object(os, "rename")
    def test_rename_subcloud_ansible_files(self, mock_rename, mock_filecmp, mock_load):
        cur_file = "subcloud1.yml"
        self.mock_os_listdir.return_value = [cur_file]
        data = {"key1": "value1", "key2": "value2"}
        mock_load.return_value = data
        self.mock_builtins_open().return_value = f"{ANS_PATH}/subcloud1_inventory.yml"
        rehome_data = '{"saved_payload": {"system_mode": "simplex",\
            "name": "test_sub_migrate", "bootstrap-address": "128.224.119.56"}}'
        db_api.subcloud_update(self.ctx, self.subcloud.id, rehome_data=rehome_data)
        self.sm.rename_subcloud(
            self.ctx, self.subcloud.id, self.subcloud.name, self.new_subcloud_name
        )
        ret = db_api.subcloud_get_by_name(self.ctx, self.new_subcloud_name)
        self.assertEqual(self.new_subcloud_name, ret.name)
        Calls = [
            mock.call(
                f"{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1.yml",
                f"{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/testsubcloud.yml",
            ),
            mock.call(
                f"{consts.DC_ANSIBLE_LOG_DIR}/subcloud1.yml",
                f"{consts.DC_ANSIBLE_LOG_DIR}/testsubcloud.yml",
            ),
        ]
        mock_rename.assert_has_calls(Calls)

    @mock.patch.object(filecmp, "cmp")
    def test_rename_subcloud_inventory_file_failed(self, mock_filecmp):
        self.mock_os_path_exists.return_value = False
        self.mock_os_listdir.return_value = ["testfile1", "testfile2"]

        db_api.subcloud_update(self.ctx, self.subcloud.id, self.subcloud.name)
        self.sm.rename_subcloud(
            self.ctx, self.subcloud.id, self.subcloud.name, self.new_subcloud_name
        )
        ret = db_api.subcloud_get_by_name(self.ctx, self.new_subcloud_name)
        self.mock_log_subcloud_manager.warn.assert_called_once_with(
            f"Could not rename inventory file {dccommon_consts.ANSIBLE_OVERRIDES_PATH}/"
            "testsubcloud_inventory.yml because it does not exist."
        )
        self.assertEqual(self.new_subcloud_name, ret.name)
        self.assertEqual(self.mock_os_listdir.call_count, 2)


class TestSubcloudEnrollment(BaseTestSubcloudManager):
    """Test class for testing Subcloud Enrollment"""

    def setUp(self):
        super().setUp()
        self.rel_version = "24.09"
        self.subcloud_name = "test_subcloud"
        self.iso_dir = (
            f"/opt/platform/iso/{self.rel_version}/nodes/{self.subcloud_name}"
        )
        self.iso_file = f"{self.iso_dir}/seed.iso"
        self.seed_data_dir = "/temp/seed_data"
        self.enroll_init = subcloud_enrollment.SubcloudEnrollmentInit(
            self.subcloud_name
        )
        self.fake_install_values = copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)

        self.iso_values = {
            "software_version": self.rel_version,
            "sysadmin_password": "St8rlingX*",
            "bootstrap_interface": "enp2s1",
            "external_oam_floating_address": "10.10.10.2",
            "network_mask": "255.255.255.0",
            "external_oam_gateway_address": "10.10.10.1",
            "external_oam_subnet": "10.10.10.0/24",
            "install_values": self.fake_install_values,
            "system_mode": "simplex",
            "bmc_password": "bmc_pass",
        }

        self.mock_temporary_directory = self._mock_object(
            tempfile, "TemporaryDirectory"
        )
        self.mock_os_makedirs = self._mock_object(os, "makedirs")
        self._mock_object(shutil, "rmtree")
        self.mock_log_subcloud_enrollment = self._mock_object(
            subcloud_enrollment, "LOG"
        )

        self.mock_os_path_exists.return_value = True
        self.mock_temporary_directory.return_value.__enter__.return_value = (
            self.seed_data_dir
        )
        self.mock_os_path_isdir.return_value = True
        self.mock_subprocess_run.return_value = mock.MagicMock(
            returncode=0, stdout=b"Success"
        )

    def patched_isdir(self, path):
        return path != self.iso_dir

    def test_build_seed_meta_config(self):
        result = self.enroll_init._build_seed_meta_data(
            self.seed_data_dir, self.iso_values
        )

        self.assertTrue(result)
        self.mock_builtins_open.assert_called_once_with(
            f"{self.seed_data_dir}/meta-data", "w"
        )

    @mock.patch("os.chmod")
    def test_build_seed_user_config(self, mock_chmod):
        scripts_dir = os.path.join(self.seed_data_dir, "cloud-init-config", "scripts")

        result = self.enroll_init._build_seed_user_config(
            self.seed_data_dir, self.iso_values
        )

        self.assertTrue(result)
        self.mock_os_makedirs.assert_any_call(scripts_dir, exist_ok=True)

        # The user-data file must be created
        self.mock_builtins_open.assert_any_call(f"{self.seed_data_dir}/user-data", "w")

        # The platform script must be created
        platform_script = os.path.join(
            scripts_dir,
            dccommon_consts.PLATFORM_RECONFIGURE_FILE_NAME,
        )
        self.mock_builtins_open.assert_any_call(platform_script, "w")

        # Test with incomplete iso_values, expect KeyError
        copied_dict = self.iso_values.copy()
        copied_dict.pop("sysadmin_password")

        self.assertRaises(
            KeyError,
            self.enroll_init._build_seed_user_config,
            self.seed_data_dir,
            copied_dict,
        )

    def test_build_seed_network_config(self):
        copied_dict = self.iso_values.copy()
        copied_dict["bootstrap_vlan"] = 401

        result = self.enroll_init._build_seed_network_config(
            self.seed_data_dir, copied_dict
        )

        self.assertTrue(result)
        self.mock_builtins_open.assert_called_once_with(
            f"{self.seed_data_dir}/network-config", "w"
        )

        # Test with incomplete iso_values, expect KeyError
        copied_dict.pop("external_oam_subnet")

        self.assertRaises(
            KeyError,
            self.enroll_init._build_seed_network_config,
            self.seed_data_dir,
            copied_dict,
        )

    @mock.patch("os.chmod")
    def test_generate_seed_iso(self, mock_chmod):
        with mock.patch("os.path.isdir", side_effect=self.patched_isdir):
            self.assertTrue(self.enroll_init._generate_seed_iso(self.iso_values, None))

            self.mock_log_subcloud_enrollment.info.assert_any_call(
                f"Preparing seed iso generation for {self.subcloud_name}"
            )

            # Iso command must be invoked (subprocess.run)
            self.mock_subprocess_run.assert_called_once()
            # Temp seed data dir must be created
            self.mock_temporary_directory.assert_called_once_with(prefix="seed_")
            # Seed files must be generated in temp seed dir
            self.mock_builtins_open.assert_any_call(
                f"{self.seed_data_dir}/meta-data", "w"
            )
            self.mock_builtins_open.assert_any_call(
                f"{self.seed_data_dir}/user-data", "w"
            )
            self.mock_builtins_open.assert_any_call(
                f"{self.seed_data_dir}/network-config", "w"
            )
            # The scripts directory must be created
            scripts_dir = os.path.join(
                self.seed_data_dir,
                "cloud-init-config",
                "scripts",
            )
            self.mock_os_makedirs.assert_any_call(scripts_dir, exist_ok=True)
            # The platform script must be created
            platform_script = os.path.join(
                scripts_dir,
                dccommon_consts.PLATFORM_RECONFIGURE_FILE_NAME,
            )
            self.mock_builtins_open.assert_any_call(platform_script, "w")

    @mock.patch.object(
        subcloud_install.SubcloudInstall,
        "get_image_base_url",
        return_value="https://10.10.10.12:8080",
    )
    @mock.patch.object(subcloud_enrollment.SubcloudEnrollmentInit, "_generate_seed_iso")
    @mock.patch.object(
        subcloud_enrollment.SubcloudEnrollmentInit, "validate_enroll_init_values"
    )
    def test_enroll_prep(
        self, mock_validate, mock_generate_seed_iso, mock_get_image_base_url
    ):
        self.mock_builtins_open.side_effect = mock.mock_open()
        with mock.patch("os.path.isdir", side_effect=self.patched_isdir):
            override_path = os.path.join(ANS_PATH, self.subcloud_name)
            result = self.enroll_init.prep(ANS_PATH, self.iso_values, 4)

            self.assertTrue(result)

            self.mock_log_subcloud_enrollment.info.assert_called_with(
                f"Prepare config for {self.subcloud_name} enroll init"
            )

            # Assert that validate_enroll_init_values was called with the payload
            mock_validate.assert_called_once_with(self.iso_values)

            # ISO dir must be created
            self.mock_os_makedirs.assert_called_once()
            self.assertEqual(self.mock_os_makedirs.call_args.args[0], self.iso_dir)

            mock_generate_seed_iso.assert_called_once_with(self.iso_values, None)

            # create rvmc config file
            self.mock_builtins_open.assert_any_call(
                f"{override_path}/{dccommon_consts.RVMC_CONFIG_FILE_NAME}", "w"
            )

            mock_url = (
                '"https://10.10.10.12:8080/iso/24.09/nodes/test_subcloud/seed.iso"'
            )
            mock_bmc_address = '"128.224.64.180"'

            self.mock_builtins_open().write.assert_any_call(
                f"bmc_address: {mock_bmc_address}\n"
            )
            self.mock_builtins_open().write.assert_any_call(f"image: {mock_url}\n")

            self.mock_builtins_open.assert_any_call(
                f"{override_path}/enroll_overrides.yml", "w"
            )

            self.mock_builtins_open().write.assert_any_call(
                "---" "\nenroll_reconfigured_oam: " + "10.10.10.2" + "\n"
            )

    @mock.patch.object(
        subcloud_install.SubcloudInstall,
        "get_image_base_url",
        return_value="https://10.10.10.12:8080",
    )
    @mock.patch("os.chmod")
    def test_enroll_prep_iso_cleanup(self, mock_chmod, mock_validate):
        result = self.enroll_init.prep(ANS_PATH, self.iso_values, 4)
        self.assertTrue(result)
        self.mock_log_subcloud_enrollment.info.assert_any_call(
            f"Prepare config for {self.subcloud_name} enroll init"
        )

        # Previous iso file must be cleaned up
        self.mock_os_remove.assert_called_once_with(self.iso_file)

        # Now makedirs *should* be called for the scripts dir at least once
        scripts_dir = os.path.join(self.seed_data_dir, "cloud-init-config", "scripts")
        self.mock_os_makedirs.assert_called_once_with(scripts_dir, exist_ok=True)

        self.mock_log_subcloud_enrollment.info.assert_any_call(
            f"Found preexisting seed iso for subcloud {self.subcloud_name}, cleaning up"
        )

    def test_enroll_init(self):
        result = self.enroll_init.enroll_init(consts.DC_ANSIBLE_LOG_DIR, mock.ANY)
        self.assertTrue(result)
        self.mock_ansible_run_playbook.assert_called_once()

        expected_log_entry = f"Start enroll init for {self.subcloud_name}"

        self.mock_log_subcloud_enrollment.info.assert_any_call(expected_log_entry)

        subcloud_log_base_path = os.path.join(
            consts.DC_ANSIBLE_LOG_DIR, self.subcloud_name
        )
        expected_log_file = f"{subcloud_log_base_path}_playbook_output.log"
        self.mock_ansible_run_playbook.assert_called_with(expected_log_file, mock.ANY)


class TestEnrollOverrides(BaseTestSubcloudManager):
    """Test class for testing enroll override file creation methods."""

    def setUp(self):
        super().setUp()
        self.override_path = "/test/override/path"
        self.rel_version = "25.09"
        self.subcloud_name = "test_subcloud"
        self.enroll_init = subcloud_enrollment.SubcloudEnrollmentInit(
            self.subcloud_name
        )
        self.fake_install_values = copy.copy(fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES)
        self.iso_values = {
            "software_version": self.rel_version,
            "external_oam_floating_address": "10.10.10.2",
            "install_values": self.fake_install_values,
        }

        # Base variables that can be modified in individual test cases
        self.enroll_overrides = {"key2": "value2", "key3": "value3"}
        self.expected_content = [
            "enroll_reconfigured_oam: 10.10.10.2",
            "key2: value2",
            "key3: value3",
        ]

    def _run_test_scenario(
        self,
        enroll_overrides,
        cloud_init_tarball,
        expected_content,
        unexpected_content=None,
    ):
        self.mock_builtins_open.side_effect = mock.mock_open()
        test_iso_values = self.iso_values.copy()
        if enroll_overrides:
            test_iso_values["install_values"]["enroll_overrides"] = enroll_overrides

        self.enroll_init.create_enroll_override_file(
            self.override_path, test_iso_values, cloud_init_tarball
        )

        expected_file_path = f"{self.override_path}/enroll_overrides.yml"
        self.mock_builtins_open.assert_called_with(expected_file_path, "w")

        write_calls = self.mock_builtins_open().write.call_args_list
        content = "".join([call[0][0] for call in write_calls])

        for expected in expected_content:
            self.assertIn(expected, content)

        if unexpected_content:
            for unexpected in unexpected_content:
                self.assertNotIn(unexpected, content)

    def test_create_enroll_override_file_without_cloud_tarball_and_ipmi_monitoring(
        self,
    ):
        expected_content = self.expected_content.copy()
        expected_content.append("ipmi_sel_event_monitoring: false")
        self._run_test_scenario(self.enroll_overrides, None, expected_content)

    def test_create_enroll_override_file_no_cloud_tarball_with_ipmi_monitoring(
        self,
    ):
        self.enroll_overrides["ipmi_sel_event_monitoring"] = True
        expected_content = self.expected_content.copy()
        expected_content.append("ipmi_sel_event_monitoring: true")
        self._run_test_scenario(self.enroll_overrides, None, expected_content)

    def test_create_enroll_override_file_no_cloud_tarball_ipmi_false(
        self,
    ):
        self.enroll_overrides["ipmi_sel_event_monitoring"] = False
        expected_content = self.expected_content.copy()
        expected_content.append("ipmi_sel_event_monitoring: false")
        self._run_test_scenario(self.enroll_overrides, None, expected_content)

    def test_create_enroll_override_file_with_cloud_tarball_and_ipmi_monitoring(
        self,
    ):
        self.enroll_overrides["ipmi_sel_event_monitoring"] = True
        expected_content = self.expected_content.copy()
        expected_content.append("ipmi_sel_event_monitoring: true")
        self._run_test_scenario(
            self.enroll_overrides, "/path/to/cloud_init.tar", expected_content
        )

    def test_create_enroll_override_file_with_cloud_tarball_no_ipmi_override(self):
        unexpected_content = ["ipmi_sel_event_monitoring"]
        self._run_test_scenario(
            self.enroll_overrides,
            "/path/to/cloud_init.tar",
            self.expected_content,
            unexpected_content,
        )

    def test_create_enroll_override_file_with_cloud_init_tarball_ipmi_false(self):
        self.enroll_overrides["ipmi_sel_event_monitoring"] = False
        expected_content = self.expected_content.copy()
        expected_content.append("ipmi_sel_event_monitoring: false")
        self._run_test_scenario(
            self.enroll_overrides, "/path/to/cloud_init.tar", expected_content
        )
