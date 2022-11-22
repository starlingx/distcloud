#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_utils import timeutils

import base64
import copy
import mock
import six
import webtest

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.rpc import client as rpc_client

from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests import utils

FAKE_TENANT = utils.UUID1
FAKE_URL_CREATE = '/v1.0/subcloud-backup'
FAKE_URL_DELETE = '/v1.0/subcloud-backup/delete/'
FAKE_URL_RESTORE = '/v1.0/subcloud-backup/restore'
FAKE_HEADERS = {'X-Tenant-Id': FAKE_TENANT, 'X_ROLE': 'admin,member,reader',
                'X-Identity-Status': 'Confirmed', 'X-Project-Name': 'admin',
                'Content-Type': 'json'}
FAKE_GOOD_SYSTEM_HEALTH = \
    ("System Health:\n"
     "All hosts are provisioned: [OK]\n"
     "All hosts are unlocked/enabled: [OK]\n"
     "All hosts have current configurations: [OK]\n"
     "All hosts are patch current: [OK]\n"
     "No alarms: [Fail]\n"
     "[1] alarms found, [0] of which are management affecting\n"
     "All kubernetes nodes are ready: [OK]\n"
     "All kubernetes control plane pods are ready: [OK]\n")
FAKE_GOOD_SYSTEM_HEALTH_NO_ALARMS = \
    ("System Health:"
     "All hosts are provisioned: [OK]"
     "All hosts are unlocked/enabled: [OK]"
     "All hosts have current configurations: [OK]"
     "All hosts are patch current: [OK]"
     "No alarms: [OK]"
     "All kubernetes nodes are ready: [OK]"
     "All kubernetes control plane pods are ready: [OK]")
FAKE_SYSTEM_HEALTH_CEPH_FAIL = \
    ("System Health:\n"
     "All hosts are provisioned: [OK]\n"
     "All hosts are unlocked/enabled: [OK]\n"
     "All hosts have current configurations: [OK]\n"
     "All hosts are patch current: [OK]\n"
     "Ceph Storage Healthy: [Fail]\n"
     "No alarms: [Fail]\n"
     "[2] alarms found, [2] of which are management affecting\n"
     "All kubernetes nodes are ready: [OK]\n"
     "All kubernetes control plane pods are ready: [OK]\n")
FAKE_SYSTEM_HEALTH_MGMT_ALARM = \
    ("System Health:\n"
     "All hosts are provisioned: [OK]\n"
     "All hosts are unlocked/enabled: [OK]\n"
     "All hosts have current configurations: [OK]\n"
     "All hosts are patch current: [OK]\n"
     "Ceph Storage Healthy: [Fail]\n"
     "No alarms: [Fail]\n"
     "[2] alarms found, [2] of which are management affecting\n"
     "All kubernetes nodes are ready: [OK]\n"
     "All kubernetes control plane pods are ready: [OK]\n")
FAKE_SYSTEM_HEALTH_K8S_FAIL = \
    ("System Health:\n"
     "All hosts are provisioned: [OK]\n"
     "All hosts are unlocked/enabled: [OK]\n"
     "All hosts have current configurations: [OK]\n"
     "All hosts are patch current: [OK]\n"
     "Ceph Storage Healthy: [Fail]\n"
     "No alarms: [Fail]\n"
     "[2] alarms found, [2] of which are management affecting\n"
     "All kubernetes nodes are ready: [OK]\n"
     "All kubernetes control plane pods are ready: [OK]\n")


class TestSubcloudCreate(testroot.DCManagerApiTest):

    def setUp(self):

        super(TestSubcloudCreate, self).setUp()
        self.ctx = utils.dummy_context()

        p = mock.patch.object(rpc_client, 'SubcloudStateClient')
        self.mock_rpc_state_client = p.start()
        self.addCleanup(p.stop)

    @mock.patch('dcmanager.common.utils.OpenStackDriver')
    @mock.patch('dcmanager.common.utils.SysinvClient')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud(self, mock_rpc_client, mock_sysinv,
                                    mock_openstack):

        mock_rpc_client().backup_subclouds.return_value = True
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1'}
        good_health_states = [FAKE_GOOD_SYSTEM_HEALTH,
                              FAKE_GOOD_SYSTEM_HEALTH_NO_ALARMS]

        for system_health in good_health_states:

            mock_sysinv().get_system_health.return_value = system_health
            db_api.subcloud_update(self.ctx,
                                   subcloud.id,
                                   availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                                   management_state=dccommon_consts.MANAGEMENT_MANAGED,
                                   backup_datetime=None,
                                   backup_status=consts.BACKUP_STATE_UNKNOWN)

            response = self.app.post_json(FAKE_URL_CREATE,
                                          headers=FAKE_HEADERS,
                                          params=data)

            self.assertEqual(response.status_int, 200)

    @mock.patch('dcmanager.common.utils.OpenStackDriver')
    @mock.patch('dcmanager.common.utils.SysinvClient')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud_with_bad_system_health(
        self, mock_rpc_client, mock_sysinv, mock_openstack):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        mock_rpc_client().backup_subclouds.return_value = True
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password, 'subcloud': '1'}

        bad_health_states = [FAKE_SYSTEM_HEALTH_MGMT_ALARM, FAKE_SYSTEM_HEALTH_CEPH_FAIL,
                             FAKE_SYSTEM_HEALTH_K8S_FAIL]

        for system_health in bad_health_states:

            mock_sysinv().get_system_health.return_value = system_health
            db_api.subcloud_update(self.ctx,
                                   subcloud.id,
                                   availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                                   management_state=dccommon_consts.MANAGEMENT_MANAGED,
                                   backup_datetime=None,
                                   backup_status=consts.BACKUP_STATE_UNKNOWN)

            six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                                  self.app.post_json, FAKE_URL_CREATE,
                                  headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_unknown_subcloud(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '123'}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_offline_subcloud(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1'}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_unmanaged_subcloud(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1'}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud_invalid_state(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN,
                               deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1'}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_group(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'group': '1'}

        mock_rpc_client().backup_subclouds.return_value = True

        response = self.app.post_json(FAKE_URL_CREATE,
                                      headers=FAKE_HEADERS,
                                      params=data)

        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_unknown_group(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'group': 'Fake'}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_group_not_online(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'group': '1'}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_group_not_managed(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'group': '1'}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_group_no_valid_state(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN,
                               deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'group': '1'}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud_and_group(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1',
                'group': '1'}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_no_subcloud_no_group(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch('dcmanager.common.utils.OpenStackDriver')
    @mock.patch('dcmanager.common.utils.SysinvClient')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud_backup_values(self, mock_rpc_client, mock_sysinv, mock_openstack):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1',
                'backup_values': 'TestFileDirectory'}

        mock_rpc_client().backup_subclouds.return_value = True
        mock_sysinv().get_system_health.return_value = FAKE_GOOD_SYSTEM_HEALTH

        response = self.app.post_json(FAKE_URL_CREATE,
                                      headers=FAKE_HEADERS,
                                      params=data)

        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_no_password(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        data = {'subcloud': '1'}
        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch('dcmanager.common.utils.OpenStackDriver')
    @mock.patch('dcmanager.common.utils.SysinvClient')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud_local_only(self, mock_rpc_client, mock_sysinv,
                                               mock_openstack):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1',
                'local_only': 'True'}
        mock_rpc_client().backup_subclouds.return_value = True
        mock_sysinv().get_system_health.return_value = FAKE_GOOD_SYSTEM_HEALTH

        response = self.app.post_json(FAKE_URL_CREATE,
                                      headers=FAKE_HEADERS,
                                      params=data)

        self.assertEqual(response.status_int, 200)

    @mock.patch('dcmanager.common.utils.OpenStackDriver')
    @mock.patch('dcmanager.common.utils.SysinvClient')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud_local_only_registry_images(
        self, mock_rpc_client, mock_sysinv, mock_openstack):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1',
                'local_only': 'True',
                'registry_images': 'True'}
        mock_rpc_client().backup_subclouds.return_value = True
        mock_sysinv().get_system_health.return_value = FAKE_GOOD_SYSTEM_HEALTH

        response = self.app.post_json(FAKE_URL_CREATE,
                                      headers=FAKE_HEADERS,
                                      params=data)

        self.assertEqual(response.status_int, 200)

    @mock.patch('dcmanager.common.utils.OpenStackDriver')
    @mock.patch('dcmanager.common.utils.SysinvClient')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud_no_local_only_registry_images(
        self, mock_rpc_client, mock_sysinv, mock_openstack):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1',
                'registry_images': 'True'}

        mock_rpc_client().backup_subclouds.return_value = True
        mock_sysinv().get_system_health.return_value = FAKE_GOOD_SYSTEM_HEALTH

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud_unknown_parameter(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1',
                'unkown_variable': 'FakeValue'}

        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud_invalid_payload_format(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        data = 'WrongFormat'
        mock_rpc_client().backup_subclouds.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.post_json, FAKE_URL_CREATE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch('dcmanager.common.utils.OpenStackDriver')
    @mock.patch('dcmanager.common.utils.SysinvClient')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_create_subcloud_json_file(self, mock_rpc_client, mock_sysinv,
                                              mock_openstack):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1'}
        mock_rpc_client().backup_subclouds.return_value = True
        mock_sysinv().get_system_health.return_value = FAKE_GOOD_SYSTEM_HEALTH

        response = self.app.post_json(FAKE_URL_CREATE,
                                      headers=FAKE_HEADERS,
                                      params=data)

        self.assertEqual(response.status_int, 200)


class TestSubcloudDelete(testroot.DCManagerApiTest):

    def setUp(self):

        super(TestSubcloudDelete, self).setUp()
        self.ctx = utils.dummy_context()

        p = mock.patch.object(rpc_client, 'SubcloudStateClient')
        self.mock_rpc_state_client = p.start()
        self.addCleanup(p.stop)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_subcloud(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1'}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        response = self.app.patch_json(FAKE_URL_DELETE + release_version,
                                       headers=FAKE_HEADERS,
                                       params=data)

        self.assertEqual(response.status_int, 207)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_unknown_group(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'group': '999'}

        mock_rpc_client().delete_subcloud_backups.return_value = True
        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.patch_json, FAKE_URL_DELETE + release_version,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def _test_backup_delete_subcloud_unmanaged(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'group': '1'}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_DELETE + release_version,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_group(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'group': '1'}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        response = self.app.patch_json(FAKE_URL_DELETE + release_version,
                                       headers=FAKE_HEADERS,
                                       params=data)

        self.assertEqual(response.status_int, 207)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_subcloud_and_group(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)
        HEADER = copy.copy(FAKE_HEADERS)
        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1',
                'group': '1'}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_DELETE + release_version,
                              headers=HEADER, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_no_subcloud_no_group(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_DELETE + release_version,
                              headers=FAKE_HEADERS, params=data)

# from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
# from dccommon.drivers.openstack.sysinv_v1 import SysinvClient

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_invalid_url(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        invalid_url = '/v1.0/subcloud-backup/fake/'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1'}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.patch_json, invalid_url,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_no_release_version(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1'}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_DELETE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_no_content(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1'}

        mock_rpc_client().delete_subcloud_backups.return_value = None

        response = self.app.patch_json(FAKE_URL_DELETE + release_version,
                                       headers=FAKE_HEADERS,
                                       params=data)

        self.assertEqual(response.status_int, 204)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_exception(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1'}

        mock_rpc_client().delete_subcloud_backups.side_effect = Exception()

        six.assertRaisesRegex(self, webtest.app.AppError, "500 *",
                              self.app.patch_json, FAKE_URL_DELETE + release_version,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_local_only(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1',
                'local_only': 'True'}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        response = self.app.patch_json(FAKE_URL_DELETE + release_version,
                                       headers=FAKE_HEADERS,
                                       params=data)

        self.assertEqual(response.status_int, 207)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_no_local_only(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1',
                'local_only': 'False'}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        response = self.app.patch_json(FAKE_URL_DELETE + release_version,
                                       headers=FAKE_HEADERS,
                                       params=data)

        self.assertEqual(response.status_int, 207)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_unknown_local_only(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '1',
                'local_only': 'Fake'}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_DELETE + release_version,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_delete_local_only_unknown_subcloud(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)

        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=timeutils.utcnow(),
                               backup_status=consts.BACKUP_STATE_COMPLETE)

        release_version = '22.12'
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'subcloud': '123',
                'local_only': 'True'}

        mock_rpc_client().delete_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.patch_json, FAKE_URL_DELETE + release_version,
                              headers=FAKE_HEADERS, params=data)


class TestSubcloudRestore(testroot.DCManagerApiTest):

    def setUp(self):

        super(TestSubcloudRestore, self).setUp()
        self.ctx = utils.dummy_context()
        p = mock.patch.object(rpc_client, 'SubcloudStateClient')
        self.mock_rpc_state_client = p.start()
        self.addCleanup(p.stop)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_subcloud(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password, 'subcloud': '1'}

        mock_rpc_client().restore_subcloud_backups.return_value = True
        response = self.app.patch_json(FAKE_URL_RESTORE,
                                       headers=FAKE_HEADERS,
                                       params=data)

        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_unknown_subcloud(self, mock_rpc_client):

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password, 'subcloud': '999'}

        mock_rpc_client().restore_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_RESTORE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_subcloud_group(self, mock_rpc_client):

        test_group_id = 1
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx, group_id=test_group_id)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password, 'group': str(test_group_id)}

        mock_rpc_client().restore_subcloud_backups.return_value = True
        response = self.app.patch_json(FAKE_URL_RESTORE,
                                       headers=FAKE_HEADERS,
                                       params=data)

        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_group_single_valid_subcloud(self, mock_rpc_client):

        test_group_id = 1
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx, group_id=test_group_id)
        subcloud2 = fake_subcloud.create_fake_subcloud(self.ctx, group_id=test_group_id, name='subcloud2')
        # Valid subcloud, management state is 'unmanaged'
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)
        # Invalid subcloud, management state is 'managed'
        db_api.subcloud_update(self.ctx,
                               subcloud2.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password, 'group': str(test_group_id)}

        mock_rpc_client().restore_subcloud_backups.return_value = True
        response = self.app.patch_json(FAKE_URL_RESTORE,
                                       headers=FAKE_HEADERS,
                                       params=data)

        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_unknown_subcloud_group(self, mock_rpc_client):

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password, 'group': '123'}

        mock_rpc_client().restore_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.patch_json, FAKE_URL_RESTORE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_no_payload(self, mock_rpc_client):

        test_group_id = 1
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx, group_id=test_group_id)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        mock_rpc_client().restore_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_RESTORE,
                              headers=FAKE_HEADERS)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_no_local_only_registry_images(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password, 'subcloud': '1',
                'local_only': 'false', 'registry_images': 'true'}

        mock_rpc_client().restore_subcloud_backups.return_value = True
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_RESTORE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_subcloud_managed(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password, 'subcloud': '1'}

        mock_rpc_client().restore_subcloud_backups.return_value = True
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_RESTORE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_subcloud_invalid_deploy_states(self, mock_rpc_client):

        invalid_deploy_states = [consts.DEPLOY_STATE_INSTALLING,
                                 consts.DEPLOY_STATE_BOOTSTRAPPING,
                                 consts.DEPLOY_STATE_DEPLOYING,
                                 consts.DEPLOY_STATE_REHOMING]

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password, 'subcloud': '1'}
        mock_rpc_client().restore_subcloud_backups.return_value = True

        for status in invalid_deploy_states:
            db_api.subcloud_update(self.ctx,
                                   subcloud.id,
                                   availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                                   management_state=dccommon_consts.MANAGEMENT_MANAGED,
                                   deploy_status=status,
                                   backup_datetime=None,
                                   backup_status=consts.BACKUP_STATE_UNKNOWN)

            six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                                  self.app.patch_json, FAKE_URL_RESTORE,
                                  headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_subcloud_and_group(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password, 'subcloud': '1', 'group': '1'}
        mock_rpc_client().restore_subcloud_backups.return_value = True
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_RESTORE,
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_backup_restore_no_subcloud_no_group(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                               management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
                               backup_datetime=None,
                               backup_status=consts.BACKUP_STATE_UNKNOWN)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password}
        mock_rpc_client().restore_subcloud_backups.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL_RESTORE,
                              headers=FAKE_HEADERS, params=data)
