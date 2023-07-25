#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import copy
import json

import mock
import os
from os import path as os_path
import six
from tsconfig.tsconfig import SW_VERSION
import webtest

from dcmanager.api.controllers.v1 import phased_subcloud_deploy as psd_api
from dcmanager.common import consts
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import utils as dutils
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client
from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests.unit.api.v1.controllers.test_subclouds import \
    FakeAddressPool
from dcmanager.tests.unit.api.v1.controllers.test_subclouds import \
    TestSubcloudPost
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests import utils

FAKE_URL = '/v1.0/phased-subcloud-deploy'

FAKE_SOFTWARE_VERSION = '21.12'
FAKE_TENANT = utils.UUID1

FAKE_HEADERS = {'X-Tenant-Id': FAKE_TENANT, 'X_ROLE': 'admin,member,reader',
                'X-Identity-Status': 'Confirmed', 'X-Project-Name': 'admin'}
FAKE_SUBCLOUD_INSTALL_VALUES = fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES


class FakeRPCClient(object):
    def subcloud_deploy_create(self, context, subcloud_id, _):
        subcloud = db_api.subcloud_get(context, subcloud_id)
        return db_api.subcloud_db_model_to_dict(subcloud)


# Apply the TestSubcloudPost parameter validation tests to the subcloud deploy
# add endpoint as it uses the same parameter validation functions
class TestSubcloudDeployCreate(TestSubcloudPost):
    API_PREFIX = FAKE_URL
    RESULT_KEY = 'phased-subcloud-deploy'

    def setUp(self):
        super().setUp()

        p = mock.patch.object(psd_common, 'get_network_address_pool')
        self.mock_get_network_address_pool = p.start()
        self.mock_get_network_address_pool.return_value = \
            self.management_address_pool
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_ks_client')
        self.mock_get_ks_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common.PatchingClient, 'query')
        self.mock_query = p.start()
        self.addCleanup(p.stop)

        self.mock_rpc_client.return_value = FakeRPCClient()

    def test_subcloud_create_missing_bootstrap_address(self):
        """Test POST operation without bootstrap-address."""
        params = self.get_post_params()
        del params['bootstrap-address']

        upload_files = self.get_post_upload_files()

        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers(),
                                 expect_errors=True)
        self._verify_post_failure(response, "bootstrap-address", None)


class TestSubcloudDeployBootstrap(testroot.DCManagerApiTest):
    def setUp(self):
        super().setUp()
        self.ctx = utils.dummy_context()

        p = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = p.start()
        self.addCleanup(p.stop)

        self.management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                       '192.168.204.2',
                                                       '192.168.204.100')

        p = mock.patch.object(psd_common, 'get_network_address_pool')
        self.mock_get_network_address_pool = p.start()
        self.mock_get_network_address_pool.return_value = \
            self.management_address_pool
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_ks_client')
        self.mock_get_ks_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common.PatchingClient, 'query')
        self.mock_query = p.start()
        self.addCleanup(p.stop)

    @mock.patch.object(dutils, 'load_yaml_file')
    @mock.patch.object(os_path, 'exists')
    def test_subcloud_bootstrap(self, mock_path_exists, mock_load_yaml):
        mock_path_exists.side_effect = [False, False, False, False, True]
        mock_load_yaml.return_value = {
            "software_version": fake_subcloud.FAKE_SOFTWARE_VERSION}

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED)

        fake_content = json.dumps(
            fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA).encode("utf-8")
        response = self.app.patch(
            FAKE_URL + '/' + str(subcloud.id) + '/bootstrap',
            headers=FAKE_HEADERS,
            params=fake_subcloud.FAKE_BOOTSTRAP_VALUE,
            upload_files=[("bootstrap_values",
                           "bootstrap_fake_filename",
                           fake_content)])

        self.assertEqual(response.status_int, 200)
        self.mock_rpc_client.return_value.subcloud_deploy_bootstrap.\
            assert_called_once()

        expected_payload = {**fake_subcloud.FAKE_BOOTSTRAP_VALUE,
                            **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA}
        expected_payload["sysadmin_password"] = "testpass"
        expected_payload["software_version"] = \
            fake_subcloud.FAKE_SOFTWARE_VERSION

        (_, res_subcloud_id, res_payload), _ = self.mock_rpc_client.\
            return_value.subcloud_deploy_bootstrap.call_args

        self.assertDictEqual(res_payload, expected_payload)
        self.assertEqual(res_subcloud_id, subcloud.id)

    def test_subcloud_bootstrap_no_body(self):
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED)
        url = FAKE_URL + '/' + str(subcloud.id) + '/bootstrap'
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, url,
                              headers=FAKE_HEADERS, params={})

    def test_subcloud_bootstrap_subcloud_not_found(self):
        url = FAKE_URL + '/' + "nonexistent_subcloud" + '/bootstrap'
        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.patch_json, url,
                              headers=FAKE_HEADERS, params={})

    @mock.patch.object(dutils, 'load_yaml_file')
    @mock.patch.object(os_path, 'exists')
    def test_subcloud_bootstrap_no_bootstrap_values_on_request(
        self, mock_path_exists, mock_load_yaml_file):
        mock_path_exists.side_effect = [False, False, False, False, True]
        fake_bootstrap_values = copy.copy(
            fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        fake_bootstrap_values["software_version"] = \
            fake_subcloud.FAKE_SOFTWARE_VERSION
        mock_load_yaml_file.return_value = \
            fake_bootstrap_values

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED)

        response = self.app.patch(
            FAKE_URL + '/' + str(subcloud.id) + '/bootstrap',
            headers=FAKE_HEADERS,
            params=fake_subcloud.FAKE_BOOTSTRAP_VALUE)

        self.assertEqual(response.status_int, 200)
        self.mock_rpc_client.return_value.subcloud_deploy_bootstrap.\
            assert_called_once()

        expected_payload = {**fake_subcloud.FAKE_BOOTSTRAP_VALUE,
                            **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA}
        expected_payload["sysadmin_password"] = "testpass"
        expected_payload["software_version"] = \
            fake_subcloud.FAKE_SOFTWARE_VERSION

        (_, res_subcloud_id, res_payload), _ = self.mock_rpc_client.\
            return_value.subcloud_deploy_bootstrap.call_args

        self.assertDictEqual(res_payload, expected_payload)
        self.assertEqual(res_subcloud_id, subcloud.id)

    def test_subcloud_bootstrap_management_subnet_conflict(self):
        conflicting_subnet = {
            "management_subnet": "192.168.102.0/24",
            "management_start_ip": "192.168.102.2",
            "management_end_ip": "192.168.102.50",
            "management_gateway_ip": "192.168.102.1"}

        fake_subcloud.create_fake_subcloud(
            self.ctx,
            name="existing_subcloud",
            deploy_status=consts.DEPLOY_STATE_DONE,
            **conflicting_subnet
            )

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_INSTALLED)

        modified_bootstrap_data = copy.copy(
            fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        modified_bootstrap_data.update(conflicting_subnet)

        fake_content = json.dumps(modified_bootstrap_data).encode("utf-8")
        url = FAKE_URL + '/' + str(subcloud.id) + '/bootstrap'
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch, url,
                              headers=FAKE_HEADERS,
                              params=fake_subcloud.FAKE_BOOTSTRAP_VALUE,
                              upload_files=[("bootstrap_values",
                                             "bootstrap_fake_filename",
                                             fake_content)])


class TestSubcloudDeployConfig(testroot.DCManagerApiTest):
    def setUp(self):
        super(TestSubcloudDeployConfig, self).setUp()
        self.ctx = utils.dummy_context()

        p = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'populate_payload_with_pre_existing_data')
        self.mock_populate_payload = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_request_data')
        self.mock_get_request_data = p.start()
        self.addCleanup(p.stop)

    def test_configure_subcloud(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password}

        self.mock_rpc_client().subcloud_deploy_config.return_value = True
        self.mock_get_request_data.return_value = data

        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id) +
                                       '/configure',
                                       headers=FAKE_HEADERS,
                                       params=data)
        self.mock_rpc_client().subcloud_deploy_config.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            mock.ANY)
        self.assertEqual(response.status_int, 200)

    def test_configure_subcloud_no_body(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        # Pass an empty request body
        data = {}
        self.mock_rpc_client().subcloud_deploy_config.return_value = True
        self.mock_get_request_data.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/configure',
                              headers=FAKE_HEADERS, params=data)

    def test_configure_subcloud_bad_password(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        # Pass a sysadmin_password which is not base64 encoded
        data = {'sysadmin_password': 'not_base64'}
        self.mock_rpc_client().subcloud_deploy_config.return_value = True
        self.mock_get_request_data.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/configure',
                              headers=FAKE_HEADERS, params=data)

    def test_configure_invalid_deploy_status(self):
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED)
        fake_password = base64.b64encode('testpass'.encode("utf-8")).decode("utf-8")
        data = {'sysadmin_password': fake_password}
        self.mock_rpc_client().subcloud_deploy_config.return_value = True
        self.mock_get_request_data.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/configure',
                              headers=FAKE_HEADERS, params=data)


class TestSubcloudDeployInstall(testroot.DCManagerApiTest):
    def setUp(self):
        super(TestSubcloudDeployInstall, self).setUp()
        self.ctx = utils.dummy_context()

        p = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(dutils, 'get_vault_load_files')
        self.mock_get_vault_load_files = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_subcloud_db_install_values')
        self.mock_get_subcloud_db_install_values = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'validate_k8s_version')
        self.mock_validate_k8s_version = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_request_data')
        self.mock_get_request_data = p.start()
        self.addCleanup(p.stop)

    def test_install_subcloud(self):

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=consts.DEPLOY_STATE_CREATED,
            software_version=SW_VERSION)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data.pop('software_version')

        fake_sysadmin_password = base64.b64encode(
            'testpass'.encode("utf-8")).decode('utf-8')
        fake_bmc_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        bmc_password = {'bmc_password': fake_bmc_password}
        install_data.update(bmc_password)
        install_payload = {'install_values': install_data,
                           'sysadmin_password': fake_sysadmin_password,
                           'bmc_password': fake_bmc_password}
        self.mock_get_request_data.return_value = install_payload
        self.mock_get_subcloud_db_install_values.return_value = install_data

        self.mock_rpc_client().subcloud_deploy_install.return_value = True
        self.mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')

        response = self.app.patch_json(
            FAKE_URL + '/' + str(subcloud.id) + '/install',
            headers=FAKE_HEADERS, params=install_payload)

        self.assertEqual(response.status_int, 200)
        self.assertEqual(consts.DEPLOY_STATE_PRE_INSTALL,
                         response.json['deploy-status'])
        self.assertEqual(SW_VERSION, response.json['software-version'])

    def test_install_subcloud_with_release_parameter(self):

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=consts.DEPLOY_STATE_CREATED,
            software_version=SW_VERSION)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data.pop('software_version')

        fake_sysadmin_password = base64.b64encode(
            'testpass'.encode("utf-8")).decode('utf-8')
        fake_bmc_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        bmc_password = {'bmc_password': fake_bmc_password}
        install_data.update(bmc_password)
        install_payload = {'install_values': install_data,
                           'sysadmin_password': fake_sysadmin_password,
                           'bmc_password': fake_bmc_password,
                           'release': FAKE_SOFTWARE_VERSION}
        self.mock_get_request_data.return_value = install_payload
        self.mock_get_subcloud_db_install_values.return_value = install_data

        self.mock_rpc_client().subcloud_deploy_install.return_value = True
        self.mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')

        response = self.app.patch_json(
            FAKE_URL + '/' + str(subcloud.id) + '/install',
            headers=FAKE_HEADERS, params=install_payload)

        self.assertEqual(response.status_int, 200)
        self.assertEqual(consts.DEPLOY_STATE_PRE_INSTALL,
                         response.json['deploy-status'])

    def test_install_subcloud_no_body(self):

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=consts.DEPLOY_STATE_CREATED,
            software_version=SW_VERSION)

        self.mock_get_request_data.return_value = {}

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/install',
                              headers=FAKE_HEADERS, params={})

    def test_install_subcloud_no_install_values_on_request_or_db(self):

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=consts.DEPLOY_STATE_CREATED,
            software_version=SW_VERSION,
            data_install='')

        fake_sysadmin_password = base64.b64encode(
            'testpass'.encode("utf-8")).decode('utf-8')
        fake_bmc_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        install_payload = {'sysadmin_password': fake_sysadmin_password,
                           'bmc_password': fake_bmc_password}
        self.mock_get_request_data.return_value = install_payload

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/install',
                              headers=FAKE_HEADERS, params=install_payload)

    def test_install_subcloud_no_install_values_on_request(self):

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=consts.DEPLOY_STATE_CREATED,
            software_version=SW_VERSION)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data.pop('software_version')

        fake_sysadmin_password = base64.b64encode(
            'testpass'.encode("utf-8")).decode('utf-8')
        fake_bmc_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        bmc_password = {'bmc_password': fake_bmc_password}
        install_data.update(bmc_password)
        install_payload = {'sysadmin_password': fake_sysadmin_password}
        self.mock_get_request_data.return_value = install_payload
        self.mock_get_subcloud_db_install_values.return_value = install_data

        self.mock_rpc_client().subcloud_deploy_install.return_value = True
        self.mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')

        response = self.app.patch_json(
            FAKE_URL + '/' + str(subcloud.id) + '/install',
            headers=FAKE_HEADERS, params=install_payload)

        self.assertEqual(response.status_int, 200)
        self.assertEqual(consts.DEPLOY_STATE_PRE_INSTALL,
                         response.json['deploy-status'])
        self.assertEqual(SW_VERSION, response.json['software-version'])


class TestSubcloudDeployAbort(testroot.DCManagerApiTest):
    def setUp(self):
        super(TestSubcloudDeployAbort, self).setUp()
        self.ctx = utils.dummy_context()

        p = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = p.start()
        self.addCleanup(p.stop)

    def test_abort_subcloud(self):
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=consts.DEPLOY_STATE_INSTALLING)

        self.mock_rpc_client().subcloud_deploy_abort.return_value = True

        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id) +
                                       '/abort',
                                       headers=FAKE_HEADERS)
        self.mock_rpc_client().subcloud_deploy_abort.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            subcloud.deploy_status)
        self.assertEqual(response.status_int, 200)

    def test_abort_subcloud_invalid_deploy_status(self):
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=consts.DEPLOY_STATE_INSTALLED)
        self.mock_rpc_client().subcloud_deploy_config.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/abort',
                              headers=FAKE_HEADERS)


class TestSubcloudDeployResume(testroot.DCManagerApiTest):
    def setUp(self):
        super().setUp()
        self.ctx = utils.dummy_context()

        p = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(dutils, 'get_vault_load_files')
        self.mock_get_vault_load_files = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_subcloud_db_install_values')
        self.mock_get_subcloud_db_install_values = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'validate_k8s_version')
        self.mock_validate_k8s_version = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_request_data')
        self.mock_get_request_data = p.start()
        self.addCleanup(p.stop)

        self.management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                       '192.168.204.2',
                                                       '192.168.204.100')

        p = mock.patch.object(psd_common, 'get_network_address_pool')
        self.mock_get_network_address_pool = p.start()
        self.mock_get_network_address_pool.return_value = \
            self.management_address_pool
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_ks_client')
        self.mock_get_ks_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common.PatchingClient, 'query')
        self.mock_query = p.start()
        self.addCleanup(p.stop)

    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(os, 'listdir')
    def test_resume_subcloud(self,
                             mock_os_listdir,
                             mock_os_isdir):
        mock_os_isdir.return_value = True
        mock_os_listdir.return_value = ['deploy_chart_fake.tgz',
                                        'deploy_overrides_fake.yaml',
                                        'deploy_playbook_fake.yaml']

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_CREATED,
            software_version=SW_VERSION)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data.pop('software_version')

        self.mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')
        self.mock_rpc_client().subcloud_deploy_resume.return_value = True

        for state in psd_api.RESUMABLE_STATES:
            fake_sysadmin_password = base64.b64encode(
                'testpass'.encode("utf-8")).decode('utf-8')
            fake_bmc_password = base64.b64encode(
                'bmc_password'.encode("utf-8")).decode('utf-8')
            bmc_password = {'bmc_password': fake_bmc_password}
            install_data.update(bmc_password)
            install_request = {'install_values': install_data,
                               'sysadmin_password': fake_sysadmin_password,
                               'bmc_password': fake_bmc_password}
            bootstrap_request = {'bootstrap_values': fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA}
            config_request = {'deploy_config': 'deploy config values',
                              'sysadmin_password': fake_sysadmin_password}
            resume_request = {**install_request,
                              **bootstrap_request,
                              **config_request}
            resume_payload = {**install_request,
                              **fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA,
                              **config_request}

            subcloud = db_api.subcloud_update(self.ctx,
                                              subcloud.id,
                                              deploy_status=state)
            next_deploy_phase = psd_api.RESUMABLE_STATES[subcloud.deploy_status][0]
            next_deploy_state = psd_api.RESUME_PREP_UPDATE_STATUS[next_deploy_phase]

            self.mock_get_request_data.return_value = resume_payload
            response = self.app.patch(
                FAKE_URL + '/' + str(subcloud.id) + '/resume',
                headers=FAKE_HEADERS, params=resume_request)

            self.assertEqual(response.status_int, 200)
            self.assertEqual(next_deploy_state,
                             response.json['deploy-status'])
            self.assertEqual(SW_VERSION, response.json['software-version'])

    def test_resume_subcloud_invalid_state(self):

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_CREATED,
            software_version=SW_VERSION)

        self.mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')
        self.mock_rpc_client().subcloud_deploy_resume.return_value = True
        invalid_resume_states = [consts.DEPLOY_STATE_INSTALLING,
                                 consts.DEPLOY_STATE_BOOTSTRAPPING,
                                 consts.DEPLOY_STATE_CONFIGURING]

        for state in invalid_resume_states:
            subcloud = db_api.subcloud_update(self.ctx,
                                              subcloud.id,
                                              deploy_status=state)

            six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                                  self.app.patch_json, FAKE_URL + '/' +
                                  str(subcloud.id) + '/resume',
                                  headers=FAKE_HEADERS)

    @mock.patch.object(dutils, 'load_yaml_file')
    @mock.patch.object(os_path, 'exists')
    @mock.patch.object(os_path, 'isdir')
    @mock.patch.object(os, 'listdir')
    def test_resume_subcloud_no_request_data(self,
                                             mock_os_listdir,
                                             mock_os_isdir,
                                             mock_path_exists,
                                             mock_load_yaml):
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            deploy_status=consts.DEPLOY_STATE_CREATED,
            software_version=SW_VERSION)

        config_file = psd_common.get_config_file_path(subcloud.name,
                                                      consts.DEPLOY_CONFIG)
        mock_path_exists.side_effect = lambda x: True if x == config_file else False
        mock_load_yaml.return_value = {
            "software_version": fake_subcloud.FAKE_SOFTWARE_VERSION}
        mock_os_isdir.return_value = True
        mock_os_listdir.return_value = ['deploy_chart_fake.tgz',
                                        'deploy_overrides_fake.yaml',
                                        'deploy_playbook_fake.yaml']
        self.mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')
        self.mock_rpc_client().subcloud_deploy_resume.return_value = True

        for state in psd_api.RESUMABLE_STATES:
            fake_sysadmin_password = base64.b64encode(
                'testpass'.encode("utf-8")).decode('utf-8')
            resume_request = {'sysadmin_password': fake_sysadmin_password}

            subcloud = db_api.subcloud_update(self.ctx,
                                              subcloud.id,
                                              deploy_status=state)
            next_deploy_phase = psd_api.RESUMABLE_STATES[subcloud.deploy_status][0]
            next_deploy_state = psd_api.RESUME_PREP_UPDATE_STATUS[next_deploy_phase]

            self.mock_get_request_data.return_value = resume_request
            response = self.app.patch(
                FAKE_URL + '/' + str(subcloud.id) + '/resume',
                headers=FAKE_HEADERS, params=resume_request)

            self.assertEqual(response.status_int, 200)
            self.assertEqual(next_deploy_state,
                             response.json['deploy-status'])
            self.assertEqual(SW_VERSION, response.json['software-version'])
