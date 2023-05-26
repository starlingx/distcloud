#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import json
import mock
from os import path as os_path
import six
import webtest

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

FAKE_TENANT = utils.UUID1

FAKE_HEADERS = {'X-Tenant-Id': FAKE_TENANT, 'X_ROLE': 'admin,member,reader',
                'X-Identity-Status': 'Confirmed', 'X-Project-Name': 'admin'}


class FakeRPCClient(object):
    def subcloud_deploy_create(self, context, subcloud_id, _):
        subcloud = db_api.subcloud_get(context, subcloud_id)
        return db_api.subcloud_db_model_to_dict(subcloud)


# Apply the TestSubcloudPost parameter validation tests to the subcloud deploy
# add endpoint as it uses the same parameter validation functions
class TestSubcloudDeployCreate(TestSubcloudPost):
    API_PREFIX = '/v1.0/phased-subcloud-deploy'
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
