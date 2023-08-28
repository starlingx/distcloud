# Copyright (c) 2017 Ericsson AB
# Copyright (c) 2017-2023 Wind River Systems, Inc.
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
import copy
import json
import os

import keyring
import mock
from oslo_utils import timeutils
import six
from six.moves import http_client
from tsconfig.tsconfig import SW_VERSION
import webtest

from dccommon import consts as dccommon_consts
from dcmanager.api.controllers.v1 import phased_subcloud_deploy as psd
from dcmanager.api.controllers.v1 import subclouds
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.common import prestage
from dcmanager.common import utils as cutils
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.rpc import client as rpc_client
from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests.unit.api.v1.controllers.mixins import APIMixin
from dcmanager.tests.unit.api.v1.controllers.mixins import PostMixin
from dcmanager.tests.unit.common import fake_subcloud
from dcmanager.tests import utils

SAMPLE_SUBCLOUD_NAME = 'SubcloudX'
SAMPLE_SUBCLOUD_DESCRIPTION = 'A Subcloud of mystery'

FAKE_ID = fake_subcloud.FAKE_ID
FAKE_URL = fake_subcloud.FAKE_URL
WRONG_URL = fake_subcloud.WRONG_URL
FAKE_HEADERS = fake_subcloud.FAKE_HEADERS
FAKE_SUBCLOUD_DATA = fake_subcloud.FAKE_SUBCLOUD_DATA
FAKE_BOOTSTRAP_VALUE = fake_subcloud.FAKE_BOOTSTRAP_VALUE
FAKE_SUBCLOUD_INSTALL_VALUES = fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES
FAKE_SUBCLOUD_INSTALL_VALUES_WITH_PERSISTENT_SIZE = \
    fake_subcloud.FAKE_SUBCLOUD_INSTALL_VALUES_WITH_PERSISTENT_SIZE
FAKE_SUBCLOUD_BOOTSTRAP_PAYLOAD = fake_subcloud.FAKE_SUBCLOUD_BOOTSTRAP_PAYLOAD
OAM_FLOATING_IP = '10.10.10.12'

FAKE_PATCH = {
    "value": {
        "patchstate": "Partial-Apply"
    }
}

health_report_no_alarm = \
    "System Health:\n \
    All hosts are provisioned: [Fail]\n \
    1 Unprovisioned hosts\n \
    All hosts are unlocked/enabled: [OK]\n \
    All hosts have current configurations: [OK]\n \
    All hosts are patch current: [OK]\n \
    No alarms: [OK]\n \
    All kubernetes nodes are ready: [OK]\n \
    All kubernetes control plane pods are ready: [OK]"


health_report_no_mgmt_alarm = \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "Ceph Storage Healthy: [OK]\n" \
    "No alarms: [Fail]\n" \
    "[1] alarms found, [0] of which are management affecting\n" \
    "All kubernetes nodes are ready: [OK]\n" \
    "All kubernetes control plane pods are ready: [OK]"


health_report_mgmt_alarm = \
    "System Health:\n" \
    "All hosts are provisioned: [OK]\n" \
    "All hosts are unlocked/enabled: [OK]\n" \
    "All hosts have current configurations: [OK]\n" \
    "All hosts are patch current: [OK]\n" \
    "Ceph Storage Healthy: [OK]\n" \
    "No alarms: [Fail]\n" \
    "[1] alarms found, [1] of which are management affecting\n" \
    "All kubernetes nodes are ready: [OK]\n" \
    "All kubernetes control plane pods are ready: [OK]"


class Subcloud(object):
    def __init__(self, data, is_online):
        self.id = data['id']
        self.name = data['name']
        self.description = data['description']
        self.location = data['location']
        self.management_state = dccommon_consts.MANAGEMENT_UNMANAGED
        if is_online:
            self.availability_status = dccommon_consts.AVAILABILITY_ONLINE
        else:
            self.availability_status = dccommon_consts.AVAILABILITY_OFFLINE
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
        self.data_install = ''
        self.data_upgrade = ''


class FakeAddressPool(object):
    def __init__(self, pool_network, pool_prefix, pool_start, pool_end):
        self.network = pool_network
        self.prefix = pool_prefix
        range = list()
        range.append(pool_start)
        range.append(pool_end)
        self.ranges = list()
        self.ranges.append(range)


class FakeOAMAddressPool(object):
    def __init__(self, oam_subnet, oam_start_ip,
                 oam_end_ip, oam_c1_ip,
                 oam_c0_ip, oam_gateway_ip,
                 oam_floating_ip):
        self.oam_start_ip = oam_start_ip
        self.oam_end_ip = oam_end_ip
        self.oam_c1_ip = oam_c1_ip
        self.oam_c0_ip = oam_c0_ip
        self.oam_subnet = oam_subnet
        self.oam_gateway_ip = oam_gateway_ip
        self.oam_floating_ip = oam_floating_ip


class SubcloudAPIMixin(APIMixin):
    API_PREFIX = '/v1.0/subclouds'
    RESULT_KEY = 'subclouds'
    # todo: populate the entire expected fields
    EXPECTED_FIELDS = ['id',
                       'name',
                       'description',
                       'location',
                       'management-state',
                       'created-at',
                       'updated-at']

    FAKE_BOOTSTRAP_DATA = {
        "system_mode": "simplex",
        "name": "fake subcloud1",
        "management_subnet": "192.168.101.0/24",
        "management_start_address": "192.168.101.2",
        "management_end_address": "192.168.101.50",
        "management_gateway_address": "192.168.101.1",
        "external_oam_subnet": "10.10.10.0/24",
        "external_oam_gateway_address": "10.10.10.1",
        "external_oam_floating_address": "10.10.10.12",
        "systemcontroller_gateway_address": "192.168.204.101",
    }

    OPTIONAL_BOOTSTRAP_DATA = {
        "location": "fake location",
        "description": "fake description",
    }

    # based off MANDATORY_INSTALL_VALUES
    # bmc_password must be passed as a param
    FAKE_INSTALL_DATA = {
        "bootstrap_interface": "fake interface",
        "bootstrap_address": "10.10.10.12",
        "bootstrap_address_prefix": "10.10.10.12",
        "bmc_address": "128.224.64.1",
        "bmc_username": "fake bmc user",
        "install_type": 2,
    }

    list_of_post_files = psd.SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS
    bootstrap_data = copy.copy(FAKE_BOOTSTRAP_DATA)
    install_data = copy.copy(FAKE_INSTALL_DATA)

    def setUp(self):
        super(SubcloudAPIMixin, self).setUp()

    def _get_test_subcloud_dict(self, **kw):
        # id should not be part of the structure
        subcloud = {
            'name': kw.get('name', SAMPLE_SUBCLOUD_NAME),
            'description': kw.get('description',
                                  SAMPLE_SUBCLOUD_DESCRIPTION),
        }
        return subcloud

    def _post_get_test_subcloud(self, **kw):
        post_body = self._get_test_subcloud_dict(**kw)
        return post_body

    # The following methods are required for subclasses of APIMixin
    def get_api_prefix(self):
        return self.API_PREFIX

    def get_result_key(self):
        return self.RESULT_KEY

    def get_expected_api_fields(self):
        return self.EXPECTED_FIELDS

    def get_omitted_api_fields(self):
        return []

    def _create_db_object(self, context, **kw):
        creation_fields = self._get_test_subcloud_dict(**kw)
        return db_api.subcloud_create(context, **creation_fields)

    def get_post_params(self):
        return copy.copy(FAKE_BOOTSTRAP_VALUE)

    def set_list_of_post_files(self, value):
        self.list_of_post_files = value

    def get_post_upload_files(self):
        fields = list()
        for f in self.list_of_post_files:
            fake_name = f + "_fake"
            # The data in the bootstrap file needs to be dictionary syntax
            if f == consts.BOOTSTRAP_VALUES:
                fake_content = json.dumps(self.bootstrap_data).encode("utf-8")
            elif f == consts.INSTALL_VALUES:
                fake_content = json.dumps(self.install_data).encode("utf-8")
            else:
                fake_content = "fake content".encode("utf-8")
            fields.append((f, fake_name, fake_content))
        return fields

    def get_post_object(self):
        return self._post_get_test_subcloud()

    def get_update_object(self):
        update_object = {
            'description': 'Updated description'
        }
        return update_object


# Combine Subcloud Group API with mixins to test post, get, update and delete
class TestSubcloudPost(testroot.DCManagerApiTest,
                       SubcloudAPIMixin,
                       PostMixin):
    def setUp(self):
        super(TestSubcloudPost, self).setUp()
        self.list_of_post_files = psd.SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS
        self.bootstrap_data = copy.copy(self.FAKE_BOOTSTRAP_DATA)
        self.install_data = copy.copy(self.FAKE_INSTALL_DATA)

        self.management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                       '192.168.204.2',
                                                       '192.168.204.100')

        p = mock.patch.object(psd_common, 'get_network_address_pool')
        self.mock_get_network_address_pool = p.start()
        self.mock_get_network_address_pool.return_value = \
            self.management_address_pool
        self.addCleanup(p.stop)

        p = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_ks_client')
        self.mock_get_ks_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common.PatchingClient, 'query')
        self.mock_query = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(rpc_client, 'SubcloudStateClient')
        self.mock_rpc_state_client = p.start()
        self.addCleanup(p.stop)

    def _verify_post_failure(self, response, param, value):
        self.assertEqual(http_client.BAD_REQUEST,
                         response.status_code,
                         message=("%s=%s returned %s instead of %s"
                                  % (param,
                                     value,
                                     response.status_code,
                                     http_client.BAD_REQUEST)))
        # Note: response failures return 'text' rather than json
        self.assertEqual('text/plain', response.content_type)

    def _verify_post_success(self, response):
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual('application/json', response.content_type)
        self.assert_fields(response.json)

    def test_post_subcloud_wrong_url(self):
        """Test POST operation rejected when going to the wrong URL."""
        params = self.get_post_params()
        upload_files = self.get_post_upload_files()
        six.assertRaisesRegex(self,
                              webtest.app.AppError,
                              "404 *",
                              self.app.post,
                              WRONG_URL,
                              params=params,
                              upload_files=upload_files,
                              headers=self.get_api_headers())

    def test_post_no_body(self):
        """Test POST operation with nearly everything wrong with it."""
        six.assertRaisesRegex(self,
                              webtest.app.AppError,
                              "400 *",
                              self.app.post,
                              self.get_api_prefix(),
                              params={},
                              headers=self.get_api_headers())

    def test_post_subcloud_boostrap_entries_missing(self):
        """Test POST operation with some mandatory boostrap fields missing.

        Example: name is a required field
        """

        self.list_of_post_files = psd.SUBCLOUD_BOOTSTRAP_GET_FILE_CONTENTS
        params = self.get_post_params()

        for key in self.FAKE_BOOTSTRAP_DATA:
            self.bootstrap_data = copy.copy(self.FAKE_BOOTSTRAP_DATA)
            del self.bootstrap_data[key]
            upload_files = self.get_post_upload_files()
            response = self.app.post(self.get_api_prefix(),
                                     params=params,
                                     upload_files=upload_files,
                                     headers=self.get_api_headers(),
                                     expect_errors=True)
            self._verify_post_failure(response, key, None)

        # try with nothing removed and verify it works
        self.bootstrap_data = copy.copy(self.FAKE_BOOTSTRAP_DATA)
        upload_files = self.get_post_upload_files()
        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers())
        self._verify_post_success(response)

    def _test_post_param_inputs(self, param_key, bad_values, good_value):
        upload_files = self.get_post_upload_files()
        params = self.get_post_params()

        # Test all the bad param values
        for bad_value in bad_values:
            params[param_key] = bad_value
            response = self.app.post(self.get_api_prefix(),
                                     params=params,
                                     upload_files=upload_files,
                                     headers=self.get_api_headers(),
                                     expect_errors=True)
            self._verify_post_failure(response, param_key, bad_value)

        # Test that a good value will work
        params[param_key] = good_value
        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers())
        self._verify_post_success(response)

    def test_post_subcloud_bad_bootstrap_address(self):
        """Test POST operation with a bad bootstrap-address"""

        param_key = "bootstrap-address"
        # bootstrap-address must be valid IP address
        bad_values = ["10.10.10.wut",  # including letters in the IP
                      "10.10.10.276"   # 276 is invalid
                      ]
        good_values = "10.10.10.3"
        self._test_post_param_inputs(param_key,
                                     bad_values,
                                     good_values)

    def test_post_subcloud_bad_IPv6_bootstrap_address(self):
        """Test POST operation with a bad bootstrap-address"""

        param_key = "bootstrap-address"
        # bootstrap-address must be valid IP address
        bad_values = ["2620::10a:a103::1135",      # more than one double colons
                      "2620:10a:a001:a103::wut",   # invalid letter
                      "2620:10a:a001:a103:1135"    # Incomplete IP
                      ]
        good_values = "2620:10a:a001:a103::1135"
        self._test_post_param_inputs(param_key,
                                     bad_values,
                                     good_values)

    def test_post_subcloud_bad_gateway(self):
        """Test POST with an invalid gateway."""

        param_key = "systemcontroller_gateway_address"
        # systemcontroller_gateway_address must be appropriate address within
        # the management address pool which is
        # 192.168.204.0/24 greater than 100
        bad_values = ["192.168.205.101",  # 205.xx not in the pool
                      "192.168.204.99",   # 99 is reserved in the pool
                      "192.168.276.276",  # 276 is not a valid IP address
                      "192.168.206.wut",  # including letters in the IP
                      "192.168.204",      # incomplete IP
                      ]
        good_value = "192.168.204.101"
        self._test_post_param_inputs(param_key,
                                     bad_values,
                                     good_value)

    def test_post_subcloud_bad_subnet(self):
        """Test POST with an invalid subnet."""

        param_key = "management_subnet"
        bad_values = ["192.168.101.0/32",    # /32 would be just one IP
                      "192.168.101.0/33",    # /33 is an invalid CIDR
                      "192.168.276.0/24",    # 276 makes no sense as an IP
                      "192.168.206.wut/24",  # including letters in the IP
                      "192.168.204/24",      # incomplete CIDR
                      ]
        good_value = "192.168.101.0/24"
        self._test_post_param_inputs(param_key,
                                     bad_values,
                                     good_value)

    def test_post_subcloud_bad_start_ip(self):
        """Test POST with an invalid management_start_address.

        The management_start_address cannot be after the end or too close
        since there must be enough range to allocate the IPs.
        """

        param_key = "management_start_address"
        # subnet is 192.168.101.0/24
        # end address is 192.168.101.50
        bad_values = ["192.168.100.2",      # xx.xx.100.xx is not in the subnet
                      "192.168.101.51",     # start is higher than end
                      "192.168.101.48",     # start is too close to end
                      "192.168.276.0",      # 276 makes no sense as an IP
                      "192.168.206.wut",    # including letters in the IP
                      "192.168.204",        # incomplete IP
                      ]
        good_value = "192.168.101.2"
        self._test_post_param_inputs(param_key,
                                     bad_values,
                                     good_value)

    def test_post_subcloud_bad_end_ip(self):
        """Test POST with an invalid management_end_address.

        The management_end_address cannot be less than the start or too close
        since there must be enough range to allocate the IPs.
        """

        param_key = "management_end_address"
        # subnet is 192.168.101.0/24
        # start address is 192.168.101.2
        bad_values = ["192.168.100.50",     # xx.xx.100.xx is not in the subnet
                      "192.168.101.1",      # end is less than start
                      "192.168.101.4",      # end is too close to start
                      "192.168.276.50",     # 276 makes no sense as an IP
                      "192.168.206.wut",    # including letters in the IP
                      "192.168.204",        # incomplete IP
                      ]
        good_value = "192.168.101.50"
        self._test_post_param_inputs(param_key,
                                     bad_values,
                                     good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_values(self, mock_vault_files):
        """Test POST operation with install values is supported by the API."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')

        # pass a different "install" list of files for this POST
        self.set_list_of_post_files(subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS)
        upload_files = self.get_post_upload_files()

        params = self.get_post_params()
        # add bmc_password to params
        params.update(
            {'bmc_password':
             base64.b64encode('fake pass'.encode("utf-8")).decode("utf-8")})

        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers())
        self._verify_post_success(response)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_without_release_parameter(self, mock_vault_files):
        """Test POST operation without release parameter."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')

        self.set_list_of_post_files(subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS)
        upload_files = self.get_post_upload_files()

        params = self.get_post_params()
        # add bmc_password to params
        params.update(
            {'bmc_password':
             base64.b64encode('fake pass'.encode("utf-8")).decode("utf-8")})

        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers())
        self._verify_post_success(response)
        # Verify that the subcloud installed with the active release
        # when no release parameter provided.
        self.assertEqual(SW_VERSION, response.json['software-version'])

    def test_post_subcloud_release_not_match_install_values_sw(self):
        """Release parameter not match software_version in the install_values."""

        self.set_list_of_post_files(subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS)
        upload_files = self.get_post_upload_files()

        params = self.get_post_params()
        # add bmc_password and release to params
        params.update(
            {'bmc_password':
             base64.b64encode('fake pass'.encode("utf-8")).decode("utf-8"),
             'release': '21.12'})

        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers(),
                                 expect_errors=True)

        # Verify the request was rejected
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch.object(psd_common, 'validate_k8s_version')
    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_with_release_parameter(self, mock_vault_files,
                                                  mock_validate_k8s_version):
        """Test POST operation with release parameter."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        software_version = '21.12'
        # Update the software_version value to match the release parameter value,
        # otherwise, the request will be rejected
        self.install_data['software_version'] = software_version

        self.set_list_of_post_files(subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS)
        upload_files = self.get_post_upload_files()

        params = self.get_post_params()
        # add bmc_password and release to params
        params.update(
            {'bmc_password':
             base64.b64encode('fake pass'.encode("utf-8")).decode("utf-8"),
             'release': software_version})

        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers(),
                                 expect_errors=True)

        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(software_version, response.json['software-version'])

        # Revert the software_version value
        self.install_data['software_version'] = SW_VERSION

    @mock.patch.object(psd_common.PatchingClient, 'query')
    def test_post_subcloud_when_partial_applied_patch(self, mock_query):
        """Test POST operation when there is a partial-applied patch."""

        upload_files = self.get_post_upload_files()
        params = self.get_post_params()
        mock_query.return_value = FAKE_PATCH
        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers(),
                                 expect_errors=True)
        self.assertEqual(http_client.UNPROCESSABLE_ENTITY, response.status_code)
        self.assertEqual('text/plain', response.content_type)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_values_no_bmc_password(self, mock_vault_files):
        """Test POST operation with install values is supported by the API."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')

        # pass a different "install" list of files for this POST
        self.set_list_of_post_files(subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS)
        upload_files = self.get_post_upload_files()

        params = self.get_post_params()
        # for this unit test, omit adding bmc_password to params

        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers(),
                                 expect_errors=True)
        self._verify_post_failure(response, "bmc_password", None)

        # add the bmc_password  and verify that now it works
        params.update(
            {'bmc_password':
             base64.b64encode('fake pass'.encode("utf-8")).decode("utf-8")})
        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers())
        self._verify_post_success(response)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_missing_image(self, mock_vault_files):
        """Test POST operation without image in install values and vault files."""

        mock_vault_files.return_value = (None, None)

        params = self.get_post_params()
        # add bmc_password to params
        params.update(
            {'bmc_password':
             base64.b64encode('fake pass'.encode("utf-8")).decode("utf-8")})

        self.set_list_of_post_files(subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS)
        self.install_data = copy.copy(self.FAKE_INSTALL_DATA)
        upload_files = self.get_post_upload_files()
        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers(),
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_values_missing(self, mock_vault_files):
        """Test POST operation with install values fails if data missing."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')

        params = self.get_post_params()
        # add bmc_password to params
        params.update(
            {'bmc_password':
             base64.b64encode('fake pass'.encode("utf-8")).decode("utf-8")})

        self.set_list_of_post_files(subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS)
        # for each entry in install content, try with one key missing
        for key in self.FAKE_INSTALL_DATA:
            self.install_data = copy.copy(self.FAKE_INSTALL_DATA)
            del self.install_data[key]
            upload_files = self.get_post_upload_files()
            response = self.app.post(self.get_api_prefix(),
                                     params=params,
                                     upload_files=upload_files,
                                     headers=self.get_api_headers(),
                                     expect_errors=True)
            self._verify_post_failure(response, key, None)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    @mock.patch.object(cutils, 'get_playbook_for_software_version')
    @mock.patch.object(cutils, 'get_value_from_yaml_file')
    def test_post_subcloud_bad_kubernetes_version(self,
                                                  mock_get_value_from_yaml_file,
                                                  mock_get_playbook_for_software_version,
                                                  mock_vault_files):
        """Test POST operation with bad kubernetes_version."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')

        software_version = '21.12'
        # Update the software_version value to match the release parameter value,
        # otherwise, the request will be rejected
        self.install_data['software_version'] = software_version

        params = self.get_post_params()
        # add bmc_password to params
        params.update(
            {'bmc_password':
             base64.b64encode('fake pass'.encode("utf-8")).decode("utf-8"),
             'release': software_version})

        # Add kubernetes version to bootstrap_data
        self.bootstrap_data['kubernetes_version'] = '1.21.8'
        mock_get_value_from_yaml_file.return_value = '1.23.1'

        self.set_list_of_post_files(subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS)
        self.install_data = copy.copy(self.FAKE_INSTALL_DATA)
        upload_files = self.get_post_upload_files()
        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers(),
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

        # Revert the change of bootstrap_data
        del self.bootstrap_data['kubernetes_version']

    def _test_post_input_value_inputs(self,
                                      setup_overrides,
                                      required_overrides,
                                      param_key, bad_values, good_value):
        """This utility checks for test permutions.

        The setup_overrides are the initial modifications to the install data
        The required_overrides are all tested to see that if any of them are
        missing, the 'good' value will not work.
        The param_key is tested with the list of bad_values to ensure they fail
        The param_key is tested with the good value to ensure it passes.
        """
        params = self.get_post_params()
        params.update(
            {'bmc_password':
             base64.b64encode('fake pass'.encode("utf-8")).decode("utf-8")})
        self.set_list_of_post_files(subclouds.SUBCLOUD_ADD_GET_FILE_CONTENTS)

        # Setup starting install data
        # Note: upload_files are populated based on the install values data.
        starting_data = copy.copy(self.FAKE_INSTALL_DATA)
        for key, val in setup_overrides.items():
            starting_data[key] = val
        starting_data['image'] = 'fake image'

        # Test all the bad param values
        for bad_value in bad_values:
            self.install_data = copy.copy(starting_data)
            # Apply all required_overrides
            for key, val in required_overrides.items():
                self.install_data[key] = val
            # Apply the bad value
            self.install_data[param_key] = bad_value
            upload_files = self.get_post_upload_files()
            response = self.app.post(self.get_api_prefix(),
                                     params=params,
                                     upload_files=upload_files,
                                     headers=self.get_api_headers(),
                                     expect_errors=True)
            self._verify_post_failure(response, param_key, bad_value)

        # Test that any missing override required to use with the good value
        # will cause a failure
        for missing_override in required_overrides:
            self.install_data = copy.copy(starting_data)
            # We cannot simply delete the missing override, but we can skip it
            for key, val in required_overrides.items():
                if key != missing_override:
                    self.install_data[key] = val
            # The 'good' value should still fail if a required override missing
            self.install_data[param_key] = good_value
            upload_files = self.get_post_upload_files()
            response = self.app.post(self.get_api_prefix(),
                                     params=params,
                                     upload_files=upload_files,
                                     headers=self.get_api_headers(),
                                     expect_errors=True)
            self._verify_post_failure(response, param_key, bad_value)

        # Test that a good value and all required overrides works
        self.install_data = copy.copy(starting_data)
        for key, val in required_overrides.items():
            self.install_data[key] = val
        self.install_data[param_key] = good_value
        upload_files = self.get_post_upload_files()
        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers())
        self._verify_post_success(response)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_values_invalid_type(self, mock_vault_files):
        """Test POST with an invalid type specified in install values."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        setup_overrides = {}
        required_overrides = {}
        # the install_type must a number 0 <= X <=5
        install_key = "install_type"
        bad_values = [-1,    # negative
                      6,     # too big
                      "3",   # alphbetical
                      "w",   # really alphbetical
                      "",    # empty
                      None,  # None
                      ]
        good_value = 3
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_bad_bootstrap_ip(self, mock_vault_files):
        """Test POST with invalid boostrap ip specified in install values."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        setup_overrides = {}
        required_overrides = {}
        install_key = "bootstrap_address"
        bad_values = ["192.168.1.256",    # 256 is not valid
                      "192.168.206.wut",  # including letters in the IP
                      None,               # None
                      ]
        # Note: an incomplete IP address is 10.10.10 is considered valid
        good_value = "10.10.10.12"
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_bad_bmc_ip(self, mock_vault_files):
        """Test POST with invalid bmc ip specified in install values."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        setup_overrides = {}
        required_overrides = {}
        install_key = "bmc_address"
        bad_values = ["128.224.64.256",   # 256 is not valid
                      "128.224.64.wut",   # including letters in the IP
                      None,               # None
                      ]
        good_value = "128.224.64.1"
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_bad_persistent_size(self, mock_vault_files):
        """Test POST with invalid persistent_size specified in install values."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        setup_overrides = {}
        required_overrides = {}
        install_key = "persistent_size"
        bad_values = ["4000o",   # not an integer
                      "20000",   # less than 30000
                      40000.1,   # fraction
                      None,      # None
                      ]
        good_value = 40000
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_bad_nexthop_gateway(self, mock_vault_files):
        """Test POST with invalid nexthop_gateway in install values."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        setup_overrides = {}
        required_overrides = {}
        # nexthop_gateway is not required. but if provided, it must be valid
        install_key = "nexthop_gateway"
        bad_values = ["128.224.64.256",   # 256 is not valid
                      "128.224.64.wut",   # including letters in the IP
                      None,               # None
                      ]
        good_value = "192.168.1.2"
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_bad_network_address(self, mock_vault_files):
        """Test POST with invalid network_address in install values."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        setup_overrides = {}
        # The nexthop_gateway is required when network_address is present
        # The network mask is required when network address is present
        required_overrides = {
            "nexthop_gateway": "192.168.1.2",
            "network_mask": 32,  # Note: this netmask is validated when used
        }
        # network_address is not required. but if provided, it must be valid
        install_key = "network_address"
        # todo(abailey): None will cause the API to fail
        bad_values = ["fd01:6::0",     # mis-match ipv6 vs ipv4
                      ]
        good_value = "192.168.101.10"  # ipv4
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_bad_network_mask(self, mock_vault_files):
        """Test POST with invalid network_mask in install values."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        # network_address is not required. but if provided a valid network_mask
        # is needed
        setup_overrides = {
            "nexthop_gateway": "192.168.1.2",
            "network_address": "192.168.101.10"
        }
        required_overrides = {}

        install_key = "network_mask"
        bad_values = [None,    # None
                      64,      # network_mask cannot really be greater than 32
                      -1,      # network_mask cannot really be negative
                      "junk",  # network_mask cannot be a junk string
                      ]
        good_value = 32
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_diff_bmc_ip_version(self, mock_vault_files):
        """Test POST install values with mismatched(ipv4/ipv6) bmc ip."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        setup_overrides = {
            "bootstrap_address": "192.168.1.2"
        }
        required_overrides = {}
        # bootstrap address ip version must match bmc_address. default ipv4
        install_key = "bmc_address"
        bad_values = ["fd01:6::7",     # ipv6
                      None,            # None
                      "192.168.-1.1",  # bad ipv4
                      ]
        good_value = "192.168.1.7"     # ipv4
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_diff_bmc_ip_version_ipv6(self, mock_vault_files):
        """Test POST install values with mismatched(ipv6/ipv4) bmc ip."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        # version of bootstrap address must be same as bmc_address
        setup_overrides = {
            "bootstrap_address": "fd01:6::7"
        }
        required_overrides = {}
        install_key = "bmc_address"
        bad_values = ["192.168.1.7",  # ipv4
                      None,           # None
                      "fd01:6:-1",    # bad ipv6
                      ]
        good_value = "fd01:6::7"      # ipv6
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_diff_nexthop_ip_version(self, mock_vault_files):
        """Test POST install values mismatched(ipv4/ipv6) nexthop_gateway."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        # ip version of bootstrap address must be same as nexthop_gateway
        # All required addresses (like bmc address) much match bootstrap
        # default bmc address is ipv4
        setup_overrides = {
            "bootstrap_address": "192.168.1.5"
        }
        required_overrides = {}
        install_key = "nexthop_gateway"
        bad_values = ["fd01:6::7", ]  # ipv6
        good_value = "192.168.1.7"   # ipv4
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)

    @mock.patch('dcmanager.common.utils.get_vault_load_files')
    def test_post_subcloud_install_diff_nexthop_ip_version_ipv6(self,
                                                                mock_vault_files):
        """Test POST install values with mismatched(ipv6/ipv4) bmc ip."""

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        # version of bootstrap address must be same as nexthop_gateway
        # All required addresses must also be setup ipv6 such as bmc_address
        # default bmc address is ipv4
        setup_overrides = {
            "bootstrap_address": "fd01:6::6"
        }
        required_overrides = {
            "bmc_address": "fd01:6::7"
        }

        install_key = "nexthop_gateway"
        bad_values = ["192.168.1.7", ]   # ipv4
        good_value = "fd01:6::8"         # ipv6
        self._test_post_input_value_inputs(setup_overrides, required_overrides,
                                           install_key, bad_values, good_value)


class TestSubcloudAPIOther(testroot.DCManagerApiTest):

    """Test GET, delete and patch API calls"""
    def setUp(self):
        super(TestSubcloudAPIOther, self).setUp()
        self.ctx = utils.dummy_context()

        p = mock.patch.object(rpc_client, 'SubcloudStateClient')
        self.mock_rpc_state_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_ks_client')
        self.mock_get_ks_client = p.start()
        self.addCleanup(p.stop)

    def test_delete_subcloud(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        delete_url = FAKE_URL + '/' + str(subcloud.id)
        self.mock_rpc_client().delete_subcloud.return_value = True
        response = self.app.delete_json(delete_url, headers=FAKE_HEADERS)
        self.mock_rpc_client().delete_subcloud.assert_called_once_with(
            mock.ANY, mock.ANY)
        self.assertEqual(response.status_int, 200)

    def test_delete_wrong_request(self):
        delete_url = WRONG_URL + '/' + FAKE_ID
        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.delete_json, delete_url,
                              headers=FAKE_HEADERS)

    @mock.patch.object(subclouds.SubcloudsController, '_get_oam_addresses')
    def test_get_subcloud(self,
                          mock_get_oam_addresses):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        get_url = FAKE_URL + '/' + str(subcloud.id)
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json.get('oam_floating_ip', None), None)
        self.assertEqual(response.json['name'], subcloud.name)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_deploy_config_sync_status')
    @mock.patch.object(subclouds.SubcloudsController, '_get_oam_addresses')
    def test_get_online_subcloud_with_additional_detail(self,
                                                        mock_get_oam_addresses,
                                                        mock_get_deploy_config_sync_status):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        updated_subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        get_url = FAKE_URL + '/' + str(updated_subcloud.id) + '/detail'
        oam_addresses = FakeOAMAddressPool('10.10.10.254',
                                           '10.10.10.1',
                                           '10.10.10.254',
                                           '10.10.10.4',
                                           '10.10.10.3',
                                           '10.10.10.1',
                                           '10.10.10.2')
        mock_get_oam_addresses.return_value = oam_addresses
        mock_get_deploy_config_sync_status.return_value = dccommon_consts.DEPLOY_CONFIG_UP_TO_DATE
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual('10.10.10.2', response.json['oam_floating_ip'])
        self.assertEqual(
            'Deployment: configurations up-to-date', response.json['deploy_config_sync_status'])

    def test_get_offline_subcloud_with_additional_detail(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        get_url = FAKE_URL + '/' + str(subcloud.id) + '/detail'
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual('unavailable', response.json['oam_floating_ip'])
        self.assertEqual('unknown', response.json['deploy_config_sync_status'])

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_deploy_config_sync_status')
    @mock.patch.object(subclouds.SubcloudsController, '_get_oam_addresses')
    def test_get_subcloud_deploy_config_status_unknown(self,
                                                       mock_get_oam_addresses,
                                                       mock_get_deploy_config_sync_status):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        updated_subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=dccommon_consts.AVAILABILITY_ONLINE)
        get_url = FAKE_URL + '/' + str(updated_subcloud.id) + '/detail'
        mock_get_oam_addresses.return_value = None
        mock_get_deploy_config_sync_status.return_value = None
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual('unknown', response.json['deploy_config_sync_status'])

    @mock.patch.object(subclouds.SubcloudsController, '_get_oam_addresses')
    def test_get_subcloud_oam_ip_unavailable(self, mock_get_oam_addresses):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        updated_subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        get_url = FAKE_URL + '/' + str(updated_subcloud.id) + '/detail'
        self.mock_get_ks_client.return_value = 'ks_client'
        mock_get_oam_addresses.return_value = None
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual('unavailable', response.json['oam_floating_ip'])

    def test_get_wrong_request(self):
        get_url = WRONG_URL + '/' + FAKE_ID
        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.get, get_url,
                              headers=FAKE_HEADERS)

    def test_get_subcloud_all(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        get_url = FAKE_URL
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.json['subclouds'][0]['name'], subcloud.name)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud(self, mock_get_patch_data):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'management-state': dccommon_consts.MANAGEMENT_UNMANAGED}
        self.mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = data
        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id),
                                       headers=FAKE_HEADERS,
                                       params=data)
        self.assertEqual(response.status_int, 200)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(dccommon_consts.MANAGEMENT_UNMANAGED,
                         updated_subcloud.management_state)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_update_subcloud_group_value(self, mock_get_patch_data):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        good_values = [1, "1"]
        expected_group_id = 1
        for x in good_values:
            data = {'group_id': x}
            self.mock_rpc_client().update_subcloud.return_value = True
            mock_get_patch_data.return_value = data
            response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id),
                                           headers=FAKE_HEADERS,
                                           params=data)
            self.assertEqual(response.status_int, 200)
            # Verify subcloud was updated with correct values
            updated_subcloud = db_api.subcloud_get_by_name(self.ctx,
                                                           subcloud.name)
            self.assertEqual(expected_group_id,
                             updated_subcloud.group_id)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_update_subcloud_group_value_by_name(self, mock_get_patch_data):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        expected_group_id = 1
        data = {'group_id': 'Default'}
        self.mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = data
        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id),
                                       headers=FAKE_HEADERS,
                                       params=data)
        self.assertEqual(response.status_int, 200)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(expected_group_id,
                         updated_subcloud.group_id)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_update_subcloud_group_bad_value(self, mock_get_patch_data):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        # There is only 1 subcloud group 'Default' which has id '1'
        # This should test that boolean, zero, negative, float and bad values
        # all get rejected
        bad_values = [0, -1, 2, "0", "-1", 0.5, "BadName", "False", "True"]
        for x in bad_values:
            data = {'group_id': x}
            self.mock_rpc_client().update_subcloud.return_value = True
            mock_get_patch_data.return_value = data
            response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id),
                                           headers=FAKE_HEADERS,
                                           params=data,
                                           expect_errors=True)
            self.assertEqual(response.status_int, 400)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    @mock.patch.object(cutils, 'get_vault_load_files')
    def test_update_subcloud_install_values_persistent_size(self, mock_vault_files,
                                                            mock_get_patch_data):
        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx, data_install=None)
        payload = {}
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES_WITH_PERSISTENT_SIZE)
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        data = {'bmc_password': encoded_password}
        payload.update({'install_values': install_data})
        payload.update(data)
        self.mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = payload

        fake_content = "fake content".encode("utf-8")
        response = self.app.patch(FAKE_URL + '/' + str(subcloud.id),
                                  headers=FAKE_HEADERS,
                                  params=data,
                                  upload_files=[("install_values",
                                                 "fake_name",
                                                 fake_content)])
        install_data.update({'bmc_password': encoded_password})
        self.mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            management_state=None,
            description=None,
            location=None,
            group_id=None,
            data_install=json.dumps(install_data),
            force=None,
            peer_group_id=None,
            bootstrap_values=None,
            bootstrap_address=None)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(psd_common, 'get_network_address_pool')
    @mock.patch.object(subclouds.SubcloudsController,
                       '_validate_network_reconfiguration')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_network_values(
            self, mock_get_patch_data, mock_validate_network_reconfiguration,
            mock_mgmt_address_pool):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE)
        fake_password = (
            base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        payload = {'sysadmin_password': fake_password,
                   'bootstrap_address': "192.168.102.2",
                   'management_subnet': "192.168.102.0/24",
                   'management_start_ip': "192.168.102.5",
                   'management_end_ip': "192.168.102.49",
                   'management_gateway_ip': "192.168.102.1"}

        fake_management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                       '192.168.204.2',
                                                       '192.168.204.100')
        mock_mgmt_address_pool.return_value = fake_management_address_pool

        self.mock_rpc_client().update_subcloud_with_network_reconfig.return_value = True
        mock_get_patch_data.return_value = payload
        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id),
                                       headers=FAKE_HEADERS,
                                       params=payload)
        self.assertEqual(response.status_int, 200)
        mock_validate_network_reconfiguration.assert_called_once()
        self.mock_rpc_client().update_subcloud_with_network_reconfig.\
            assert_called_once_with(mock.ANY, subcloud.id, payload)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    @mock.patch.object(cutils, 'get_vault_load_files')
    def test_patch_subcloud_install_values(self, mock_vault_files,
                                           mock_get_patch_data):
        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx, data_install=None)
        payload = {}
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        data = {'bmc_password': encoded_password}
        payload.update({'install_values': install_data})
        payload.update(data)
        self.mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = payload

        fake_content = "fake content".encode("utf-8")
        response = self.app.patch(FAKE_URL + '/' + str(subcloud.id),
                                  headers=FAKE_HEADERS,
                                  params=data,
                                  upload_files=[("install_values",
                                                 "fake_name",
                                                 fake_content)])
        install_data.update({'bmc_password': encoded_password})
        self.mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            management_state=None,
            description=None,
            location=None,
            group_id=None,
            data_install=json.dumps(install_data),
            force=None,
            peer_group_id=None,
            bootstrap_values=None,
            bootstrap_address=None)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    @mock.patch.object(cutils, 'get_vault_load_files')
    def test_patch_subcloud_install_values_with_existing_data_install(
        self, mock_vault_files, mock_get_patch_data):
        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, data_install=json.dumps(install_data))
        install_data.update({"install_type": 2})
        payload = {}
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        data = {'bmc_password': encoded_password}
        payload.update({'install_values': install_data})
        payload.update(data)
        self.mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = payload

        fake_content = "fake content".encode("utf-8")
        response = self.app.patch(FAKE_URL + '/' + str(subcloud.id),
                                  headers=FAKE_HEADERS,
                                  params=data,
                                  upload_files=[("install_values",
                                                 "fake_name",
                                                 fake_content)])
        install_data.update({'bmc_password': encoded_password})
        self.mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            management_state=None,
            description=None,
            location=None,
            group_id=None,
            data_install=json.dumps(install_data),
            force=None,
            peer_group_id=None,
            bootstrap_values=None,
            bootstrap_address=None)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_no_body(self, mock_get_patch_data):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {}
        mock_get_patch_data.return_value = data
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json,
                              FAKE_URL + '/' + str(subcloud.id),
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_bad_status(self, mock_get_patch_data):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'management-state': 'bad-status'}
        mock_get_patch_data.return_value = data
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json,
                              FAKE_URL + '/' + str(subcloud.id),
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_bad_force_value(self, mock_get_patch_data):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'management-state': dccommon_consts.MANAGEMENT_MANAGED,
                'force': 'bad-value'}
        mock_get_patch_data.return_value = data
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json,
                              FAKE_URL + '/' + str(subcloud.id),
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_forced_unmanaged(self, mock_get_patch_data):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'management-state': dccommon_consts.MANAGEMENT_UNMANAGED,
                'force': True}
        mock_get_patch_data.return_value = data
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json,
                              FAKE_URL + '/' + str(subcloud.id),
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_forced_manage(self, mock_get_patch_data):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        payload = {'management-state': dccommon_consts.MANAGEMENT_MANAGED,
                   'force': True}
        self.mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = payload
        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id),
                                       headers=FAKE_HEADERS,
                                       params=payload)
        self.mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            mock.ANY,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            description=None,
            location=None,
            group_id=None,
            data_install=None,
            force=True,
            peer_group_id=None,
            bootstrap_values=None,
            bootstrap_address=None)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(subclouds.SubcloudsController, '_get_updatestatus_payload')
    def test_subcloud_updatestatus(self, mock_get_updatestatus_payload):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'endpoint': 'dc-cert', 'status': 'in-sync'}
        mock_get_updatestatus_payload.return_value = data

        self.mock_rpc_state_client().update_subcloud_endpoint_status.return_value = True
        response = self.app.patch_json(
            FAKE_URL + '/' + str(subcloud.id) + '/update_status',
            data, headers=FAKE_HEADERS)

        self.mock_rpc_state_client().update_subcloud_endpoint_status.\
            assert_called_once_with(mock.ANY, subcloud.name, subcloud.region_name,
                                    'dc-cert', 'in-sync')

        self.assertEqual(response.status_int, 200)

    @mock.patch.object(subclouds.SubcloudsController, '_get_updatestatus_payload')
    def test_subcloud_updatestatus_invalid_endpoint(
            self, mock_get_updatestatus_payload):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'endpoint': 'any-other-endpoint', 'status': 'in-sync'}
        mock_get_updatestatus_payload.return_value = data

        self.mock_rpc_client().update_subcloud_endpoint_status.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/update_status',
                              headers=FAKE_HEADERS, params=data)
        self.mock_rpc_client().update_subcloud_endpoint_status.assert_not_called()

    @mock.patch.object(subclouds.SubcloudsController, '_get_updatestatus_payload')
    def test_subcloud_updatestatus_invalid_status(
            self, mock_get_updatestatus_payload):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'endpoint': 'dc-cert', 'status': 'not-sure'}
        mock_get_updatestatus_payload.return_value = data

        self.mock_rpc_client().update_subcloud_endpoint_status.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/update_status',
                              headers=FAKE_HEADERS, params=data)
        self.mock_rpc_client().update_subcloud_endpoint_status.assert_not_called()

    def test_get_config_file_path(self):
        bootstrap_file = psd_common.get_config_file_path("subcloud1")
        install_values = psd_common.get_config_file_path("subcloud1",
                                                         "install_values")
        deploy_config = psd_common.get_config_file_path("subcloud1",
                                                        consts.DEPLOY_CONFIG)
        self.assertEqual(bootstrap_file,
                         f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1.yml')
        self.assertEqual(install_values,
                         f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1/install_values.yml')
        self.assertEqual(deploy_config,
                         f'{dccommon_consts.ANSIBLE_OVERRIDES_PATH}/subcloud1_deploy_config.yml')

    def test_format_ip_address(self):
        fake_payload = {}
        good_values = {
            '10.10.10.3': '10.10.10.3',
            '2620:10a:a001:a103::1135': '2620:10a:a001:a103::1135',
            '2620:10A:A001:A103::1135': '2620:10a:a001:a103::1135',      # with upper case letters
            '2620:010a:a001:a103::1135': '2620:10a:a001:a103::1135',     # with leading zeros
            '2620:10a:a001:a103:0000::1135': '2620:10a:a001:a103::1135'  # with a string of zeros
            }

        for k, v in good_values.items():
            fake_payload['bootstrap-address'] = k
            psd_common.format_ip_address(fake_payload)
            self.assertEqual(fake_payload['bootstrap-address'], v)

        fake_payload[consts.INSTALL_VALUES] = {}
        for k, v in good_values.items():
            fake_payload[consts.INSTALL_VALUES]['bmc_address'] = k
            psd_common.format_ip_address(fake_payload)
            self.assertEqual(fake_payload[consts.INSTALL_VALUES]['bmc_address'], v)

        fake_payload['othervalues1'] = 'othervalues1'
        fake_payload[consts.INSTALL_VALUES]['othervalues2'] = 'othervalues2'
        psd_common.format_ip_address(fake_payload)
        self.assertEqual(fake_payload['othervalues1'], 'othervalues1')
        self.assertEqual(fake_payload[consts.INSTALL_VALUES]['othervalues2'], 'othervalues2')

    def test_get_subcloud_db_install_values(self):
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        install_data['bmc_password'] = encoded_password
        test_subcloud = copy.copy(FAKE_SUBCLOUD_DATA)
        subcloud_info = Subcloud(test_subcloud, False)
        subcloud_info.data_install = json.dumps(install_data)

        actual_result = psd_common.get_subcloud_db_install_values(subcloud_info)

        self.assertEqual(
            json.loads(json.dumps(install_data)),
            json.loads(json.dumps(actual_result)))

    @mock.patch.object(keyring, 'get_password')
    def test_get_subcloud_db_install_values_without_bmc_password(
            self, mock_keyring):
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, data_install=json.dumps(install_data))

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/redeploy',
                              headers=FAKE_HEADERS)

    @mock.patch.object(psd_common, 'upload_config_file')
    @mock.patch.object(psd_common.PatchingClient, 'query')
    @mock.patch.object(os.path, 'isdir')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(psd_common, 'validate_k8s_version')
    @mock.patch.object(psd_common, 'validate_subcloud_config')
    @mock.patch.object(psd_common, 'validate_bootstrap_values')
    def test_redeploy_subcloud(
            self, mock_validate_bootstrap_values, mock_validate_subcloud_config,
            mock_validate_k8s_version, mock_get_vault_load_files,
            mock_os_listdir, mock_os_isdir, mock_query, mock_upload_config_file):

        fake_bmc_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        fake_sysadmin_password = base64.b64encode(
            'sysadmin_password'.encode("utf-8")).decode('utf-8')

        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data.pop('software_version')
        bootstrap_data = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        config_data = {'deploy_config': 'deploy config values'}
        redeploy_data = {**install_data, **bootstrap_data, **config_data,
                         'sysadmin_password': fake_sysadmin_password,
                         'bmc_password': fake_bmc_password}

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, name=bootstrap_data["name"])

        mock_query.return_value = {}
        mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')
        mock_os_isdir.return_value = True
        mock_upload_config_file.return_value = True
        mock_os_listdir.return_value = ['deploy_chart_fake.tgz',
                                        'deploy_overrides_fake.yaml',
                                        'deploy_playbook_fake.yaml']

        upload_files = [("install_values", "install_fake_filename",
                         json.dumps(install_data).encode("utf-8")),
                        ("bootstrap_values", "bootstrap_fake_filename",
                         json.dumps(bootstrap_data).encode("utf-8")),
                        ("deploy_config", "config_fake_filename",
                         json.dumps(config_data).encode("utf-8"))]

        response = self.app.patch(
            FAKE_URL + '/' + str(subcloud.id) + '/redeploy',
            headers=FAKE_HEADERS, params=redeploy_data,
            upload_files=upload_files)

        mock_validate_bootstrap_values.assert_called_once()
        mock_validate_subcloud_config.assert_called_once()
        mock_validate_k8s_version.assert_called_once()
        self.mock_rpc_client().redeploy_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            mock.ANY)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(SW_VERSION, response.json['software-version'])

    @mock.patch.object(cutils, 'load_yaml_file')
    @mock.patch.object(psd_common.PatchingClient, 'query')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os.path, 'isdir')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(psd_common, 'validate_k8s_version')
    def test_redeploy_subcloud_no_request_data(
            self, mock_validate_k8s_version, mock_get_vault_load_files,
            mock_os_listdir, mock_os_isdir, mock_path_exists, mock_query,
            mock_load_yaml):

        fake_bmc_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        fake_sysadmin_password = base64.b64encode(
            'sysadmin_password'.encode("utf-8")).decode('utf-8')

        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data.pop('software_version')
        install_data['bmc_password'] = fake_bmc_password
        redeploy_data = {'sysadmin_password': fake_sysadmin_password}

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            data_install=json.dumps(install_data))

        config_file = psd_common.get_config_file_path(subcloud.name,
                                                      consts.DEPLOY_CONFIG)
        mock_query.return_value = {}
        mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')
        mock_os_isdir.return_value = True
        mock_os_listdir.return_value = ['deploy_chart_fake.tgz',
                                        'deploy_overrides_fake.yaml',
                                        'deploy_playbook_fake.yaml']
        mock_path_exists.side_effect = lambda x: True if x == config_file else False
        mock_load_yaml.return_value = {"software_version": SW_VERSION}

        response = self.app.patch(
            FAKE_URL + '/' + str(subcloud.id) + '/redeploy',
            headers=FAKE_HEADERS, params=redeploy_data)

        mock_validate_k8s_version.assert_called_once()
        self.mock_rpc_client().redeploy_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            mock.ANY)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(SW_VERSION, response.json['software-version'])

    @mock.patch.object(psd_common, 'upload_config_file')
    @mock.patch.object(psd_common.PatchingClient, 'query')
    @mock.patch.object(os.path, 'isdir')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(psd_common, 'validate_k8s_version')
    @mock.patch.object(psd_common, 'validate_subcloud_config')
    @mock.patch.object(psd_common, 'validate_bootstrap_values')
    def test_redeploy_subcloud_with_release_version(
            self, mock_validate_bootstrap_values, mock_validate_subcloud_config,
            mock_validate_k8s_version, mock_get_vault_load_files,
            mock_os_listdir, mock_os_isdir, mock_query, mock_upload_config_file):

        fake_bmc_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        fake_sysadmin_password = base64.b64encode(
            'sysadmin_password'.encode("utf-8")).decode('utf-8')

        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data.pop('software_version')
        bootstrap_data = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        config_data = {'deploy_config': 'deploy config values'}
        redeploy_data = {**install_data, **bootstrap_data, **config_data,
                         'sysadmin_password': fake_sysadmin_password,
                         'bmc_password': fake_bmc_password,
                         'release': fake_subcloud.FAKE_SOFTWARE_VERSION}

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, name=bootstrap_data["name"],
            software_version=SW_VERSION)

        mock_query.return_value = {}
        mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')
        mock_os_isdir.return_value = True
        mock_upload_config_file.return_value = True
        mock_os_listdir.return_value = ['deploy_chart_fake.tgz',
                                        'deploy_overrides_fake.yaml',
                                        'deploy_playbook_fake.yaml']

        upload_files = [("install_values", "install_fake_filename",
                         json.dumps(install_data).encode("utf-8")),
                        ("bootstrap_values", "bootstrap_fake_filename",
                         json.dumps(bootstrap_data).encode("utf-8")),
                        ("deploy_config", "config_fake_filename",
                         json.dumps(config_data).encode("utf-8"))]

        response = self.app.patch(
            FAKE_URL + '/' + str(subcloud.id) + '/redeploy',
            headers=FAKE_HEADERS, params=redeploy_data,
            upload_files=upload_files)

        mock_validate_bootstrap_values.assert_called_once()
        mock_validate_subcloud_config.assert_called_once()
        mock_validate_k8s_version.assert_called_once()
        self.mock_rpc_client().redeploy_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            mock.ANY)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(fake_subcloud.FAKE_SOFTWARE_VERSION,
                         response.json['software-version'])

    @mock.patch.object(cutils, 'load_yaml_file')
    @mock.patch.object(psd_common.PatchingClient, 'query')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os.path, 'isdir')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(cutils, 'get_vault_load_files')
    def test_redeploy_subcloud_no_request_body(
            self, mock_get_vault_load_files, mock_os_listdir,
            mock_os_isdir, mock_path_exists, mock_query, mock_load_yaml):

        fake_bmc_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')

        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data.pop('software_version')
        install_data['bmc_password'] = fake_bmc_password

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            data_install=json.dumps(install_data))

        config_file = psd_common.get_config_file_path(subcloud.name,
                                                      consts.DEPLOY_CONFIG)
        mock_query.return_value = {}
        mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')
        mock_os_isdir.return_value = True
        mock_os_listdir.return_value = ['deploy_chart_fake.tgz',
                                        'deploy_overrides_fake.yaml',
                                        'deploy_playbook_fake.yaml']
        mock_path_exists.side_effect = lambda x: True if x == config_file else False
        mock_load_yaml.return_value = {"software_version": SW_VERSION}

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/redeploy',
                              headers=FAKE_HEADERS, params={})

    def test_redeploy_online_subcloud(self):

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"])
        db_api.subcloud_update(self.ctx, subcloud.id,
                               availability_status=dccommon_consts.AVAILABILITY_ONLINE)

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/redeploy',
                              headers=FAKE_HEADERS, params={})
        self.mock_rpc_client().redeploy_subcloud.assert_not_called()

    def test_redeploy_managed_subcloud(self):

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"])
        db_api.subcloud_update(self.ctx, subcloud.id,
                               management_state=dccommon_consts.MANAGEMENT_MANAGED)

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/redeploy',
                              headers=FAKE_HEADERS, params={})
        self.mock_rpc_client().redeploy_subcloud.assert_not_called()

    @mock.patch.object(cutils, 'load_yaml_file')
    @mock.patch.object(psd_common.PatchingClient, 'query')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os.path, 'isdir')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(psd_common, 'validate_k8s_version')
    def test_redeploy_subcloud_missing_required_value(
            self, mock_validate_k8s_version, mock_get_vault_load_files,
            mock_os_listdir, mock_os_isdir, mock_path_exists, mock_query,
            mock_load_yaml):

        fake_bmc_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        fake_sysadmin_password = base64.b64encode(
            'sysadmin_password'.encode("utf-8")).decode('utf-8')

        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data.pop('software_version')
        install_data['bmc_password'] = fake_bmc_password

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, name=fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA["name"],
            data_install=json.dumps(install_data))

        config_file = psd_common.get_config_file_path(subcloud.name,
                                                      consts.DEPLOY_CONFIG)
        mock_query.return_value = {}
        mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')
        mock_os_isdir.return_value = True
        mock_os_listdir.return_value = ['deploy_chart_fake.tgz',
                                        'deploy_overrides_fake.yaml',
                                        'deploy_playbook_fake.yaml']
        mock_path_exists.side_effect = lambda x: True if x == config_file else False
        mock_load_yaml.return_value = {"software_version": SW_VERSION}

        for k in ['name', 'system_mode', 'external_oam_subnet',
                  'external_oam_gateway_address', 'external_oam_floating_address',
                  'sysadmin_password']:
            bootstrap_values = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
            redeploy_data = {**bootstrap_values,
                             'sysadmin_password': fake_sysadmin_password}
            del redeploy_data[k]
            upload_files = [("bootstrap_values", "bootstrap_fake_filename",
                             json.dumps(redeploy_data).encode("utf-8"))]
            six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                                  self.app.patch_json, FAKE_URL + '/' +
                                  str(subcloud.id) + '/redeploy',
                                  headers=FAKE_HEADERS, params=redeploy_data,
                                  upload_files=upload_files)

    @mock.patch.object(psd_common, 'upload_config_file')
    @mock.patch.object(psd_common.PatchingClient, 'query')
    @mock.patch.object(os.path, 'isdir')
    @mock.patch.object(os, 'listdir')
    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(psd_common, 'validate_k8s_version')
    @mock.patch.object(psd_common, 'validate_subcloud_config')
    @mock.patch.object(psd_common, 'validate_bootstrap_values')
    def test_redeploy_subcloud_missing_stored_values(
            self, mock_validate_bootstrap_values, mock_validate_subcloud_config,
            mock_validate_k8s_version, mock_get_vault_load_files,
            mock_os_listdir, mock_os_isdir, mock_query, mock_upload_config_values):

        fake_bmc_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        fake_sysadmin_password = base64.b64encode(
            'sysadmin_password'.encode("utf-8")).decode('utf-8')

        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        install_data.pop('software_version')
        bootstrap_data = copy.copy(fake_subcloud.FAKE_BOOTSTRAP_FILE_DATA)
        config_data = {'deploy_config': 'deploy config values'}

        for k in ['management_subnet', 'management_start_address',
                  'management_end_address', 'management_gateway_address',
                  'systemcontroller_gateway_address']:
            del bootstrap_data[k]

        redeploy_data = {**install_data, **bootstrap_data, **config_data,
                         'sysadmin_password': fake_sysadmin_password,
                         'bmc_password': fake_bmc_password}

        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, name=bootstrap_data["name"])

        mock_query.return_value = {}
        mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')
        mock_os_isdir.return_value = True
        mock_upload_config_values.return_value = True
        mock_os_listdir.return_value = ['deploy_chart_fake.tgz',
                                        'deploy_overrides_fake.yaml',
                                        'deploy_playbook_fake.yaml']

        upload_files = [("install_values", "install_fake_filename",
                         json.dumps(install_data).encode("utf-8")),
                        ("bootstrap_values", "bootstrap_fake_filename",
                         json.dumps(bootstrap_data).encode("utf-8")),
                        ("deploy_config", "config_fake_filename",
                         json.dumps(config_data).encode("utf-8"))]

        response = self.app.patch(
            FAKE_URL + '/' + str(subcloud.id) + '/redeploy',
            headers=FAKE_HEADERS, params=redeploy_data,
            upload_files=upload_files)

        mock_validate_bootstrap_values.assert_called_once()
        mock_validate_subcloud_config.assert_called_once()
        mock_validate_k8s_version.assert_called_once()
        self.mock_rpc_client().redeploy_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            mock.ANY)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(SW_VERSION, response.json['software-version'])

    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(prestage, '_get_prestage_subcloud_info')
    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    def test_prestage_subcloud_validate_detailed(self, mock_get_prestage_payload,
                                                 mock_prestage_subcloud_info,
                                                 mock_controller_upgrade):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'force': False}
        mock_controller_upgrade.return_value = list()
        mock_prestage_subcloud_info.return_value = consts.SYSTEM_MODE_SIMPLEX, \
            health_report_no_alarm, \
            OAM_FLOATING_IP

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id) +
                                       '/prestage',
                                       headers=FAKE_HEADERS,
                                       params=data)
        self.mock_rpc_client().prestage_subcloud.assert_called_once_with(
            mock.ANY,
            mock.ANY)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(cutils, 'get_systemcontroller_installed_loads')
    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    def test_prestage_subcloud_invalid_release(self, mock_get_prestage_payload,
                                               mock_controller_upgrade,
                                               mock_installed_loads):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED)

        fake_release = '21.12'
        mock_installed_loads.return_value = ['22.12']

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))). \
            decode('ascii')
        data = {'sysadmin_password': fake_password,
                'force': False,
                'release': fake_release}
        mock_controller_upgrade.return_value = list()

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/prestage',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    def test_prestage_subcloud_unmanaged(self, mock_controller_upgrade,
                                         mock_get_prestage_payload):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password}
        mock_controller_upgrade.return_value = list()

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/prestage',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    def test_prestage_subcloud_offline(self, mock_controller_upgrade,
                                       mock_get_prestage_payload):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password}
        mock_controller_upgrade.return_value = list()

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/prestage',
                              headers=FAKE_HEADERS, params=data)

    def test_prestage_subcloud_backup_in_progress(self):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        subcloud = db_api.subcloud_update(
            self.ctx,
            subcloud.id,
            availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            deploy_status=consts.DEPLOY_STATE_DONE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED,
            backup_status=consts.BACKUP_STATE_IN_PROGRESS)

        self.assertRaises(exceptions.PrestagePreCheckFailedException,
                          prestage.initial_subcloud_validate,
                          subcloud,
                          [fake_subcloud.FAKE_SOFTWARE_VERSION],
                          fake_subcloud.FAKE_SOFTWARE_VERSION)

    @mock.patch.object(cutils, 'get_systemcontroller_installed_loads')
    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(prestage, '_get_prestage_subcloud_info')
    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    def test_prestage_subcloud_duplex(self, mock_get_prestage_payload,
                                      mock_prestage_subcloud_info,
                                      mock_controller_upgrade,
                                      mock_installed_loads):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED)

        fake_release = '21.12'
        mock_installed_loads.return_value = [fake_release]

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).\
            decode('ascii')
        data = {'sysadmin_password': fake_password,
                'force': False}
        mock_controller_upgrade.return_value = list()
        mock_prestage_subcloud_info.return_value = consts.SYSTEM_MODE_DUPLEX, \
            health_report_no_alarm, \
            OAM_FLOATING_IP

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/prestage',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(prestage, '_get_prestage_subcloud_info')
    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    def test_prestage_subcloud_non_mgmt_alarm(self, mock_get_prestage_payload,
                                              mock_prestage_subcloud_info,
                                              mock_controller_upgrade):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'force': False}
        mock_controller_upgrade.return_value = list()
        mock_prestage_subcloud_info.return_value = consts.SYSTEM_MODE_SIMPLEX, \
            health_report_no_mgmt_alarm, \
            OAM_FLOATING_IP

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id) +
                                       '/prestage',
                                       headers=FAKE_HEADERS,
                                       params=data)
        self.mock_rpc_client().prestage_subcloud.assert_called_once_with(
            mock.ANY,
            mock.ANY)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(prestage, '_get_prestage_subcloud_info')
    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    def test_prestage_subcloud_mgmt_alarm(self, mock_get_prestage_payload,
                                          mock_prestage_subcloud_info,
                                          mock_controller_upgrade):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'force': False}
        mock_controller_upgrade.return_value = list()
        mock_prestage_subcloud_info.return_value = consts.SYSTEM_MODE_SIMPLEX, \
            health_report_mgmt_alarm, \
            OAM_FLOATING_IP

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/prestage',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(prestage, '_get_prestage_subcloud_info')
    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    def test_prestage_subcloud_mgmt_alarm_force(self, mock_get_prestage_payload,
                                                mock_prestage_subcloud_info,
                                                mock_controller_upgrade):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=dccommon_consts.AVAILABILITY_ONLINE,
            management_state=dccommon_consts.MANAGEMENT_MANAGED)

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'force': True}
        mock_controller_upgrade.return_value = list()
        mock_prestage_subcloud_info.return_value = consts.SYSTEM_MODE_SIMPLEX, \
            health_report_mgmt_alarm, \
            OAM_FLOATING_IP

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id) +
                                       '/prestage',
                                       headers=FAKE_HEADERS,
                                       params=data)
        self.mock_rpc_client().prestage_subcloud.assert_called_once_with(
            mock.ANY,
            mock.ANY)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(prestage, '_get_prestage_subcloud_info')
    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    def test_prestage_subcloud_not_allowed_state(self, mock_get_prestage_payload,
                                                 mock_prestage_subcloud_info,
                                                 mock_controller_upgrade):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        subcloud = db_api.subcloud_update(self.ctx, subcloud.id,
                                          availability_status=dccommon_consts.AVAILABILITY_ONLINE,
                                          management_state=dccommon_consts.MANAGEMENT_MANAGED,
                                          deploy_status='NotAllowedState')

        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password,
                'force': False}
        mock_controller_upgrade.return_value = list()
        mock_prestage_subcloud_info.return_value = consts.SYSTEM_MODE_SIMPLEX, \
            health_report_no_alarm, \
            OAM_FLOATING_IP

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/prestage',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    def test_prestage_subcloud_controller_upgrading(self, mock_get_prestage_payload,
                                                    mock_controller_upgrade):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password}
        mock_controller_upgrade.return_value = list('upgrade')

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/prestage',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    def test_prestage_subcloud_no_password(self, mock_get_prestage_payload,
                                           mock_controller_upgrade):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {}
        mock_controller_upgrade.return_value = list()

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/prestage',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(prestage, '_get_system_controller_upgrades')
    @mock.patch.object(subclouds.SubcloudsController, '_get_prestage_payload')
    def test_prestage_subcloud_password_not_encoded(self, mock_get_prestage_payload,
                                                    mock_controller_upgrade):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'sysadmin_password': 'notencoded'}
        mock_controller_upgrade.return_value = list()

        self.mock_rpc_client().prestage_subcloud.return_value = True
        mock_get_prestage_payload.return_value = data

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/prestage',
                              headers=FAKE_HEADERS, params=data)

    def test_get_management_subnet(self):
        payload = {
            'management_subnet': "192.168.204.0/24"
        }
        self.assertEqual(cutils.get_management_subnet(payload),
                         payload['management_subnet'])

    def test_get_management_subnet_return_admin(self):
        payload = {
            'admin_subnet': "192.168.205.0/24",
            'management_subnet': "192.168.204.0/24"
        }
        self.assertEqual(cutils.get_management_subnet(payload),
                         payload['admin_subnet'])

    def test_get_management_start_address(self):
        payload = {
            'management_start_address': "192.168.204.2"
        }
        self.assertEqual(cutils.get_management_start_address(payload),
                         payload['management_start_address'])

    def test_get_management_start_address_return_admin(self):
        payload = {
            'admin_start_address': "192.168.205.2",
            'management_start_address': "192.168.204.2"
        }
        self.assertEqual(cutils.get_management_start_address(payload),
                         payload['admin_start_address'])

    def test_get_management_end_address(self):
        payload = {
            'management_end_address': "192.168.204.50"
        }
        self.assertEqual(cutils.get_management_end_address(payload),
                         payload['management_end_address'])

    def test_get_management_end_address_return_admin(self):
        payload = {
            'admin_end_address': "192.168.205.50",
            'management_end_address': "192.168.204.50"
        }
        self.assertEqual(cutils.get_management_end_address(payload),
                         payload['admin_end_address'])

    def test_get_management_gateway_address(self):
        payload = {
            'management_gateway_address': "192.168.204.1"
        }
        self.assertEqual(cutils.get_management_gateway_address(payload),
                         payload['management_gateway_address'])

    def test_get_management_gateway_address_return_admin(self):
        payload = {
            'admin_gateway_address': "192.168.205.1",
            'management_gateway_address': "192.168.204.1"
        }
        self.assertEqual(cutils.get_management_gateway_address(payload),
                         payload['admin_gateway_address'])

    def test_validate_admin_config_subnet_small(self):

        admin_subnet = "192.168.205.0/32"
        admin_start_address = "192.168.205.2"
        admin_end_address = "192.168.205.50"
        admin_gateway_address = "192.168.205.1"

        six.assertRaisesRegex(self,
                              Exception,
                              "Subnet too small*",
                              psd_common.validate_admin_network_config,
                              admin_subnet,
                              admin_start_address,
                              admin_end_address,
                              admin_gateway_address,
                              existing_networks=None,
                              operation=None)

    def test_validate_admin_config_start_address_outOfSubnet(self):

        admin_subnet = "192.168.205.0/28"
        admin_start_address = "192.168.205.200"
        admin_end_address = "192.168.205.50"
        admin_gateway_address = "192.168.205.1"

        six.assertRaisesRegex(self,
                              Exception,
                              "Address must be in subnet*",
                              psd_common.validate_admin_network_config,
                              admin_subnet,
                              admin_start_address,
                              admin_end_address,
                              admin_gateway_address,
                              existing_networks=None,
                              operation=None)

    def test_validate_admin_config_end_address_outOfSubnet(self):

        admin_subnet = "192.168.205.0/28"
        admin_start_address = "192.168.205.1"
        admin_end_address = "192.168.205.50"
        admin_gateway_address = "192.168.205.1"

        six.assertRaisesRegex(self,
                              Exception,
                              "Address must be in subnet*",
                              psd_common.validate_admin_network_config,
                              admin_subnet,
                              admin_start_address,
                              admin_end_address,
                              admin_gateway_address,
                              existing_networks=None,
                              operation=None)

    def test_validate_admin_config_gateway_address_outOfSubnet(self):

        admin_subnet = "192.168.205.0/28"
        admin_start_address = "192.168.205.1"
        admin_end_address = "192.168.205.12"
        admin_gateway_address = "192.168.205.50"

        six.assertRaisesRegex(self,
                              Exception,
                              "Address must be in subnet*",
                              psd_common.validate_admin_network_config,
                              admin_subnet,
                              admin_start_address,
                              admin_end_address,
                              admin_gateway_address,
                              existing_networks=None,
                              operation=None)
