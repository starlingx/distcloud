# Copyright (c) 2017 Ericsson AB
# Copyright (c) 2017-2021 Wind River Systems, Inc.
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

from oslo_utils import timeutils

import base64
import copy
import json
import keyring
import mock
import six
from six.moves import http_client
import webtest

from dcmanager.api.controllers.v1 import subclouds
from dcmanager.common import consts
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


class Subcloud(object):
    def __init__(self, data, is_online):
        self.id = data['id']
        self.name = data['name']
        self.description = data['description']
        self.location = data['location']
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
        "image": "fake image",
        "software_version": "123.456",
        "bootstrap_interface": "fake interface",
        "bootstrap_address": "10.10.10.12",
        "bootstrap_address_prefix": "10.10.10.12",
        "bmc_address": "128.224.64.1",
        "bmc_username": "fake bmc user",
        "install_type": 2,
    }

    list_of_post_files = subclouds.SUBCLOUD_ADD_MANDATORY_FILE
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
            if f == subclouds.BOOTSTRAP_VALUES:
                fake_content = json.dumps(self.bootstrap_data).encode("utf-8")
            elif f == subclouds.INSTALL_VALUES:
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
        self.list_of_post_files = subclouds.SUBCLOUD_ADD_MANDATORY_FILE
        self.bootstrap_data = copy.copy(self.FAKE_BOOTSTRAP_DATA)
        self.install_data = copy.copy(self.FAKE_INSTALL_DATA)

        self.management_address_pool = FakeAddressPool('192.168.204.0', 24,
                                                       '192.168.204.2',
                                                       '192.168.204.100')

        p = mock.patch.object(subclouds.SubcloudsController,
                              '_get_management_address_pool')
        self.mock_get_management_address_pool = p.start()
        self.mock_get_management_address_pool.return_value = \
            self.management_address_pool
        self.addCleanup(p.stop)

        p = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = p.start()
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

        self.list_of_post_files = subclouds.SUBCLOUD_ADD_MANDATORY_FILE
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

    def test_post_subcloud_install_values(self):
        """Test POST operation with install values is supported by the API."""

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

    def test_post_subcloud_install_values_no_bmc_password(self):
        """Test POST operation with install values is supported by the API."""

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
    def test_post_subcloud_install_values_missing(self, mock_vault_files):
        """Test POST operation with install values fails if data missing."""

        # todo(abailey): add a new unit test with no image and no vault files
        mock_vault_files.return_value = (None, None)

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

        mock_vault_files.return_value = ('fake_iso', 'fake_sig')
        # try with nothing removed and verify it works
        self.install_data = copy.copy(self.FAKE_INSTALL_DATA)
        upload_files = self.get_post_upload_files()
        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers())
        self._verify_post_success(response)

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

    def test_post_subcloud_install_values_invalid_type(self):
        """Test POST with an invalid type specified in install values."""

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

    def test_post_subcloud_install_bad_bootstrap_ip(self):
        """Test POST with invalid boostrap ip specified in install values."""

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

    def test_post_subcloud_install_bad_bmc_ip(self):
        """Test POST with invalid bmc ip specified in install values."""

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

    def test_post_subcloud_install_bad_persistent_size(self):
        """Test POST with invalid persistent_size specified in install values."""

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

    def test_post_subcloud_install_bad_nexthop_gateway(self):
        """Test POST with invalid nexthop_gateway in install values."""

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

    def test_post_subcloud_install_bad_network_address(self):
        """Test POST with invalid network_address in install values."""

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

    def test_post_subcloud_install_bad_network_mask(self):
        """Test POST with invalid network_mask in install values."""

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

    def test_post_subcloud_install_diff_bmc_ip_version(self):
        """Test POST install values with mismatched(ipv4/ipv6) bmc ip."""

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

    def test_post_subcloud_install_diff_bmc_ip_version_ipv6(self):
        """Test POST install values with mismatched(ipv6/ipv4) bmc ip."""

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

    def test_post_subcloud_install_diff_nexthop_ip_version(self):
        """Test POST install values mismatched(ipv4/ipv6) nexthop_gateway."""

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

    def test_post_subcloud_install_diff_nexthop_ip_version_ipv6(self):
        """Test POST install values with mismatched(ipv6/ipv4) bmc ip."""

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

    FAKE_RESTORE_PAYLOAD = {
        'sysadmin_password':
            (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii'),
        'with_install': 'true',
        'restore_values': {'on_box_data': 'false',
                           'backup_filename': 'some_fake_tarfile'}
    }

    """Test GET, delete and patch API calls"""
    def setUp(self):
        super(TestSubcloudAPIOther, self).setUp()
        self.ctx = utils.dummy_context()

        p = mock.patch.object(rpc_client, 'SubcloudStateClient')
        self.mock_rpc_state_client = p.start()
        self.addCleanup(p.stop)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_delete_subcloud(self, mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        delete_url = FAKE_URL + '/' + str(subcloud.id)
        mock_rpc_client().delete_subcloud.return_value = True
        response = self.app.delete_json(delete_url, headers=FAKE_HEADERS)
        mock_rpc_client().delete_subcloud.assert_called_once_with(
            mock.ANY, mock.ANY)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_delete_wrong_request(self, mock_rpc_client):
        delete_url = WRONG_URL + '/' + FAKE_ID
        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.delete_json, delete_url,
                              headers=FAKE_HEADERS)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_oam_addresses')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_subcloud(self,
                          mock_rpc_client,
                          mock_get_oam_addresses):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        get_url = FAKE_URL + '/' + str(subcloud.id)
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json.get('oam_floating_ip', None), None)
        self.assertEqual(response.json['name'], subcloud.name)

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_oam_addresses')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_online_subcloud_with_additional_detail(self,
                                                        mock_rpc_client,
                                                        mock_get_oam_addresses):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        updated_subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=consts.AVAILABILITY_ONLINE)

        get_url = FAKE_URL + '/' + str(updated_subcloud.id) + '/detail'
        oam_addresses = FakeOAMAddressPool('10.10.10.254',
                                           '10.10.10.1',
                                           '10.10.10.254',
                                           '10.10.10.4',
                                           '10.10.10.3',
                                           '10.10.10.1',
                                           '10.10.10.2')
        mock_get_oam_addresses.return_value = oam_addresses
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual('10.10.10.2', response.json['oam_floating_ip'])

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_offline_subcloud_with_additional_detail(self,
                                                         mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        get_url = FAKE_URL + '/' + str(subcloud.id) + '/detail'
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual('unavailable', response.json['oam_floating_ip'])

    @mock.patch.object(subclouds.SubcloudsController,
                       '_get_oam_addresses')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_subcloud_oam_ip_unavailable(self,
                                             mock_rpc_client,
                                             mock_get_oam_addresses):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        updated_subcloud = db_api.subcloud_update(
            self.ctx, subcloud.id, availability_status=consts.AVAILABILITY_ONLINE)

        get_url = FAKE_URL + '/' + str(updated_subcloud.id) + '/detail'
        mock_get_oam_addresses.return_value = None
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual('unavailable', response.json['oam_floating_ip'])

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_wrong_request(self, mock_rpc_client):
        get_url = WRONG_URL + '/' + FAKE_ID
        six.assertRaisesRegex(self, webtest.app.AppError, "404 *",
                              self.app.get, get_url,
                              headers=FAKE_HEADERS)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_subcloud_all(self, mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        get_url = FAKE_URL
        response = self.app.get(get_url, headers=FAKE_HEADERS)
        self.assertEqual(response.json['subclouds'][0]['name'], subcloud.name)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud(self, mock_get_patch_data,
                            mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'management-state': consts.MANAGEMENT_UNMANAGED}
        mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = data
        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id),
                                       headers=FAKE_HEADERS,
                                       params=data)
        self.assertEqual(response.status_int, 200)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(consts.MANAGEMENT_UNMANAGED,
                         updated_subcloud.management_state)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_update_subcloud_group_value(self,
                                         mock_get_patch_data,
                                         mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        good_values = [1, "1"]
        expected_group_id = 1
        for x in good_values:
            data = {'group_id': x}
            mock_rpc_client().update_subcloud.return_value = True
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

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_update_subcloud_group_value_by_name(self,
                                                 mock_get_patch_data,
                                                 mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        expected_group_id = 1
        data = {'group_id': 'Default'}
        mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = data
        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id),
                                       headers=FAKE_HEADERS,
                                       params=data)
        self.assertEqual(response.status_int, 200)

        # Verify subcloud was updated with correct values
        updated_subcloud = db_api.subcloud_get_by_name(self.ctx, subcloud.name)
        self.assertEqual(expected_group_id,
                         updated_subcloud.group_id)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_update_subcloud_group_bad_value(self,
                                             mock_get_patch_data,
                                             mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        # There is only 1 subcloud group 'Default' which has id '1'
        # This should test that boolean, zero, negative, float and bad values
        # all get rejected
        bad_values = [0, -1, 2, "0", "-1", 0.5, "BadName", "False", "True"]
        for x in bad_values:
            data = {'group_id': x}
            mock_rpc_client().update_subcloud.return_value = True
            mock_get_patch_data.return_value = data
            response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id),
                                           headers=FAKE_HEADERS,
                                           params=data,
                                           expect_errors=True)
            self.assertEqual(response.status_int, 400)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_update_subcloud_install_values_persistent_size(self,
                                                            mock_get_patch_data,
                                                            mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx, data_install=None)
        payload = {}
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES_WITH_PERSISTENT_SIZE)
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        data = {'bmc_password': encoded_password}
        payload.update({'install_values': install_data})
        payload.update(data)
        mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = payload

        fake_content = "fake content".encode("utf-8")
        response = self.app.patch(FAKE_URL + '/' + str(subcloud.id),
                                  headers=FAKE_HEADERS,
                                  params=data,
                                  upload_files=[("install_values",
                                                 "fake_name",
                                                 fake_content)])
        install_data.update({'bmc_password': encoded_password})
        mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            management_state=None,
            description=None,
            location=None,
            group_id=None,
            data_install=json.dumps(install_data),
            force=None)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_install_values(self, mock_get_patch_data,
                                           mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx, data_install=None)
        payload = {}
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        data = {'bmc_password': encoded_password}
        payload.update({'install_values': install_data})
        payload.update(data)
        mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = payload

        fake_content = "fake content".encode("utf-8")
        response = self.app.patch(FAKE_URL + '/' + str(subcloud.id),
                                  headers=FAKE_HEADERS,
                                  params=data,
                                  upload_files=[("install_values",
                                                 "fake_name",
                                                 fake_content)])
        install_data.update({'bmc_password': encoded_password})
        mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            management_state=None,
            description=None,
            location=None,
            group_id=None,
            data_install=json.dumps(install_data),
            force=None)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_install_values_with_existing_data_install(
        self, mock_get_patch_data, mock_rpc_client):
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, data_install=json.dumps(install_data))
        install_data.update({"software_version": "18.04"})
        payload = {}
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        data = {'bmc_password': encoded_password}
        payload.update({'install_values': install_data})
        payload.update(data)
        mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = payload

        fake_content = "fake content".encode("utf-8")
        response = self.app.patch(FAKE_URL + '/' + str(subcloud.id),
                                  headers=FAKE_HEADERS,
                                  params=data,
                                  upload_files=[("install_values",
                                                 "fake_name",
                                                 fake_content)])
        install_data.update({'bmc_password': encoded_password})
        mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            management_state=None,
            description=None,
            location=None,
            group_id=None,
            data_install=json.dumps(install_data),
            force=None)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_no_body(self, mock_get_patch_data,
                                    mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {}
        mock_get_patch_data.return_value = data
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json,
                              FAKE_URL + '/' + str(subcloud.id),
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_bad_status(self, mock_get_patch_data,
                                       mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'management-state': 'bad-status'}
        mock_get_patch_data.return_value = data
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json,
                              FAKE_URL + '/' + str(subcloud.id),
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_bad_force_value(self, mock_get_patch_data,
                                            mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'management-state': consts.MANAGEMENT_MANAGED,
                'force': 'bad-value'}
        mock_get_patch_data.return_value = data
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json,
                              FAKE_URL + '/' + str(subcloud.id),
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_forced_unmanaged(self, mock_get_patch_data,
                                             mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'management-state': consts.MANAGEMENT_UNMANAGED,
                'force': True}
        mock_get_patch_data.return_value = data
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json,
                              FAKE_URL + '/' + str(subcloud.id),
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_patch_data')
    def test_patch_subcloud_forced_manage(self, mock_get_patch_data,
                                          mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'management-state': consts.MANAGEMENT_MANAGED,
                'force': True}
        mock_rpc_client().update_subcloud.return_value = True
        mock_get_patch_data.return_value = data
        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id),
                                       headers=FAKE_HEADERS,
                                       params=data)
        mock_rpc_client().update_subcloud.assert_called_once_with(
            mock.ANY,
            mock.ANY,
            management_state=consts.MANAGEMENT_MANAGED,
            description=None,
            location=None,
            group_id=None,
            data_install=None,
            force=True)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_reconfig_payload')
    def test_reconfigure_subcloud(self, mock_get_reconfig_payload,
                                  mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        fake_password = (base64.b64encode('testpass'.encode("utf-8"))).decode('ascii')
        data = {'sysadmin_password': fake_password}

        mock_rpc_client().reconfigure_subcloud.return_value = True
        mock_get_reconfig_payload.return_value = data

        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id) +
                                       '/reconfigure',
                                       headers=FAKE_HEADERS,
                                       params=data)
        mock_rpc_client().reconfigure_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            mock.ANY)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_reconfig_payload')
    def test_reconfigure_subcloud_no_body(self, mock_get_reconfig_payload,
                                          mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        # Pass an empty request body
        data = {}
        mock_get_reconfig_payload.return_value = data
        mock_rpc_client().reconfigure_subcloud.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/reconfigure',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_reconfig_payload')
    def test_reconfigure_subcloud_bad_password(self, mock_get_reconfig_payload,
                                               mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        # Pass a sysadmin_password which is not base64 encoded
        data = {'sysadmin_password': 'not_base64'}
        mock_get_reconfig_payload.return_value = data
        mock_rpc_client().reconfigure_subcloud.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/reconfigure',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_reconfig_payload')
    def test_reconfigure_invalid_deploy_status(self,
                                               mock_get_reconfig_payload,
                                               mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx,
            deploy_status=consts.DEPLOY_STATE_BOOTSTRAP_FAILED)
        fake_password = base64.b64encode('testpass'.encode("utf-8")).decode("utf-8")
        data = {'sysadmin_password': fake_password}
        mock_get_reconfig_payload.return_value = data
        mock_rpc_client().reconfigure_subcloud.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/reconfigure',
                              headers=FAKE_HEADERS, params=data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(rpc_client, 'SubcloudStateClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_updatestatus_payload')
    def test_subcloud_updatestatus(self, mock_get_updatestatus_payload,
                                   mock_rpc_state_client, _):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'endpoint': 'dc-cert', 'status': 'in-sync'}
        mock_get_updatestatus_payload.return_value = data

        mock_rpc_state_client().update_subcloud_endpoint_status.return_value = True
        response = self.app.patch_json(
            FAKE_URL + '/' + str(subcloud.id) + '/update_status',
            data, headers=FAKE_HEADERS)

        mock_rpc_state_client().update_subcloud_endpoint_status.assert_called_once_with(
            mock.ANY,
            subcloud.name,
            'dc-cert',
            'in-sync')

        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_updatestatus_payload')
    def test_subcloud_updatestatus_invalid_endpoint(
            self, mock_get_updatestatus_payload,
            mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'endpoint': 'any-other-endpoint', 'status': 'in-sync'}
        mock_get_updatestatus_payload.return_value = data

        mock_rpc_client().update_subcloud_endpoint_status.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/update_status',
                              headers=FAKE_HEADERS, params=data)
        mock_rpc_client().update_subcloud_endpoint_status.assert_not_called()

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_updatestatus_payload')
    def test_subcloud_updatestatus_invalid_status(
            self, mock_get_updatestatus_payload,
            mock_rpc_client):
        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        data = {'endpoint': 'dc-cert', 'status': 'not-sure'}
        mock_get_updatestatus_payload.return_value = data

        mock_rpc_client().update_subcloud_endpoint_status.return_value = True

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/update_status',
                              headers=FAKE_HEADERS, params=data)
        mock_rpc_client().update_subcloud_endpoint_status.assert_not_called()

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_config_file_path(self, mock_rpc_client):
        sc = subclouds.SubcloudsController()
        bootstrap_file = sc._get_config_file_path("subcloud1")
        install_values = sc._get_config_file_path("subcloud1", "install_values")
        deploy_config = sc._get_config_file_path("subcloud1", consts.DEPLOY_CONFIG)
        self.assertEqual(bootstrap_file, "/opt/dc/ansible/subcloud1.yml")
        self.assertEqual(install_values, "/opt/dc/ansible/subcloud1/install_values.yml")
        self.assertEqual(deploy_config, "/opt/dc/ansible/subcloud1_deploy_config.yml")

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_format_ip_address(self, mock_rpc_client):
        sc = subclouds.SubcloudsController()
        fake_payload = dict()
        good_values = {
            '10.10.10.3': '10.10.10.3',
            '2620:10a:a001:a103::1135': '2620:10a:a001:a103::1135',
            '2620:10A:A001:A103::1135': '2620:10a:a001:a103::1135',      # with upper case letters
            '2620:010a:a001:a103::1135': '2620:10a:a001:a103::1135',     # with leading zeros
            '2620:10a:a001:a103:0000::1135': '2620:10a:a001:a103::1135'  # with a string of zeros
            }

        for k, v in good_values.items():
            fake_payload.update({'bootstrap-address': k})
            sc._format_ip_address(fake_payload)
            self.assertEqual(fake_payload['bootstrap-address'], v)

        fake_payload[subclouds.INSTALL_VALUES] = dict()
        for k, v in good_values.items():
            fake_payload[subclouds.INSTALL_VALUES].update({'bmc_address': k})
            sc._format_ip_address(fake_payload)
            self.assertEqual(fake_payload[subclouds.INSTALL_VALUES]['bmc_address'], v)

        fake_payload.update({'othervalues1': 'othervalues1'})
        fake_payload[subclouds.INSTALL_VALUES].update({'othervalues2': 'othervalues2'})
        sc._format_ip_address(fake_payload)
        self.assertEqual(fake_payload['othervalues1'], 'othervalues1')
        self.assertEqual(fake_payload[subclouds.INSTALL_VALUES]['othervalues2'], 'othervalues2')

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(keyring, 'get_password')
    def test_get_subcloud_db_install_values(
        self, mock_keyring, mock_rpc_client):
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        bmc_password = {'bmc_password': encoded_password}
        install_data.update(bmc_password)
        test_subcloud = copy.copy(FAKE_SUBCLOUD_DATA)
        subcloud_info = Subcloud(test_subcloud, False)
        subcloud_info.data_install = json.dumps(install_data)

        sc = subclouds.SubcloudsController()
        actual_result = sc._get_subcloud_db_install_values(subcloud_info)
        actual_result.update({
            'admin_password': 'adminpass'
        })
        install_data.update({
            'ansible_become_pass': consts.TEMP_SYSADMIN_PASSWORD,
            'ansible_ssh_pass': consts.TEMP_SYSADMIN_PASSWORD,
            'admin_password': 'adminpass'
        })
        self.assertEqual(
            json.loads(json.dumps(install_data)),
            json.loads(json.dumps(actual_result)))

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(keyring, 'get_password')
    def test_get_subcloud_db_install_values_without_bmc_password(
        self, mock_keyring, mock_rpc_client):
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        subcloud = fake_subcloud.create_fake_subcloud(
            self.ctx, data_install=json.dumps(install_data))

        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/reinstall',
                              headers=FAKE_HEADERS)

    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_subcloud_db_install_values')
    @mock.patch.object(subclouds.SubcloudsController, '_validate_oam_network_config')
    @mock.patch.object(subclouds.SubcloudsController, '_get_request_data')
    def test_reinstall_subcloud(
        self, mock_get_request_data, mock_validate_oam_network_config,
        mock_get_subcloud_db_install_values, mock_rpc_client,
        mock_get_vault_load_files):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        reinstall_data = copy.copy(FAKE_SUBCLOUD_BOOTSTRAP_PAYLOAD)
        mock_get_request_data.return_value = reinstall_data

        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        bmc_password = {'bmc_password': encoded_password}
        install_data.update(bmc_password)
        mock_get_subcloud_db_install_values.return_value = install_data

        mock_rpc_client().reinstall_subcloud.return_value = True
        mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')

        response = self.app.patch_json(
            FAKE_URL + '/' + str(subcloud.id) + '/reinstall',
            headers=FAKE_HEADERS, params=reinstall_data)

        mock_validate_oam_network_config.assert_called_once()
        mock_rpc_client().reinstall_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            mock.ANY)
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_subcloud_db_install_values')
    @mock.patch.object(subclouds.SubcloudsController, '_validate_oam_network_config')
    @mock.patch.object(subclouds.SubcloudsController, '_get_request_data')
    def test_reinstall_subcloud_no_body(
        self, mock_get_request_data, mock_validate_oam_network_config,
        mock_get_subcloud_db_install_values, mock_rpc_client,
        mock_get_vault_load_files):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        mock_get_request_data.return_value = {}
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        bmc_password = {'bmc_password': encoded_password}
        install_data.update(bmc_password)

        mock_validate_oam_network_config.assert_not_called()
        mock_get_subcloud_db_install_values.return_value = install_data
        mock_rpc_client().reinstall_subcloud.return_value = True
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/reinstall',
                              headers=FAKE_HEADERS, params={})

    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_subcloud_db_install_values')
    @mock.patch.object(subclouds.SubcloudsController, '_validate_oam_network_config')
    @mock.patch.object(subclouds.SubcloudsController, '_get_request_data')
    def test_reinstall_online_subcloud(
        self, mock_get_request_data, mock_validate_oam_network_config,
        mock_get_subcloud_db_install_values, mock_rpc_client,
        mock_get_vault_load_files):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               availability_status=consts.AVAILABILITY_ONLINE)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        reinstall_data = copy.copy(FAKE_SUBCLOUD_BOOTSTRAP_PAYLOAD)
        mock_get_request_data.return_value = reinstall_data
        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        bmc_password = {'bmc_password': encoded_password}
        install_data.update(bmc_password)

        mock_validate_oam_network_config.assert_not_called()
        mock_get_subcloud_db_install_values.return_value = install_data
        mock_rpc_client().reinstall_subcloud.return_value = True
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/reinstall',
                              headers=FAKE_HEADERS, params={})

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_subcloud_db_install_values')
    @mock.patch.object(subclouds.SubcloudsController, '_get_request_data')
    def test_reinstall_subcloud_missing_required_value(
        self, mock_get_request_data, mock_get_subcloud_db_install_values,
        mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)

        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        bmc_password = {'bmc_password': encoded_password}
        install_data.update(bmc_password)
        mock_get_subcloud_db_install_values.return_value = install_data
        mock_rpc_client().reinstall_subcloud.return_value = True

        for k in ['name', 'system_mode', 'external_oam_subnet',
                  'external_oam_gateway_address', 'external_oam_floating_address',
                  'sysadmin_password']:
            reinstall_data = copy.copy(FAKE_SUBCLOUD_BOOTSTRAP_PAYLOAD)
            del reinstall_data[k]
            mock_get_request_data.return_value = reinstall_data
            six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                                  self.app.patch_json, FAKE_URL + '/' +
                                  str(subcloud.id) + '/reinstall',
                                  headers=FAKE_HEADERS, params=reinstall_data)

    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_subcloud_db_install_values')
    @mock.patch.object(subclouds.SubcloudsController, '_validate_oam_network_config')
    @mock.patch.object(subclouds.SubcloudsController, '_get_request_data')
    def test_reinstall_subcloud_missing_stored_value(
        self, mock_get_request_data, mock_validate_oam_network_config,
        mock_get_subcloud_db_install_values, mock_rpc_client,
        mock_get_vault_load_files):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)

        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        bmc_password = {'bmc_password': encoded_password}
        install_data.update(bmc_password)
        mock_get_subcloud_db_install_values.return_value = install_data

        mock_rpc_client().reinstall_subcloud.return_value = True
        mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')

        for k in ['management_subnet', 'management_start_address', 'management_end_address',
                  'management_gateway_address', 'systemcontroller_gateway_address']:
            reinstall_data = copy.copy(FAKE_SUBCLOUD_BOOTSTRAP_PAYLOAD)
            del reinstall_data[k]
            mock_get_request_data.return_value = reinstall_data
            response = self.app.patch_json(
                FAKE_URL + '/' + str(subcloud.id) + '/reinstall',
                headers=FAKE_HEADERS, params=reinstall_data)
            self.assertEqual(response.status_int, 200)

    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_subcloud_db_install_values')
    @mock.patch.object(subclouds.SubcloudsController, '_validate_subcloud_config')
    @mock.patch.object(subclouds.SubcloudsController, '_get_request_data')
    def test_reinstall_subcloud_stored_value_not_match(
        self, mock_get_request_data, mock_validate_subcloud_config,
        mock_get_subcloud_db_install_values, mock_rpc_client,
        mock_get_vault_load_files):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)

        encoded_password = base64.b64encode(
            'bmc_password'.encode("utf-8")).decode('utf-8')
        bmc_password = {'bmc_password': encoded_password}
        install_data.update(bmc_password)
        mock_get_subcloud_db_install_values.return_value = install_data

        mock_rpc_client().reinstall_subcloud.return_value = True
        mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')

        for k in ['management_subnet', 'management_start_address', 'management_end_address',
                  'management_gateway_address', 'systemcontroller_gateway_address']:
            reinstall_data = copy.copy(FAKE_SUBCLOUD_BOOTSTRAP_PAYLOAD)
            reinstall_data[k] = 'wrong_value'
            mock_get_request_data.return_value = reinstall_data
            six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                                  self.app.patch_json, FAKE_URL + '/' +
                                  str(subcloud.id) + '/reinstall',
                                  headers=FAKE_HEADERS, params=reinstall_data)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_restore_payload')
    def test_restore_subcloud_no_body(self, mock_get_restore_payload,
                                      mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        restore_payload = {}

        mock_rpc_client().restore_subcloud.return_value = True
        mock_get_restore_payload.return_value = restore_payload
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/restore',
                              headers=FAKE_HEADERS, params=restore_payload)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_restore_subcloud_missing_restore_values(self, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        restore_payload = copy.copy(self.FAKE_RESTORE_PAYLOAD)
        del restore_payload['restore_values']

        mock_rpc_client().restore_subcloud.return_value = True
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/restore',
                              headers=FAKE_HEADERS, params=restore_payload)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_restore_payload')
    def test_restore_subcloud_in_managed_state(self, mock_get_restore_payload,
                                               mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               management_state=consts.MANAGEMENT_MANAGED)
        restore_payload = copy.copy(self.FAKE_RESTORE_PAYLOAD)

        mock_rpc_client().restore_subcloud.return_value = True
        mock_get_restore_payload.return_value = restore_payload
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/restore',
                              headers=FAKE_HEADERS, params=restore_payload)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_restore_payload')
    def test_restore_subcloud_undergoing_bootstrap(self, mock_get_restore_payload,
                                                   mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        db_api.subcloud_update(self.ctx,
                               subcloud.id,
                               deploy_status=consts.DEPLOY_STATE_BOOTSTRAPPING)
        restore_payload = copy.copy(self.FAKE_RESTORE_PAYLOAD)

        mock_rpc_client().restore_subcloud.return_value = True
        mock_get_restore_payload.return_value = restore_payload
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/restore',
                              headers=FAKE_HEADERS, params=restore_payload)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_restore_payload')
    def test_restore_subcloud_bad_sysadmin_password(self, mock_get_restore_payload,
                                                    mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        restore_payload = copy.copy(self.FAKE_RESTORE_PAYLOAD)
        restore_payload['sysadmin_password'] = 'not_base64_encoded'

        mock_rpc_client().restore_subcloud.return_value = True
        mock_get_restore_payload.return_value = restore_payload
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/restore',
                              headers=FAKE_HEADERS, params=restore_payload)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_restore_payload')
    def test_restore_subcloud_without_remote_install(self, mock_get_restore_payload,
                                                     mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        restore_payload = copy.copy(self.FAKE_RESTORE_PAYLOAD)
        del restore_payload['with_install']

        mock_rpc_client().restore_subcloud.return_value = True
        mock_get_restore_payload.return_value = restore_payload
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/restore',
                              headers=FAKE_HEADERS, params=restore_payload)

    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_restore_payload')
    def test_restore_subcloud_missing_mandatory_restore_parameter(
        self, mock_get_restore_payload, mock_rpc_client):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        restore_payload = copy.copy(self.FAKE_RESTORE_PAYLOAD)
        restore_payload['restore_values'] = {'on_box_data': 'false'}

        mock_rpc_client().restore_subcloud.return_value = True
        mock_get_restore_payload.return_value = restore_payload
        six.assertRaisesRegex(self, webtest.app.AppError, "400 *",
                              self.app.patch_json, FAKE_URL + '/' +
                              str(subcloud.id) + '/restore',
                              headers=FAKE_HEADERS, params=restore_payload)

    @mock.patch.object(cutils, 'get_vault_load_files')
    @mock.patch.object(rpc_client, 'ManagerClient')
    @mock.patch.object(subclouds.SubcloudsController, '_get_subcloud_db_install_values')
    @mock.patch.object(subclouds.SubcloudsController, '_get_restore_payload')
    def test_restore_subcloud(self, mock_get_restore_payload,
                              mock_get_subcloud_db_install_values,
                              mock_rpc_client, mock_get_vault_load_files):

        subcloud = fake_subcloud.create_fake_subcloud(self.ctx)
        install_data = copy.copy(FAKE_SUBCLOUD_INSTALL_VALUES)
        restore_payload = copy.copy(self.FAKE_RESTORE_PAYLOAD)

        mock_get_subcloud_db_install_values.return_value = install_data
        mock_rpc_client().restore_subcloud.return_value = True
        mock_get_restore_payload.return_value = restore_payload
        mock_get_vault_load_files.return_value = ('iso_file_path', 'sig_file_path')
        response = self.app.patch_json(FAKE_URL + '/' + str(subcloud.id) +
                                       '/restore',
                                       headers=FAKE_HEADERS,
                                       params=restore_payload)
        mock_rpc_client().restore_subcloud.assert_called_once_with(
            mock.ANY,
            subcloud.id,
            mock.ANY)
        self.assertEqual(response.status_int, 200)
