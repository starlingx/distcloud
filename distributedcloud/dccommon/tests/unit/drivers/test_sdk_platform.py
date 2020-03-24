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
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import mock

from dccommon.drivers.openstack import sdk_platform as sdk
from dccommon import exceptions
from dccommon.tests import base


class TestOpenStackDriver(base.DCCommonTestCase):

    @mock.patch.object(sdk, 'KeystoneClient')
    @mock.patch.object(sdk.OpenStackDriver, '_is_token_valid')
    def test_init(self, mock_keystone_client, mock_is_token_valid):
        region_name = 'subcloud1'

        os_client = sdk.OpenStackDriver(region_name, region_clients=None)
        self.assertIsNotNone(os_client)
        new_keystone_client = os_client.keystone_client
        self.assertIsNotNone(new_keystone_client)
        mock_is_token_valid(region_name).return_value = True
        cached_keystone_client = sdk.OpenStackDriver(
            region_name, region_clients=None).keystone_client
        self.assertEqual(new_keystone_client, cached_keystone_client)

        self.assertRaises(exceptions.InvalidInputError,
                          sdk.OpenStackDriver,
                          region_name, region_clients=['fake_client'])
