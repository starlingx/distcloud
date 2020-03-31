# Copyright 2015 Huawei Technologies Co., Ltd.
# All Rights Reserved
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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from mock import patch

from oslo_config import cfg

from dccommon import endpoint_cache
from dccommon.tests import base
from dccommon.tests import utils

FAKE_REGION = 'fake_region'
FAKE_SERVICE = 'fake_service'
FAKE_URL = 'fake_url'

FAKE_REGION_2 = 'fake_region_2'
FAKE_NOVA_SERVICE = 'fake_nova_service'
FAKE_NEUTRON_SERVICE = 'fake_neutron_service'
FAKE_CINDER_SERVICE = 'fake_cinder_service'
FAKE_NOVA_URL_1 = 'fake_url_nova_1'
FAKE_NOVA_URL_2 = 'fake_url_nova_2'
FAKE_CINDER_URL_2 = 'fake_url_cinder_2'
FAKE_NEUTRON_URL_1 = 'fake_url_neutron_1'


class EndpointCacheTest(base.DCCommonTestCase):
    def setUp(self):
        super(EndpointCacheTest, self).setUp()
        auth_uri_opts = [
            cfg.StrOpt('auth_uri',
                       default="fake_auth_uri")]
        cfg.CONF.register_opts(auth_uri_opts, 'cache')

    @patch.object(endpoint_cache.EndpointCache, '_initialize_keystone_client')
    @patch.object(endpoint_cache.EndpointCache, '_get_endpoint_from_keystone')
    def test_get_endpoint(self, mock_method, mock_init):
        endpoint_dict = utils.create_endpoint_dict(base.KEYSTONE_ENDPOINT_0)
        mock_method.return_value = {endpoint_dict['region_id']: {
            endpoint_dict['service_id']: endpoint_dict['url']}}
        mock_init.return_value = None
        cache = endpoint_cache.EndpointCache()
        self.assertEqual(cache.get_endpoint(endpoint_dict['region_id'],
                                            endpoint_dict['service_id']),
                         endpoint_dict['url'])

    @patch.object(endpoint_cache.EndpointCache, '_initialize_keystone_client')
    @patch.object(endpoint_cache.EndpointCache, '_get_endpoint_from_keystone')
    def test_get_endpoint_not_found(self, mock_method, mock_init):
        endpoint_dict = utils.create_endpoint_dict(base.KEYSTONE_ENDPOINT_0)
        mock_method.return_value = {endpoint_dict['region_id']: {
            endpoint_dict['service_id']: endpoint_dict['url']}}
        mock_init.return_value = None
        cache = endpoint_cache.EndpointCache()
        self.assertEqual(cache.get_endpoint('another_fake_region',
                                            endpoint_dict['service_id']), '')
        self.assertEqual(cache.get_endpoint(endpoint_dict['region_id'],
                                            'another_fake_service'), '')

    @patch.object(endpoint_cache.EndpointCache, '_initialize_keystone_client')
    @patch.object(endpoint_cache.EndpointCache, '_get_endpoint_from_keystone')
    def test_get_endpoint_retry(self, mock_method, mock_init):
        endpoint_dict = utils.create_endpoint_dict(base.KEYSTONE_ENDPOINT_0)
        mock_init.return_value = None
        cache = endpoint_cache.EndpointCache()
        mock_method.return_value = {'another_region': {
            endpoint_dict['service_id']: 'another_fake_url'}}
        self.assertEqual(cache.get_endpoint('another_region',
                                            endpoint_dict['service_id']),
                         'another_fake_url')

    @patch.object(endpoint_cache.EndpointCache, '_initialize_keystone_client')
    @patch.object(endpoint_cache.EndpointCache, '_get_endpoint_from_keystone')
    def test_update_endpoint(self, mock_method, mock_init):
        endpoint_dict = utils.create_endpoint_dict(base.KEYSTONE_ENDPOINT_0)
        mock_method.return_value = {endpoint_dict['region_id']: {
            endpoint_dict['service_id']: endpoint_dict['url']}}
        mock_init.return_value = None
        cache = endpoint_cache.EndpointCache()
        mock_method.return_value = {endpoint_dict['region_id']: {
            endpoint_dict['service_id']: 'another_fake_url'}}
        self.assertEqual(cache.get_endpoint(endpoint_dict['region_id'],
                                            endpoint_dict['service_id']),
                         endpoint_dict['url'])
        cache.update_endpoints()
        self.assertEqual(cache.get_endpoint(endpoint_dict['region_id'],
                                            endpoint_dict['service_id']),
                         'another_fake_url')

    @patch.object(endpoint_cache.EndpointCache, '_initialize_keystone_client')
    @patch.object(endpoint_cache.EndpointCache, '_get_endpoint_from_keystone')
    def test_get_all_regions(self, mock_method, mock_init):
        mock_method.return_value = {
            FAKE_REGION: {FAKE_NOVA_SERVICE: FAKE_NOVA_URL_1,
                          FAKE_NEUTRON_SERVICE: FAKE_NEUTRON_URL_1},
            FAKE_REGION_2: {FAKE_NOVA_SERVICE: FAKE_NOVA_URL_2,
                            FAKE_CINDER_SERVICE: FAKE_CINDER_URL_2}
            }
        mock_init.return_value = None
        cache = endpoint_cache.EndpointCache()
        region_list = cache.get_all_regions()
        self.assertIn(FAKE_REGION, region_list)
        self.assertIn(FAKE_REGION_2, region_list)
