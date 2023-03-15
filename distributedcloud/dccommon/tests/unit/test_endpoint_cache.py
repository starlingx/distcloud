# Copyright 2015 Huawei Technologies Co., Ltd.
# Copyright (c) 2017-2023 Wind River Systems, Inc.
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

import collections
import copy
import mock
from mock import patch

from oslo_config import cfg

from dccommon import endpoint_cache
from dccommon.tests import base
from keystoneclient.v3 import services
from keystoneclient.v3 import tokens

FAKE_REGIONONE_SYSINV_ENDPOINT = "http://[2620:10a:a001:a114::d00]:6385/v1"
FAKE_REGIONONE_KEYSTONE_ENDPOINT = "http://[2620:10a:a001:a114::d00]:5000/v3"
FAKE_SUBCLOUD1_SYSINV_ENDPOINT = "https://[2620:10a:a001:ac05::7d02]:6386/v1"
FAKE_SUBCLOUD1_KEYSTONE_ENDPOINT = "https://[2620:10a:a001:ac05::7d02]:5001/v3"

CENTRAL_REGION = "RegionOne"
SUBCLOUD1_REGION = "subcloud1"

FAKE_MASTER_SERVICE_ENDPOINT_MAP = {
    CENTRAL_REGION: {"sysinv": FAKE_REGIONONE_SYSINV_ENDPOINT,
                     "keystone": FAKE_REGIONONE_KEYSTONE_ENDPOINT},
    SUBCLOUD1_REGION: {"sysinv": FAKE_SUBCLOUD1_SYSINV_ENDPOINT,
                       "keystone": FAKE_SUBCLOUD1_KEYSTONE_ENDPOINT}
}

FAKE_SERVICE_ENDPOINT_MAP = {"sysinv": FAKE_REGIONONE_SYSINV_ENDPOINT,
                             "keystone": FAKE_REGIONONE_KEYSTONE_ENDPOINT}


class FakeKeystoneClient(object):
    def __init__(self):
        self.session = mock.MagicMock()
        self.tokens = mock.MagicMock()


class FakeService(object):
    def __init__(self, id, name, type, enabled):
        self.id = id
        self.name = name
        self.type = type
        self.enabled = enabled

FAKE_SERVICES_LIST = [FakeService(1, "keystone", "identity", True),
                      FakeService(2, "sysinv", "platform", True),
                      FakeService(3, "patching", "patching", True),
                      FakeService(4, "barbican", "key-manager", True),
                      FakeService(5, "vim", "nfv", True),
                      FakeService(6, "dcmanager", "dcmanager", True),
                      FakeService(7, "dcorch", "dcorch", True)]


class EndpointCacheTest(base.DCCommonTestCase):
    def setUp(self):
        super(EndpointCacheTest, self).setUp()
        auth_uri_opts = [
            cfg.StrOpt('auth_uri',
                       default="fake_auth_uri"),
            cfg.StrOpt('username',
                       default="fake_user"),
            cfg.StrOpt('password',
                       default="fake_password"),
            cfg.StrOpt('project_name',
                       default="fake_project_name"),
            cfg.StrOpt('user_domain_name',
                       default="fake_user_domain_name"),
            cfg.StrOpt('project_domain_name',
                       default="fake_project_domain_name")]
        cfg.CONF.register_opts(auth_uri_opts, 'endpoint_cache')

        # Mock the token validator (which is confusing so here is the info)
        # endpoint_cache.py has an import:
        #    from dccommon.utils import is_token_expiring_soon
        # so to patch where that function is called we use this syntax:
        #    patch.object(endpoint_cache, 'is_token_expiring_soon')
        # instead of:
        #    patch.object(dccommon.utils, 'is_token_expiring_soon')
        p = mock.patch.object(endpoint_cache, 'is_token_expiring_soon')
        self.mock_is_token_expiring_soon = p.start()
        self.mock_is_token_expiring_soon.return_value = True
        self.addCleanup(p.stop)

    def tearDown(self):
        super(EndpointCacheTest, self).tearDown()
        # purge the cache values (except the lock)
        endpoint_cache.EndpointCache.plugin_loader = None
        endpoint_cache.EndpointCache.master_keystone_client = None
        endpoint_cache.EndpointCache.master_token = {}
        endpoint_cache.EndpointCache.master_services_list = None
        endpoint_cache.EndpointCache.master_service_endpoint_map = \
            collections.defaultdict(dict)

    @patch.object(endpoint_cache.EndpointCache, 'get_admin_session')
    @patch.object(endpoint_cache.EndpointCache,
                  'get_cached_master_keystone_client_and_region_endpoint_map')
    def test_get_endpoint(self, mock_get_cached_data, mock_get_admin_session):
        mock_get_cached_data.return_value = (FakeKeystoneClient(), FAKE_SERVICE_ENDPOINT_MAP)
        cache = endpoint_cache.EndpointCache("RegionOne", None)
        endpoint = cache.get_endpoint("sysinv")
        self.assertEqual(endpoint, FAKE_REGIONONE_SYSINV_ENDPOINT)

    @patch.object(endpoint_cache.EndpointCache, 'get_admin_session')
    @patch.object(tokens.TokenManager, 'validate')
    @patch.object(endpoint_cache.EndpointCache,
                  '_generate_master_service_endpoint_map')
    def test_get_all_regions(self, mock_generate_cached_data, mock_tokens_validate,
                             mock_admin_session):
        mock_generate_cached_data.return_value = FAKE_MASTER_SERVICE_ENDPOINT_MAP
        cache = endpoint_cache.EndpointCache("RegionOne", None)
        region_list = cache.get_all_regions()
        self.assertIn(CENTRAL_REGION, region_list)
        self.assertIn(SUBCLOUD1_REGION, region_list)

    @patch.object(endpoint_cache.EndpointCache, 'get_admin_session')
    @patch.object(tokens.TokenManager, 'validate')
    @patch.object(services.ServiceManager, 'list')
    @patch.object(endpoint_cache.EndpointCache,
                  '_generate_master_service_endpoint_map')
    def test_get_services_list(self, mock_generate_cached_data, mock_services_list,
                               mock_tokens_validate, mock_admin_session):
        mock_services_list.return_value = FAKE_SERVICES_LIST
        mock_generate_cached_data.return_value = FAKE_MASTER_SERVICE_ENDPOINT_MAP
        endpoint_cache.EndpointCache("RegionOne", None)
        services_list = endpoint_cache.EndpointCache.get_master_services_list()
        self.assertEqual(FAKE_SERVICES_LIST, services_list)

    @patch.object(endpoint_cache.EndpointCache, 'get_admin_session')
    @patch.object(tokens.TokenManager, 'validate')
    @patch.object(endpoint_cache.EndpointCache,
                  '_generate_master_service_endpoint_map')
    def test_update_master_service_endpoint_region(
            self, mock_generate_cached_data, mock_tokens_validate,
            mock_admin_session):
        mock_generate_cached_data.return_value = (
            copy.deepcopy(FAKE_MASTER_SERVICE_ENDPOINT_MAP))
        region_name = SUBCLOUD1_REGION
        new_endpoints = {
            'sysinv': 'https://[fake_ip]:6386/v1',
            'keystone': 'https://[fake_ip]:5001/v3'
        }
        cache = endpoint_cache.EndpointCache("RegionOne", None)
        self.assertEqual(
            endpoint_cache.EndpointCache.master_service_endpoint_map,
            FAKE_MASTER_SERVICE_ENDPOINT_MAP
        )
        cache.update_master_service_endpoint_region(region_name, new_endpoints)
        self.assertNotEqual(
            endpoint_cache.EndpointCache.master_service_endpoint_map,
            FAKE_MASTER_SERVICE_ENDPOINT_MAP
        )
