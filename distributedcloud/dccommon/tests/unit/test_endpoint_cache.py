# Copyright 2015 Huawei Technologies Co., Ltd.
# Copyright (c) 2017-2024 Wind River Systems, Inc.
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
import threading
import time

from keystoneauth1 import access
from keystoneclient.v3 import services
from keystoneclient.v3 import tokens
import mock
import netaddr
from oslo_config import cfg

from dccommon import endpoint_cache
from dccommon.tests import base
from dccommon import utils

FAKE_REGIONONE_SYSINV_ENDPOINT = "http://[2620:10a:a001:a114::d00]:6385/v1"
FAKE_REGIONONE_KEYSTONE_ENDPOINT = "http://[2620:10a:a001:a114::d00]:5000/v3"
FAKE_SUBCLOUD1_SYSINV_ENDPOINT = "https://[2620:10a:a001:ac05::7d02]:6386/v1"
FAKE_SUBCLOUD1_KEYSTONE_ENDPOINT = "https://[2620:10a:a001:ac05::7d02]:5001/v3"

CENTRAL_REGION = "RegionOne"
SUBCLOUD1_REGION = "subcloud1"

FAKE_MASTER_SERVICE_ENDPOINT_MAP = {
    CENTRAL_REGION: {
        "sysinv": FAKE_REGIONONE_SYSINV_ENDPOINT,
        "keystone": FAKE_REGIONONE_KEYSTONE_ENDPOINT,
    },
    SUBCLOUD1_REGION: {
        "sysinv": FAKE_SUBCLOUD1_SYSINV_ENDPOINT,
        "keystone": FAKE_SUBCLOUD1_KEYSTONE_ENDPOINT,
    },
}

FAKE_SERVICE_ENDPOINT_MAP = {
    "sysinv": FAKE_REGIONONE_SYSINV_ENDPOINT,
    "keystone": FAKE_REGIONONE_KEYSTONE_ENDPOINT,
}


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


FAKE_SERVICES_LIST = [
    FakeService(1, "keystone", "identity", True),
    FakeService(2, "sysinv", "platform", True),
    FakeService(3, "patching", "patching", True),
    FakeService(4, "barbican", "key-manager", True),
    FakeService(5, "vim", "nfv", True),
    FakeService(6, "dcmanager", "dcmanager", True),
    FakeService(7, "dcorch", "dcorch", True),
]

FAKE_AUTH_URL = "http://fake.auth/url"


class EndpointCacheTest(base.DCCommonTestCase):
    def setUp(self):
        super().setUp()
        auth_uri_opts = [
            cfg.StrOpt("auth_uri", default="fake_auth_uri"),
            cfg.StrOpt("username", default="fake_user"),
            cfg.StrOpt("password", default="fake_password"),
            cfg.StrOpt("project_name", default="fake_project_name"),
            cfg.StrOpt("user_domain_name", default="fake_user_domain_name"),
            cfg.StrOpt("project_domain_name", default="fake_project_domain_name"),
        ]
        cfg.CONF.register_opts(auth_uri_opts, "endpoint_cache")

        p = mock.patch.object(utils, "is_token_expiring_soon")
        self.mock_is_token_expiring_soon = p.start()
        self.mock_is_token_expiring_soon.return_value = True
        self.addCleanup(p.stop)

        # Mock the get_admin_session method
        p = mock.patch.object(endpoint_cache.EndpointCache, "get_admin_session")
        self.mock_get_admin_session = p.start()
        self.addCleanup(p.stop)

    def tearDown(self):
        super(EndpointCacheTest, self).tearDown()
        # purge the cache values (except the lock)
        endpoint_cache.EndpointCache.plugin_loader = None
        endpoint_cache.EndpointCache.master_keystone_client = None
        endpoint_cache.EndpointCache.master_token = {}
        endpoint_cache.EndpointCache.master_services_list = None
        endpoint_cache.EndpointCache.master_service_endpoint_map = (
            collections.defaultdict(dict)
        )

    @mock.patch.object(
        endpoint_cache.EndpointCache,
        "get_cached_master_keystone_client_and_region_endpoint_map",
    )
    def test_get_endpoint(self, mock_get_cached_data):
        mock_get_cached_data.return_value = (
            FakeKeystoneClient(),
            FAKE_SERVICE_ENDPOINT_MAP,
        )
        cache = endpoint_cache.EndpointCache("RegionOne", None)
        endpoint = cache.get_endpoint("sysinv")
        self.assertEqual(endpoint, FAKE_REGIONONE_SYSINV_ENDPOINT)

    @mock.patch.object(tokens.TokenManager, "validate")
    @mock.patch.object(
        endpoint_cache.EndpointCache, "_generate_master_service_endpoint_map"
    )
    def test_get_all_regions(self, mock_generate_cached_data, mock_tokens_validate):
        mock_generate_cached_data.return_value = FAKE_MASTER_SERVICE_ENDPOINT_MAP
        cache = endpoint_cache.EndpointCache("RegionOne", None)
        region_list = cache.get_all_regions()
        self.assertIn(CENTRAL_REGION, region_list)
        self.assertIn(SUBCLOUD1_REGION, region_list)

    @mock.patch.object(tokens.TokenManager, "validate")
    @mock.patch.object(services.ServiceManager, "list")
    @mock.patch.object(
        endpoint_cache.EndpointCache, "_generate_master_service_endpoint_map"
    )
    def test_get_services_list(
        self, mock_generate_cached_data, mock_services_list, mock_tokens_validate
    ):
        mock_services_list.return_value = FAKE_SERVICES_LIST
        mock_generate_cached_data.return_value = FAKE_MASTER_SERVICE_ENDPOINT_MAP
        endpoint_cache.EndpointCache("RegionOne", None)
        services_list = endpoint_cache.EndpointCache.master_services_list
        self.assertEqual(FAKE_SERVICES_LIST, services_list)

    @mock.patch.object(tokens.TokenManager, "validate")
    @mock.patch.object(
        endpoint_cache.EndpointCache, "_generate_master_service_endpoint_map"
    )
    def test_update_master_service_endpoint_region(
        self, mock_generate_cached_data, mock_tokens_validate
    ):
        mock_generate_cached_data.return_value = copy.deepcopy(
            FAKE_MASTER_SERVICE_ENDPOINT_MAP
        )
        region_name = SUBCLOUD1_REGION
        new_endpoints = {
            "sysinv": "https://[fake_ip]:6386/v1",
            "keystone": "https://[fake_ip]:5001/v3",
        }
        cache = endpoint_cache.EndpointCache("RegionOne", None)
        self.assertEqual(
            endpoint_cache.EndpointCache.master_service_endpoint_map,
            FAKE_MASTER_SERVICE_ENDPOINT_MAP,
        )
        cache.update_master_service_endpoint_region(region_name, new_endpoints)
        self.assertNotEqual(
            endpoint_cache.EndpointCache.master_service_endpoint_map,
            FAKE_MASTER_SERVICE_ENDPOINT_MAP,
        )

    def _get_expected_endpoints(self, ip: str) -> dict:
        ip_with_brackets = f"[{ip}]" if netaddr.IPAddress(ip).version == 6 else ip
        return {
            "dcagent": f"https://{ip_with_brackets}:8326",
            "fm": f"https://{ip_with_brackets}:18003",
            "keystone": f"https://{ip_with_brackets}:5001/v3",
            "patching": f"https://{ip_with_brackets}:5492",
            "sysinv": f"https://{ip_with_brackets}:6386/v1",
            "usm": f"https://{ip_with_brackets}:5498",
            "vim": f"https://{ip_with_brackets}:4546",
        }

    def test_build_subcloud_endpoint_map_succeeds(self):
        ips = ("192.168.1.1", "2620:10a:a001:ac09::7ce0")
        for ip in ips:
            expected = self._get_expected_endpoints(ip)
            result = utils.build_subcloud_endpoint_map(ip)
            self.assertEqual(expected, result)

    def test_build_subcloud_endpoint_map_fails(self):
        ips = (
            "invalid_ip",
            "192.168.0.0.0",
            "192.168.256.0",
            "2620:10a:a001:ac09::7cg0",
            "2620:10a::ac09::7ce0",
            "",
        )
        for ip in ips:
            self.assertRaises(
                netaddr.AddrFormatError,
                utils.build_subcloud_endpoint_map,
                ip,
            )

    def test_build_subcloud_endpoints_multiple_ips_succeeds(self):
        subcloud_mgmt_ips_dict = [
            {"subcloud1": "192.168.1.1"},
            {"subcloud1": "192.168.1.1", "subcloud2": "192.168.1.2"},
        ]

        for subcloud_mgmt_ips in subcloud_mgmt_ips_dict:
            expected_result = {
                k: self._get_expected_endpoints(v) for k, v in subcloud_mgmt_ips.items()
            }
            self.assertEqual(
                expected_result,
                utils.build_subcloud_endpoints(subcloud_mgmt_ips),
            )

    def test_empty_ip_dict_succeeds(self):
        empty_ips = {}
        expected_endpoints = {}
        actual_endpoints = utils.build_subcloud_endpoints(empty_ips)
        self.assertEqual(expected_endpoints, actual_endpoints)


class TestBoundedFIFOCache(base.DCCommonTestCase):
    def setUp(self):
        # pylint: disable=protected-access
        super().setUp()
        self.cache = endpoint_cache.BoundedFIFOCache()
        self.cache._maxsize = 3  # Set a small max size for testing

    def test_insertion_and_order(self):
        self.cache["a"] = 1
        self.cache["b"] = 2
        self.cache["c"] = 3
        self.assertEqual(list(self.cache.keys()), ["a", "b", "c"])

    def test_max_size_limit(self):
        self.cache["a"] = 1
        self.cache["b"] = 2
        self.cache["c"] = 3
        self.cache["d"] = 4
        self.assertEqual(len(self.cache), 3)
        self.assertEqual(list(self.cache.keys()), ["b", "c", "d"])

    def test_update_existing_key(self):
        self.cache["a"] = 1
        self.cache["b"] = 2
        self.cache["a"] = 3
        self.assertEqual(list(self.cache.keys()), ["b", "a"])
        self.assertEqual(self.cache["a"], 3)


class TestCachedV3Password(base.DCCommonTestCase):
    # pylint: disable=protected-access
    def setUp(self):
        super().setUp()
        self.auth = endpoint_cache.CachedV3Password(auth_url=FAKE_AUTH_URL)
        endpoint_cache.CachedV3Password._CACHE.clear()

        # Set a maxsize value so it doesn't try to read from the config file
        endpoint_cache.CachedV3Password._CACHE._maxsize = 50

        mock_get_auth_ref_object = mock.patch("endpoint_cache.v3.Password.get_auth_ref")
        self.mock_parent_get_auth_ref = mock_get_auth_ref_object.start()
        self.addCleanup(mock_get_auth_ref_object.stop)

    @mock.patch("endpoint_cache.utils.is_token_expiring_soon")
    def test_get_auth_ref_cached(self, mock_is_expiring):
        mock_is_expiring.return_value = False
        mock_session = mock.MagicMock()

        # Simulate a cached token
        cached_data = ({"token": "fake_token"}, "auth_token")
        self.auth._CACHE[FAKE_AUTH_URL] = cached_data

        result = self.auth.get_auth_ref(mock_session)

        self.assertIsInstance(result, access.AccessInfoV3)
        self.assertEqual(result._auth_token, "auth_token")
        # Ensure we didn't call the parent method
        self.mock_parent_get_auth_ref.assert_not_called()

    def test_get_auth_ref_new_token(self):
        mock_session = mock.MagicMock()
        mock_access_info = mock.MagicMock(spec=access.AccessInfoV3)
        mock_access_info._data = {"token": "new_token"}
        mock_access_info._auth_token = "new_auth_token"
        self.mock_parent_get_auth_ref.return_value = mock_access_info

        result = self.auth.get_auth_ref(mock_session)

        self.assertEqual(result, mock_access_info)
        self.mock_parent_get_auth_ref.assert_called_once_with(mock_session)
        self.assertEqual(
            self.auth._CACHE[FAKE_AUTH_URL],
            (mock_access_info._data, mock_access_info._auth_token),
        )

    def test_get_auth_concurrent_access(self):
        auth_obj_list = [
            endpoint_cache.CachedV3Password(auth_url=f"{FAKE_AUTH_URL}/{i}")
            for i in range(1, 51)
        ]
        call_count = 0
        generated_tokens = []

        def mock_get_auth_ref(_, **__):
            nonlocal call_count, generated_tokens
            time.sleep(0.1)  # Simulate network delay
            call_count += 1
            token = f"auth_token_{call_count}"
            generated_tokens.append(token)
            return access.AccessInfoV3({"token": token}, token)

        self.mock_parent_get_auth_ref.side_effect = mock_get_auth_ref

        threads = [
            threading.Thread(target=auth.get_auth_ref, args=(None,))
            for auth in auth_obj_list
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All URLs should have generated their own tokens
        self.assertEqual(len(endpoint_cache.CachedV3Password._CACHE), 50)
        cached_tokens = [v[1] for v in endpoint_cache.CachedV3Password._CACHE.values()]
        self.assertCountEqual(generated_tokens, cached_tokens)
        self.assertEqual(self.mock_parent_get_auth_ref.call_count, 50)

    @mock.patch("endpoint_cache.v3.Password.invalidate")
    def test_invalidate(self, mock_parent_invalidate):
        # Set up a fake cached token
        self.auth._CACHE[FAKE_AUTH_URL] = ({"token": "fake_token"}, "auth_token")

        self.auth.invalidate()

        self.assertNotIn(FAKE_AUTH_URL, self.auth._CACHE)
        mock_parent_invalidate.assert_called_once()
