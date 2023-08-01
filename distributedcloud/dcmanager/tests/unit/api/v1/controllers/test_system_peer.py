# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from six.moves import http_client
import uuid

from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.rpc import client as rpc_client

from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests.unit.api.v1.controllers.mixins import APIMixin
from dcmanager.tests.unit.api.v1.controllers.mixins import DeleteMixin
from dcmanager.tests.unit.api.v1.controllers.mixins import GetMixin
from dcmanager.tests.unit.api.v1.controllers.mixins import PostJSONMixin
from dcmanager.tests.unit.api.v1.controllers.mixins import UpdateMixin
from dcmanager.tests import utils

SAMPLE_SYSTEM_PEER_UUID = str(uuid.uuid4())
SAMPLE_SYSTEM_PEER_NAME = 'SystemPeer1'
SAMPLE_MANAGER_ENDPOINT = 'http://127.0.0.1:5000'
SAMPLE_MANAGER_USERNAME = 'admin'
SAMPLE_MANAGER_PASSWORD = 'password'
SAMPLE_ADMINISTRATIVE_STATE = 'enabled'
SAMPLE_HEARTBEAT_INTERVAL = 10
SAMPLE_HEARTBEAT_FAILURE_THRESHOLD = 3
SAMPLE_HEARTBEAT_FAILURES_POLICY = 'alarm'
SAMPLE_HEARTBEAT_MAINTENANCE_TIMEOUT = 600
SAMPLE_PEER_CONTROLLER_GATEWAY_IP = '128.128.128.1'


class SystemPeerAPIMixin(APIMixin):

    API_PREFIX = '/v1.0/system-peers'
    RESULT_KEY = 'system_peers'
    EXPECTED_FIELDS = ['id',
                       'peer-uuid',
                       'peer-name',
                       'manager-endpoint',
                       'manager-username',
                       'peer-controller-gateway-address',
                       'administrative-state',
                       'heartbeat-interval',
                       'heartbeat-failure-threshold',
                       'heartbeat-failure-policy',
                       'heartbeat-maintenance-timeout',
                       'created-at',
                       'updated-at']

    def setUp(self):
        super(SystemPeerAPIMixin, self).setUp()
        self.fake_rpc_client.some_method = mock.MagicMock()

    def _get_test_system_peer_dict(self, data_type, **kw):
        # id should not be part of the structure
        system_peer = {
            'peer_uuid': kw.get('peer_uuid', SAMPLE_SYSTEM_PEER_UUID),
            'peer_name': kw.get('peer_name', SAMPLE_SYSTEM_PEER_NAME),
            'administrative_state': kw.get('administrative_state',
                                           SAMPLE_ADMINISTRATIVE_STATE),
            'heartbeat_interval': kw.get('heartbeat_interval',
                                         SAMPLE_HEARTBEAT_INTERVAL),
            'heartbeat_failure_threshold': kw.get(
                'heartbeat_failure_threshold', SAMPLE_HEARTBEAT_FAILURE_THRESHOLD),
            'heartbeat_failure_policy': kw.get(
                'heartbeat_failure_policy', SAMPLE_HEARTBEAT_FAILURES_POLICY),
            'heartbeat_maintenance_timeout': kw.get(
                'heartbeat_maintenance_timeout',
                SAMPLE_HEARTBEAT_MAINTENANCE_TIMEOUT)
        }

        if data_type == 'db':
            system_peer['endpoint'] = kw.get('manager_endpoint',
                                             SAMPLE_MANAGER_ENDPOINT)
            system_peer['username'] = kw.get('manager_username',
                                             SAMPLE_MANAGER_USERNAME)
            system_peer['password'] = kw.get('manager_password',
                                             SAMPLE_MANAGER_PASSWORD)
            system_peer['gateway_ip'] = kw.get(
                'peer_controller_gateway_ip', SAMPLE_PEER_CONTROLLER_GATEWAY_IP)
        else:
            system_peer['manager_endpoint'] = kw.get('manager_endpoint',
                                                     SAMPLE_MANAGER_ENDPOINT)
            system_peer['manager_username'] = kw.get('manager_username',
                                                     SAMPLE_MANAGER_USERNAME)
            system_peer['manager_password'] = kw.get('manager_password',
                                                     SAMPLE_MANAGER_PASSWORD)
            system_peer['peer_controller_gateway_address'] = kw.get(
                'peer_controller_gateway_ip', SAMPLE_PEER_CONTROLLER_GATEWAY_IP)
        return system_peer

    def _post_get_test_system_peer(self, **kw):
        post_body = self._get_test_system_peer_dict('dict', **kw)
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
        creation_fields = self._get_test_system_peer_dict('db', **kw)
        return db_api.system_peer_create(context, **creation_fields)

    def get_post_object(self):
        return self._post_get_test_system_peer()

    def get_update_object(self):
        update_object = {
            'peer_controller_gateway_address': '192.168.205.1'
        }
        return update_object


# Combine System Peer API with mixins to test post, get, update and delete
class TestSystemPeerPost(testroot.DCManagerApiTest,
                         SystemPeerAPIMixin, PostJSONMixin):
    def setUp(self):
        super(TestSystemPeerPost, self).setUp()

    def verify_post_failure(self, response):
        # Failures will return text rather than JSON
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_with_numerical_uuid_fails(self, mock_client):
        # A numerical uuid is not permitted. otherwise the 'get' operations
        # which support getting by either name or ID could become confused
        # if a name for one peer was the same as an ID for another.
        ndict = self.get_post_object()
        ndict['peer_uuid'] = '123'
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_with_blank_uuid_fails(self, mock_client):
        # An empty name is not permitted
        ndict = self.get_post_object()
        ndict['peer_uuid'] = ''
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_with_empty_manager_endpoint_fails(self, mock_client):
        # An empty description is considered invalid
        ndict = self.get_post_object()
        ndict['manager_endpoint'] = ''
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_with_wrong_manager_endpoint_fails(self, mock_client):
        # An empty description is considered invalid
        ndict = self.get_post_object()
        ndict['manager_endpoint'] = 'ftp://somepath'
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_with_wrong_peergw_ip_fails(self, mock_client):
        # An empty description is considered invalid
        ndict = self.get_post_object()
        ndict['peer_controller_gateway_address'] = '123'
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_with_bad_administrative_state(self, mock_client):
        # update_apply_type must be either 'enabled' or 'disabled'
        ndict = self.get_post_object()
        ndict['administrative_state'] = 'something_invalid'
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_with_bad_heartbeat_interval(self, mock_client):
        # heartbeat_interval must be an integer between 1 and 600
        ndict = self.get_post_object()
        # All the entries in bad_values should be considered invalid
        bad_values = [0, 601, -1, 'abc']
        for bad_value in bad_values:
            ndict['heartbeat_interval'] = bad_value
            response = self.app.post_json(self.get_api_prefix(),
                                          ndict,
                                          headers=self.get_api_headers(),
                                          expect_errors=True)
            self.verify_post_failure(response)


class TestSystemPeerGet(testroot.DCManagerApiTest,
                        SystemPeerAPIMixin, GetMixin):
    def setUp(self):
        super(TestSystemPeerGet, self).setUp()

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_single_by_uuid(self, mock_client):
        # create a system peer
        context = utils.dummy_context()
        peer_uuid = str(uuid.uuid4())
        self._create_db_object(context, peer_uuid=peer_uuid)

        # Test that a GET operation for a valid ID works
        response = self.app.get(self.get_single_url(peer_uuid),
                                headers=self.get_api_headers())
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.validate_entry(response.json)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_single_by_name(self, mock_client):
        # create a system peer
        context = utils.dummy_context()
        peer_name = 'TestPeer'
        self._create_db_object(context, peer_name=peer_name)

        # Test that a GET operation for a valid ID works
        response = self.app.get(self.get_single_url(peer_name),
                                headers=self.get_api_headers())
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.validate_entry(response.json)


class TestSystemPeerUpdate(testroot.DCManagerApiTest,
                           SystemPeerAPIMixin, UpdateMixin):
    def setUp(self):
        super(TestSystemPeerUpdate, self).setUp()

    def validate_updated_fields(self, sub_dict, full_obj):
        for key, value in sub_dict.items():
            key = key.replace('_', '-')
            self.assertEqual(value, full_obj.get(key))

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_update_invalid_administrative_state(self, mock_client):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        update_data = {
            'administrative_state': 'something_bad'
        }
        response = self.app.patch_json(self.get_single_url(single_obj.id),
                                       headers=self.get_api_headers(),
                                       params=update_data,
                                       expect_errors=True)
        # Failures will return text rather than json
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_update_invalid_heartbeat_interval(self, mock_client):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        update_data = {
            'heartbeat_interval': -1
        }
        response = self.app.patch_json(self.get_single_url(single_obj.id),
                                       headers=self.get_api_headers(),
                                       params=update_data,
                                       expect_errors=True)
        # Failures will return text rather than json
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)


class TestSystemPeerDelete(testroot.DCManagerApiTest,
                           SystemPeerAPIMixin, DeleteMixin):
    def setUp(self):
        super(TestSystemPeerDelete, self).setUp()

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_delete_by_uuid(self, mock_client):
        context = utils.dummy_context()
        peer_uuid = str(uuid.uuid4())
        self._create_db_object(context, peer_uuid=peer_uuid)
        response = self.app.delete_json(self.get_single_url(peer_uuid),
                                        headers=self.get_api_headers())
        self.assertEqual(response.status_int, 200)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_delete_by_name(self, mock_client):
        context = utils.dummy_context()
        peer_name = 'TestPeer'
        self._create_db_object(context, peer_name=peer_name)
        response = self.app.delete_json(self.get_single_url(peer_name),
                                        headers=self.get_api_headers())
        self.assertEqual(response.status_int, 200)
