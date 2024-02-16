#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid

import mock

from six.moves import http_client

from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.rpc import client as rpc_client

from dcmanager.api.controllers.v1 import peer_group_association
from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests.unit.api.v1.controllers.mixins import APIMixin
from dcmanager.tests.unit.api.v1.controllers.mixins import GetMixin
from dcmanager.tests.unit.api.v1.controllers.mixins import UpdateMixin
from dcmanager.tests import utils

# SAMPLE SYSTEM PEER DATA
SAMPLE_SYSTEM_PEER_UUID = str(uuid.uuid4())
SAMPLE_SYSTEM_PEER_NAME = 'SystemPeer1'
SAMPLE_MANAGER_ENDPOINT = 'http://127.0.0.1:5000'
SAMPLE_MANAGER_USERNAME = 'admin'
SAMPLE_MANAGER_PASSWORD = 'password'
SAMPLE_PEER_CONTROLLER_GATEWAY_IP = '128.128.128.1'
SAMPLE_ADMINISTRATIVE_STATE = 'enabled'
SAMPLE_HEARTBEAT_INTERVAL = 10
SAMPLE_HEARTBEAT_FAILURE_THRESHOLD = 3
SAMPLE_HEARTBEAT_FAILURES_POLICY = 'alarm'
SAMPLE_HEARTBEAT_MAINTENANCE_TIMEOUT = 600
SAMPLE_AVAILABILITY_STATE_AVAILABLE = 'available'

# SAMPLE SUBCLOUD PEER GROUP DATA
SAMPLE_SUBCLOUD_PEER_GROUP_NAME = 'GroupX'
SAMPLE_SUBCLOUD_PEER_GROUP_SYSTEM_LEADER_ID = str(uuid.uuid4())
SAMPLE_SUBCLOUD_PEER_GROUP_SYSTEM_LEADER_NAME = 'dc-local'
SAMPLE_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING = 50
SAMPLE_SUBCLOUD_PEER_GROUP_PRIORITY = 0
SAMPLE_SUBCLOUD_PEER_GROUP_STATE = 'enabled'

# SAMPLE PEER GROUP ASSOCIATION DATA
SAMPLE_SUBCLOUD_PEER_GROUP_ID = 1
SAMPLE_SYSTEM_PEER_ID = 1
SAMPLE_PEER_GROUP_PRIORITY = 1
SAMPLE_PEER_GROUP_PRIORITY_UPDATED = 99
SAMPLE_SYNC_STATUS = 'synced'
SAMPLE_SYNC_MESSAGE = 'None'
SAMPLE_ASSOCIATION_TYPE = 'primary'


class FakeSystem(object):
    def __init__(self, uuid):
        self.uuid = uuid


class FakeKeystoneClient(object):
    def __init__(self):
        self.keystone_client = mock.MagicMock()
        self.session = mock.MagicMock()
        self.endpoint_cache = mock.MagicMock()


class FakeSysinvClient(object):
    def __init__(self):
        self.system = FakeSystem(SAMPLE_SUBCLOUD_PEER_GROUP_SYSTEM_LEADER_ID)

    def get_system(self):
        return self.system


class PeerGroupAssociationAPIMixin(APIMixin):

    API_PREFIX = '/v1.0/peer-group-associations'
    RESULT_KEY = 'peer_group_associations'
    EXPECTED_FIELDS = ['id',
                       'peer-group-id',
                       'system-peer-id',
                       'peer-group-priority',
                       'created-at',
                       'updated-at']

    def setUp(self):
        super(PeerGroupAssociationAPIMixin, self).setUp()
        self.fake_rpc_client.some_method = mock.MagicMock()

    def _get_test_system_peer_dict(self, **kw):
        # id should not be part of the structure
        system_peer = {
            'peer_uuid': kw.get('peer_uuid', SAMPLE_SYSTEM_PEER_UUID),
            'peer_name': kw.get('peer_name', SAMPLE_SYSTEM_PEER_NAME),
            'endpoint': kw.get('manager_endpoint', SAMPLE_MANAGER_ENDPOINT),
            'username': kw.get('manager_username', SAMPLE_MANAGER_USERNAME),
            'password': kw.get('manager_password', SAMPLE_MANAGER_PASSWORD),
            'gateway_ip': kw.get(
                'peer_controller_gateway_ip', SAMPLE_PEER_CONTROLLER_GATEWAY_IP),
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
        return system_peer

    def _get_test_subcloud_peer_group_dict(self, **kw):
        # id should not be part of the structure
        group = {
            'peer_group_name': kw.get('peer_group_name',
                                      SAMPLE_SUBCLOUD_PEER_GROUP_NAME),
            'system_leader_id': kw.get(
                'system_leader_id',
                SAMPLE_SUBCLOUD_PEER_GROUP_SYSTEM_LEADER_ID),
            'system_leader_name': kw.get(
                'system_leader_name',
                SAMPLE_SUBCLOUD_PEER_GROUP_SYSTEM_LEADER_NAME),
            'group_priority': kw.get(
                'group_priority',
                SAMPLE_SUBCLOUD_PEER_GROUP_PRIORITY),
            'group_state': kw.get(
                'group_state',
                SAMPLE_SUBCLOUD_PEER_GROUP_STATE),
            'max_subcloud_rehoming': kw.get(
                'max_subcloud_rehoming',
                SAMPLE_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING),
            'migration_status': None
        }
        return group

    def _get_test_peer_group_association_dict(self, **kw):
        # id should not be part of the structure
        association = {
            'peer_group_id': kw.get('peer_group_id',
                                    SAMPLE_SUBCLOUD_PEER_GROUP_ID),
            'system_peer_id': kw.get('system_peer_id', SAMPLE_SYSTEM_PEER_ID),
            'peer_group_priority': kw.get('peer_group_priority',
                                          SAMPLE_PEER_GROUP_PRIORITY),
            'sync_status': kw.get('sync_status', SAMPLE_SYNC_STATUS),
            'sync_message': kw.get('sync_message', SAMPLE_SYNC_MESSAGE),
            'association_type': kw.get('association_type',
                                       SAMPLE_ASSOCIATION_TYPE)
        }
        return association

    def _post_get_test_peer_group_association(self, **kw):
        post_body = self._get_test_peer_group_association_dict(**kw)
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

    def _create_db_related_objects(self, context):
        system_peer_fields = self._get_test_system_peer_dict()
        peer = db_api.system_peer_create(context, **system_peer_fields)

        peer_group_fields = self._get_test_subcloud_peer_group_dict()
        peer_group = db_api.subcloud_peer_group_create(context,
                                                       **peer_group_fields)

        return peer.id, peer_group.id

    def _create_db_object(self, context, **kw):

        peer_id, peer_group_id = self._create_db_related_objects(context)

        kw['peer_group_id'] = peer_group_id if kw.get('peer_group_id') is None \
            else kw.get('peer_group_id')
        kw['system_peer_id'] = peer_id if kw.get('system_peer_id') is None \
            else kw.get('system_peer_id')
        creation_fields = self._get_test_peer_group_association_dict(**kw)
        return db_api.peer_group_association_create(context, **creation_fields)

    def get_post_object(self):
        return self._post_get_test_peer_group_association()

    def get_update_object(self):
        update_object = {
            'peer_group_priority': SAMPLE_PEER_GROUP_PRIORITY_UPDATED
        }
        return update_object


# Combine Peer Group Association API with mixins to test post, get, update and delete
class TestPeerGroupAssociationPost(testroot.DCManagerApiTest,
                                   PeerGroupAssociationAPIMixin):
    def setUp(self):
        super(TestPeerGroupAssociationPost, self).setUp()

        p = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = p.start()
        self.addCleanup(p.stop)

        context = utils.dummy_context()
        self.context = context
        peer_id, _ = self._create_db_related_objects(context)
        db_api.system_peer_update(
            context, peer_id=peer_id,
            availability_state=SAMPLE_AVAILABILITY_STATE_AVAILABLE)

    def verify_post_failure(self, response):
        # Failures will return text rather than JSON
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    def test_create_success(self):
        self.mock_rpc_client().sync_subcloud_peer_group.return_value = True

        ndict = self.get_post_object()
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers())
        self.assertEqual(response.content_type, 'application/json')

    def test_create_with_string_id_fails(self):
        # A string system peer id is not permitted.
        ndict = self.get_post_object()
        ndict['system_peer_id'] = 'test-system-peer-id'
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    def test_create_with_blank_id_fails(self):
        # An empty system_peer_id is not permitted
        ndict = self.get_post_object()
        ndict['system_peer_id'] = ''
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    def test_create_with_wrong_peer_group_priority_fails(self):
        # A string peer group priority is not permitted.
        ndict = self.get_post_object()
        ndict['peer_group_id'] = 'peer-group-id'
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    def test_create_with_bad_peer_group_priority(self):
        # peer_group_priority must be an integer between 1 and 65536
        ndict = self.get_post_object()
        # All the entries in bad_values should be considered invalid
        bad_values = [0, 65537, -2, 'abc']
        for bad_value in bad_values:
            ndict['peer_group_priority'] = bad_value
            response = self.app.post_json(self.get_api_prefix(),
                                          ndict,
                                          headers=self.get_api_headers(),
                                          expect_errors=True)
            self.verify_post_failure(response)


class TestPeerGroupAssociationGet(testroot.DCManagerApiTest,
                                  PeerGroupAssociationAPIMixin,
                                  GetMixin):
    def setUp(self):
        super(TestPeerGroupAssociationGet, self).setUp()


class TestPeerGroupAssociationUpdate(testroot.DCManagerApiTest,
                                     PeerGroupAssociationAPIMixin,
                                     UpdateMixin):
    def setUp(self):
        super(TestPeerGroupAssociationUpdate, self).setUp()

    def validate_updated_fields(self, sub_dict, full_obj):
        for key, value in sub_dict.items():
            key = key.replace('_', '-')
            self.assertEqual(value, full_obj.get(key))

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_update_success(self, mock_client):
        mock_client().sync_subcloud_peer_group_only.return_value = {
            'peer-group-priority': SAMPLE_PEER_GROUP_PRIORITY_UPDATED
        }
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        update_data = self.get_update_object()
        response = self.app.patch_json(self.get_single_url(single_obj.id),
                                       headers=self.get_api_headers(),
                                       params=update_data)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.validate_updated_fields(update_data, response.json)

    @mock.patch.object(psd_common, 'OpenStackDriver')
    @mock.patch.object(peer_group_association, 'SysinvClient')
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_sync_association(
        self, mock_client, mock_sysinv_client, mock_keystone_client
    ):
        mock_client().sync_subcloud_peer_group.return_value = True
        mock_keystone_client().keystone_client = FakeKeystoneClient()
        mock_sysinv_client.return_value = FakeSysinvClient()

        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        response = self.app.patch_json(
            self.get_single_url(single_obj.id) + '/sync',
            headers=self.get_api_headers())
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        mock_client().sync_subcloud_peer_group.assert_called_once()


class TestPeerGroupAssociationDelete(testroot.DCManagerApiTest,
                                     PeerGroupAssociationAPIMixin):
    def setUp(self):
        super(TestPeerGroupAssociationDelete, self).setUp()

        p = mock.patch.object(rpc_client, 'ManagerClient')
        self.mock_rpc_client = p.start()
        self.addCleanup(p.stop)

        self.mock_rpc_client().delete_peer_group_association.return_value = True

    def test_delete_success(self):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        response = self.app.delete(self.get_single_url(single_obj.id),
                                   headers=self.get_api_headers())
        self.mock_rpc_client().delete_peer_group_association. \
            assert_called_once()
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_double_delete(self):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        response = self.app.delete(self.get_single_url(single_obj.id),
                                   headers=self.get_api_headers())
        self.mock_rpc_client().delete_peer_group_association. \
            assert_called_once()
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        db_api.peer_group_association_destroy(context, single_obj.id)
        # delete the same object a second time. this should fail (NOT_FOUND)
        response = self.app.delete(self.get_single_url(single_obj.id),
                                   headers=self.get_api_headers(),
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
