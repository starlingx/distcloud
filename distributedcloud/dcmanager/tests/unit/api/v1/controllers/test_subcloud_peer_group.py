# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
from six.moves import http_client

from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.rpc import client as rpc_client

from dcmanager.tests.unit.api import test_root_controller as testroot
from dcmanager.tests.unit.api.v1.controllers.mixins import APIMixin
from dcmanager.tests.unit.api.v1.controllers.mixins import PostJSONMixin
from dcmanager.tests.unit.api.v1.controllers.test_subclouds \
    import FAKE_SUBCLOUD_DATA
from dcmanager.tests import utils

SAMPLE_SUBCLOUD_PEER_GROUP_NAME = 'GroupX'
SAMPLE_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING = 50
SAMPLE_SUBCLOUD_PEER_GROUP_STATE = 'enabled'
SAMPLE_SUBCLOUD_PEER_GROUP_PIRORITY = 0

NEW_SUBCLOUD_PEER_GROUP_NAME = 'GroupY'
NEW_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING = 20

API_PREFIX = '/v1.0/subcloud-peer-groups'
RESULT_KEY = 'subcloud_peer_groups'
EXPECTED_FIELDS = ["id",
                   "peer_group_name",
                   "group_priority",
                   "group_state",
                   "max_subcloud_rehoming",
                   "system_leader_id",
                   "system_leader_name",
                   "created-at",
                   "updated-at"]


class SubcloudPeerGroupAPIMixin(APIMixin):

    def validate_entry(self, result_item):
        self.assert_fields(result_item)

    def setUp(self):
        super(SubcloudPeerGroupAPIMixin, self).setUp()
        self.fake_rpc_client.some_method = mock.MagicMock()

    def _get_test_subcloud_peer_group_request(self, **kw):
        # id should not be part of the structure
        group = {
            'peer-group-name': kw.get(
                'peer_group_name', SAMPLE_SUBCLOUD_PEER_GROUP_NAME
            ),
            'system-leader-id': kw.get(
                'system_leader_id', '62c9592d-f799-4db9-8d40-6786a74d6021'
            ),
            'system-leader-name': kw.get(
                'system_leader_name', 'dc-test'
            ),
            'group-priority': kw.get('group_priority', '0'),
            'group-state': kw.get('group_state', 'enabled'),
            'max-subcloud-rehoming': kw.get(
                'max_subcloud_rehoming',
                SAMPLE_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING
            )
        }
        return group

    def _get_test_subcloud_peer_group_dict(self, **kw):
        # id should not be part of the structure
        group = {
            'peer_group_name': kw.get(
                'peer_group_name', SAMPLE_SUBCLOUD_PEER_GROUP_NAME
            ),
            'system_leader_id': kw.get(
                'system_leader_id', '62c9592d-f799-4db9-8d40-6786a74d6021'
            ),
            'system_leader_name': kw.get('system_leader_name', 'dc-test'),
            'group_priority': kw.get('group_priority', '0'),
            'group_state': kw.get(
                'group_state', SAMPLE_SUBCLOUD_PEER_GROUP_STATE),
            'max_subcloud_rehoming': kw.get(
                'max_subcloud_rehoming',
                SAMPLE_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING
            ),
            'migration_status': None
        }
        return group

    def _post_get_test_subcloud_peer_group(self, **kw):
        post_body = self._get_test_subcloud_peer_group_request(**kw)
        return post_body

    # The following methods are required for subclasses of APIMixin
    def get_api_prefix(self):
        return API_PREFIX

    def get_result_key(self):
        return RESULT_KEY

    def get_expected_api_fields(self):
        return EXPECTED_FIELDS

    def get_omitted_api_fields(self):
        return []

    def _create_db_object(self, context, **kw):
        creation_fields = self._get_test_subcloud_peer_group_dict(**kw)
        return db_api.subcloud_peer_group_create(context, **creation_fields)

    def get_post_object(self):
        return self._post_get_test_subcloud_peer_group()

    def get_update_object(self):
        update_object = {
            'system_leader_name': 'Updated system_leader_name'
        }
        return update_object


# Combine Subcloud Group API with mixins to test post, get, update and delete
class TestSubcloudPeerGroupPost(testroot.DCManagerApiTest,
                                SubcloudPeerGroupAPIMixin,
                                PostJSONMixin):
    def setUp(self):
        super(TestSubcloudPeerGroupPost, self).setUp()

    def verify_post_failure(self, response):
        # Failures will return text rather than json
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_with_numerical_name_fails(self, mock_client):
        # A numerical name is not permitted. otherwise the 'get' operations
        # which support getting by either name or ID could become confused
        # if a name for one group was the same as an ID for another.
        ndict = self.get_post_object()
        ndict['peer-group-name'] = '123'
        response = self.app.post_json(API_PREFIX,
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_with_none_string_name_fails(self, mock_client):
        # A name as 'none' not permitted.
        # None is a special word for clean a peer-group-id from subcloud.
        ndict = self.get_post_object()
        ndict['peer-group-name'] = 'none'
        response = self.app.post_json(API_PREFIX,
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_with_blank_name_fails(self, mock_client):
        # An empty name is not permitted
        ndict = self.get_post_object()
        ndict['peer-group-name'] = ''
        response = self.app.post_json(API_PREFIX,
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.verify_post_failure(response)


class TestSubcloudPeerGroupGet(testroot.DCManagerApiTest,
                               SubcloudPeerGroupAPIMixin):
    def setUp(self):
        super(TestSubcloudPeerGroupGet, self).setUp()
        # Override initial_list_size. Default group is setup during db sync
        self.initial_list_size = 1

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_single_by_name(self, mock_client):
        # create a group
        context = utils.dummy_context()
        group_name = 'TestGroup'
        system_id = '0907033e-b7ec-4832-92ad-4b0913580b3b'
        self._create_db_object(
            context, peer_group_name=group_name, system_leader_id=system_id)

        # Test that a GET operation for a valid ID works
        response = self.app.get(self.get_single_url(group_name),
                                headers=self.get_api_headers())
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.validate_entry(response.json)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_list_subclouds_empty(self, mock_client):
        # API GET on: subcloud-peer-groups/<uuid>/subclouds
        # create a subcloud peer group
        context = utils.dummy_context()
        group_name = 'TestGroup'
        system_id = '0907033e-b7ec-4832-92ad-4b0913580b3b'
        self._create_db_object(
            context, peer_group_name=group_name, system_leader_id=system_id)
        url = '%s/%s/subclouds' % (API_PREFIX, group_name)
        response = self.app.get(url,
                                headers=self.get_api_headers())
        # This API returns 'subclouds' rather than 'subcloud-peer-groups'
        self.assertIn('subclouds', response.json)
        # no subclouds exist yet, so this length should be zero
        result_list = response.json.get('subclouds')
        self.assertEqual(0, len(result_list))

    def _create_subcloud_db_object(self, context):
        creation_fields = {
            'name': FAKE_SUBCLOUD_DATA.get('name'),
            'description': FAKE_SUBCLOUD_DATA.get('description'),
            'location': FAKE_SUBCLOUD_DATA.get('location'),
            'software_version': FAKE_SUBCLOUD_DATA.get('software_version'),
            'management_subnet': FAKE_SUBCLOUD_DATA.get('management_subnet'),
            'management_gateway_ip':
                FAKE_SUBCLOUD_DATA.get('management_gateway_ip'),
            'management_start_ip':
                FAKE_SUBCLOUD_DATA.get('management_start_ip'),
            'management_end_ip': FAKE_SUBCLOUD_DATA.get('management_end_ip'),
            'systemcontroller_gateway_ip':
                FAKE_SUBCLOUD_DATA.get('systemcontroller_gateway_ip'),
            'deploy_status': FAKE_SUBCLOUD_DATA.get('deploy_status'),
            'error_description': FAKE_SUBCLOUD_DATA.get('error_description'),
            'openstack_installed':
                FAKE_SUBCLOUD_DATA.get('openstack_installed'),
            'group_id': FAKE_SUBCLOUD_DATA.get('group_id', 1),
            'region_name': FAKE_SUBCLOUD_DATA.get('region_name', "RegionOne")
        }
        return db_api.subcloud_create(context, **creation_fields)

    def _update_subcloud_peer_group_id(self, ctx, subcloud, pg_id):
        return db_api.subcloud_update(ctx, subcloud.id, peer_group_id=pg_id)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_list_subclouds_populated(self, mock_client):
        context = utils.dummy_context()

        # Create subcloud peer group
        group_name = 'TestGroup'
        system_id = '0907033e-b7ec-4832-92ad-4b0913580b3b'
        pg = self._create_db_object(
            context, peer_group_name=group_name, system_leader_id=system_id)

        # Create subcloud set peer-group-id as above subcloud-peer-group
        subcloud = self._create_subcloud_db_object(context)
        self._update_subcloud_peer_group_id(context, subcloud, pg.id)

        # API GET on: subcloud-peer-groups/<uuid>/subclouds
        url = '%s/%s/subclouds' % (API_PREFIX, pg.id)
        response = self.app.get(url,
                                headers=self.get_api_headers())
        # This API returns 'subclouds' rather than 'subcloud-groups'
        self.assertIn('subclouds', response.json)
        # the subcloud created earlier will have been queried
        result_list = response.json.get('subclouds')
        self.assertEqual(1, len(result_list))

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_status(self, mock_client):
        context = utils.dummy_context()

        # Create subcloud peer group
        group_name = 'TestGroup'
        system_id = '0907033e-b7ec-4832-92ad-4b0913580b3b'
        pg = self._create_db_object(
            context, peer_group_name=group_name, system_leader_id=system_id)

        # Create subcloud set peer-group-id as above subcloud-peer-group
        subcloud = self._create_subcloud_db_object(context)
        self._update_subcloud_peer_group_id(context, subcloud, pg.id)

        # API GET on: subcloud-peer-groups/<uuid>/status
        url = '%s/%s/status' % (API_PREFIX, pg.id)
        response = self.app.get(url,
                                headers=self.get_api_headers())

        self.assertIn('total_subclouds', response.json)
        self.assertIn('peer_group_id', response.json)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_migrate(self, mock_client):
        context = utils.dummy_context()

        # Create subcloud peer group
        group_name = 'TestGroup'
        system_id = '0907033e-b7ec-4832-92ad-4b0913580b3b'
        pg = self._create_db_object(
            context, peer_group_name=group_name, system_leader_id=system_id)

        subcloud = self._create_subcloud_db_object(context)
        # Set necessary data for a subcloud
        db_api.subcloud_update(context, subcloud.id,
                               management_state='unmanaged',
                               deploy_status='secondary',
                               rehome_data="{\"saved_payload\": "
                               "{\"system_mode\": \"simplex\","
                               "\"bootstrap-address\": \"192.168.100.100\"}}")
        # Set peer-group-id as above subcloud-peer-group
        self._update_subcloud_peer_group_id(context, subcloud, pg.id)
        update_data = {
            'sysadmin_password': 'xxxx'
        }
        url = '%s/%s/migrate' % (API_PREFIX, pg.id)
        response = self.app.patch_json(url,
                                       headers=self.get_api_headers(),
                                       params=update_data,
                                       expect_errors=False)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)


class TestSubcloudPeerGroupUpdate(testroot.DCManagerApiTest,
                                  SubcloudPeerGroupAPIMixin):
    def setUp(self):
        super(TestSubcloudPeerGroupUpdate, self).setUp()

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_update_invalid_system_leader_id(self, mock_client):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        update_data = {
            'system_leader_id': 'not-valid-uuid'
        }
        response = self.app.patch_json(self.get_single_url(single_obj.id),
                                       headers=self.get_api_headers(),
                                       params=update_data,
                                       expect_errors=True)
        # Failures will return text rather than json
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_update_invalid_max_subcloud_rehoming(self, mock_client):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        update_data = {
            'max_subcloud_rehoming': -1
        }
        response = self.app.patch_json(self.get_single_url(single_obj.id),
                                       headers=self.get_api_headers(),
                                       params=update_data,
                                       expect_errors=True)
        # Failures will return text rather than json
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_rename_subcloud_peer_group(self, mock_client):
        mock_client().update_subcloud_peer_group.return_value = \
            (set(), set(mock.MagicMock()))
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        update_data = {
            'peer-group-name': NEW_SUBCLOUD_PEER_GROUP_NAME,
            'max-subcloud-rehoming':
                NEW_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING
        }
        response = self.app.patch_json(self.get_single_url(single_obj.id),
                                       headers=self.get_api_headers(),
                                       params=update_data,
                                       expect_errors=False)
        self.assertEqual(response.status_code, http_client.OK)

        mock_client().update_subcloud_peer_group.assert_called_once_with(
            mock.ANY, single_obj.id, None,
            NEW_SUBCLOUD_PEER_GROUP_MAX_SUBCLOUDS_REHOMING,
            SAMPLE_SUBCLOUD_PEER_GROUP_NAME,
            NEW_SUBCLOUD_PEER_GROUP_NAME)


class TestSubcloudPeerGroupDelete(testroot.DCManagerApiTest,
                                  SubcloudPeerGroupAPIMixin):
    def setUp(self):
        super(TestSubcloudPeerGroupDelete, self).setUp()

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_delete_success(self, mock_client):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        response = self.app.delete(self.get_single_url(single_obj.id),
                                   headers=self.get_api_headers())
        # Failures will return text rather than json
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
