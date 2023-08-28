# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import uuid
import yaml

import mock

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import dcmanager_v1
from dccommon import exceptions as dccommon_exceptions
from dccommon.tests import base

FAKE_ID = '1'
SUBCLOUD_NAME = 'Subcloud1'
SUBCLOUD_BOOTSTRAP_ADDRESS = '192.168.0.10'
SUBCLOUD_BOOTSTRAP_VALUE_PATH = '/tmp/test_subcloud_bootstrap_value.yaml'
SUBCLOUD_GROUP_NAME = 'SubcloudGroup1'
SYSTEM_PEER_UUID = str(uuid.uuid4())
SYSTEM_PEER_NAME = 'SystemPeer1'
SUBCLOUD_PEER_GROUP_ID = 1
SUBCLOUD_PEER_GROUP_NAME = 'SubcloudPeerGroup1'

FAKE_ENDPOINT = 'http://128.128.1.1:8119/v1.0'
FAKE_TOKEN = 'token'
FAKE_TIMEOUT = 600

FAKE_SUBCLOUD_DATA = {"id": FAKE_ID,
                      "name": SUBCLOUD_NAME,
                      "description": "subcloud1 description",
                      "location": "subcloud1 location",
                      "software-version": "22.12",
                      "management-state": "managed",
                      "deploy-status": "complete",
                      "management-subnet": "192.168.101.0/24",
                      "management-start-ip": "192.168.101.2",
                      "management-end-ip": "192.168.101.50",
                      "management-gateway-ip": "192.168.101.1",
                      "systemcontroller-gateway-ip": "192.168.204.101",
                      "group-id": 1,
                      "peer-group-id": SUBCLOUD_PEER_GROUP_ID,
                      "rehome-data": "null",
                      "availability-status": "disabled"}

FAKE_SUBCLOUD_PEER_GROUP_DATA = {
    "id": SUBCLOUD_PEER_GROUP_ID,
    "peer-group-name": SUBCLOUD_PEER_GROUP_NAME,
    "system-leader-id": SYSTEM_PEER_UUID,
    "system-leader-name": SYSTEM_PEER_NAME,
    "max-subcloud-rehoming": 1,
    "group-state": "enabled",
    "group-priority": 1
}


class TestDcmanagerClient(base.DCCommonTestCase):
    def setUp(self):
        super(TestDcmanagerClient, self).setUp()

    @mock.patch('requests.get')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_get_subcloud(self, mock_client_init, mock_get):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = FAKE_SUBCLOUD_DATA
        mock_get.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        actual_subcloud = client.get_subcloud(SUBCLOUD_NAME)
        self.assertEqual(SUBCLOUD_NAME, actual_subcloud.get('name'))

    @mock.patch('requests.get')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_get_subcloud_not_found(self, mock_client_init, mock_get):
        mock_response = mock.MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Subcloud not found"
        mock_get.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        self.assertRaises(dccommon_exceptions.SubcloudNotFound,
                          client.get_subcloud, SUBCLOUD_NAME)

    @mock.patch('requests.get')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_get_subcloud_list(self, mock_client_init, mock_get):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "subclouds": [FAKE_SUBCLOUD_DATA]}
        mock_get.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        actual_subclouds = client.get_subcloud_list()
        self.assertEqual(1, len(actual_subclouds))
        self.assertEqual(SUBCLOUD_NAME, actual_subclouds[0].get('name'))

    @mock.patch('requests.get')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_get_subcloud_group_list(self, mock_client_init, mock_get):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "subcloud_groups": [{"name": SUBCLOUD_GROUP_NAME}]}
        mock_get.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        actual_subcloud_groups = client.get_subcloud_group_list()
        self.assertEqual(1, len(actual_subcloud_groups))
        self.assertEqual(SUBCLOUD_GROUP_NAME,
                         actual_subcloud_groups[0].get('name'))

    @mock.patch('requests.get')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_get_subcloud_peer_group_list(self, mock_client_init, mock_get):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "subcloud_peer_groups": [FAKE_SUBCLOUD_PEER_GROUP_DATA]}
        mock_get.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        actual_peer_group = client.get_subcloud_peer_group_list()
        self.assertEqual(1, len(actual_peer_group))
        self.assertEqual(SUBCLOUD_PEER_GROUP_NAME,
                         actual_peer_group[0].get('peer-group-name'))

    @mock.patch('requests.get')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_get_subcloud_peer_group(self, mock_client_init, mock_get):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = FAKE_SUBCLOUD_PEER_GROUP_DATA
        mock_get.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        actual_peer_group = client.get_subcloud_peer_group(
            SUBCLOUD_PEER_GROUP_NAME)
        self.assertEqual(SUBCLOUD_PEER_GROUP_NAME,
                         actual_peer_group.get('peer-group-name'))

    @mock.patch('requests.get')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_get_subcloud_peer_group_not_found(
        self, mock_client_init, mock_get
    ):
        mock_response = mock.MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Subcloud Peer Group not found"
        mock_get.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        self.assertRaises(dccommon_exceptions.SubcloudPeerGroupNotFound,
                          client.get_subcloud_peer_group,
                          SUBCLOUD_PEER_GROUP_NAME)

    @mock.patch('requests.get')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_get_subcloud_list_by_peer_group(self, mock_client_init, mock_get):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "subclouds": [FAKE_SUBCLOUD_DATA]}
        mock_get.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        actual_subclouds = client.get_subcloud_list_by_peer_group(
            SUBCLOUD_PEER_GROUP_NAME)
        self.assertEqual(1, len(actual_subclouds))
        self.assertEqual(SUBCLOUD_NAME, actual_subclouds[0].get('name'))

    @mock.patch('requests.get')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_get_subcloud_list_by_peer_group_not_found(
        self, mock_client_init, mock_get
    ):
        mock_response = mock.MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Subcloud Peer Group not found"
        mock_get.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        self.assertRaises(dccommon_exceptions.SubcloudPeerGroupNotFound,
                          client.get_subcloud_list_by_peer_group,
                          SUBCLOUD_PEER_GROUP_NAME)

    @mock.patch('requests.post')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_add_subcloud_peer_group(self, mock_client_init, mock_post):
        peer_group_kwargs = {
            'peer-group-name': SUBCLOUD_PEER_GROUP_NAME
        }
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = FAKE_SUBCLOUD_PEER_GROUP_DATA
        mock_post.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        actual_peer_group = client.add_subcloud_peer_group(
            **peer_group_kwargs)
        self.assertEqual(SUBCLOUD_PEER_GROUP_NAME,
                         actual_peer_group.get('peer-group-name'))

    @mock.patch('requests.post')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_add_subcloud_with_secondary_status(self, mock_client_init,
                                                mock_post):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = FAKE_SUBCLOUD_DATA
        mock_post.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        # create the cache file for subcloud create
        yaml_data = yaml.dump(FAKE_SUBCLOUD_DATA)
        with open(SUBCLOUD_BOOTSTRAP_VALUE_PATH, 'w') as file:
            file.write(yaml_data)

        subcloud_kwargs = {
            "data": {
                "bootstrap-address": SUBCLOUD_BOOTSTRAP_ADDRESS
            },
            "files": {
                "bootstrap_values": SUBCLOUD_BOOTSTRAP_VALUE_PATH
            }
        }
        actual_subcloud = client.add_subcloud_with_secondary_status(
            **subcloud_kwargs)
        self.assertEqual(SUBCLOUD_NAME, actual_subcloud.get('name'))

        # purge the cache file
        os.remove(SUBCLOUD_BOOTSTRAP_VALUE_PATH)

    @mock.patch('requests.delete')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_delete_subcloud_peer_group(self, mock_client_init, mock_delete):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = ''
        mock_delete.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        result = client.delete_subcloud_peer_group(SUBCLOUD_PEER_GROUP_NAME)
        mock_delete.assert_called_once_with(
            FAKE_ENDPOINT + '/subcloud-peer-groups/' +
            SUBCLOUD_PEER_GROUP_NAME,
            headers={"X-Auth-Token": FAKE_TOKEN},
            timeout=FAKE_TIMEOUT
        )
        self.assertEqual(result, '')

    @mock.patch('requests.delete')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_delete_subcloud_peer_group_not_found(self, mock_client_init,
                                                  mock_delete):
        mock_response = mock.MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Subcloud Peer Group not found"
        mock_delete.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        self.assertRaises(dccommon_exceptions.SubcloudPeerGroupNotFound,
                          client.delete_subcloud_peer_group,
                          SUBCLOUD_PEER_GROUP_NAME)

    @mock.patch('requests.delete')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_delete_subcloud(self, mock_client_init, mock_delete):
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = ''
        mock_delete.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        result = client.delete_subcloud(SUBCLOUD_NAME)
        mock_delete.assert_called_once_with(
            FAKE_ENDPOINT + '/subclouds/' + SUBCLOUD_NAME,
            headers={"X-Auth-Token": FAKE_TOKEN},
            timeout=FAKE_TIMEOUT
        )
        self.assertEqual(result, '')

    @mock.patch('requests.delete')
    @mock.patch.object(dcmanager_v1.DcmanagerClient, '__init__')
    def test_delete_subcloud_not_found(self, mock_client_init,
                                       mock_delete):
        mock_response = mock.MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Subcloud not found"
        mock_delete.return_value = mock_response

        mock_client_init.return_value = None
        client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME, None)
        client.endpoint = FAKE_ENDPOINT
        client.token = FAKE_TOKEN
        client.timeout = FAKE_TIMEOUT

        self.assertRaises(dccommon_exceptions.SubcloudNotFound,
                          client.delete_subcloud,
                          SUBCLOUD_NAME)
