# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from io import BytesIO
import uuid
import yaml

import mock

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import dcmanager_v1
from dccommon import exceptions as dccommon_exceptions
from dccommon.tests import base

FAKE_ID = "1"
SUBCLOUD_NAME = "Subcloud1"
SUBCLOUD_BOOTSTRAP_ADDRESS = "192.168.0.10"
SUBCLOUD_BOOTSTRAP_VALUE_PATH = "/tmp/test_subcloud_bootstrap_value.yaml"
SUBCLOUD_GROUP_NAME = "SubcloudGroup1"
SYSTEM_PEER_UUID = str(uuid.uuid4())
SYSTEM_PEER_NAME = "SystemPeer1"
SUBCLOUD_PEER_GROUP_ID = 1
SUBCLOUD_PEER_GROUP_NAME = "SubcloudPeerGroup1"

FAKE_ENDPOINT = "http://128.128.1.1:8119/v1.0"
FAKE_TOKEN = "token"
FAKE_TIMEOUT = 600

FAKE_SUBCLOUD_DATA = {
    "id": FAKE_ID,
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
    "availability-status": "disabled",
}

FAKE_SUBCLOUD_PEER_GROUP_DATA = {
    "id": SUBCLOUD_PEER_GROUP_ID,
    "peer-group-name": SUBCLOUD_PEER_GROUP_NAME,
    "system-leader-id": SYSTEM_PEER_UUID,
    "system-leader-name": SYSTEM_PEER_NAME,
    "max-subcloud-rehoming": 1,
    "group-state": "enabled",
    "group-priority": 1,
}


class TestDcmanagerClient(base.DCCommonTestCase):
    def setUp(self):
        super(TestDcmanagerClient, self).setUp()

        self.mock_response = mock.MagicMock()
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = FAKE_SUBCLOUD_PEER_GROUP_DATA

        self.mock_session = mock.MagicMock()

        self.client = dcmanager_v1.DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME,
            session=self.mock_session,
            timeout=FAKE_TIMEOUT,
            endpoint=FAKE_ENDPOINT,
        )

    def test_get_subcloud(self):
        self.mock_response.json.return_value = FAKE_SUBCLOUD_DATA
        self.mock_session.get.return_value = self.mock_response

        actual_subcloud = self.client.get_subcloud(SUBCLOUD_NAME)
        self.assertEqual(SUBCLOUD_NAME, actual_subcloud.get("name"))

    def test_get_subcloud_not_found(self):
        self.mock_response.status_code = 404
        self.mock_response.text = "Subcloud not found"
        self.mock_session.get.return_value = self.mock_response

        self.assertRaises(
            dccommon_exceptions.SubcloudNotFound,
            self.client.get_subcloud,
            SUBCLOUD_NAME,
        )

    def test_get_subcloud_list(self):
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = {"subclouds": [FAKE_SUBCLOUD_DATA]}
        self.mock_session.get.return_value = self.mock_response

        actual_subclouds = self.client.get_subcloud_list()
        self.assertEqual(1, len(actual_subclouds))
        self.assertEqual(SUBCLOUD_NAME, actual_subclouds[0].get("name"))

    def test_get_subcloud_group_list(self):
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = {
            "subcloud_groups": [{"name": SUBCLOUD_GROUP_NAME}]
        }
        self.mock_session.get.return_value = self.mock_response

        actual_subcloud_groups = self.client.get_subcloud_group_list()
        self.assertListEqual(actual_subcloud_groups, [{"name": SUBCLOUD_GROUP_NAME}])

    def test_get_subcloud_peer_group_list(self):
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = {
            "subcloud_peer_groups": [FAKE_SUBCLOUD_PEER_GROUP_DATA]
        }
        self.mock_session.get.return_value = self.mock_response

        actual_peer_group = self.client.get_subcloud_peer_group_list()
        self.assertListEqual(actual_peer_group, [FAKE_SUBCLOUD_PEER_GROUP_DATA])

    def test_get_subcloud_peer_group(self):
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = FAKE_SUBCLOUD_PEER_GROUP_DATA
        self.mock_session.get.return_value = self.mock_response

        actual_peer_group = self.client.get_subcloud_peer_group(
            SUBCLOUD_PEER_GROUP_NAME
        )
        self.assertDictEqual(actual_peer_group, FAKE_SUBCLOUD_PEER_GROUP_DATA)

    def test_get_subcloud_peer_group_not_found(self):
        self.mock_response.status_code = 404
        self.mock_response.text = "Subcloud Peer Group not found"
        self.mock_session.get.return_value = self.mock_response

        self.assertRaises(
            dccommon_exceptions.SubcloudPeerGroupNotFound,
            self.client.get_subcloud_peer_group,
            SUBCLOUD_PEER_GROUP_NAME,
        )

    def test_get_subcloud_list_by_peer_group(self):
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = {"subclouds": [FAKE_SUBCLOUD_DATA]}
        self.mock_session.get.return_value = self.mock_response

        actual_subclouds = self.client.get_subcloud_list_by_peer_group(
            SUBCLOUD_PEER_GROUP_NAME
        )
        self.assertListEqual(actual_subclouds, [FAKE_SUBCLOUD_DATA])

    def test_get_subcloud_list_by_peer_group_not_found(self):
        self.mock_response.status_code = 404
        self.mock_response.text = "Subcloud Peer Group not found"
        self.mock_session.get.return_value = self.mock_response

        self.assertRaises(
            dccommon_exceptions.SubcloudPeerGroupNotFound,
            self.client.get_subcloud_list_by_peer_group,
            SUBCLOUD_PEER_GROUP_NAME,
        )

    def test_add_subcloud_peer_group(self):
        peer_group_kwargs = {"peer-group-name": SUBCLOUD_PEER_GROUP_NAME}
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = FAKE_SUBCLOUD_PEER_GROUP_DATA
        self.mock_session.post.return_value = self.mock_response

        actual_peer_group = self.client.add_subcloud_peer_group(**peer_group_kwargs)
        self.assertDictEqual(actual_peer_group, FAKE_SUBCLOUD_PEER_GROUP_DATA)

    @mock.patch("builtins.open", new_callable=mock.mock_open)
    def test_add_subcloud_with_secondary_status(self, mock_open):
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = FAKE_SUBCLOUD_DATA
        self.mock_session.post.return_value = self.mock_response

        # Mock the file content to be returned when reading
        yaml_data = yaml.dump(FAKE_SUBCLOUD_DATA).encode("utf-8")
        mock_open.return_value = BytesIO(yaml_data)

        subcloud_kwargs = {
            "data": {"bootstrap-address": SUBCLOUD_BOOTSTRAP_ADDRESS},
            "files": {"bootstrap_values": SUBCLOUD_BOOTSTRAP_VALUE_PATH},
        }
        actual_subcloud = self.client.add_subcloud_with_secondary_status(
            **subcloud_kwargs
        )
        self.assertDictEqual(actual_subcloud, FAKE_SUBCLOUD_DATA)

    def test_delete_subcloud_peer_group(self):
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = ""
        self.mock_session.delete.return_value = self.mock_response

        result = self.client.delete_subcloud_peer_group(SUBCLOUD_PEER_GROUP_NAME)
        self.mock_session.delete.assert_called_once_with(
            FAKE_ENDPOINT + "/subcloud-peer-groups/" + SUBCLOUD_PEER_GROUP_NAME,
            timeout=FAKE_TIMEOUT,
            raise_exc=False,
        )
        self.assertEqual(result, "")

    def test_delete_subcloud_peer_group_not_found(self):
        self.mock_response.status_code = 404
        self.mock_response.text = "Subcloud Peer Group not found"
        self.mock_session.delete.return_value = self.mock_response

        self.assertRaises(
            dccommon_exceptions.SubcloudPeerGroupNotFound,
            self.client.delete_subcloud_peer_group,
            SUBCLOUD_PEER_GROUP_NAME,
        )

    def test_delete_subcloud(self):
        self.mock_response.status_code = 200
        self.mock_response.json.return_value = ""
        self.mock_session.delete.return_value = self.mock_response

        result = self.client.delete_subcloud(SUBCLOUD_NAME)
        self.mock_session.delete.assert_called_once_with(
            FAKE_ENDPOINT + "/subclouds/" + SUBCLOUD_NAME,
            timeout=FAKE_TIMEOUT,
            user_agent=dccommon_consts.DCMANAGER_V1_HTTP_AGENT,
            raise_exc=False,
        )
        self.assertEqual(result, "")

    def test_delete_subcloud_not_found(self):
        self.mock_response.status_code = 404
        self.mock_response.text = "Subcloud not found"
        self.mock_session.delete.return_value = self.mock_response

        self.assertRaises(
            dccommon_exceptions.SubcloudNotFound,
            self.client.delete_subcloud,
            SUBCLOUD_NAME,
        )
