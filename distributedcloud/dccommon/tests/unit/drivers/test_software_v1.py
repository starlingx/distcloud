#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json

import mock
import requests

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.software_v1 import SoftwareClient
from dccommon import exceptions
from dccommon.tests import base
from dccommon.tests import utils


FAKE_ENDPOINT = "endpoint"

LIST_RESPONSE = [
    {
        "release_id": "starlingx-24.03.0",
        "state": "deployed",
        "sw_version": "24.03.0",
        "component": None,
        "status": "REL",
        "unremovable": True,
        "summary": "STX 24.03 GA release",
        "description": "STX 24.03 major GA release",
        "install_instructions": "",
        "warnings": "",
        "reboot_required": True,
        "requires": [],
        "packages": [],
    }
]

CLIENT_LIST_RESPONSE = [
    {
        "release_id": "starlingx-24.03.0",
        "state": "deployed",
        "sw_version": "24.03.0",
        "component": None,
        "status": "REL",
        "unremovable": True,
        "summary": "STX 24.03 GA release",
        "description": "STX 24.03 major GA release",
        "install_instructions": "",
        "warnings": "",
        "reboot_required": True,
        "requires": [],
        "packages": [],
    }
]

SHOW_RESPONSE = {
    "release_id": "starlingx-24.03.0",
    "state": "deployed",
    "sw_version": "24.03.0",
    "component": None,
    "status": "REL",
    "unremovable": True,
    "summary": "STX 24.03 GA release",
    "description": "STX 24.03 major GA release",
    "install_instructions": "",
    "warnings": "",
    "reboot_required": True,
    "requires": [],
    "packages": [],
}

ERROR_RESPONSE = {
    "error": "something went wrong"
}

INFO_RESPONSE = {
    "info": "Ok"
}

URLS = [
    "/deploy",
    "/commit_patch"
]


def mocked_requests_success(*args, **kwargs):
    response_content = None

    if args[0].endswith('/release'):
        response_content = json.dumps(LIST_RESPONSE)
    elif args[0].endswith("/release/DC.1"):
        response_content = json.dumps(SHOW_RESPONSE)
    elif args[0].endswith('/release/DC.1/DC.2'):
        response_content = json.dumps(INFO_RESPONSE)
    elif any([url in args[0] for url in URLS]):
        response_content = json.dumps(INFO_RESPONSE)
    response = requests.Response()
    response.status_code = 200
    response._content = str.encode(response_content)

    return response


def mocked_requests_failure(*args, **kwargs):
    response_content = json.dumps(ERROR_RESPONSE)
    response = requests.Response()
    response.status_code = 500
    response._content = str.encode(response_content)
    return response


class TestSoftwareClient(base.DCCommonTestCase):

    def setUp(self):
        super(TestSoftwareClient, self).setUp()
        self.ctx = utils.dummy_context()
        self.session = mock.MagicMock()
        self.software_client = SoftwareClient(
            region=dccommon_consts.DEFAULT_REGION_NAME,
            endpoint=FAKE_ENDPOINT,
            session=mock.MagicMock(),
        )

    @mock.patch('requests.get')
    def test_list_success(self, mock_get):
        mock_get.side_effect = mocked_requests_success
        response = self.software_client.list()
        self.assertEqual(response, CLIENT_LIST_RESPONSE)

    @mock.patch('requests.get')
    def test_list_failure(self, mock_get):
        mock_get.side_effect = mocked_requests_failure
        exc = self.assertRaises(exceptions.ApiException, self.software_client.list)
        self.assertTrue("List failed with status code: 500" in str(exc))

    @mock.patch("requests.get")
    def test_show_success(self, mock_get):
        mock_get.side_effect = mocked_requests_success
        release = "DC.1"
        response = self.software_client.show(release)
        self.assertEqual(response, SHOW_RESPONSE)

    @mock.patch("requests.get")
    def test_show_failure(self, mock_get):
        mock_get.side_effect = mocked_requests_failure
        release = 'DC.1'
        exc = self.assertRaises(
            exceptions.ApiException, self.software_client.show, release
        )
        self.assertTrue("Show failed with status code: 500" in str(exc))

    @mock.patch('requests.delete')
    def test_delete_success(self, mock_delete):
        mock_delete.side_effect = mocked_requests_success
        releases = ['DC.1', 'DC.2']
        response = self.software_client.delete(releases)
        self.assertEqual(response, INFO_RESPONSE)

    @mock.patch("requests.delete")
    def test_delete_failure(self, mock_delete):
        mock_delete.side_effect = mocked_requests_failure
        releases = ['DC.1', 'DC.2']
        exc = self.assertRaises(
            exceptions.ApiException, self.software_client.delete, releases
        )
        self.assertTrue("Delete failed with status code: 500" in str(exc))

    @mock.patch('requests.post')
    def test_commit_patch_success(self, mock_post):
        mock_post.side_effect = mocked_requests_success
        releases = ['DC.1', 'DC.2']
        response = self.software_client.commit_patch(releases)
        self.assertEqual(response, INFO_RESPONSE)

    @mock.patch('requests.post')
    def test_commit_patch_failure(self, mock_post):
        mock_post.side_effect = mocked_requests_failure
        releases = ['DC.1', 'DC.2']
        exc = self.assertRaises(
            exceptions.ApiException, self.software_client.commit_patch, releases
        )
        self.assertTrue("Commit patch failed with status code: 500" in str(exc))
