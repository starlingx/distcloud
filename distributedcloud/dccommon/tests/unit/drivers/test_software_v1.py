#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json
import os

import mock
import requests

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.software_v1 import SoftwareClient
from dccommon import exceptions
from dccommon.tests import base
from dccommon.tests import utils


FAKE_ENDPOINT = "endpoint"

QUERY_RESPONSE = {
    "sd": {
        "22.12_NRR_INSVC": {
            "state": "available",
            "sw_version": "22.12",
            "status": "DEV",
            "unremovable": "N",
            "summary": "Debian patch test",
            "description": "In service patch",
            "install_instructions": "Sample instructions",
            "restart_script": "22.12_NRR_INSVC_example-restart",
            "warnings": "Sample warning",
            "reboot_required": "N",
            "requires": []}}
}

QUERY_HOSTS_RESPONSE = {
    "data": [{
        "ip": "192.168.101.3",
        "hostname": "controller-0",
        "deployed": True,
        "secs_since_ack": 26,
        "patch_failed": False,
        "stale_details": False,
        "latest_sysroot_commit": "4b8bcc6f53",
        "nodetype": "controller",
        "subfunctions": ["controller", "worker"],
        "sw_version": "22.12",
        "state": "idle",
        "requires_reboot": False,
        "allow_insvc_patching": True,
        "interim_state": False}]
}

CLIENT_QUERY_HOSTS_RESPONSE = [{
    "allow_insvc_patching": True,
    "deployed": True,
    "hostname": "controller-0",
    "interim_state": False,
    "ip": "192.168.101.3",
    "latest_sysroot_commit": "4b8bcc6f53",
    "nodetype": "controller",
    "patch_failed": False,
    "requires_reboot": False,
    "secs_since_ack": 26,
    "stale_details": False,
    "state": "idle",
    "subfunctions": ["controller", "worker"],
    "sw_version": "22.12"
}]

CLIENT_QUERY_RESPONSE = {
    "22.12_NRR_INSVC": {
        "description": "In service patch",
        "install_instructions": "Sample instructions",
        "reboot_required": "N",
        "requires": [],
        "restart_script": "22.12_NRR_INSVC_example-restart",
        "state": "available",
        "status": "DEV",
        "summary": "Debian patch test",
        "sw_version": "22.12",
        "unremovable": "N",
        "warnings": "Sample warning"}}

ERROR_RESPONSE = {
    "error": "something went wrong"
}

INFO_RESPONSE = {
    "info": "Ok"
}

URLS = [
    "/upload",
    "/upload_dir",
    "/deploy_complete",
    "/deploy_activate",
    "/deploy_start",
    "/deploy_host",
    "/delete",
    "/commit_patch"
]


def mocked_requests_success(*args, **kwargs):
    response_content = None

    if args[0].endswith('/query_hosts'):
        response_content = json.dumps(QUERY_HOSTS_RESPONSE)
    elif args[0].endswith('/query?show=all'):
        response_content = json.dumps(QUERY_RESPONSE)
    elif any([url in args[0] for url in URLS]):
        response_content = json.dumps(INFO_RESPONSE)
    response = requests.Response()
    response.status_code = 200
    response._content = str.encode(response_content)

    return response


def mocked_requests_failure(*args, **kwargs):
    response_content = None

    if args[0].endswith('/query_hosts'):
        response_content = json.dumps(ERROR_RESPONSE)
    elif args[0].endswith('/query?show=all'):
        response_content = json.dumps(ERROR_RESPONSE)
    elif any([url in args[0] for url in URLS]):
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
            session=mock.MagicMock()
        )

    @mock.patch('requests.get')
    def test_query_success(self, mock_get):
        mock_get.side_effect = mocked_requests_success
        response = self.software_client.query()
        self.assertEqual(response, CLIENT_QUERY_RESPONSE)

    @mock.patch('requests.get')
    def test_query_failure(self, mock_get):
        mock_get.side_effect = mocked_requests_failure
        e = self.assertRaises(exceptions.ApiException,
                              self.software_client.query)

        self.assertTrue('Query failed with status code: 500'
                        in str(e))

    @mock.patch('requests.post')
    def test_delete_success(self, mock_post):
        mock_post.side_effect = mocked_requests_success
        releases = ['DC.1', 'DC.2']
        response = self.software_client.delete(releases)
        self.assertEqual(response, [])

    @mock.patch('requests.post')
    def test_delete_failure(self, mock_post):
        mock_post.side_effect = mocked_requests_failure
        releases = ['DC.1', 'DC.2']
        e = self.assertRaises(exceptions.ApiException,
                              self.software_client.delete,
                              releases)

        self.assertTrue('Delete failed with status code: 500'
                        in str(e))

    @mock.patch('requests.get')
    def test_query_hosts_success(self, mock_get):
        mock_get.side_effect = mocked_requests_success
        response = self.software_client.query_hosts()
        self.assertEqual(response, CLIENT_QUERY_HOSTS_RESPONSE)

    @mock.patch('requests.get')
    def test_query_hosts_failure(self, mock_get):
        mock_get.side_effect = mocked_requests_failure
        e = self.assertRaises(exceptions.ApiException,
                              self.software_client.query_hosts)
        self.assertTrue('Query hosts failed with status code: 500'
                        in str(e))

    @mock.patch.object(os.path, 'isdir')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch('requests.post')
    @mock.patch('builtins.open', new_callable=mock.mock_open())
    def test_upload_success(self, mock_open_file,
                            mock_post, mock_isfile, mock_isdir):
        mock_open_file.return_value = str.encode('patch')
        mock_post.side_effect = mocked_requests_success
        releases = ['DC1.patch']
        mock_isfile.return_value = True
        mock_isdir.return_value = False
        response = self.software_client.upload(releases)
        self.assertEqual(response, [])

    @mock.patch.object(os.path, 'isdir')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch('requests.post')
    @mock.patch('builtins.open', new_callable=mock.mock_open())
    def test_upload_failure(self, mock_open_file, mock_post,
                            mock_isfile, mock_isdir):
        mock_open_file.return_value = str.encode('patch')
        mock_post.side_effect = mocked_requests_success
        releases = ['DC5', 'DC4']
        mock_isfile.return_value = False
        mock_isdir.return_value = True
        e = self.assertRaises(IsADirectoryError,
                              self.software_client.upload,
                              releases)

        self.assertTrue('Error: DC4 is a directory. Please use upload-dir'
                        in str(e))

    @mock.patch('requests.post')
    def test_upload_dir_success(self, mock_post):
        mock_post.side_effect = mocked_requests_success
        releases = ['DC5', 'DC4']
        response = self.software_client.upload_dir(releases)
        self.assertEqual(response, [])

    @mock.patch('requests.post')
    def test_upload_dir_failure(self, mock_post):
        mock_post.side_effect = mocked_requests_failure
        releases = ['DC1.patch']
        e = self.assertRaises(exceptions.ApiException,
                              self.software_client.upload_dir,
                              releases)

        self.assertEqual('Upload dir failed with status code: 500', str(e))

    @mock.patch('requests.post')
    def test_deploy_activate_success(self, mock_post):
        mock_post.side_effect = mocked_requests_success
        release = 'DC.1'
        response = self.software_client.deploy_activate(release)
        self.assertEqual(response, [])

    @mock.patch('requests.post')
    def test_deploy_activate_failure(self, mock_post):
        mock_post.side_effect = mocked_requests_failure
        release = 'DC.1'
        e = self.assertRaises(exceptions.ApiException,
                              self.software_client.deploy_activate,
                              release)

        self.assertTrue('Deploy activate failed with status code: 500'
                        in str(e))

    @mock.patch('requests.post')
    def test_deploy_complete_success(self, mock_post):
        mock_post.side_effect = mocked_requests_success
        release = 'DC.1'
        response = self.software_client.deploy_complete(release)
        self.assertEqual(response, [])

    @mock.patch('requests.post')
    def test_deploy_complete_failure(self, mock_post):
        mock_post.side_effect = mocked_requests_failure
        release = 'DC.1'
        e = self.assertRaises(exceptions.ApiException,
                              self.software_client.deploy_complete,
                              release)

        self.assertTrue('Deploy complete failed with status code: 500'
                        in str(e))

    @mock.patch('requests.post')
    def test_deploy_start_success(self, mock_post):
        mock_post.side_effect = mocked_requests_success
        release = 'DC.1'
        response = self.software_client.deploy_start(release)
        self.assertEqual(response, [])

    @mock.patch('requests.post')
    def test_deploy_start_failure(self, mock_post):
        mock_post.side_effect = mocked_requests_failure
        release = 'DC.1'
        e = self.assertRaises(exceptions.ApiException,
                              self.software_client.deploy_start,
                              release)

        self.assertTrue('Deploy start failed with status code: 500'
                        in str(e))

    @mock.patch('requests.post')
    def test_deploy_host_success(self, mock_post):
        mock_post.side_effect = mocked_requests_success
        host = 'controller-0'
        response = self.software_client.deploy_host(host)
        self.assertEqual(response, [])

    @mock.patch('requests.post')
    def test_deploy_host_failure(self, mock_post):
        mock_post.side_effect = mocked_requests_failure
        host = 'controller-0'
        e = self.assertRaises(exceptions.ApiException,
                              self.software_client.deploy_host,
                              host)

        self.assertTrue('Deploy host failed with status code: 500'
                        in str(e))

    @mock.patch('requests.post')
    def test_commit_patch_success(self, mock_post):
        mock_post.side_effect = mocked_requests_success
        releases = ['DC.1', 'DC.2']
        response = self.software_client.commit_patch(releases)
        self.assertEqual(response, [])

    @mock.patch('requests.post')
    def test_commit_patch_failure(self, mock_post):
        mock_post.side_effect = mocked_requests_failure
        releases = ['DC.1', 'DC.2']
        e = self.assertRaises(exceptions.ApiException,
                              self.software_client.commit_patch,
                              releases)

        self.assertTrue('Commit patch failed with status code: 500'
                        in str(e))
