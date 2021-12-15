# Copyright (c) 2017 Ericsson AB
# Copyright (c) 2020-2021 Wind River Systems, Inc.
# All Rights Reserved.
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

import mock
from six.moves import http_client

from dcmanager.rpc import client as rpc_client

from dcmanager.tests import utils


class APIMixin(object):

    FAKE_TENANT = utils.UUID1

    api_headers = {
        'X-Tenant-Id': FAKE_TENANT,
        'X_ROLE': 'admin',
        'X-Identity-Status': 'Confirmed'
    }

    # subclasses should provide methods
    # get_api_prefix
    # get_result_key

    def setUp(self):
        super(APIMixin, self).setUp()

    def get_api_headers(self):
        return self.api_headers

    def get_single_url(self, uuid):
        return '%s/%s' % (self.get_api_prefix(), uuid)

    def get_api_prefix(self):
        raise NotImplementedError

    def get_result_key(self):
        raise NotImplementedError

    def get_expected_api_fields(self):
        raise NotImplementedError

    def get_omitted_api_fields(self):
        raise NotImplementedError

    # base mixin subclass MUST override these methods if the api supports them
    def _create_db_object(self, context):
        raise NotImplementedError

    # base mixin subclass should provide this method for testing of POST
    def get_upload_files(self):
        return None

    def get_post_object(self):
        raise NotImplementedError

    def get_update_object(self):
        raise NotImplementedError

    def assert_fields(self, api_object):
        # Verify that expected attributes are returned
        for field in self.get_expected_api_fields():
            self.assertIn(field, api_object)

        # Verify that hidden attributes are not returned
        for field in self.get_omitted_api_fields():
            self.assertNotIn(field, api_object)


#
# --------------------- POST -----------------------------------
#
# An API test will mixin only one of:
# PostMixin
# PostJSONMixin
# PostRejectedMixin
# PostJSONRejectedMixin
# depending on whether or not the API supports a post operation or not.
# upload_files kwarg is not supported by the json methods in web_test
class PostMixin(object):

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_success(self, mock_client):
        # Test that a POST operation is supported by the API
        params = self.get_post_params()
        upload_files = self.get_post_upload_files()
        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers())
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.assert_fields(response.json)


class PostRejectedMixin(object):
    # Test that a POST operation is blocked by the API
    # API should return 400 BAD_REQUEST or FORBIDDEN 403
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_not_allowed(self, mock_client):
        params = self.get_post_params()
        upload_files = self.get_post_upload_files()
        response = self.app.post(self.API_PREFIX,
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers(),
                                 expect_errors=True)
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertTrue(response.json['error_message'])
        self.assertIn("Operation not permitted.",
                      response.json['error_message'])


class PostJSONMixin(object):

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_success(self, mock_client):
        # Test that a POST (post_json) operation is supported by the API
        ndict = self.get_post_object()
        response = self.app.post_json(self.get_api_prefix(),
                                      ndict,
                                      headers=self.get_api_headers())
        self.assertEqual(response.content_type, 'application/json')


class PostJSONRejectedMixin(object):
    # Test that a POST (post_json) operation is blocked by the API
    # API should return 400 BAD_REQUEST or FORBIDDEN 403
    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_create_not_allowed(self, mock_client):
        ndict = self.get_post_object()
        response = self.app.post_json(self.API_PREFIX,
                                      ndict,
                                      headers=self.get_api_headers(),
                                      expect_errors=True)
        self.assertEqual(response.status_code, http_client.FORBIDDEN)
        self.assertTrue(response.json['error_message'])
        self.assertIn("Operation not permitted.",
                      response.json['error_message'])


# ------  API GET mixin
class GetMixin(object):

    # Mixins can override initial_list_size if a table is not empty during
    # DB creation and migration sync
    initial_list_size = 0

    # Performing a GET on this ID should fail.  subclass mixins can override
    invalid_id = '123'

    def validate_entry(self, result_item):
        self.assert_fields(result_item)

    def validate_list(self, expected_length, results):
        self.assertIn(self.get_result_key(), results)
        result_list = results.get(self.get_result_key())
        self.assertEqual(expected_length, len(result_list))
        for result_item in result_list:
            self.validate_entry(result_item)

    def validate_list_response(self, expected_length, response):
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # validate the list length
        self.validate_list(expected_length, response.json)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_initial_list_size(self, mock_client):
        # Test that a GET operation for a list is supported by the API
        response = self.app.get(self.get_api_prefix(),
                                headers=self.get_api_headers())
        # Validate the initial length
        self.validate_list_response(self.initial_list_size, response)

        # Add an entry
        context = utils.dummy_context()
        self._create_db_object(context)

        response = self.app.get(self.get_api_prefix(),
                                headers=self.get_api_headers())
        self.validate_list_response(self.initial_list_size + 1, response)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_fail_get_single(self, mock_client):
        # Test that a GET operation for an invalid ID returns the
        # appropriate error results
        response = self.app.get(self.get_single_url(self.invalid_id),
                                headers=self.get_api_headers(),
                                expect_errors=True)
        # Failures will return text rather than json
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.NOT_FOUND)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_get_single(self, mock_client):
        context = utils.dummy_context()
        db_obj = self._create_db_object(context)

        # Test that a GET operation for a valid ID works
        response = self.app.get(self.get_single_url(db_obj.id),
                                headers=self.get_api_headers())
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.validate_entry(response.json)


# ------ API  Update Mixin
class UpdateMixin(object):

    def validate_updated_fields(self, sub_dict, full_obj):
        for key, value in sub_dict.items():
            self.assertEqual(value, full_obj.get(key))

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_update_success(self, mock_client):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        update_data = self.get_update_object()
        response = self.app.patch_json(self.get_single_url(single_obj.id),
                                       headers=self.get_api_headers(),
                                       params=update_data)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        self.validate_updated_fields(update_data, response.json)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_update_empty_changeset(self, mock_client):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        update_data = {}
        response = self.app.patch_json(self.get_single_url(single_obj.id),
                                       headers=self.get_api_headers(),
                                       params=update_data,
                                       expect_errors=True)
        # Failures will return text rather than json
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)


# ------ API  Delete Mixin
class DeleteMixin(object):

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_delete_success(self, mock_client):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        response = self.app.delete(self.get_single_url(single_obj.id),
                                   headers=self.get_api_headers())
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    @mock.patch.object(rpc_client, 'ManagerClient')
    def test_double_delete(self, mock_client):
        context = utils.dummy_context()
        single_obj = self._create_db_object(context)
        response = self.app.delete(self.get_single_url(single_obj.id),
                                   headers=self.get_api_headers())
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        # delete the same object a second time. this should fail (NOT_FOUND)
        response = self.app.delete(self.get_single_url(single_obj.id),
                                   headers=self.get_api_headers(),
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'text/plain')
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
