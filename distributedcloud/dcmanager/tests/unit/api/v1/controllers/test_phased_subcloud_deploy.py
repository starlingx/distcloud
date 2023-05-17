#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from dcmanager.common import phased_subcloud_deploy as psd_common
from dcmanager.db import api as db_api
from dcmanager.tests.unit.api.v1.controllers.test_subclouds import \
    TestSubcloudPost


class FakeRPCClient(object):
    def subcloud_deploy_create(self, context, subcloud_id, _):
        subcloud = db_api.subcloud_get(context, subcloud_id)
        return db_api.subcloud_db_model_to_dict(subcloud)


# Apply the TestSubcloudPost parameter validation tests to the subcloud deploy
# add endpoint as it uses the same parameter validation functions
class TestSubcloudDeployCreate(TestSubcloudPost):
    API_PREFIX = '/v1.0/phased-subcloud-deploy'
    RESULT_KEY = 'phased-subcloud-deploy'

    def setUp(self):
        super().setUp()

        p = mock.patch.object(psd_common, 'get_network_address_pool')
        self.mock_get_network_address_pool = p.start()
        self.mock_get_network_address_pool.return_value = \
            self.management_address_pool
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common, 'get_ks_client')
        self.mock_get_ks_client = p.start()
        self.addCleanup(p.stop)

        p = mock.patch.object(psd_common.PatchingClient, 'query')
        self.mock_query = p.start()
        self.addCleanup(p.stop)

        self.mock_rpc_client.return_value = FakeRPCClient()

    def test_subcloud_create_missing_bootstrap_address(self):
        """Test POST operation without bootstrap-address."""
        params = self.get_post_params()
        del params['bootstrap-address']

        upload_files = self.get_post_upload_files()

        response = self.app.post(self.get_api_prefix(),
                                 params=params,
                                 upload_files=upload_files,
                                 headers=self.get_api_headers(),
                                 expect_errors=True)
        self._verify_post_failure(response, "bootstrap-address", None)
