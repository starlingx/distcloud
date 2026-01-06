#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from mock import MagicMock

from dccommon import consts as dccommon_consts
from dcmanager.audit import utils
from dcmanager.db import api as db_api
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


class TestAuditUtils(DCManagerTestCase):
    def setUp(self):
        super().setUp()

        self.mock_db = self._mock_object(utils, "db_api", utils.db_api)
        self.mock_dcorch = MagicMock()

        self.subcloud = create_fake_subcloud(self.ctx)
        db_api.subcloud_status_create_all(self.ctx, self.subcloud.id)

    def test_request_subcloud_audits_all(self):
        utils.request_subcloud_audits(self.ctx, True, True, True, True, True)

        self.mock_db.subcloud_audits_update_all.assert_called_once_with(
            self.ctx,
            {
                "state_update_requested": True,
                "firmware_audit_requested": True,
                "kubernetes_audit_requested": True,
                "kube_rootca_update_audit_requested": True,
                "software_audit_requested": True,
            },
        )

    def test_request_subcloud_audits_without_values(self):
        utils.request_subcloud_audits(self.ctx)

        self.mock_db.subcloud_audits_update_all.assert_not_called()

    def test_filter_endpoint_data_without_data(self):
        utils.filter_endpoint_data(self.ctx, self.subcloud, {})

        self.mock_db.subcloud_status_get_all.assert_not_called()

    def test_filter_endpoint_data_with_data(self):
        utils.filter_endpoint_data(
            self.ctx,
            self.subcloud,
            {
                dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA: None,
                dccommon_consts.ENDPOINT_TYPE_KUBERNETES: (
                    dccommon_consts.SYNC_STATUS_IN_SYNC
                ),
            },
        )

        self.mock_db.subcloud_status_get_all.assert_called_once_with(
            self.ctx, self.subcloud.id
        )

    def test_update_subcloud_software_version_without_endpoint_data(self):
        utils.update_subcloud_software_version(
            self.ctx, self.subcloud, {}, self.mock_dcorch
        )

        self.mock_dcorch.update_subcloud_version.assert_not_called()
        self.mock_db.subcloud_update.assert_not_called()

    def test_update_subcloud_software_version_without_software_data(self):
        utils.update_subcloud_software_version(
            self.ctx,
            self.subcloud,
            {
                dccommon_consts.ENDPOINT_TYPE_KUBERNETES: (
                    dccommon_consts.SYNC_STATUS_IN_SYNC
                )
            },
            self.mock_dcorch,
        )

        self.mock_dcorch.update_subcloud_version.assert_not_called()
        self.mock_db.subcloud_update.assert_not_called()

    def test_update_subcloud_software_version_with_new_software_version(self):
        software_version = "stx-10.0.0"

        utils.update_subcloud_software_version(
            self.ctx,
            self.subcloud,
            {
                dccommon_consts.AUDIT_TYPE_SOFTWARE: {
                    "sync_status": dccommon_consts.SYNC_STATUS_IN_SYNC,
                    "software_version": software_version,
                }
            },
            self.mock_dcorch,
        )

        self.mock_dcorch.update_subcloud_version.assert_called_once_with(
            self.ctx, self.subcloud.region_name, software_version
        )
        self.mock_db.subcloud_update.assert_called_once_with(
            self.ctx, self.subcloud.id, software_version=software_version
        )

    def test_update_subcloud_software_version_with_subcloud_software_version(self):
        utils.update_subcloud_software_version(
            self.ctx,
            self.subcloud,
            {
                dccommon_consts.AUDIT_TYPE_SOFTWARE: {
                    "sync_status": dccommon_consts.SYNC_STATUS_IN_SYNC,
                    "software_version": self.subcloud.software_version,
                }
            },
            self.mock_dcorch,
        )

        self.mock_dcorch.update_subcloud_version.assert_not_called()
        self.mock_db.subcloud_update.assert_not_called()
