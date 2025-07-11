#
# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Kube root-ca strategy validation tests
"""

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.orchestrator.validators.kube_root_ca_validator import (
    KubeRootCaStrategyValidator,
)
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.orchestrator.validators.validators_mixin import (
    StrategyRequirementsMixin,
    BaseMixin,
    BuildExtraArgsMixin,
)
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


class TestKubeRootCaValidator(
    DCManagerTestCase, BaseMixin, StrategyRequirementsMixin, BuildExtraArgsMixin
):
    """Test class for kube root-ca validator"""

    def setUp(self):
        super().setUp()

        self.subcloud = create_fake_subcloud(self.ctx)
        self.mock_db_api = self._mock_object(
            db_api, "subcloud_status_get", wraps=db_api.subcloud_status_get
        )

        self.validator = KubeRootCaStrategyValidator()

    def _get_mock_db_api(self):
        return self.mock_db_api

    def _get_validator(self):
        return self.validator

    def _get_build_extra_args_payload(self):
        return {
            consts.EXTRA_ARGS_EXPIRY_DATE: "2024-06-28",
            consts.EXTRA_ARGS_SUBJECT: None,
            consts.EXTRA_ARGS_CERT_FILE: None,
        }

    def test_build_sync_status_without_force(self):
        response = self.validator.build_sync_status_filter(False)

        self.assertEqual(response, [dccommon_consts.SYNC_STATUS_OUT_OF_SYNC])

    def test_build_sync_status_with_force(self):
        response = self.validator.build_sync_status_filter(True)

        self.assertTrue(
            response,
            [
                dccommon_consts.SYNC_STATUS_IN_SYNC,
                dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            ],
        )
