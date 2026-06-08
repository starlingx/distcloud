#
# Copyright (c) 2024-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Software deploy strategy validation tests
"""

from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.orchestrator.validators.sw_deploy_validator import (
    SoftwareDeployStrategyValidator,
)
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.orchestrator.validators.validators_mixin import (
    StrategyRequirementsMixin,
    BaseMixin,
    BuildExtraArgsMixin,
)
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


class TestSoftwareDeployValidator(
    DCManagerTestCase, BaseMixin, StrategyRequirementsMixin, BuildExtraArgsMixin
):
    """Test class for software deploy validator"""

    def setUp(self):
        super().setUp()

        self.subcloud = create_fake_subcloud(self.ctx)
        self.mock_db_api = self._mock_object(
            db_api, "subcloud_status_get", wraps=db_api.subcloud_status_get
        )

        self.validator = SoftwareDeployStrategyValidator()

    def _get_mock_db_api(self):
        return self.mock_db_api

    def _get_validator(self):
        return self.validator

    def _get_build_extra_args_payload(self):
        return {
            consts.EXTRA_ARGS_RELEASE_ID: "stx-10.0.0",
        }

    def test_build_extra_args_includes_kube_upgrade(self):
        """Test build_extra_args includes kube_upgrade when provided"""

        payload = {
            consts.EXTRA_ARGS_RELEASE_ID: "stx-10.0.0",
            consts.EXTRA_ARGS_KUBE_UPGRADE: "v1.29.1",
        }

        extra_args = self.validator.build_extra_args(payload)

        self.assertEqual(extra_args[consts.EXTRA_ARGS_KUBE_UPGRADE], "v1.29.1")
        self.assertEqual(extra_args[consts.EXTRA_ARGS_RELEASE_ID], "stx-10.0.0")

    def test_build_extra_args_includes_cleanup(self):
        """Test build_extra_args includes cleanup when provided"""

        payload = {
            consts.EXTRA_ARGS_CLEANUP: True,
        }

        extra_args = self.validator.build_extra_args(payload)

        self.assertTrue(extra_args[consts.EXTRA_ARGS_CLEANUP])

    def test_build_extra_args_defaults_kube_upgrade_to_none(self):
        """Test build_extra_args defaults kube_upgrade to None"""

        payload = {consts.EXTRA_ARGS_RELEASE_ID: "stx-10.0.0"}

        extra_args = self.validator.build_extra_args(payload)

        self.assertIsNone(extra_args[consts.EXTRA_ARGS_KUBE_UPGRADE])

    def test_build_extra_args_defaults_cleanup_to_false(self):
        """Test build_extra_args defaults cleanup to False"""

        payload = {consts.EXTRA_ARGS_RELEASE_ID: "stx-10.0.0"}

        extra_args = self.validator.build_extra_args(payload)

        self.assertFalse(extra_args[consts.EXTRA_ARGS_CLEANUP])
