#
# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Kubernetes strategy validation tests
"""

from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.orchestrator.validators.kubernetes_validator import (
    KubernetesStrategyValidator,
)
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.orchestrator.validators.validators_mixin import (
    StrategyRequirementsMixin,
    BaseMixin,
    BuildExtraArgsMixin,
)
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


class TestKubernetesValidator(
    DCManagerTestCase, BaseMixin, StrategyRequirementsMixin, BuildExtraArgsMixin
):
    """Test class for kubernetes validator"""

    def setUp(self):
        super().setUp()

        self.subcloud = create_fake_subcloud(self.ctx)
        self.mock_db_api = self._mock_object(
            db_api, "subcloud_status_get", wraps=db_api.subcloud_status_get
        )

        self.validator = KubernetesStrategyValidator()

    def _get_mock_db_api(self):
        return self.mock_db_api

    def _get_validator(self):
        return self.validator

    def _get_build_extra_args_payload(self, version="v1.32.2"):
        return {consts.EXTRA_ARGS_TO_VERSION: version}

    def _get_expected_extra_args(self):
        return {consts.EXTRA_ARGS_TO_VERSION: "v1.32.2"}

    def test_build_extra_args_succeeds_without_v_prefix(self):
        """Test build_extra_args succeeds without v prefix

        When the v prefix is not specified for a kube version, it should be
        automatically included.
        """

        payload = self._get_build_extra_args_payload("1.32.2")
        expected_extra_args = self._get_expected_extra_args()

        extra_args = self._get_validator().build_extra_args(payload)

        if payload and not expected_extra_args:
            expected_extra_args = payload

        if expected_extra_args:
            for key, value in expected_extra_args.items():
                self.assertEqual(extra_args[key], value)
        else:
            self.assertIsNone(extra_args)
