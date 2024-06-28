#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Kubernetes strategy validation tests
"""

from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.orchestrator.validators.kubernetes_validator import (
    KubernetesStrategyValidator
)
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.orchestrator.validators.validators_mixin import (
    StrategyRequirementsMixin, BuildExtraArgsMixin
)


class TestKubernetesValidator(
    DCManagerTestCase, StrategyRequirementsMixin, BuildExtraArgsMixin
):
    """Test class for kubernetes validator"""

    def setUp(self):
        super().setUp()

        self._mock_db_api("subcloud_status_get", db_api.subcloud_status_get)

        self.validator = KubernetesStrategyValidator()

    def _get_mock_db_api(self):
        return self.mock_db_api

    def _get_validator(self):
        return self.validator

    def _get_build_extra_args_payload(self):
        return {
            consts.EXTRA_ARGS_TO_VERSION: "22.09",
        }
