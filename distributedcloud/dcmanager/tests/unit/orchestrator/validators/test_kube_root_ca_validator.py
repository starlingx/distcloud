#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Kube root-ca strategy validation tests
"""

from dcmanager.db import api as db_api
from dcmanager.orchestrator.validators.kube_root_ca_validator import (
    KubeRootCaStrategyValidator
)
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.orchestrator.validators.validators_mixin import (
    StrategyRequirementsMixin
)


class TestKubeRootCaValidator(DCManagerTestCase, StrategyRequirementsMixin):
    """Test class for kube root-ca validator"""

    def setUp(self):
        super().setUp()

        self._mock_db_api("subcloud_status_get", db_api.subcloud_status_get)

        self.validator = KubeRootCaStrategyValidator()

    def _get_mock_db_api(self):
        return self.mock_db_api

    def _get_validator(self):
        return self.validator
