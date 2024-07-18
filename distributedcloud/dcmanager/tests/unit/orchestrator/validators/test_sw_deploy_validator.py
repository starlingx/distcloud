#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Software deploy strategy validation tests
"""

from dcmanager.db import api as db_api
from dcmanager.orchestrator.validators.software_deploy_validator import (
    SoftwareDeployStrategyValidator
)
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.orchestrator.validators.validators_mixin import (
    StrategyRequirementsMixin
)


class TestSoftwareDeployValidator(DCManagerTestCase, StrategyRequirementsMixin):
    """Test class for software deploy validator"""

    def setUp(self):
        super().setUp()

        self._mock_db_api("subcloud_status_get", db_api.subcloud_status_get)

        self.validator = SoftwareDeployStrategyValidator()

    def _get_mock_db_api(self):
        return self.mock_db_api

    def _get_validator(self):
        return self.validator
