#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Prestage strategy validation tests
"""

from dcmanager.db import api as db_api
from dcmanager.orchestrator.validators.prestage_validator import (
    PrestageStrategyValidator
)
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.orchestrator.validators.validators_mixin import (
    StrategyRequirementsMixin
)


class TestPrestageValidator(DCManagerTestCase, StrategyRequirementsMixin):
    """Test class for prestage validator"""

    def setUp(self):
        super().setUp()

        self._mock_db_api("subcloud_status_get", db_api.subcloud_status_get)

        self.validator = PrestageStrategyValidator()

    def _get_mock_db_api(self):
        return self.mock_db_api

    def _get_validator(self):
        return self.validator
