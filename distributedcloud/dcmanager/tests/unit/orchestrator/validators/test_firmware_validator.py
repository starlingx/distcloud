#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Firmware strategy validation tests
"""

from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.orchestrator.validators.firmware_validator import (
    FirmwareStrategyValidator,
)
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.orchestrator.validators.validators_mixin import (
    StrategyRequirementsMixin,
    BaseMixin,
    BuildExtraArgsMixin,
)
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


class TestFirmwareValidator(
    DCManagerTestCase, BaseMixin, StrategyRequirementsMixin, BuildExtraArgsMixin
):
    """Test class for firmware validator"""

    def setUp(self):
        super().setUp()

        self.subcloud = create_fake_subcloud(self.ctx)
        self._mock_db_api("subcloud_status_get", wraps=db_api.subcloud_status_get)

        self.validator = FirmwareStrategyValidator()

    def _get_mock_db_api(self):
        return self.mock_db_api

    def _get_validator(self):
        return self.validator
