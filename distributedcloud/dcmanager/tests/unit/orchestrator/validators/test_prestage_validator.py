#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Prestage strategy validation tests
"""

from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.orchestrator.validators.prestage_validator import (
    PrestageStrategyValidator
)
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud
from dcmanager.tests.unit.orchestrator.validators.validators_mixin import (
    BaseMixin
)


# TODO(rlima): add the mixins once prestage logic is moved to the validator
class TestPrestageValidator(DCManagerTestCase, BaseMixin):
    """Test class for prestage validator"""

    def setUp(self):
        super().setUp()

        self.subcloud = create_fake_subcloud(self.ctx)
        self._mock_db_api("subcloud_status_get", wraps=db_api.subcloud_status_get)

        self.validator = PrestageStrategyValidator()

    def _get_mock_db_api(self):
        return self.mock_db_api

    def _get_validator(self):
        return self.validator
