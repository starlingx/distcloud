#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Patch strategy validation tests
"""

from dcmanager.common import consts
from dcmanager.db.sqlalchemy import api as db_api
from dcmanager.orchestrator.validators.patch_validator import PatchStrategyValidator
from dcmanager.tests.base import DCManagerTestCase
from dcmanager.tests.unit.orchestrator.validators.validators_mixin import (
    StrategyRequirementsMixin,
    BaseMixin,
    BuildExtraArgsMixin,
)
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


class TestPatchValidator(
    DCManagerTestCase, BaseMixin, StrategyRequirementsMixin, BuildExtraArgsMixin
):
    """Test class for patch validator"""

    def setUp(self):
        super().setUp()

        self.subcloud = create_fake_subcloud(self.ctx)
        self._mock_db_api("subcloud_status_get", wraps=db_api.subcloud_status_get)

        self.validator = PatchStrategyValidator()

    def _get_mock_db_api(self):
        return self.mock_db_api

    def _get_validator(self):
        return self.validator

    def _get_build_extra_args_payload(self):
        return {consts.EXTRA_ARGS_UPLOAD_ONLY: True, consts.EXTRA_ARGS_PATCH: None}

    def _get_expected_extra_args(self):

        extra_args = self._get_build_extra_args_payload()
        extra_args[consts.EXTRA_ARGS_UPLOAD_ONLY] = False

        return extra_args
