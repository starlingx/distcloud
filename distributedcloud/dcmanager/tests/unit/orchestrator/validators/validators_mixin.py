#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Test classes for generic strategy validation tests
"""

import abc
import mock

from dccommon import consts as dccommon_consts
from dcmanager.common import exceptions
from dcmanager.db import api as db_api
from dcmanager.tests.unit.common.fake_subcloud import create_fake_subcloud


class BaseMixin(object, metaclass=abc.ABCMeta):
    """Base mixin class to declare common methods"""

    def setUp(self):
        self.subcloud = create_fake_subcloud(self.ctx)

    @abc.abstractmethod
    def _get_mock_db_api(self):
        """Returns the mocked db api object"""

    @abc.abstractmethod
    def _get_validator(self):
        """Returns the validator object"""


class StrategyRequirementsMixin(BaseMixin):
    """Mixin class for validate_strategy_requirements method tests"""

    def test_validate_strategy_requirements_suceeds(self):
        """Test validate_strategy_requirements succeeds"""

        self._get_validator().validate_strategy_requirements(
            self.ctx, self.subcloud.id, self.subcloud.name, False
        )

        self._get_mock_db_api().assert_called_once_with(
            mock.ANY, self.subcloud.id, self._get_validator().endpoint_type
        )

    def test_validate_strategy_requirements_suceeds_with_force(self):
        """Test validate_strategy_requirements succeeds with force

        If the strategy being tested does not accept force, it should execute
        normally. If it does, the execution is skipped.
        """

        self._get_validator().validate_strategy_requirements(
            self.ctx, self.subcloud.id, self.subcloud.name, True
        )

        if self._get_validator().accepts_force:
            self._get_mock_db_api().assert_not_called()
        else:
            self._get_mock_db_api().assert_called_once_with(
                mock.ANY, self.subcloud.id, self._get_validator().endpoint_type
            )

    def test_validate_strategy_requirements_fails_with_sync_status_out_of_sync(self):
        """Test validate_strategy_requirements fails with sync status out-of-sync"""

        db_api.subcloud_status_update(
            self.ctx, self.subcloud.id, self._get_validator().endpoint_type,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        )

        self.assertRaises(
            exceptions.BadRequest,
            self._get_validator().validate_strategy_requirements,
            self.ctx, self.subcloud.id, self.subcloud.name, False
        )

        self._get_mock_db_api().assert_called_once_with(
            mock.ANY, self.subcloud.id, self._get_validator().endpoint_type
        )
