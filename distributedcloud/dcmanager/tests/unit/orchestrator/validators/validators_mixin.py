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

    def _get_build_extra_args_payload(self):
        """Returns the payload for the BuildExtraArgsMixin tests

        By default, None is returned since most strategies don't allow
        extra arguments.
        """

        return None


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


class BuildExtraArgsMixin(BaseMixin):
    """Mixin class for build_extra_args method tests"""

    def test_build_extra_args_succeeds(self):
        """Test build_extra_args succeeds"""

        payload = self._get_build_extra_args_payload()

        extra_args = self._get_validator().build_extra_args(payload)

        if payload:
            for key, value in payload.items():
                self.assertEqual(extra_args[key], value)
        else:
            self.assertIsNone(extra_args)
