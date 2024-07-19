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


class BaseMixin(object, metaclass=abc.ABCMeta):
    """Base mixin class to declare common methods"""

    @abc.abstractmethod
    def _get_mock_db_api(self):
        """Returns the mocked db api object"""

    @abc.abstractmethod
    def _get_validator(self):
        """Returns the validator object"""

    def _get_build_extra_args_payload(self):
        """Returns the payload for the BuildExtraArgsMixin tests

        By default, an empty dict is returned since most strategies don't allow
        extra arguments.
        """

        return {}

    def _get_expected_extra_args(self):
        """Returns the expected extra args built by build_extra_args

        By default, it is empty so that the original payload is used in the
        validation.
        """

        return {}


class StrategyRequirementsMixin(object):
    """Mixin class for validate_strategy_requirements method tests"""

    def test_validate_strategy_requirements_suceeds(self):
        """Test validate_strategy_requirements succeeds"""

        self._get_validator().validate_strategy_requirements(
            self.ctx, self.subcloud.id, self.subcloud.name, False
        )

        self._get_mock_db_api().assert_called_with(
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
            self._get_mock_db_api().assert_called_with(
                mock.ANY, self.subcloud.id, self._get_validator().endpoint_type
            )

    def test_validate_strategy_requirements_succeeds_with_endpoint_out_of_sync(self):
        """Test validate_strategy_requirements succeeds with endpoint out of sync"""

        db_api.subcloud_status_update(
            self.ctx, self.subcloud.id, self._get_validator().endpoint_type,
            dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        )

        self._get_validator().validate_strategy_requirements(
            self.ctx, self.subcloud.id, self.subcloud.name, True
        )

        self._get_mock_db_api().assert_called_with(
            mock.ANY, self.subcloud.id, self._get_validator().endpoint_type
        )

    def test_validate_strategy_requirements_fails_with_endpoint_in_sync(self):
        """Test validate_strategy_requirements fails with endpoint in sync"""

        db_api.subcloud_status_update(
            self.ctx, self.subcloud.id, self._get_validator().endpoint_type,
            dccommon_consts.SYNC_STATUS_IN_SYNC
        )

        self.assertRaises(
            exceptions.BadRequest,
            self._get_validator().validate_strategy_requirements,
            self.ctx, self.subcloud.id, self.subcloud.name, False
        )

        self._get_mock_db_api().assert_called_with(
            mock.ANY, self.subcloud.id, self._get_validator().endpoint_type
        )


class BuildExtraArgsMixin(object):
    """Mixin class for build_extra_args method tests"""

    def test_build_extra_args_succeeds(self):
        """Test build_extra_args succeeds"""

        payload = self._get_build_extra_args_payload()
        expected_extra_args = self._get_expected_extra_args()

        extra_args = self._get_validator().build_extra_args(payload)

        if payload and not expected_extra_args:
            expected_extra_args = payload

        if expected_extra_args:
            for key, value in expected_extra_args.items():
                self.assertEqual(extra_args[key], value)
        else:
            self.assertIsNone(extra_args)
