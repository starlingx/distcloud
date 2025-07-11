#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.orchestrator.cache import clients
from dcmanager.tests.unit.orchestrator.states.software.test_base import (
    TestSoftwareOrchestrator,
)

MISSING_LICENSE_RESPONSE = {
    "content": "",
    "error": "License file not found. A license may not have been installed.",
}

GENERIC_ERROR_RESPONSE = {"content": "", "error": "Invalid license"}

LICENSE_VALID_RESPONSE = {"content": "A valid license", "error": ""}

ALTERNATE_LICENSE_RESPONSE = {"content": "A different valid license", "error": ""}


class TestInstallLicenseState(TestSoftwareOrchestrator):

    def setUp(self):
        super().setUp()

        # next state after install a license is 'upload'
        self.on_success_state = consts.STRATEGY_STATE_SW_CREATE_VIM_STRATEGY

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_SW_INSTALL_LICENSE
        )

        # Mock the sysinv client from cache
        mock_get_sysinv_client = self._mock_object(clients, "get_sysinv_client")
        mock_get_sysinv_client.return_value = self.sysinv_client

    def test_install_license_failure(self):
        """Test the installing license step where the install fails.

        The system controller has a license, but the API call to install on the
        subcloud fails.
        """

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be missing)
        self.sysinv_client.get_license.side_effect = [
            LICENSE_VALID_RESPONSE,
            MISSING_LICENSE_RESPONSE,
        ]

        # Simulate a license install failure on the subcloud
        self.sysinv_client.install_license.return_value = MISSING_LICENSE_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.strategy_type, self.subcloud.region_name, self.strategy_step
        )

        # verify the license install was invoked
        self.sysinv_client.install_license.assert_called()

        # Verify a install_license failure leads to a state failure
        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )

    def test_install_license_succeeds(self):
        """Test the install license step succeeds.

        The license will be installed on the subcloud when system controller
        has a license, the subcloud does not have a license, and the API call
        succeeds.
        """

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be missing)
        self.sysinv_client.get_license.side_effect = [
            LICENSE_VALID_RESPONSE,
            MISSING_LICENSE_RESPONSE,
        ]

        # A license install should return a success
        self.sysinv_client.install_license.return_value = LICENSE_VALID_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.strategy_type, self.subcloud.region_name, self.strategy_step
        )

        # verify the license install was invoked
        self.sysinv_client.install_license.assert_called()

        # On success, the next state after installing license is importing load
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    def test_install_license_skip_existing(self):
        """Test the install license step skipped due to license up to date"""

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud
        self.sysinv_client.get_license.side_effect = [
            LICENSE_VALID_RESPONSE,
            LICENSE_VALID_RESPONSE,
        ]

        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.strategy_type, self.subcloud.region_name, self.strategy_step
        )

        # A license install should not have been attempted due to the license
        # already being up to date
        self.sysinv_client.install_license.assert_not_called()

        # On success, the next state after installing license is importing load
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    def test_install_license_overrides_mismatched_license(self):
        """Test the install license overrides a mismatched license"""

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be valid but different)
        self.sysinv_client.get_license.side_effect = [
            LICENSE_VALID_RESPONSE,
            ALTERNATE_LICENSE_RESPONSE,
        ]

        # A license install should return a success
        self.sysinv_client.install_license.return_value = LICENSE_VALID_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.strategy_type, self.subcloud.region_name, self.strategy_step
        )

        # verify the license install was invoked
        self.sysinv_client.install_license.assert_called()

        # Verify it successfully moves to the next step
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    def test_install_license_skips_with_sys_controller_without_license(self):
        """Test license install skips when sys controller doesn't have a license"""

        # Only makes one query: to system controller
        self.sysinv_client.get_license.return_value = MISSING_LICENSE_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.strategy_type, self.subcloud.region_name, self.strategy_step
        )

        # Should skip install_license API call
        self.sysinv_client.install_license.assert_not_called()

        # Verify it successfully moves to the next step
        self.assert_step_updated(self.strategy_step.subcloud_id, self.on_success_state)

    def test_install_license_fails_with_generic_error_response(self):
        """Test license install fails with generic error response"""

        # Only makes one query: to system controller
        self.sysinv_client.get_license.return_value = GENERIC_ERROR_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker._perform_state_action(
            self.strategy_type, self.subcloud.region_name, self.strategy_step
        )

        subcloud = db_api.subcloud_get(self.ctx, self.subcloud.id)

        self.assertEqual(
            subcloud.error_description,
            "An unexpected error occurred querying the license "
            f"{dccommon_consts.SYSTEM_CONTROLLER_NAME}. "
            f"Detail: {GENERIC_ERROR_RESPONSE['error']}",
        )

        # Should skip install_license API call
        self.sysinv_client.install_license.assert_not_called()

        # Verify it successfully moves to the next step
        self.assert_step_updated(
            self.strategy_step.subcloud_id, consts.STRATEGY_STATE_FAILED
        )
