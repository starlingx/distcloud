#
# Copyright (c) 2020, 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts

from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState

MISSING_LICENSE_RESPONSE = {
    u'content': u'',
    u'error': u'License file not found. A license may not have been installed.'
}

LICENSE_VALID_RESPONSE = {
    u'content': u'A valid license',
    u'error': u''
}

ALTERNATE_LICENSE_RESPONSE = {
    u'content': u'A different valid license',
    u'error': u''
}


class TestSwUpgradeInstallingLicenseStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeInstallingLicenseStage, self).setUp()

        # next state after installing a license is 'importing load'
        self.on_success_state = consts.STRATEGY_STATE_IMPORTING_LOAD

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(self.subcloud.id, consts.STRATEGY_STATE_INSTALLING_LICENSE)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_license = mock.MagicMock()
        self.sysinv_client.install_license = mock.MagicMock()

    def test_upgrade_subcloud_license_install_failure(self):
        """Test the installing license step where the install fails.

        The system controller has a license, but the API call to install on the
        subcloud fails.
        """

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be missing)
        self.sysinv_client.get_license.side_effect = [LICENSE_VALID_RESPONSE,
                                                      MISSING_LICENSE_RESPONSE]

        # Simulate a license install failure on the subcloud
        self.sysinv_client.install_license.return_value = \
            MISSING_LICENSE_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the license install was invoked
        self.sysinv_client.install_license.assert_called()

        # Verify a install_license failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_license_install_success(self):
        """Test the install license step succeeds.

        The license will be installed on the subcloud when system controller
        has a license, the subcloud does not have a license, and the API call
        succeeds.
        """

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be missing)
        self.sysinv_client.get_license.side_effect = [LICENSE_VALID_RESPONSE,
                                                      MISSING_LICENSE_RESPONSE]

        # A license install should return a success
        self.sysinv_client.install_license.return_value = \
            LICENSE_VALID_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the license install was invoked
        self.sysinv_client.install_license.assert_called()

        # On success, the next state after installing license is importing load
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_license_skip_existing(self):
        """Test the install license step skipped due to license up to date"""

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud
        self.sysinv_client.get_license.side_effect = [LICENSE_VALID_RESPONSE,
                                                      LICENSE_VALID_RESPONSE]

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # A license install should not have been attempted due to the license
        # already being up to date
        self.sysinv_client.install_license.assert_not_called()

        # On success, the next state after installing license is importing load
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_license_overrides_mismatched_license(self):
        """Test the install license overrides a mismatched license"""

        # Order of get_license calls:
        # first license query is to system controller
        # second license query is to subcloud (should be valid but different)
        self.sysinv_client.get_license.side_effect = \
            [LICENSE_VALID_RESPONSE,
             ALTERNATE_LICENSE_RESPONSE]

        # A license install should return a success
        self.sysinv_client.install_license.return_value = \
            LICENSE_VALID_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the license install was invoked
        self.sysinv_client.install_license.assert_called()

        # Verify it successfully moves to the next step
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_license_skip_when_no_sys_controller_lic(self):
        """Test license install skipped when no license on system controller."""

        # Only makes one query: to system controller
        self.sysinv_client.get_license.return_value = MISSING_LICENSE_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # Should skip install_license API call
        self.sysinv_client.install_license.assert_not_called()

        # Verify it successfully moves to the next step
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)
