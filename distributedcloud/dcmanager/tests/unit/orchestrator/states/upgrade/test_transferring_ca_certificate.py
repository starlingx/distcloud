#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.orchestrator.states.upgrade import transfer_ca_certificate

from dcmanager.tests.unit.orchestrator.states.fakes import FakeSystem
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base \
    import TestSwUpgradeState

FAKE_CERT = "-----BEGIN CERTIFICATE-----\nMIIDAO\n-----END CERTIFICATE-----\n"
FAKE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIDAO\n-----END PRIVATE KEY-----\n"


class TestSwUpgradeSimplexTransferringCACertificateStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeSimplexTransferringCACertificateStage, self).setUp()

        # next state after 'transferring CA certificate' is 'locking controller-0'
        self.on_success_state = consts.STRATEGY_STATE_LOCKING_CONTROLLER_0

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_TRANSFERRING_CA_CERTIFICATE)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.update_certificate = mock.MagicMock()
        self.sysinv_client.get_system = mock.MagicMock()
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_SIMPLEX
        self.sysinv_client.get_system.return_value = system_values

    def test_upgrade_subcloud_upgrade_transferring_ca_certificate_skipped(self):
        """Test transferring CA certificate is skipped for the Simplex."""

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the API call was not invoked
        self.sysinv_client.update_certificate.assert_not_called()

        # On simplex, the step is skipped and the state should transition to
        # the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)


@mock.patch("dcmanager.orchestrator.states.upgrade.transfer_ca_certificate"
            ".DEFAULT_SLEEP_DURATION", 1)
class TestSwUpgradeDuplexTransferringCACertificateStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeDuplexTransferringCACertificateStage, self).setUp()

        # next state after 'transferring CA certificate' is 'locking controller-1'
        self.on_success_state = consts.STRATEGY_STATE_LOCKING_CONTROLLER_1

        # Add the subcloud being processed by this unit test
        self.subcloud = self.setup_subcloud()

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = self.setup_strategy_step(
            self.subcloud.id, consts.STRATEGY_STATE_TRANSFERRING_CA_CERTIFICATE)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.update_certificate = mock.MagicMock()
        self.sysinv_client.get_system = mock.MagicMock()
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_DUPLEX
        self.sysinv_client.get_system.return_value = system_values

    def test_upgrade_subcloud_upgrade_transferring_ca_certificate_success(self):
        """Test transferring_ca_certificate where the API call succeeds."""

        # simulate get_certificate_from_secret finding the openldap ca certificate
        p = mock.patch('dcmanager.common.utils.get_certificate_from_secret')
        self.mock_cert_file = p.start()
        self.mock_cert_file.return_value = (FAKE_CERT, FAKE_KEY)
        self.addCleanup(p.stop)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify update_certificate was invoked
        self.sysinv_client.update_certificate.assert_called_with(
            '', FAKE_CERT + FAKE_KEY, {'mode': 'openldap_ca'})

        # On success, the state should transition to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_upgrade_transferring_ca_certificate_fails_get_cert(
            self):
        """Test API call fails due to failing to get certificate from secret."""

        # simulate get_certificate_from_secret failing to get
        # the openldap ca certificate
        p = mock.patch('dcmanager.common.utils.get_certificate_from_secret')
        self.mock_cert_file = p.start()
        self.mock_cert_file.side_effect = Exception("Invalid certificated")
        self.addCleanup(p.stop)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify update_certificate was not invoked
        self.sysinv_client.update_certificate.assert_not_called()

        # Verify the failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_upgrade_transferring_ca_certificate_fails_update_cert(
            self):
        """Test API call fails due to failing to update certificate."""

        # simulate get_certificate_from_secret finding the openldap ca certificate
        p = mock.patch('dcmanager.common.utils.get_certificate_from_secret')
        self.mock_cert_file = p.start()
        self.mock_cert_file.return_value = (FAKE_CERT, FAKE_KEY)
        self.addCleanup(p.stop)

        # simulate update_certificate failing to update
        self.sysinv_client.update_certificate.side_effect = Exception(
            "Faile to update certificated")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify update_certificate was invoked
        self.sysinv_client.update_certificate.assert_called_with(
            '', FAKE_CERT + FAKE_KEY, {'mode': 'openldap_ca'})

        # verify the update_certificate was invoked: 1 + max_retries times
        self.assertEqual(transfer_ca_certificate.DEFAULT_MAX_RETRIES + 1,
                         self.sysinv_client.update_certificate.call_count)

        # Verify the failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
