#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from dcmanager.common import consts
from dcmanager.common.exceptions import VaultLoadMissingError

from dcmanager.tests.unit.manager.states.upgrade.test_base import FakeLoad
from dcmanager.tests.unit.manager.states.upgrade.test_base import FakeSystem
from dcmanager.tests.unit.manager.states.upgrade.test_base \
    import PREVIOUS_VERSION
from dcmanager.tests.unit.manager.states.upgrade.test_base  \
    import TestSwUpgradeState
from dcmanager.tests.unit.manager.states.upgrade.test_base \
    import UPGRADED_VERSION

PREVIOUS_LOAD = FakeLoad(1, software_version=PREVIOUS_VERSION)
UPGRADED_LOAD = FakeLoad(2,
                         compatible_version=PREVIOUS_VERSION,
                         software_version=UPGRADED_VERSION)

DEST_LOAD_EXISTS = [PREVIOUS_LOAD, UPGRADED_LOAD, ]
DEST_LOAD_MISSING = [PREVIOUS_LOAD, ]

FAKE_ISO = '/opt/dc-vault/loads/' + UPGRADED_VERSION + '/bootimage.iso'
FAKE_SIG = '/opt/dc-vault/loads/' + UPGRADED_VERSION + '/bootimage.sig'

FAILED_IMPORT_RESPONSE = 'kaboom'
SUCCESS_IMPORT_RESPONSE = {
    'new_load': {
        'id': 2,
        'uuid': 'aaa4b4c6-8536-41f6-87ea-211d208a723b',
        'compatible_version': PREVIOUS_VERSION,
        'required_patches': '',
        'software_version': UPGRADED_VERSION,
        'state': 'importing',
        'created_at': '2020-06-01 12:12:12+00:00',
        'updated_at': None
    }
}


class TestSwUpgradeImportingLoadStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeImportingLoadStage, self).setUp()

        # next state after 'importing load' is 'starting upgrade'
        self.on_success_state = consts.STRATEGY_STATE_STARTING_UPGRADE

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_IMPORTING_LOAD)

        # Add mock API endpoints for sysinv client calls invcked by this state
        self.sysinv_client.get_system = mock.MagicMock()
        self.sysinv_client.get_system.return_value = FakeSystem()
        self.sysinv_client.get_loads = mock.MagicMock()
        self.sysinv_client.import_load = mock.MagicMock()

    @mock.patch('dcmanager.manager.states.upgrade.utils.get_vault_load_files')
    def test_upgrade_subcloud_importing_load_failure(self, mock_vault_files):
        """Test importing load step where the import_load API call fails."""

        # simulate determine_matching_load finding the iso and sig in the vault
        mock_vault_files.return_value = (FAKE_ISO, FAKE_SIG)

        # Simulate the target load has not been imported yet on the subcloud
        self.sysinv_client.get_loads.return_value = DEST_LOAD_MISSING

        # Simulate an API failure on the subcloud.
        self.sysinv_client.import_load.return_value = FAILED_IMPORT_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the import load API call was invoked
        self.sysinv_client.import_load.assert_called()

        # Verify a failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    @mock.patch('dcmanager.manager.states.upgrade.utils.get_vault_load_files')
    def test_upgrade_subcloud_importing_load_success(self, mock_vault_files):
        """Test the importing load step succeeds.

        The load will be imported on the subcloud when the subcloud does not
        have the load already imported, and the API call succeeds to import it.
        """
        # simulate determine_matching_load finding the iso and sig in the vault
        mock_vault_files.return_value = (FAKE_ISO, FAKE_SIG)

        # Simulate the target load has not been imported yet on the subcloud
        self.sysinv_client.get_loads.return_value = DEST_LOAD_MISSING

        # Simulate an API success on the subcloud.
        self.sysinv_client.import_load.return_value = SUCCESS_IMPORT_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the import load API call was invoked
        self.sysinv_client.import_load.assert_called()

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    @mock.patch('dcmanager.manager.states.upgrade.utils.get_vault_load_files')
    def test_upgrade_subcloud_importing_load_fails_missing_vault_files(
            self,
            mock_determine_matching_load):
        """Test importing load fails when files are not in the vault."""

        mock_determine_matching_load.side_effect = \
            VaultLoadMissingError(file_type='.iso', vault_dir='/mock/vault/')

        # Simulate the target load has not been imported yet on the subcloud
        self.sysinv_client.get_loads.return_value = DEST_LOAD_MISSING

        # Simulate an API success on the subcloud. It should not get here.
        self.sysinv_client.import_load.return_value = SUCCESS_IMPORT_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the import load API call was never invoked
        self.sysinv_client.import_load.assert_not_called()

        # Verify a failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_importing_load_skip_existing(self):
        """Test the importing load step skipped due to load already there"""

        # Simulate the target load has been previously imported on the subcloud
        self.sysinv_client.get_loads.return_value = DEST_LOAD_EXISTS

        # Simulate an API failure for import_load.  It should not be called.
        self.sysinv_client.import_load.return_value = FAILED_IMPORT_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # The import_load should not have been attempted
        self.sysinv_client.import_load.assert_not_called()

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)
