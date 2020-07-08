#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dcmanager.common import consts
from dcmanager.common.exceptions import VaultLoadMissingError
from dcmanager.manager.states.upgrade import importing_load

from dcmanager.tests.unit.manager.states.fakes import FakeLoad
from dcmanager.tests.unit.manager.states.fakes import FakeSystem
from dcmanager.tests.unit.manager.states.fakes import PREVIOUS_VERSION
from dcmanager.tests.unit.manager.states.fakes import UPGRADED_VERSION
from dcmanager.tests.unit.manager.states.upgrade.test_base  \
    import TestSwUpgradeState

PREVIOUS_LOAD = FakeLoad(1, software_version=PREVIOUS_VERSION)
UPGRADED_LOAD = FakeLoad(2,
                         compatible_version=PREVIOUS_VERSION,
                         software_version=UPGRADED_VERSION)
# Use the same fields for the IMPORTING_LOAD as UPGRADED_LOAD
IMPORTING_LOAD = FakeLoad(UPGRADED_LOAD.id,
                          state='importing',
                          compatible_version=UPGRADED_LOAD.compatible_version,
                          software_version=UPGRADED_LOAD.software_version)
# Use the same fields for the IMPORTED_LOAD as UPGRADED_LOAD
IMPORTED_LOAD = FakeLoad(UPGRADED_LOAD.id,
                         state='imported',
                         compatible_version=UPGRADED_LOAD.compatible_version,
                         software_version=UPGRADED_LOAD.software_version)

DEST_LOAD_EXISTS = [PREVIOUS_LOAD, UPGRADED_LOAD, ]
DEST_LOAD_MISSING = [PREVIOUS_LOAD, ]

FAKE_ISO = '/opt/dc-vault/loads/' + UPGRADED_VERSION + '/bootimage.iso'
FAKE_SIG = '/opt/dc-vault/loads/' + UPGRADED_VERSION + '/bootimage.sig'

FAILED_IMPORT_RESPONSE = 'kaboom'
SUCCESS_IMPORTING_RESPONSE = {
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


@mock.patch("dcmanager.manager.states.upgrade.importing_load."
            "DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.manager.states.upgrade.importing_load."
            "DEFAULT_SLEEP_DURATION", 1)
class TestSwUpgradeImportingLoadStage(TestSwUpgradeState):

    def setUp(self):
        super(TestSwUpgradeImportingLoadStage, self).setUp()

        # next state after 'importing load' is 'starting upgrade'
        self.on_success_state = consts.STRATEGY_STATE_STARTING_UPGRADE

        # Add the strategy_step state being processed by this unit test
        self.strategy_step = \
            self.setup_strategy_step(consts.STRATEGY_STATE_IMPORTING_LOAD)

        # Mock the get_vault_load_files utility method
        p = mock.patch(
            'dcmanager.manager.states.upgrade.utils.get_vault_load_files')
        self.mock_vault_files = p.start()
        # simulate get_vault_load_files finding the iso and sig in the vault
        self.mock_vault_files.return_value = (FAKE_ISO, FAKE_SIG)
        self.addCleanup(p.stop)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_system = mock.MagicMock()
        self.sysinv_client.get_system.return_value = FakeSystem()
        self.sysinv_client.get_loads = mock.MagicMock()
        self.sysinv_client.get_load = mock.MagicMock()
        self.sysinv_client.import_load = mock.MagicMock()

    def test_upgrade_subcloud_importing_load_failure(self):
        """Test importing load step where the import_load API call fails."""

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

    def test_upgrade_subcloud_importing_load_success(self):
        """Test the importing load step succeeds.

        The load will be imported on the subcloud when the subcloud does not
        have the load already imported, and the API call succeeds to import it.
        """

        # Simulate the target load has not been imported yet on the subcloud
        self.sysinv_client.get_loads.return_value = DEST_LOAD_MISSING

        # Simulate an API success on the subcloud.
        self.sysinv_client.import_load.return_value = \
            SUCCESS_IMPORTING_RESPONSE

        # mock the get_load queries to return 'imported' and not 'importing'
        self.sysinv_client.get_load.return_value = IMPORTED_LOAD

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the import load API call was invoked
        self.sysinv_client.import_load.assert_called()

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_subcloud_importing_load_fails_missing_vault_files(self):
        """Test importing load fails when files are not in the vault."""

        self.mock_vault_files.side_effect = \
            VaultLoadMissingError(file_type='.iso', vault_dir='/mock/vault/')

        # Simulate the target load has not been imported yet on the subcloud
        self.sysinv_client.get_loads.return_value = DEST_LOAD_MISSING

        # import_load will not be invoked, so nothing to mock for it

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

        # import_load will not be invoked, so nothing to mock for it

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # The import_load should not have been attempted
        self.sysinv_client.import_load.assert_not_called()

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_importing_load_timeout(self):
        """Test import_load invoked and fails if times out before 'imported'

        The API call succeeds, however the state times out waiting for
        load state to transition from 'importing' to 'imported'
        """
        # Simulate the target load has not been imported yet on the subcloud
        self.sysinv_client.get_loads.return_value = DEST_LOAD_MISSING

        # Simulate an API success on the subcloud.
        self.sysinv_client.import_load.return_value = \
            SUCCESS_IMPORTING_RESPONSE

        # mock the get_load queries to return 'importing' and not 'imported'
        self.sysinv_client.get_load.side_effect = \
            itertools.repeat(IMPORTING_LOAD)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the import load API call was invoked
        self.sysinv_client.import_load.assert_called()

        # verify the query was invoked max_attempts times
        self.assertEqual(importing_load.DEFAULT_MAX_QUERIES,
                         self.sysinv_client.get_load.call_count)

        # verify that state failed due to the import_load never finishing
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
