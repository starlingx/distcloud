#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import itertools
import mock

from dcmanager.common import consts
from dcmanager.common.exceptions import VaultLoadMissingError
from dcmanager.orchestrator.states.upgrade import importing_load

from dcmanager.tests.unit.orchestrator.states.fakes import FakeLoad
from dcmanager.tests.unit.orchestrator.states.fakes import FakeSystem
from dcmanager.tests.unit.orchestrator.states.fakes import PREVIOUS_PREVIOUS_VERSION
from dcmanager.tests.unit.orchestrator.states.fakes import PREVIOUS_VERSION
from dcmanager.tests.unit.orchestrator.states.fakes import UPGRADED_VERSION
from dcmanager.tests.unit.orchestrator.states.upgrade.test_base  \
    import TestSwUpgradeState


PREVIOUS_PREVIOUS_LOAD = FakeLoad(0, software_version=PREVIOUS_PREVIOUS_VERSION,
                                  state='imported')
PREVIOUS_LOAD = FakeLoad(1, software_version=PREVIOUS_VERSION,
                         state='active')
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

DEST_LOAD_EXISTS = [UPGRADED_LOAD, ]
DEST_LOAD_MISSING = [PREVIOUS_LOAD, ]
DEST_LOAD_MISSING_2_LOADS = [PREVIOUS_LOAD, PREVIOUS_PREVIOUS_LOAD, ]

FAKE_ISO = '/opt/dc-vault/loads/' + UPGRADED_VERSION + '/bootimage.iso'
FAKE_SIG = '/opt/dc-vault/loads/' + UPGRADED_VERSION + '/bootimage.sig'

FAILED_IMPORT_RESPONSE = 'kaboom'

# To simulate a response where a database record has already been created
# but the state was set to 'error'.
FAILED_IMPORT_RESPONSE_PROCESSING_ERROR = FakeLoad.from_dict({
    'obj_id': 2,
    'compatible_version': PREVIOUS_VERSION,
    'required_patches': '',
    'software_version': UPGRADED_VERSION,
    'state': 'error',
    'created_at': '2020-06-01 12:12:12+00:00',
    'updated_at': None
})

SUCCESS_IMPORTING_RESPONSE = FakeLoad.from_dict({
    'obj_id': 2,
    'compatible_version': PREVIOUS_VERSION,
    'required_patches': '',
    'software_version': UPGRADED_VERSION,
    'state': 'importing',
    'created_at': '2020-06-01 12:12:12+00:00',
    'updated_at': None
})

SUCCESS_IMPORT_METADATA_RESPONSE = FakeLoad.from_dict({
    'obj_id': 2,
    'compatible_version': PREVIOUS_VERSION,
    'required_patches': '',
    'software_version': UPGRADED_VERSION,
    'state': 'imported-metadata',
    'created_at': '2020-06-01 12:12:12+00:00',
    'updated_at': None
})

SUCCESS_DELETE_RESPONSE = {
    'id': 0,
    'uuid': 'aaa4b4c6-8536-41f6-87ea-211d208a723b',
    'compatible_version': PREVIOUS_VERSION,
    'required_patches': '',
    'software_version': PREVIOUS_PREVIOUS_VERSION,
    'state': 'deleting',
    'created_at': '2020-06-01 12:12:12+00:00',
    'updated_at': None
}


@mock.patch("dcmanager.orchestrator.states.upgrade.importing_load."
            "DEFAULT_MAX_QUERIES", 3)
@mock.patch("dcmanager.orchestrator.states.upgrade.importing_load."
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
            'dcmanager.common.utils.get_vault_load_files')
        self.mock_vault_files = p.start()
        # simulate get_vault_load_files finding the iso and sig in the vault
        self.mock_vault_files.return_value = (FAKE_ISO, FAKE_SIG)
        self.addCleanup(p.stop)

        # Add mock API endpoints for sysinv client calls invoked by this state
        self.sysinv_client.get_system = mock.MagicMock()
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_DUPLEX
        self.sysinv_client.get_system.return_value = system_values
        self.sysinv_client.get_loads = mock.MagicMock()
        self.sysinv_client.get_load = mock.MagicMock()
        self.sysinv_client.delete_load = mock.MagicMock()
        self.sysinv_client.import_load = mock.MagicMock()
        self.sysinv_client.import_load_metadata = mock.MagicMock()

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

    def test_upgrade_subcloud_importing_load_with_old_load_success(self):
        """Test the importing load step succeeds with existing old load

        The old (N-1) load already exists and is removed before importing the
        new (N+1) load. Both the delete_load and import_load call succeed.
        """

        # Simulate the target load has not been imported yet on the subcloud
        # Mock get_loads API to return 2 loads in the first call and 1 load
        # in subsequent call.
        self.sysinv_client.get_loads.side_effect = [
            DEST_LOAD_MISSING_2_LOADS, DEST_LOAD_MISSING, ]

        # Simulate a delete_load API success on the subcloud.
        self.sysinv_client.delete_load.return_value = \
            SUCCESS_DELETE_RESPONSE

        # Simulate an API success on the subcloud.
        self.sysinv_client.import_load.return_value = \
            SUCCESS_IMPORTING_RESPONSE

        # mock the get_load queries to return 'imported' and not 'importing'
        self.sysinv_client.get_load.return_value = IMPORTED_LOAD

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the delete load API call was invoked
        self.sysinv_client.delete_load.assert_called()

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

    def test_upgrade_subcloud_importing_load_general_failure(self):
        """Test import_load invoked and fails due to general failure condition

        The API call returns no new load data. This scenario can be
        observed following a connection, disk space, sematic check or load
        validation failure.
        """

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

    def test_upgrade_subcloud_importing_load_processing_error(self):
        """Test import_load invoked and fails due to error state

        The API call succeeds, however subsequent get_load call
        returns a load in error state. This scenario can be observed
        if sysinv conductor fails to process the import request in
        the background.
        """

        # Simulate the target load has not been imported yet on the subcloud
        self.sysinv_client.get_loads.return_value = DEST_LOAD_MISSING

        # Simulate an API success on the subclould.
        self.sysinv_client.import_load.return_value = SUCCESS_IMPORTING_RESPONSE

        # mock the get_load queries to return 'error' state load data
        self.sysinv_client.get_load.return_value = \
            FAILED_IMPORT_RESPONSE_PROCESSING_ERROR

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the import load API call was invoked
        self.sysinv_client.import_load.assert_called()

        # Verify a failure leads to a state failure
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_subcloud_importing_load_timeout(self):
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

    def test_upgrade_subcloud_deleting_load_timeout(self):
        """Test delete_load invoked and fails if times out

        The subcloud still has an N-1 load that needs to be removed before
        the N+1 load can be imported. The API call to delete this old load
        succeeds, however the state times out waiting for the load to be
        removed.
        """
        # Simulate the target load has not been imported yet on the subcloud
        self.sysinv_client.get_loads.return_value = DEST_LOAD_MISSING_2_LOADS

        # Simulate a delete_load API success on the subcloud.
        self.sysinv_client.delete_load.return_value = \
            SUCCESS_DELETE_RESPONSE

        # mock the get_loads queries to return 2 loads
        self.sysinv_client.get_loads.side_effect = \
            itertools.repeat(DEST_LOAD_MISSING_2_LOADS)

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the import load API call was invoked
        self.sysinv_client.delete_load.assert_called()

        # verify the get_loads query was invoked 1 + max_attempts times
        self.assertEqual(importing_load.DEFAULT_MAX_QUERIES + 1,
                         self.sysinv_client.get_loads.call_count)

        # verify that state failed due to the delete load never finishing
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)

    def test_upgrade_sx_subcloud_import_success(self):
        """Test import_load_metadata invoked and strategy continues as expected"""
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_SIMPLEX
        self.sysinv_client.get_system.return_value = system_values

        # Two get load calls. One to the subcloud one to the system controller
        self.sysinv_client.get_loads.side_effect = [
            DEST_LOAD_MISSING, DEST_LOAD_EXISTS, ]

        # Simulate an API success on the subcloud.
        self.sysinv_client.import_load_metadata.return_value = \
            SUCCESS_IMPORT_METADATA_RESPONSE

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the import load metadata API call was invoked
        self.sysinv_client.import_load_metadata.assert_called()

        # On success, should have moved to the next state
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 self.on_success_state)

    def test_upgrade_sx_subcloud_import_failure(self):
        """Test when import_load_metadata fails the strategy exits"""
        system_values = FakeSystem()
        system_values.system_mode = consts.SYSTEM_MODE_SIMPLEX
        self.sysinv_client.get_system.return_value = system_values

        # Two get load calls. One to the subcloud one to the system controller
        self.sysinv_client.get_loads.side_effect = [
            DEST_LOAD_MISSING, DEST_LOAD_EXISTS, ]

        # Simulate an API failure on the subcloud.
        self.sysinv_client.import_load_metadata.side_effect = \
            Exception("Failure to create load")

        # invoke the strategy state operation on the orch thread
        self.worker.perform_state_action(self.strategy_step)

        # verify the import load metadata API call was invoked
        self.sysinv_client.import_load_metadata.assert_called()

        # verify that strategy state is set to failed
        self.assert_step_updated(self.strategy_step.subcloud_id,
                                 consts.STRATEGY_STATE_FAILED)
