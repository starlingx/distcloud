#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import mock

from keystoneauth1.exceptions import EndpointNotFound
from oslo_utils import timeutils

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.vim import STATE_BUILDING
from dccommon.drivers.openstack.vim import STRATEGY_NAME_SW_USM
from dcmanager.common import consts
from dcmanager.common.exceptions import StrategyNotFound
from dcmanager.db import api as db_api
from dcmanager.orchestrator import orchestrator_worker
from dcmanager.orchestrator.strategies.base import BaseStrategy
from dcmanager.tests import base
from dcmanager.tests.unit.common import fake_strategy
from dcmanager.tests.unit.common import fake_subcloud


class BaseTestOrchestratorWorker(base.DCManagerTestCase):
    """Base test class for Orchestrator Worker"""

    def setUp(self):
        super().setUp()

        self._mock_object(orchestrator_worker, "ManagerOrchestratorClient")
        self.mock_scheduler = self._mock_object(orchestrator_worker, "scheduler")
        self.mock_log = self._mock_object(orchestrator_worker, "LOG")
        self.mock_db_api = self._mock_object(
            orchestrator_worker, "db_api", wraps=db_api
        )
        self._mock_object(orchestrator_worker, "time")

        self.orchestrator_worker = orchestrator_worker.OrchestratorWorker()

        self.strategy = fake_strategy.create_fake_strategy(
            self.ctx, consts.SW_UPDATE_TYPE_SOFTWARE, stop_on_failure=False
        )
        self.subclouds = [
            fake_subcloud.create_fake_subcloud(
                self.ctx,
                name="subcloud1",
                region_name=base.SUBCLOUD_1["region_name"],
                deploy_status=consts.DEPLOY_STATE_NONE,
            ),
            fake_subcloud.create_fake_subcloud(
                self.ctx, name="subcloud2", region_name=base.SUBCLOUD_2["region_name"]
            ),
            fake_subcloud.create_fake_subcloud(
                self.ctx, name="subcloud3", region_name=base.SUBCLOUD_3["region_name"]
            ),
            fake_subcloud.create_fake_subcloud(
                self.ctx, name="subcloud4", region_name=base.SUBCLOUD_4["region_name"]
            ),
        ]

        for subcloud in self.subclouds:
            db_api.subcloud_update(
                self.ctx,
                subcloud.id,
                management_state=dccommon_consts.MANAGEMENT_MANAGED,
            )

        self.steps = (
            fake_strategy.create_fake_strategy_step(self.ctx, self.subclouds[0].id),
            fake_strategy.create_fake_strategy_step(self.ctx, self.subclouds[1].id),
            fake_strategy.create_fake_strategy_step(self.ctx, self.subclouds[2].id),
            fake_strategy.create_fake_strategy_step(self.ctx, self.subclouds[3].id),
        )
        self.steps_id = set([step.id for step in self.steps])


class TestOrchestratorWorker(BaseTestOrchestratorWorker):
    """Test class for the Orchestrator Worker"""

    def test_orchestrator_worker_stop(self):
        """Test orchestrator worker's stop"""

        self.orchestrator_worker.stop()

        self.mock_scheduler.ThreadGroupManager().stop.assert_called_once()
        self.assertIsNone(self.orchestrator_worker.thread_group_manager)

    def test_orchestrator_worker_stop_processing(self):
        """Test orchestrator worker's stop processing"""

        self.orchestrator_worker.stop_processing()

        self.assertTrue(self.orchestrator_worker._stop.is_set())


class TestOrchestratorWorkerOrchestrate(BaseTestOrchestratorWorker):
    """Test class for Orchestrator Worker's orchestrate method"""

    def test_orchestrate_without_active_strategy(self):
        """Test orchestrate without active strategy

        When there isn't an active strategy being orchestrated, the steps_received
        should be set and the orchestration thread started.
        """

        self.orchestrator_worker.orchestrate(self.steps_id, self.strategy.type)

        self.mock_log.info(
            f"({self.strategy.type}) Orchestration starting with steps: {self.steps_id}"
        )
        self.mock_scheduler.ThreadGroupManager().start.assert_called_once()
        self.assertEqual(self.orchestrator_worker.strategy_type, self.strategy.type)
        self.assertEqual(self.orchestrator_worker.steps_received, self.steps_id)
        self.assertIsNotNone(self.orchestrator_worker._last_update)

    def test_orchestrate_with_active_strategy(self):
        """Test orchestrate with active strategy

        When there is an active strategy, the self.strategy_type is set and the
        orchestration thread is running, so only the steos_received is updated.
        """

        # Force the strategy_type to be set so the orchestration is identified as
        # running
        self.orchestrator_worker.strategy_type = self.strategy.type
        steps_id = [self.steps[0].id]

        self.orchestrator_worker.orchestrate(steps_id, self.strategy.type)

        self.mock_log.info(
            f"({self.strategy.type}) New steps were received for processing: {steps_id}"
        )
        self.mock_scheduler.ThreadGroupManager().start.assert_not_called()
        self.assertEqual(self.orchestrator_worker.strategy_type, self.strategy.type)
        self.assertEqual(self.orchestrator_worker.steps_received, set(steps_id))


class TestOrchestratorWorkerOrchestrationThread(BaseTestOrchestratorWorker):
    """Test class for Orchestrator Worker's orchestration thread method"""

    def setUp(self):
        super().setUp()

        self.orchestrator_worker.strategy_type = self.strategy.type
        self.orchestrator_worker.steps_to_process = self.steps_id
        self.orchestrator_worker._last_update = timeutils.utcnow()

        # Because the thread group manager is mocked, the execution will not perform
        # all steps. Therefore, the specific _apply, _abort and _delete method will
        # be tested in their respective classes.
        self.orchestrator_worker._apply = mock.MagicMock()
        self.orchestrator_worker._abort = mock.MagicMock()
        self.orchestrator_worker._delete = mock.MagicMock()

    def _mock_method_execution(self, strategy, steps):
        """Replicates the execution of the orchestration methods

        Once they finish their processing, the steps_to_process is cleared and the
        strategy proceeds.
        """

        if self.strategy.state == consts.SW_UPDATE_STATE_ABORT_REQUESTED:
            db_api.sw_update_strategy_update(
                self.ctx, state=consts.SW_UPDATE_STATE_ABORTED
            )
            return

        self.orchestrator_worker.steps_to_process.clear()

    def _assert_orchestration(
        self, strategy_get_calls=0, apply_calls=0, abort_calls=0, delete_calls=0
    ):
        """Assert the class variables are reset when the orchestration completes"""

        self.assertEqual(
            self.mock_db_api.sw_update_strategy_get.call_count, strategy_get_calls
        )
        self.assertEqual(self.orchestrator_worker._apply.call_count, apply_calls)
        self.assertEqual(self.orchestrator_worker._abort.call_count, abort_calls)
        self.assertEqual(self.orchestrator_worker._delete.call_count, delete_calls)
        self.assertIsNone(self.orchestrator_worker.strategy_type)
        self.assertEqual(self.orchestrator_worker.steps_to_process, set())
        self.assertIsNone(self.orchestrator_worker._last_update)
        self.assertEqual(
            self.orchestrator_worker._sleep_time,
            orchestrator_worker.DEFAULT_SLEEP_TIME_IN_SECONDS,
        )

    def test_orchestration_thread_apply(self):
        """Test orchestration thread's apply"""

        # Verify that the steps_received become the steps_to_process
        self.orchestrator_worker.steps_received = self.steps_id
        self.orchestrator_worker.steps_to_process = set()

        # Simulate the worker processing all steps
        self.orchestrator_worker._apply.side_effect = self._mock_method_execution

        db_api.sw_update_strategy_update(
            self.ctx, state=consts.SW_UPDATE_STATE_APPLYING
        )

        self.orchestrator_worker.orchestration_thread()

        self._assert_orchestration(strategy_get_calls=1, apply_calls=1)
        self.assertEqual(self.orchestrator_worker.steps_received, set())
        self.mock_log.info("There are no further steps to process, stopping.")

    def test_orchestration_thread_abort(self):
        """Test orchestration thread's abort

        When the strategy is in abort requested, it will move all steps in initial state
        to aborted and wait for the manager to move the strategy to either aborting or
        aborted. In the latter, the orchestration thread should identify the change,
        execute one last apply to finish the remaining steps and stop.
        """

        # Simulate the worker processing all steps
        self.orchestrator_worker._abort.side_effect = self._mock_method_execution
        self.orchestrator_worker._apply.side_effect = self._mock_method_execution

        self.strategy = db_api.sw_update_strategy_update(
            self.ctx, state=consts.SW_UPDATE_STATE_ABORT_REQUESTED
        )

        self.orchestrator_worker.orchestration_thread()

        self._assert_orchestration(strategy_get_calls=2, abort_calls=1, apply_calls=1)
        self.assertEqual(self.orchestrator_worker.steps_received, set())
        self.mock_log.info(f"({self.strategy.type}) Orchestration stopped")

    def test_orchestration_thread_delete(self):
        """Test orchestration thread's delete"""

        # Simulate the worker processing all steps
        self.orchestrator_worker._delete.side_effect = self._mock_method_execution

        db_api.sw_update_strategy_update(
            self.ctx, state=consts.SW_UPDATE_STATE_DELETING
        )

        self.orchestrator_worker.orchestration_thread()

        self._assert_orchestration(strategy_get_calls=1, delete_calls=1)
        self.assertEqual(self.orchestrator_worker.steps_received, set())
        self.mock_log.info("There are no further steps to process, stopping.")

    def test_orchestration_thread_no_steps_to_process(self):
        """Test orchestration thread's stops when there are no steps to process"""

        self.orchestrator_worker.steps_to_process = set()

        self.orchestrator_worker.orchestration_thread()

        self._assert_orchestration()
        self.mock_log.info("There are no further steps to process, stopping.")

    def test_orchestration_thread_stops_on_strategy_not_found_exception(self):
        """Test orchestration thread stops on strategy not found exception"""

        self.mock_db_api.sw_update_strategy_get.side_effect = StrategyNotFound()
        self.mock_db_api.reset_mock()

        self.orchestrator_worker.orchestration_thread()

        self._assert_orchestration(strategy_get_calls=1)
        self.mock_log.error(
            f"({self.strategy.type}) The strategy was not found, stopping orchestration"
        )

    def test_orchestration_thread_continues_on_generic_exception(self):
        """Test orchestration thread continues on generic exception

        When a generic exception occurs, the execution should not stop. Instead, the
        error is logged and the processing continues.
        """

        # First cause the generic exception to test the expected behavior and generate
        # a StrategyNotFound in the second execution to quit it.
        self.mock_db_api.sw_update_strategy_get.side_effect = [
            Exception(),
            StrategyNotFound(),
        ]
        self.mock_db_api.reset_mock()

        self.orchestrator_worker.orchestration_thread()

        self._assert_orchestration(strategy_get_calls=2)
        self.mock_log.exception(
            f"({self.strategy.type}) Orchestration got an unexpected exception when "
            "processing strategy"
        )


class TestOrchestratorWorkerApply(BaseTestOrchestratorWorker):
    """Test class for Orchestrator Worker's apply method"""

    def setUp(self):
        super().setUp()

        self.steps = [
            db_api.strategy_step_update(
                self.ctx, self.subclouds[0].id, state=consts.STRATEGY_STATE_COMPLETE
            ),
            db_api.strategy_step_update(
                self.ctx, self.subclouds[1].id, state=consts.STRATEGY_STATE_ABORTED
            ),
            db_api.strategy_step_update(
                self.ctx, self.subclouds[2].id, state=consts.STRATEGY_STATE_FAILED
            ),
            db_api.strategy_step_update(
                self.ctx, self.subclouds[3].id, state=consts.STRATEGY_STATE_INITIAL
            ),
        ]
        self.orchestrator_worker._stop.clear()

    def test_apply_with_different_states(self):
        """Test apply with different states"""

        self.orchestrator_worker._apply(self.strategy, self.steps_id)

        self.mock_db_api.strategy_step_get_all.assert_called_once()
        self.mock_db_api.strategy_step_bulk_update.assert_called_once()
        # The step 3 is the only one that did not finish execution
        steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(steps[3].stage, consts.STAGE_SUBCLOUD_ORCHESTRATION_STARTED)
        self.assertEqual(
            steps[3].state,
            self.orchestrator_worker.strategies[self.strategy.type].starting_state,
        )


class TestOrchestratorWorkerAbort(BaseTestOrchestratorWorker):
    """Test class for Orchestrator Worker's abort method"""

    def test_abort_succeeds(self):
        """Test abort succeeds"""

        # Update one of the steps to an applying state to verify it won't be updated
        db_api.strategy_step_update(
            self.ctx,
            self.steps[0].subcloud_id,
            state=consts.STRATEGY_STATE_SW_PRE_CHECK,
        )

        self.orchestrator_worker._abort(self.strategy, self.steps_id)

        steps = db_api.strategy_step_get_all(self.ctx)
        self.assertEqual(len(self.steps_id), len(steps))

        # The database returns the steps in order, so they can be checked by accessing
        # the index directly
        expected_states = [
            consts.STRATEGY_STATE_SW_PRE_CHECK,
            consts.STRATEGY_STATE_ABORTED,
            consts.STRATEGY_STATE_ABORTED,
        ]

        for index, state in enumerate(expected_states):
            self.assertEqual(steps[index].state, state)

        self.mock_db_api.strategy_step_update_all.assert_called_once()
        self.assertEqual(
            self.orchestrator_worker._sleep_time,
            orchestrator_worker.MANAGER_SLEEP_TIME_IN_SECONDS,
        )


class TestOrchestratorWorkerDelete(BaseTestOrchestratorWorker):
    """Test class for Orchestrator Worker's delete method"""

    def test_delete_succeeds_with_step_not_being_processed(self):
        """Test delete succeeds with step not being processed

        When the delete is requested for the first time, the deletion thread for the
        step won't exist and it will be created.
        """

        # Mock one of the subclouds being in process
        self.orchestrator_worker.subcloud_workers[self.subclouds[0].region_name] = (
            self.orchestrator_worker.thread_group_manager.start(
                self.orchestrator_worker._delete_subcloud_strategy,
                self.strategy.type,
                self.subclouds[0].region_name,
                self.steps[0],
            )
        )

        self.orchestrator_worker._delete(self.strategy, self.steps_id)

        self.assertEqual(self.orchestrator_worker.steps_to_process, set())
        self.mock_db_api.strategy_step_get_all.assert_called_once()
        self.mock_db_api.strategy_step_destroy_all.assert_called_once()
        calls = [
            mock.call.info(f"({self.strategy.type}) Deleting strategy"),
            mock.call.debug(
                f"({self.strategy.type}) Worker already exists for "
                f"{self.subclouds[0].region_name}"
            ),
            mock.call.info(f"({self.strategy.type}) Finished deleting strategy steps"),
        ]
        self.mock_log.assert_has_calls(calls)

    def test_delete_succeeds_with_orchestration_stopped(self):
        """Test delete succeeds with orchestration stopped"""

        self.orchestrator_worker.stop_processing()

        self.orchestrator_worker._delete(self.strategy, self.steps_id)

        self.mock_db_api.strategy_step_get_all.assert_called_once()
        self.mock_db_api.strategy_step_destroy_all.assert_not_called()
        calls = [
            mock.call.info(f"({self.strategy.type}) Deleting strategy"),
            mock.call.info(
                f"({self.strategy.type}) Exiting because task is stopped for strategy"
            ),
        ]
        self.mock_log.assert_has_calls(calls)

    def test_delete_fails_with_database_exception(self):
        """Test delete fails with database exception"""

        self.mock_db_api.strategy_step_destroy_all.side_effect = base.FakeException(
            "fake"
        )

        self.assertRaises(
            base.FakeException,
            self.orchestrator_worker._delete,
            self.strategy,
            self.steps_id,
        )

        self.mock_db_api.strategy_step_get_all.assert_called_once()
        self.mock_db_api.strategy_step_destroy_all.assert_called_once()
        calls = [
            mock.call.info(f"({self.strategy.type}) Deleting strategy"),
            mock.call.exception(f"({self.strategy.type}) exception during delete"),
        ]
        self.mock_log.assert_has_calls(calls)


class TestOrchestratorWorkerDeleteSubcloudStrategy(BaseTestOrchestratorWorker):
    """Test class for Orchestrator Worker's _delete_subcloud_strategy method

    Because the thread group manager is mocked for most tests, a specific class is
    required to validate the deletion method called by _delete.
    """

    def setUp(self):
        super().setUp()

        self.mock_vim_client = self._mock_object(BaseStrategy, "get_vim_client")

        self.region_name = self.subclouds[0].region_name
        self.step = db_api.strategy_step_update(
            self.ctx, self.steps[0].subcloud_id, state=consts.STRATEGY_STATE_COMPLETE
        )

    def _assert_calls(self, message=None, delete_called=False):
        self.mock_vim_client.assert_called_once()
        self.mock_vim_client().get_strategy.assert_called_once()

        if delete_called:
            self.mock_vim_client().delete_strategy.assert_called_once()
        else:
            self.mock_vim_client().delete_strategy.assert_not_called()

        if message:
            self.mock_log.warn.assert_called_once_with(message)
        else:
            self.mock_log.warn.assert_not_called()

    def test_delete_subcloud_strategy_succeeds(self):
        """Test delete subcloud strategy succeeds"""

        # Add a fake subcloud worker for the region to confirm that it will be removed
        # once the execution completes
        self.orchestrator_worker.subcloud_workers[self.region_name] = "fake"

        self.orchestrator_worker._delete_subcloud_strategy(
            self.strategy.type, self.region_name, self.step
        )

        self.assertNotIn(self.region_name, self.orchestrator_worker.subcloud_workers)
        self._assert_calls(delete_called=True)

    def test_delete_subcloud_strategy_fails_with_get_strategy_exception(self):
        """Test delete subcloud strategy fails with get_strategy exception"""

        self.mock_vim_client().get_strategy.side_effect = EndpointNotFound()
        self.mock_vim_client.reset_mock()

        self.orchestrator_worker._delete_subcloud_strategy(
            self.strategy.type, self.region_name, self.step
        )

        self._assert_calls(
            f"({self.strategy.type}) Endpoint for subcloud: {self.region_name} not "
            "found"
        )

    def test_delete_subcloud_strategy_fails_with_get_strategy_generic_exception(self):
        """Test delete subcloud strategy fails with get_strategy generic exception"""

        self.mock_vim_client().get_strategy.side_effect = Exception()
        self.mock_vim_client.reset_mock()

        self.orchestrator_worker._delete_subcloud_strategy(
            self.strategy.type, self.region_name, self.step
        )

        self._assert_calls()

    def test_delete_subcloud_strategy_fails_with_invalid_strategy_state(self):
        """Test delete subcloud strategy fails with invalid strategy state"""

        mock_state = mock.MagicMock()
        mock_state.state = STATE_BUILDING
        self.mock_vim_client().get_strategy.return_value = mock_state
        self.mock_vim_client.reset_mock()

        self.orchestrator_worker._delete_subcloud_strategy(
            self.strategy.type, self.region_name, self.step
        )

        self._assert_calls(
            f"({self.strategy.type}) Vim strategy:({STRATEGY_NAME_SW_USM}) for region:("
            f"{self.region_name}) in wrong state:({mock_state.state}) for delete."
        )

    def test_delete_subcloud_strategy_fails_with_delete_strategy_exception(self):
        """Test delete subcloud strategy fails with delete_strategy exception"""

        self.mock_vim_client().delete_strategy.side_effect = Exception()
        self.mock_vim_client.reset_mock()

        self.orchestrator_worker._delete_subcloud_strategy(
            self.strategy.type, self.region_name, self.step
        )

        self._assert_calls(
            f"({self.strategy.type}) Vim strategy:({STRATEGY_NAME_SW_USM}) delete "
            f"failed for region:({self.region_name})",
            True,
        )
