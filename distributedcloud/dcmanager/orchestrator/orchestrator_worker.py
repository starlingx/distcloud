# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2025 Wind River Systems, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

import datetime
import threading
import time

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import prestage
from dcmanager.common import scheduler
from dcmanager.db import api as db_api
from dcmanager.orchestrator.rpcapi import ManagerOrchestratorClient
from dcmanager.orchestrator.strategies.firmware import FirmwareStrategy
from dcmanager.orchestrator.strategies.kube_rootca import KubeRootcaStrategy
from dcmanager.orchestrator.strategies.kubernetes import KubernetesStrategy
from dcmanager.orchestrator.strategies.prestage import PrestageStrategy
from dcmanager.orchestrator.strategies.software import SoftwareStrategy

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
DEFAULT_SLEEP_TIME_IN_SECONDS = 10
DELETE_COUNTER = 18
MANAGER_SLEEP_TIME_IN_SECONDS = 30


class OrchestratorWorker(object):
    """Orchestrator worker

    This class is responsible for orchestrating strategy steps based on the requests
    from the orchestrator manager, which sends the steps and strategy step to process.
    """

    def __init__(self):
        self.context = context.get_admin_context()
        # Keeps track of greenthreads we create to do work.
        # The one additional thread is used to run the orchestration itself
        self.thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=(
                (consts.MAX_PARALLEL_SUBCLOUDS_LIMIT / CONF.orch_worker_workers) + 1
            )
        )
        # Track worker created for each subcloud.
        self.subcloud_workers = dict()
        # Track the steps that needs to be processed in the worker
        self.steps_to_process = set()
        self.steps_received = set()
        self.steps_lock = threading.Lock()
        # Track the strategy type being executed in the worker
        self.strategy_type = None
        self.orchestrator_manager_rpc_client = ManagerOrchestratorClient()
        # Determines if the worker is still processing the strategy steps or if the
        # execution should finish
        self._processing = True
        # Determines if the worker should not process new steps
        self._stop = threading.Event()
        # Time for the orchestration to sleep after every loop
        self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS
        # Time for the last cycle evaluation. Because the manager thread retrieves
        # the subclouds that needs to be processed every so often, the workers needs
        # to ensure the updated_at is reset after some time to avoid the manager
        # picking a subcloud that is still being processed
        self._last_update = None
        # Strategies orchestration process
        self.strategies = {
            consts.SW_UPDATE_TYPE_FIRMWARE: FirmwareStrategy(),
            consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE: KubeRootcaStrategy(),
            consts.SW_UPDATE_TYPE_KUBERNETES: KubernetesStrategy(),
            consts.SW_UPDATE_TYPE_PRESTAGE: PrestageStrategy(),
            consts.SW_UPDATE_TYPE_SOFTWARE: SoftwareStrategy(),
        }
        # Handlers for strategy step data update
        self.strategy_step_data = list()
        self.strategy_step_lock = threading.Lock()
        # Handlers for subcloud data update
        self.subcloud_data = list()
        self.subcloud_lock = threading.Lock()

    def stop(self):
        self.thread_group_manager.stop()
        self.thread_group_manager = None

    def _update_strategy_step_data(self, step_id, **kwargs):
        with self.strategy_step_lock:
            self.strategy_step_data.append({"id": step_id, **kwargs})

    def _update_subcloud_data(self, subcloud_id, **kwargs):
        with self.subcloud_lock:
            self.subcloud_data.append({"id": subcloud_id, **kwargs})

    def _bulk_update_subcloud_and_strategy_steps(self):
        with self.strategy_step_lock:
            if self.strategy_step_data:
                LOG.info(
                    f"({self.strategy_type}) Bulk updating "
                    f"{len(self.strategy_step_data)} strategy steps"
                )
                db_api.strategy_step_bulk_update(self.context, self.strategy_step_data)

                self.strategy_step_data.clear()

        with self.subcloud_lock:
            if self.subcloud_data:
                LOG.info(
                    f"({self.strategy_type}) Bulk updating {len(self.subcloud_data)} "
                    "subclouds"
                )
                db_api.subcloud_bulk_update(self.context, self.subcloud_data)

                self.subcloud_data.clear()

    @staticmethod
    def _get_region_name(step):
        """Get the region name for a step"""
        return step.subcloud.region_name

    @staticmethod
    def _format_update_details(last_state, info):
        # Optionally include the last state, since the current state is likely 'failed'
        if last_state:
            details = "%s: %s" % (last_state, info)
        else:
            details = str(info)
        # details cannot exceed 1000 chars. inform user to check full logs
        if len(details) > 1000:
            details = (
                "Error message longer than 1000 characters, "
                "please check orchestrator logs for additional details."
            )
        return details

    def stop_processing(self):
        self._stop.set()

    def reset_updated_at(self):
        # Everytime half of the orchestration interval has passed, the updated_at
        # field needs to be reset to the current time to show that the subclouds
        # are in active orchestration, avoiding the manager identifying them as idle
        if (timeutils.utcnow() - self._last_update).total_seconds() > (
            CONF.scheduler.orchestration_interval / 2
        ):
            last_update_threshold = timeutils.utcnow() - datetime.timedelta(
                seconds=(CONF.scheduler.orchestration_interval / 2)
            )
            self._last_update = timeutils.utcnow()

            with self.strategy_step_lock:
                db_api.strategy_step_update_reset_updated_at(
                    self.context, self.steps_to_process, last_update_threshold
                )

    def orchestrate(self, steps_id, strategy_type):
        if self.strategy_type is None:
            LOG.info(f"({strategy_type}) Orchestration starting with steps: {steps_id}")
            # If the strategy does not exist, set the steps to process directly
            with self.steps_lock:
                self.steps_received = set(steps_id)
            self.strategy_type = strategy_type
            self.thread_group_manager.start(self.orchestration_thread)
            self._last_update = timeutils.utcnow()
        else:
            # There can only be a single strategy executing at all times. Because of
            # that, if the strategy is already being tracked in the worker, only the
            # steps needs to be extended
            LOG.info(
                f"({strategy_type}) New steps were received for processing: {steps_id}"
            )
            # When the strategy exists, the steps should not be set directly to avoid
            # concurrency issues.
            with self.steps_lock:
                self.steps_received.update(steps_id)

    def orchestration_thread(self):
        # Reset the control flags since a new process started
        self._stop.clear()
        self._processing = True

        while self._processing:
            with self.steps_lock:
                if self.steps_received:
                    self.steps_to_process.update(self.steps_received)
                    self.steps_received.clear()

            # When the steps to process is empty, it means that there is no further
            # processing required and the worker should stop until new steps are
            # received.
            if not self.steps_to_process:
                LOG.info("There are no further steps to process, stopping.")
                self._processing = False

                # Confirm that there are no pending database requests before stopping
                # the worker
                self._bulk_update_subcloud_and_strategy_steps()
                break

            self.reset_updated_at()

            try:
                LOG.debug(
                    f"({self.strategy_type}) Orchestration is running for "
                    f"{len(self.steps_to_process)}"
                )

                strategy = db_api.sw_update_strategy_get(
                    self.context, update_type=self.strategy_type
                )

                if strategy.state in [
                    consts.SW_UPDATE_STATE_APPLYING,
                    consts.SW_UPDATE_STATE_ABORTING,
                ]:
                    self.strategies[strategy.type]._pre_apply_setup(strategy)
                    self._apply(strategy, self.steps_to_process)
                elif strategy.state == consts.SW_UPDATE_STATE_ABORT_REQUESTED:
                    self._abort(strategy, self.steps_to_process)
                elif strategy.state == consts.SW_UPDATE_STATE_DELETING:
                    self._delete(strategy, self.steps_to_process)
                # When a strategy reaches a finished state, it needs to return to
                # stop the thread
                else:
                    # When a strategy is set to aborted, it is possible that some
                    # steps were not yet removed from the orchestrator_workers.
                    # Because of that, an additional loop is required.
                    if self.steps_to_process:
                        self._apply(strategy, self.steps_to_process)

                    LOG.info(f"({self.strategy_type}) Orchestration stopped")
                    self._processing = False
                    continue
            except exceptions.StrategyNotFound:
                LOG.error(
                    f"({self.strategy_type}) The strategy was not found, "
                    "stopping orchestration"
                )
                self._processing = False
            except Exception:
                # We catch all exceptions to avoid terminating the thread.
                LOG.exception(
                    f"({self.strategy_type}) Orchestration got an unexpected exception "
                    "when processing strategy"
                )

            # Wake up every so often to see if there is work to do.
            time.sleep(self._sleep_time)

        self.strategies[self.strategy_type].teardown()

        # The strategy_type needs to be reset so that a new orchestration request
        # is identified in orchestrate(), starting the orchestration thread again
        with self.steps_lock:
            self.strategy_type = None
            self.steps_to_process.clear()
            self.steps_received.clear()

        self._last_update = None
        self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS

    def _adjust_sleep_time(self, number_of_subclouds, strategy_type):
        prev_sleep_time = self._sleep_time

        if number_of_subclouds <= 0:
            new_sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS
        else:
            new_sleep_time = min(
                (DEFAULT_SLEEP_TIME_IN_SECONDS * 60)
                / min(number_of_subclouds, consts.MAX_PARALLEL_SUBCLOUDS_LIMIT),
                DEFAULT_SLEEP_TIME_IN_SECONDS,
            )

        if new_sleep_time != prev_sleep_time:
            self._sleep_time = new_sleep_time
            LOG.debug(
                f"({strategy_type}) Adjusted orch thread sleep time "
                f"from {prev_sleep_time} to {self._sleep_time} "
                f"based on {number_of_subclouds} parallel subclouds."
            )

    def _delete_subcloud_worker(self, region, subcloud_id, step_id):
        self._update_strategy_step_data(
            step_id, stage=consts.STAGE_SUBCLOUD_ORCHESTRATION_PROCESSED
        )
        if region in self.subcloud_workers:
            # The orchestration for this subcloud has either completed/failed/aborted,
            # remove it from the dictionary.
            LOG.debug(
                f"({self.strategy_type}) Remove {region} from subcloud workers dict"
            )
            del self.subcloud_workers[region]

        # Remove the step from the steps to process
        self.steps_to_process.discard(step_id)

    def _strategy_step_update(
        self, strategy_type, step_id, state=None, details=None, stage=None
    ):
        """Update the strategy step in the DB

        Sets the start and finished timestamp if necessary, based on state.
        """

        fields = dict()

        if state == self.strategies[strategy_type].starting_state:
            fields["started_at"] = datetime.datetime.now()
        elif state in [
            consts.STRATEGY_STATE_COMPLETE,
            consts.STRATEGY_STATE_ABORTED,
            consts.STRATEGY_STATE_FAILED,
        ]:
            fields["finished_at"] = datetime.datetime.now()

        if state is not None:
            fields["state"] = state
        if details is not None:
            fields["details"] = details
        if stage is not None:
            fields["stage"] = stage

        if fields:
            self._update_strategy_step_data(step_id, **fields)

    def _perform_state_action(self, strategy_type, region, step):
        """Extensible state handler for processing and transitioning states"""

        try:
            LOG.info(
                f"({strategy_type}) Stage: {step.stage}, State: {step.state}, "
                f"Subcloud: {step.subcloud.name}"
            )
            # Instantiate the state operator and perform the state actions
            state_operator = self.strategies[strategy_type].determine_state_operator(
                region, step
            )
            state_operator.registerStopEvent(self._stop)
            next_state = state_operator.perform_state_action(step)
            self._strategy_step_update(
                strategy_type, step.id, state=next_state, details=""
            )
        except exceptions.StrategySkippedException as ex:
            LOG.info(
                f"({strategy_type}) Skipping subcloud, Stage: {step.stage}, "
                f"State: {step.state}, Subcloud: {step.subcloud.name}"
            )
            # Transition immediately to complete. Update the details to show
            # that this subcloud has been skipped
            self._strategy_step_update(
                strategy_type,
                step.id,
                state=consts.STRATEGY_STATE_COMPLETE,
                details=self._format_update_details(None, str(ex)),
            )

            if self.strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
                self._update_subcloud_data(step.subcloud.id, prestage_status=None)
        except Exception as ex:
            # Catch ALL exceptions and set the strategy to failed
            LOG.exception(
                f"({strategy_type}) Failed! Stage: {step.stage}, State: {step.state}, "
                f"Subcloud: {step.subcloud.name}"
            )
            self._strategy_step_update(
                strategy_type,
                step.id,
                state=consts.STRATEGY_STATE_FAILED,
                details=self._format_update_details(step.state, str(ex)),
            )

            if self.strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
                self._update_subcloud_data(
                    step.subcloud.id, prestage_status=consts.PRESTAGE_STATE_FAILED
                )

    def _process_update_step(self, strategy_type, region, step, log_error=False):
        """Manages the green thread for calling perform_state_action"""

        if region in self.subcloud_workers:
            if self.subcloud_workers[region][0] == step.state:
                # A worker already exists. Let it finish whatever it was doing.
                if log_error:
                    LOG.error(f"({strategy_type}) Worker should not exist for {region}")
                else:
                    LOG.debug(f"({strategy_type}) Update worker exists for {region}")
            else:
                LOG.debug(
                    f"({strategy_type}) Starting a new worker for region {region} at "
                    f"state {step.state} (update) in strategy"
                )
                # Advance to the next state. The previous greenthread has exited,
                # create a new one.
                self.subcloud_workers[region] = (
                    step.state,
                    self.thread_group_manager.start(
                        self._perform_state_action, strategy_type, region, step
                    ),
                )
        else:
            # This is the first state. Create a greenthread to start processing the
            # update for the subcloud and invoke the perform_state_action method.
            LOG.debug(
                f"({strategy_type}) Starting a new worker for region {region} at state "
                f"{step.state}"
            )
            self.subcloud_workers[region] = (
                step.state,
                self.thread_group_manager.start(
                    self._perform_state_action, strategy_type, region, step
                ),
            )

    def _apply(self, strategy, steps_id):
        """Apply a strategy"""

        LOG.debug(f"({strategy.type}) Applying strategy")
        steps = db_api.strategy_step_get_all(self.context, steps_id)
        # Adjust sleep time based on the number of subclouds being processed
        # in parallel
        self._adjust_sleep_time(len(steps), strategy.type)

        for step in steps:
            if step.state == consts.STRATEGY_STATE_COMPLETE:
                subcloud_update = dict()

                # If an exception occurs during the create/apply of the VIM strategy,
                # the deploy_status will be set to 'apply-strategy-failed'. If we
                # retry the orchestration and the process completes successfully, we
                # need to update the deploy_status to 'complete'.
                if step.subcloud.deploy_status != consts.DEPLOY_STATE_DONE:
                    # Update deploy state for subclouds to complete
                    subcloud_update["deploy_status"] = consts.DEPLOY_STATE_DONE

                if self.strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
                    subcloud_update["prestage_versions"] = (
                        prestage.get_prestage_versions(step.subcloud.name)
                    )
                    subcloud_update["prestage_status"] = consts.PRESTAGE_STATE_COMPLETE

                if subcloud_update:
                    self._update_subcloud_data(step.subcloud.id, **subcloud_update)

                # This step is complete
                self._delete_subcloud_worker(
                    step.subcloud.region_name, step.subcloud_id, step.id
                )
                continue
            elif step.state == consts.STRATEGY_STATE_ABORTED:
                # This step was aborted
                self._delete_subcloud_worker(
                    step.subcloud.region_name, step.subcloud_id, step.id
                )
                continue
            elif step.state == consts.STRATEGY_STATE_FAILED:
                self._delete_subcloud_worker(
                    step.subcloud.region_name, step.subcloud_id, step.id
                )

                if strategy.stop_on_failure:
                    # We have been told to stop on failures
                    self._stop.set()
                    self.orchestrator_manager_rpc_client.stop_strategy(
                        self.context, strategy.type
                    )
                    break
                continue
            # We have found the first step that isn't complete or failed.
            break
        else:
            # Update the steps and subclouds
            self._bulk_update_subcloud_and_strategy_steps()

            # The strategy application is complete
            self.subcloud_workers.clear()
            self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS
            return

        # The worker is not allowed to process new steps. It should only finish the
        # ones it is currently executing before it quits
        if self._stop.is_set():
            work_remaining = False
            # We are going to stop after the steps that are in progress finish.
            if len(self.subcloud_workers) > 0:
                work_remaining = True

            if not work_remaining:
                # We have completed the remaining steps
                LOG.info(f"({strategy.type}) Stopping strategy due to failure")
                self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS

        for step in steps:
            region = self._get_region_name(step)
            if self._stop.is_set():
                LOG.info(f"({strategy.type}) Exiting strategy because task is stopped")
                self._bulk_update_subcloud_and_strategy_steps()

                self.subcloud_workers.clear()
                self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS
                self._processing = False
                return
            if step.state == consts.STRATEGY_STATE_COMPLETE:
                subcloud_update = dict()

                # If an exception occurs during the create/apply of the VIM strategy,
                # the deploy_status will be set to 'apply-strategy-failed'. If we
                # retry the orchestration and the process completes successfully, we
                # need to update the deploy_status to 'complete'.
                if step.subcloud.deploy_status != consts.DEPLOY_STATE_DONE:
                    # Update deploy state for subclouds to complete
                    subcloud_update["deploy_status"] = consts.DEPLOY_STATE_DONE

                if self.strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
                    subcloud_update["prestage_versions"] = (
                        prestage.get_prestage_versions(step.subcloud.name)
                    )
                    subcloud_update["prestage_status"] = consts.PRESTAGE_STATE_COMPLETE

                if subcloud_update:
                    self._update_subcloud_data(step.subcloud.id, **subcloud_update)

                # This step is complete
                self._delete_subcloud_worker(
                    step.subcloud.region_name, step.subcloud_id, step.id
                )
                continue
            elif step.state in [
                consts.STRATEGY_STATE_FAILED,
                consts.STRATEGY_STATE_ABORTED,
            ]:
                LOG.debug(
                    f"({strategy.type}) Intermediate step is {step.state} for strategy"
                )
                self._delete_subcloud_worker(region, step.subcloud_id, step.id)
            elif step.state == consts.STRATEGY_STATE_INITIAL:
                if (
                    strategy.max_parallel_subclouds > len(self.subcloud_workers)
                    and not self._stop.is_set()
                ):
                    # Don't start upgrading this subcloud if it has been unmanaged by
                    # the user. If orchestration was already started, it will be allowed
                    # to complete.
                    if (
                        step.subcloud_id is not None
                        and step.subcloud.management_state
                        == dccommon_consts.MANAGEMENT_UNMANAGED
                    ):
                        message = f"Subcloud {step.subcloud.name} is unmanaged."
                        LOG.warn(f"({strategy.type}) {message}")
                        self._strategy_step_update(
                            strategy.type,
                            step.id,
                            state=consts.STRATEGY_STATE_FAILED,
                            details=message,
                        )
                        continue

                    # We are just getting started, enter the first state
                    # Use the updated value for calling process_update_step
                    self._strategy_step_update(
                        strategy.type,
                        step.id,
                        stage=consts.STAGE_SUBCLOUD_ORCHESTRATION_STARTED,
                        state=self.strategies[strategy.type].starting_state,
                    )
                    # Use the updated value for calling process_update_step
                    step.stage = consts.STAGE_SUBCLOUD_ORCHESTRATION_STARTED
                    step.state = self.strategies[strategy.type].starting_state
                    # Starting state should log an error if greenthread exists
                    self._process_update_step(
                        strategy.type, region, step, log_error=True
                    )

                    if self.strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
                        self._update_subcloud_data(
                            step.subcloud.id,
                            prestage_status=consts.PRESTAGE_STATE_PRESTAGING,
                        )
            else:
                self._process_update_step(strategy.type, region, step, log_error=False)

        # Update the steps and subclouds
        self._bulk_update_subcloud_and_strategy_steps()

        # Verify if there are any steps currently executing. In case there isn't,
        # stop the processing
        if not self.subcloud_workers:
            self._processing = False

    def _abort(self, strategy, steps_id):
        """Abort a strategy"""

        LOG.info(f"({strategy.type}) Aborting strategy")

        # Only strategy steps that did not start processing can be updated to aborted
        filters = {"state": consts.STRATEGY_STATE_INITIAL}
        values = {"state": consts.STRATEGY_STATE_ABORTED, "details": ""}

        # Currently, the orchestrator only supports executing a single strategy at
        # a time and there isn't any database relationship between the steps and the
        # strategy, so we just update all the steps
        db_api.strategy_step_update_all(self.context, filters, values, steps_id)

        # Since the steps were just recently updated, the manager needs to confirm
        # all workers completed the request before proceeding, so the sleep is longer
        # to avoid unnecessary requests
        self._sleep_time = MANAGER_SLEEP_TIME_IN_SECONDS

    def _do_delete_subcloud_strategy(self, strategy_type, region, step):
        """Delete the vim strategy in the subcloud"""

        LOG.info(
            f"({strategy_type}) Deleting vim strategy:({strategy_type}) for "
            f"region:({region})"
        )

        # First check if the strategy has been created.
        try:
            vim_client = self.strategies[strategy_type].get_vim_client(region)
            subcloud_strategy = vim_client.get_strategy(
                self.strategies[strategy_type].vim_strategy_name
            )
        except (keystone_exceptions.EndpointNotFound, IndexError):
            LOG.warn(f"({strategy_type}) Endpoint for subcloud: {region} not found")
            return
        except Exception:
            # Strategy doesn't exist so there is nothing to do
            return

        if subcloud_strategy.state in [
            vim.STATE_BUILDING,
            vim.STATE_APPLYING,
            vim.STATE_ABORTING,
        ]:
            # Can't delete a vim strategy in these states
            LOG.warn(
                f"({strategy_type}) Vim strategy:("
                f"{self.strategies[strategy_type].vim_strategy_name}) for region:("
                f"{region}) in wrong state:({subcloud_strategy.state}) for delete."
            )
            return

        # If we are here, we need to delete the strategy
        try:
            vim_client.delete_strategy(self.strategies[strategy_type].vim_strategy_name)
        except Exception:
            LOG.warn(
                f"({strategy_type}) Vim strategy:"
                f"({self.strategies[strategy_type].vim_strategy_name}) delete failed "
                f"for region:({region})"
            )
            return

    def _delete_subcloud_strategy(self, strategy_type, region, step):
        """Delete the strategy in the subcloud

        Removes the worker reference after the operation is complete.
        """

        try:
            self._do_delete_subcloud_strategy(strategy_type, region, step)
        except Exception as e:
            LOG.exception(f"({strategy_type}) {e}")
        finally:
            # The worker is done.
            if region in self.subcloud_workers:
                del self.subcloud_workers[region]

    def _delete(self, strategy, steps_id):
        """Delete an update strategy"""

        LOG.info(f"({strategy.type}) Deleting strategy")

        steps = db_api.strategy_step_get_all(self.context, steps_id)

        # Adjust sleep time based on the number of subclouds being processed
        # in parallel
        self._adjust_sleep_time(len(steps), strategy.type)

        for step in steps:
            region = self._get_region_name(step)

            if region in self.subcloud_workers:
                # A worker already exists. Let it finish whatever it was doing.
                LOG.debug(f"({strategy.type}) Worker already exists for {region}")
            else:
                # Create a greenthread to delete the subcloud strategy
                delete_thread = self.thread_group_manager.start(
                    self._delete_subcloud_strategy, strategy.type, region, step
                )
                if delete_thread:
                    self.subcloud_workers[region] = delete_thread

            if self._stop.is_set():
                LOG.info(
                    f"({strategy.type}) Exiting because task is stopped for strategy"
                )
                return

        # Wait for 180 seconds so that last 100 workers can complete their execution
        counter = 0
        while len(self.subcloud_workers) > 0:
            time.sleep(DEFAULT_SLEEP_TIME_IN_SECONDS)
            counter = counter + 1
            if counter > DELETE_COUNTER:
                break

        # Remove the strategy from the database if all workers have completed their
        # execution
        try:
            db_api.strategy_step_destroy_all(self.context, steps_id)

            # Because the execution is synchronous in this case, the steps_to_process
            # is not updated as the loop did not finish yet.
            self.steps_to_process.clear()
        except Exception as e:
            LOG.exception(f"({strategy.type}) exception during delete")
            raise e

        LOG.info(f"({strategy.type}) Finished deleting strategy steps")
