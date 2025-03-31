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
import os
import threading
import time

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import scheduler
from dcmanager.db import api as db_api
from dcmanager.orchestrator.strategies.firmware import FirmwareStrategy
from dcmanager.orchestrator.strategies.kube_rootca import KubeRootcaStrategy
from dcmanager.orchestrator.strategies.kubernetes import KubernetesStrategy
from dcmanager.orchestrator.strategies.patch import PatchStrategy
from dcmanager.orchestrator.strategies.prestage import PrestageStrategy
from dcmanager.orchestrator.strategies.software import SoftwareStrategy

LOG = logging.getLogger(__name__)
DEFAULT_SLEEP_TIME_IN_SECONDS = 10
MANAGER_SLEEP_TIME_IN_SECONDS = 30


class OrchestratorWorker(object):
    """Orchestrator worker

    This class is responsible for orchestrating strategy steps based on the requests
    from the orchestrator manager, which sends the steps and strategy step to process.
    """

    def __init__(self, audit_rpc_client):
        self.context = context.get_admin_context()
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(thread_pool_size=5000)
        # Track worker created for each subcloud.
        self.subcloud_workers = dict()
        # self.orchestrator_rpc_client = (
        #    orchestrator_rpc_client.OrchestratorManagerClient()
        # )
        self.pid = os.getpid()
        # Determines if the worker is still processing the strategy steps or if the
        # execution should finish
        self._processing = True
        # Determines if the worker should not process new steps
        self._stop = threading.Event()
        # Time for the orchestration to sleep after every loop
        self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS
        # Strategies orchestration process
        self.strategies = {
            consts.SW_UPDATE_TYPE_FIRMWARE: FirmwareStrategy(audit_rpc_client),
            consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE: KubeRootcaStrategy(
                audit_rpc_client
            ),
            consts.SW_UPDATE_TYPE_KUBERNETES: KubernetesStrategy(audit_rpc_client),
            consts.SW_UPDATE_TYPE_PATCH: PatchStrategy(audit_rpc_client),
            consts.SW_UPDATE_TYPE_PRESTAGE: PrestageStrategy(audit_rpc_client),
            consts.SW_UPDATE_TYPE_SOFTWARE: SoftwareStrategy(audit_rpc_client),
        }

    @staticmethod
    def _get_subcloud_name(step):
        """Get the subcloud name for a step"""
        return step.subcloud.name

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

    def orchestrate(self, steps_id, strategy_type):
        LOG.info(f"({self.pid}) Orchestration starting for {strategy_type}")
        # Reset the control flags since a new process started
        self._stop.clear()
        self._processing = True

        while self._processing:
            try:
                LOG.debug(f"({self.pid}) Orchestration is running for {strategy_type}")

                strategy = db_api.sw_update_strategy_get(
                    self.context, update_type=strategy_type
                )

                if strategy.state in [
                    consts.SW_UPDATE_STATE_APPLYING,
                    consts.SW_UPDATE_STATE_ABORTING,
                ]:
                    self.strategies[strategy_type]._pre_apply_setup()
                    self._apply(strategy, steps_id)
                elif strategy.state == consts.SW_UPDATE_STATE_ABORT_REQUESTED:
                    self._abort(strategy, steps_id)
                elif strategy.state == consts.SW_UPDATE_STATE_DELETING:
                    self._delete(strategy, steps_id)
                    self.strategies[strategy_type]._post_delete_teardown()
            except exceptions.StrategyNotFound:
                self._processing = False
                LOG.error(
                    f"({self.pid}) A strategy of type {strategy_type} was not found"
                )
            except Exception:
                # We catch all exceptions to avoid terminating the thread.
                LOG.exception(
                    f"({self.pid}) Orchestration got an unexpected exception when "
                    f"processing strategy {strategy_type}"
                )

            # Wake up every so often to see if there is work to do.
            time.sleep(self._sleep_time)

        LOG.info(f"({self.pid}) Orchestration finished for {strategy_type}")
        self.thread_group_manager.stop()

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
                f"({self.pid}) Adjusted {strategy_type} orch thread sleep time "
                f"from {prev_sleep_time} to {self._sleep_time} "
                f"based on {number_of_subclouds} parallel subclouds."
            )

    def _update_subcloud_deploy_status(self, subcloud):
        # If an exception occurs during the create/apply of the VIM strategy, the
        # deploy_status will be set to 'apply-strategy-failed'. If we retry the
        # orchestration and the process completes successfully, we need to update the
        # deploy_status to 'complete'.
        if subcloud.deploy_status != consts.DEPLOY_STATE_DONE:
            # Update deploy state for subclouds to complete
            db_api.subcloud_update(
                self.context,
                subcloud.id,
                deploy_status=consts.DEPLOY_STATE_DONE,
            )

    def _delete_subcloud_worker(self, region, subcloud_id):
        db_api.strategy_step_update(
            self.context,
            subcloud_id,
            stage=consts.STAGE_SUBCLOUD_ORCHESTRATION_PROCESSED,
        )
        if region in self.subcloud_workers:
            # The orchestration for this subcloud has either completed/failed/aborted,
            # remove it from the dictionary.
            LOG.debug(f"({self.pid}) Remove {region} from subcloud workers dict")
            del self.subcloud_workers[region]

    def strategy_step_update(
        self, strategy_type, subcloud_id, state=None, details=None, stage=None
    ):
        """Update the strategy step in the DB

        Sets the start and finished timestamp if necessary, based on state.
        """
        started_at = None
        finished_at = None
        if state == self.strategies[strategy_type].starting_state:
            started_at = datetime.datetime.now()
        elif state in [
            consts.STRATEGY_STATE_COMPLETE,
            consts.STRATEGY_STATE_ABORTED,
            consts.STRATEGY_STATE_FAILED,
        ]:
            finished_at = datetime.datetime.now()
        # Return the updated object, in case we need to use its updated values
        return db_api.strategy_step_update(
            self.context,
            subcloud_id,
            stage=stage,
            state=state,
            details=details,
            started_at=started_at,
            finished_at=finished_at,
        )

    def _perform_state_action(self, strategy_type, region, step):
        """Extensible state handler for processing and transitioning states"""

        try:
            LOG.info(
                f"({self.pid}) Strategy: {strategy_type} Stage: {step.stage}, "
                f"State: {step.state}, Subcloud: {self._get_subcloud_name(step)}"
            )
            # Instantiate the state operator and perform the state actions
            state_operator = self.strategies[strategy_type].determine_state_operator(
                region, step
            )
            state_operator.registerStopEvent(self._stop)
            next_state = state_operator.perform_state_action(step)
            self.strategy_step_update(
                strategy_type, step.subcloud_id, state=next_state, details=""
            )
        except exceptions.StrategySkippedException as ex:
            LOG.info(
                f"({self.pid}) Skipping subcloud, Strategy: {strategy_type} "
                f"Stage: {step.stage}, State: {step.state}, "
                f"Subcloud: {step.subcloud_name}"
            )
            # Transition immediately to complete. Update the details to show
            # that this subcloud has been skipped
            self.strategy_step_update(
                strategy_type,
                step.subcloud_id,
                state=consts.STRATEGY_STATE_COMPLETE,
                details=self._format_update_details(None, str(ex)),
            )
        except Exception as ex:
            # Catch ALL exceptions and set the strategy to failed
            LOG.exception(
                f"({self.pid}) Failed! Strategy: {strategy_type} Stage: {step.stage}, "
                f"State: {step.state}, Subcloud: {step.subcloud_name}"
            )
            self.strategy_step_update(
                strategy_type,
                step.subcloud_id,
                state=consts.STRATEGY_STATE_FAILED,
                details=self._format_update_details(step.state, str(ex)),
            )

    def _process_update_step(self, strategy_type, region, step, log_error=False):
        """Manages the green thread for calling perform_state_action"""

        if region in self.subcloud_workers:
            if self.subcloud_workers[region][0] == step.state:
                # A worker already exists. Let it finish whatever it was doing.
                if log_error:
                    LOG.error(
                        f"({self.pid}) Worker should not exist for {region} "
                        f"in strategy {strategy_type}."
                    )
                else:
                    LOG.info(
                        f"({self.pid}) Update worker exists for {region} "
                        f"in strategy {strategy_type}."
                    )
            else:
                LOG.info(
                    f"({self.pid}) Starting a new worker for region {region} at state "
                    f"{step.state} (update) in strategy {strategy_type}"
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
            LOG.info(
                f"({self.pid}) Starting a new worker for region {region} at state "
                f"{step.state} in strategy {strategy_type}"
            )
            self.subcloud_workers[region] = (
                step.state,
                self.thread_group_manager.start(
                    self._perform_state_action, strategy_type, region, step
                ),
            )

    def _apply(self, strategy, steps_id):
        """Apply a strategy"""

        LOG.debug(f"({self.pid}) Applying strategy {strategy.type}")
        steps = db_api.strategy_step_get_all(self.context, steps_id)
        # Adjust sleep time based on the number of subclouds being processed
        # in parallel
        self._adjust_sleep_time(len(steps), strategy.type)

        for step in steps:
            if step.state == consts.STRATEGY_STATE_COMPLETE:
                # Update deploy state for subclouds to complete
                self._update_subcloud_deploy_status(step.subcloud)
                # This step is complete
                self._delete_subcloud_worker(
                    step.subcloud.region_name, step.subcloud_id
                )
                continue
            elif step.state == consts.STRATEGY_STATE_ABORTED:
                # This step was aborted
                self._delete_subcloud_worker(
                    step.subcloud.region_name, step.subcloud_id
                )
                continue
            elif step.state == consts.STRATEGY_STATE_FAILED:
                self._delete_subcloud_worker(
                    step.subcloud.region_name, step.subcloud_id
                )
                # This step has failed and needs no further action
                if step.subcloud_id is None:
                    # Strategy on SystemController failed. We are done.
                    LOG.info(
                        f"({self.pid}) Stopping strategy {strategy.type} due to "
                        "failure while processing update step on SystemController"
                    )
                    # TODO(rlima): Remove this request and replace with the
                    # stop rpc call
                    # with self.strategy_lock:
                    #    db_api.sw_update_strategy_update(
                    #        self.context,
                    # state=consts.SW_UPDATE_STATE_FAILED,
                    # update_type=self.update_type,
                    # )
                    self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS
                    # Trigger audit to update the sync status for each subcloud.
                    self.strategies[strategy.type].trigger_audit()
                    return
                elif strategy.stop_on_failure:
                    # We have been told to stop on failures
                    self._stop.set()
                    break
                continue
            # We have found the first step that isn't complete or failed.
            break
        else:
            # The strategy application is complete
            self.subcloud_workers.clear()
            self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS

            # Trigger audit to update the sync status for each subcloud.
            LOG.info(f"({self.pid}) Trigger audit for {strategy.type}")
            self.strategies[strategy.type].trigger_audit()
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
                LOG.info(
                    f"({self.pid}) Stopping strategy {strategy.type} due to failure"
                )
                self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS
                # Trigger audit to update the sync status for each subcloud.
                self.strategies[strategy.type].trigger_audit()

        for step in steps:
            region = self._get_region_name(step)
            if not self._processing:
                LOG.info(
                    f"({self.pid}) Exiting {strategy.type} strategy because task "
                    "is stopped"
                )
                self.subcloud_workers.clear()
                self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS
                return
            if step.state in [
                consts.STRATEGY_STATE_FAILED,
                consts.STRATEGY_STATE_COMPLETE,
                consts.STRATEGY_STATE_ABORTED,
            ]:
                LOG.debug(
                    f"({self.pid}) Intermediate step is {step.state} for strategy "
                    f"{strategy.type}"
                )
                self._delete_subcloud_worker(region, step.subcloud_id)
            elif step.state == consts.STRATEGY_STATE_INITIAL:
                if (
                    # TODO(rlima): replace the calculation to consider the
                    # amount of workers
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
                        message = f"Subcloud {step.subcloud_name} is unmanaged."
                        LOG.warn(f"({self.pid}) {message}")
                        self.strategy_step_update(
                            strategy.type,
                            step.subcloud_id,
                            state=consts.STRATEGY_STATE_FAILED,
                            details=message,
                        )
                        continue

                    # We are just getting started, enter the first state
                    # Use the updated value for calling process_update_step
                    step = self.strategy_step_update(
                        strategy.type,
                        step.subcloud_id,
                        stage=consts.STAGE_SUBCLOUD_ORCHESTRATION_STARTED,
                        state=self.strategies[strategy.type].starting_state,
                    )
                    # Starting state should log an error if greenthread exists
                    self._process_update_step(
                        strategy.type, region, step, log_error=True
                    )
            else:
                self._process_update_step(strategy.type, region, step, log_error=False)

    def _abort(self, strategy, steps_id):
        """Abort a strategy"""

        LOG.info(f"({self.pid}) Aborting strategy {strategy.type}")

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
            f"({self.pid}) Deleting vim strategy:({strategy_type}) for "
            f"region:({region})"
        )

        # First check if the strategy has been created.
        try:
            vim_client = self.strategies[strategy_type].get_vim_client(region)
            subcloud_strategy = vim_client.get_strategy(
                self.strategies[strategy_type].vim_strategy_name
            )
        except (keystone_exceptions.EndpointNotFound, IndexError):
            LOG.warn(
                f"({self.pid}) Endpoint for subcloud: {region} not found in "
                f"strategy {strategy_type}."
            )
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
                f"({self.pid}) Vim strategy:("
                f"{self.strategies[strategy_type].vim_strategy_name}) for region:("
                f"{region}) in wrong state:({subcloud_strategy.state}) for delete."
            )
            return

        # If we are here, we need to delete the strategy
        try:
            vim_client.delete_strategy(self.strategies[strategy_type].vim_strategy_name)
        except Exception:
            LOG.warn(
                f"({self.pid}) Vim strategy:"
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
            LOG.exception(e)
        finally:
            # The worker is done.
            if region in self.subcloud_workers:
                del self.subcloud_workers[region]

    def _delete(self, strategy, steps_id):
        """Delete an update strategy"""

        LOG.info(f"({self.pid}) Deleting strategy {strategy.type}")

        steps = db_api.strategy_step_get_all(self.context, steps_id)

        # Adjust sleep time based on the number of subclouds being processed
        # in parallel
        self._adjust_sleep_time(len(steps), strategy.type)

        for step in steps:
            region = self._get_region_name(step)

            if region in self.subcloud_workers:
                # A worker already exists. Let it finish whatever it was doing.
                LOG.debug(
                    f"({self.pid}) Worker already exists for {region} in strategy "
                    f"{strategy.type}."
                )
            else:
                # Create a greenthread to delete the subcloud strategy
                delete_thread = self.thread_group_manager.start(
                    self._delete_subcloud_strategy, strategy.type, region, step
                )
                if delete_thread:
                    self.subcloud_workers[region] = delete_thread

            if self._stop.is_set():
                LOG.info(
                    f"({self.pid}) Exiting because task is stopped for strategy "
                    f"{strategy.type}"
                )
                return

        # Wait for 180 seconds so that last 100 workers can complete their execution
        counter = 0
        while len(self.subcloud_workers) > 0:
            time.sleep(10)
            counter = counter + 1
            if counter > 18:
                break

        # Remove the strategy from the database if all workers have completed their
        # execution
        try:
            db_api.strategy_step_destroy_all(self.context, steps_id)
        except Exception as e:
            LOG.exception(
                f"({self.pid}) exception during delete in strategy {strategy.type}"
            )
            raise e
        finally:
            # The orchestration is complete, halt the processing
            self._processing = False
            self._sleep_time = DEFAULT_SLEEP_TIME_IN_SECONDS

        LOG.info(f"({self.pid}) Finished deleting strategy {strategy.type}")
