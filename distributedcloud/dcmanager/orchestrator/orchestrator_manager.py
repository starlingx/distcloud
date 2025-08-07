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
import shutil
import threading

import eventlet
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from dccommon import consts as dccommon_consts
from dccommon import ostree_mount
from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import manager
from dcmanager.common import prestage
from dcmanager.common import scheduler
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.orchestrator import rpcapi as orchestrator_rpc_api
from dcmanager.orchestrator.orchestrator_worker import (
    DEFAULT_SLEEP_TIME_IN_SECONDS,
    DELETE_COUNTER,
)
from dcmanager.orchestrator.validators.firmware_validator import (
    FirmwareStrategyValidator,
)
from dcmanager.orchestrator.validators.kube_root_ca_validator import (
    KubeRootCaStrategyValidator,
)
from dcmanager.orchestrator.validators.kubernetes_validator import (
    KubernetesStrategyValidator,
)
from dcmanager.orchestrator.validators.prestage_validator import (
    PrestageStrategyValidator,
)
from dcmanager.orchestrator.validators.sw_deploy_validator import (
    SoftwareDeployStrategyValidator,
)

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
ORCHESTRATION_STRATEGY_MONITORING_INTERVAL = 30


class OrchestratorManager(manager.Manager):
    """Manages tasks related to software updates."""

    def __init__(self, *args, **kwargs):
        LOG.debug("Orchestrator manager initialization...")

        super().__init__(service_name="orchestrator_manager", *args, **kwargs)
        self.context = context.get_admin_context()

        # Used to protect strategies when an atomic read/update is required.
        self.strategy_lock = threading.Lock()
        self.sleep_time = ORCHESTRATION_STRATEGY_MONITORING_INTERVAL

        # Software and kubernetes are audited every loop and don't need to be triggered
        audit_rpc_client = dcmanager_audit_rpc_client.ManagerAuditClient()
        self.audit_trigger = {
            consts.SW_UPDATE_TYPE_SOFTWARE: lambda context: None,
            consts.SW_UPDATE_TYPE_FIRMWARE: audit_rpc_client.trigger_firmware_audit,
            consts.SW_UPDATE_TYPE_KUBERNETES: lambda context: None,
            consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE: (
                audit_rpc_client.trigger_kube_rootca_update_audit
            ),
            consts.SW_UPDATE_TYPE_PRESTAGE: lambda context: None,
        }
        self.orchestrator_worker_rpc_client = (
            orchestrator_rpc_api.ManagerOrchestratorWorkerClient()
        )

        # Used to determine the continuous execution of the strategy monitoring
        self._monitor_strategy = False

        # Start worker threads
        self.strategy_validators = {
            consts.SW_UPDATE_TYPE_SOFTWARE: SoftwareDeployStrategyValidator(),
            consts.SW_UPDATE_TYPE_FIRMWARE: FirmwareStrategyValidator(),
            consts.SW_UPDATE_TYPE_KUBERNETES: KubernetesStrategyValidator(),
            consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE: KubeRootCaStrategyValidator(),
            consts.SW_UPDATE_TYPE_PRESTAGE: PrestageStrategyValidator(),
        }
        self.thread_group_manager = scheduler.ThreadGroupManager(thread_pool_size=1)

        # Stores the time in which the strategy deletion started
        self.delete_start_at = None

        # When starting the manager service, it is necessary to confirm if there
        # are any strategies in a state different from initial, because that means
        # the service was unexpectedly restarted and the periodic strategy monitoring
        # should be restarted to finish the original processing.
        try:
            strategy = db_api.sw_update_strategy_get(self.context)

            if strategy and strategy.state not in [
                consts.SW_UPDATE_STATE_INITIAL,
                consts.SW_UPDATE_STATE_COMPLETE,
                consts.SW_UPDATE_STATE_ABORTED,
                consts.SW_UPDATE_STATE_FAILED,
            ]:
                LOG.info(
                    f"({strategy.type}) An active strategy was found, restarting "
                    "its monitoring"
                )

                # Set the delete start time when the strategy is deleting
                if strategy.state == consts.SW_UPDATE_STATE_DELETING:
                    self.delete_start_at = timeutils.utcnow()

                # The steps will only start processing after the orchestration interval
                # This is done to avoid sending the steps to the workers in cases
                # where only the manager service was restarted
                self.thread_group_manager.start(
                    self.periodic_strategy_monitoring, strategy.type
                )
        except exceptions.StrategyNotFound:
            LOG.debug(
                "There isn't an active strategy to orchestrate, skipping monitoring"
            )

    def stop_strategy(self, strategy_type):
        LOG.info(f"({strategy_type}) A request to stop the strategy was performed")

        # Once a strategy with stop on failure has a failed step in any of the
        # workers, it needs to be set to failed and the workers must stop executing
        # new steps
        with self.strategy_lock:
            db_api.sw_update_strategy_update(
                self.context,
                update_type=strategy_type,
                state=consts.SW_UPDATE_STATE_FAILED,
            )
        self.orchestrator_worker_rpc_client.stop_processing(self.context)

    # In order to avoid concurrency issues, the worker does not update the strategy
    # since their execution is based on the strategy's state and, if a worker updates
    # it while another is running, the change would not be identified until the
    # worker's loop restarted for the subsequent execution
    # Because of that, the manager is responsible for updating the sw_update_strategy
    # table while the worker is responsible for the strategy steps.
    def periodic_strategy_monitoring(self, strategy_type):
        # Reset the flag to start the monitoring
        LOG.debug(f"({strategy_type}) Starting periodic monitoring")
        self._monitor_strategy = True

        while self._monitor_strategy:
            try:
                eventlet.greenthread.sleep(self.sleep_time)
                self._periodic_strategy_monitoring_loop(strategy_type)
            except eventlet.greenlet.GreenletExit:
                # Exit the execution
                return
            except exceptions.StrategyNotFound:
                LOG.exception(
                    f"({strategy_type}) The strategy does not exist anymore, "
                    "stopping monitoring"
                )
                return
            except Exception:
                LOG.exception(
                    f"({strategy_type}) An error occurred in the strategy "
                    "monitoring loop"
                )

    def _create_and_send_step_batches(self, strategy_type, steps, update=False):
        steps_to_orchestrate = list()
        steps_to_update = list()

        chunksize = (len(steps) + CONF.orch_worker_workers) // (
            CONF.orch_worker_workers
        )

        for step in steps:
            steps_to_orchestrate.append(step.id)

            if len(steps_to_orchestrate) == chunksize:
                LOG.info(
                    f"({strategy_type}) Sending {len(steps_to_orchestrate)} steps "
                    "to orchestrate"
                )
                self.orchestrator_worker_rpc_client.orchestrate(
                    self.context, steps_to_orchestrate, strategy_type
                )

                if update:
                    steps_to_update.extend(steps_to_orchestrate)
                steps_to_orchestrate = []

        if steps_to_orchestrate:
            LOG.info(
                f"({strategy_type}) Sending final {len(steps_to_orchestrate)} steps "
                "to orchestrate"
            )
            self.orchestrator_worker_rpc_client.orchestrate(
                self.context, steps_to_orchestrate, strategy_type
            )

            if update:
                steps_to_update.extend(steps_to_orchestrate)

        # When retrieving steps that were not processing, the update_at field
        # needs to be reset to avoid it being identified in subsequent verifications
        if update:
            db_api.strategy_step_update_all(
                self.context, {}, {"updated_at": timeutils.utcnow()}, steps_to_update
            )

        if steps:
            LOG.info(f"({strategy_type}) Finished sending steps to orchestrate")

    def _verify_pending_steps(self, strategy_type, max_parallel_subclouds):
        """Verifies if there are any steps that were not updated in the threshold

        If there is, send them to be processed in the workers.

        :param strategy_type: the type of the strategy being monitored
        :return: True if there are pending steps and False otherwise
        """

        last_update_threshold = timeutils.utcnow() - datetime.timedelta(
            seconds=CONF.scheduler.orchestration_interval
        )
        steps_to_process = db_api.strategy_step_get_all_to_process(
            self.context,
            last_update_threshold=last_update_threshold,
            max_parallel_subclouds=max_parallel_subclouds,
        )

        if steps_to_process:
            LOG.info(
                f"({strategy_type}) {len(steps_to_process)} pending steps were found, "
                "start processing"
            )
            self._create_and_send_step_batches(strategy_type, steps_to_process, True)
            return True

        return False

    def _periodic_strategy_monitoring_loop(self, strategy_type):
        """Verifies strategy and subcloud states"""

        LOG.debug(f"({strategy_type}) Running periodic monitoring")

        strategy = db_api.sw_update_strategy_get(self.context, strategy_type)

        if strategy.state in [
            consts.SW_UPDATE_STATE_APPLYING,
            consts.SW_UPDATE_STATE_ABORTING,
            consts.SW_UPDATE_STATE_ABORT_REQUESTED,
        ] and self._verify_pending_steps(
            strategy_type, strategy.max_parallel_subclouds
        ):
            return

        # When the strategy is not in a finished state, it is necessary to verify the
        # step's state to update the strategy accordingly.
        steps_count = db_api.strategy_step_states_to_dict(
            db_api.strategy_step_count_all_states(self.context)
        )
        total_steps = steps_count["total"]

        # When a strategy has a stop on failure and it reaches a failed state, it
        # is necesary to monitor the completion of the steps that were already
        # processing
        if strategy.state == consts.SW_UPDATE_STATE_FAILED and strategy.stop_on_failure:
            initial_steps = steps_count[consts.STRATEGY_STATE_INITIAL]
            failed_steps = steps_count[consts.STRATEGY_STATE_FAILED]
            complete_steps = steps_count[consts.STRATEGY_STATE_COMPLETE]

            # A strategy, when stopped on failure, does not have steps aborted, so
            # the audit can only be triggered once all applying steps have finished.
            if total_steps == initial_steps + failed_steps + complete_steps:
                self.audit_trigger[strategy_type](self.context)
                self._monitor_strategy = False
        elif strategy.state in [
            consts.SW_UPDATE_STATE_APPLYING,
            consts.SW_UPDATE_STATE_ABORTING,
        ]:
            LOG.debug(
                f"({strategy_type}) The strategy is not complete, verifying possible "
                "state update"
            )

            new_state = None
            failed_steps = steps_count[consts.STRATEGY_STATE_FAILED]
            complete_steps = steps_count[consts.STRATEGY_STATE_COMPLETE]
            aborted_steps = steps_count[consts.STRATEGY_STATE_ABORTED]

            # If all steps are completed, the strategy state is to be updated
            if total_steps == failed_steps + complete_steps + aborted_steps:
                if failed_steps > 0:
                    new_state = consts.SW_UPDATE_STATE_FAILED
                elif aborted_steps > 0:
                    new_state = consts.SW_UPDATE_STATE_ABORTED
                else:
                    new_state = consts.SW_UPDATE_STATE_COMPLETE

            if new_state:
                # Once the strategy is set to a finished state, it does not need to
                # be monitored anymore until it is requested to delete, so the
                # execution is stopped
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context,
                        update_type=strategy_type,
                        state=new_state,
                    )
                self.audit_trigger[strategy_type](self.context)
                self._monitor_strategy = False
        elif strategy.state == consts.SW_UPDATE_STATE_ABORT_REQUESTED:
            # When the strategy is set to abort requested, it needs to have all of
            # the steps in initial state updated to aborted before proceeding
            if steps_count[consts.STRATEGY_STATE_INITIAL] == 0:
                with self.strategy_lock:
                    db_api.sw_update_strategy_update(
                        self.context,
                        update_type=strategy_type,
                        state=consts.SW_UPDATE_STATE_ABORTING,
                    )
                self.sleep_time = ORCHESTRATION_STRATEGY_MONITORING_INTERVAL
        elif strategy.state == consts.SW_UPDATE_STATE_DELETING:
            if total_steps != 0:
                # In the worker process, the deletion step has a wait of up to 180
                # seconds, which is greater than the orchestration interval. Because
                # of that, the threshold needs to be higher to ensure a step that is
                # still being process is not identified as idle.
                last_update_threshold = timeutils.utcnow() - datetime.timedelta(
                    seconds=(DEFAULT_SLEEP_TIME_IN_SECONDS * (DELETE_COUNTER + 1))
                )

                # If there are steps that were not deleted yet, verify if there is
                # any that needs to be sent to the workers.
                steps = db_api.strategy_step_get_all_to_delete(
                    self.context,
                    self.delete_start_at,
                    last_update_threshold,
                    strategy.max_parallel_subclouds,
                )

                if steps:
                    LOG.info(
                        f"({strategy_type}) {len(steps)} pending steps were found, "
                        "start processing"
                    )
                    self._create_and_send_step_batches(strategy_type, steps, True)

                return

            # If all steps were deleted, delete the strategy
            with self.strategy_lock:
                db_api.sw_update_strategy_destroy(self.context, strategy_type)

            LOG.info(f"({strategy_type}) Subcloud strategy deleted")
            self._monitor_strategy = False
            self.delete_start_at = None
            self.sleep_time = ORCHESTRATION_STRATEGY_MONITORING_INTERVAL

    def stop(self):
        self.thread_group_manager.stop()
        self.thread_group_manager = None

    # todo(abailey): dc-vault actions are normally done by dcorch-api-proxy
    # However this situation is unique since the strategy drives vault contents
    def _vault_upload(self, vault_dir, src_file):
        """Copies the file to the dc-vault, and returns the new path"""
        # make sure the vault directory exists, create, if it is missing
        if not os.path.isdir(vault_dir):
            os.makedirs(vault_dir)
        # determine the destination name for the file
        dest_file = os.path.join(vault_dir, os.path.basename(src_file))
        # copy the file to the vault dir
        # use 'copy' to preserve file system permissions
        # note: if the dest and src are the same file, this operation fails
        shutil.copy(src_file, dest_file)
        return dest_file

    def _vault_remove(self, vault_dir, vault_file):
        """Removes the the file from the dc-vault."""
        # no point in deleting if the file does not exist
        if os.path.isfile(vault_file):
            # no point in deleting if the file is not under a vault path
            if vault_file.startswith(os.path.abspath(vault_dir) + os.sep):
                # remove it
                os.remove(vault_file)

    def _process_extra_args_creation(self, strategy_type, extra_args):
        if extra_args:
            # cert-file extra_arg needs vault handling for kube rootca update
            if strategy_type == consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE:
                # extra_args can be 'cert-file'  or 'subject / expiry_date'
                # but combining both is not supported
                cert_file = extra_args.get(consts.EXTRA_ARGS_CERT_FILE)
                expiry_date = extra_args.get(consts.EXTRA_ARGS_EXPIRY_DATE)
                subject = extra_args.get(consts.EXTRA_ARGS_SUBJECT)
                if expiry_date:
                    is_valid, reason = utils.validate_expiry_date(expiry_date)
                    if not is_valid:
                        raise exceptions.BadRequest(resource="strategy", msg=reason)
                if subject:
                    is_valid, reason = utils.validate_certificate_subject(subject)
                    if not is_valid:
                        raise exceptions.BadRequest(resource="strategy", msg=reason)
                if cert_file:
                    if expiry_date or subject:
                        raise exceptions.BadRequest(
                            resource="strategy",
                            msg=(
                                "Invalid extra args. <cert-file> cannot be specified "
                                "along with <subject> or <expiry-date>."
                            ),
                        )
                    # copy the cert-file to the vault
                    vault_file = self._vault_upload(consts.CERTS_VAULT_DIR, cert_file)
                    # update extra_args with the new path (in the vault)
                    extra_args[consts.EXTRA_ARGS_CERT_FILE] = vault_file

    def _process_extra_args_deletion(self, strategy_type, extra_args):
        if extra_args:
            # cert-file extra_arg needs vault handling for kube rootca update
            if strategy_type == consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE:
                cert_file = extra_args.get(consts.EXTRA_ARGS_CERT_FILE)
                if cert_file:
                    # remove this cert file from the vault
                    self._vault_remove(consts.CERTS_VAULT_DIR, cert_file)

    def create_sw_update_strategy(self, context, payload):
        """Create software update strategy.

        :param context: request context object
        :param payload: strategy configuration
        """

        LOG.info(f"Creating software update strategy of type {payload['type']}.")

        # Don't create a strategy if one exists. No need to filter by type
        try:
            strategy = db_api.sw_update_strategy_get(context, update_type=None)
        except exceptions.StrategyNotFound:
            pass
        else:
            msg = f"Strategy of type: '{strategy.type}' already exists"

            LOG.error(
                "Failed creating software update strategy of type "
                f"{payload['type']}. {msg}"
            )
            raise exceptions.BadRequest(resource="strategy", msg=msg)

        single_group = None
        subcloud_group = payload.get("subcloud_group")

        if subcloud_group:
            single_group = utils.subcloud_group_get_by_ref(context, subcloud_group)
            subcloud_apply_type = single_group.update_apply_type
            max_parallel_subclouds = single_group.max_parallel_subclouds
        else:
            subcloud_apply_type = payload.get("subcloud-apply-type")
            max_parallel_subclouds_str = payload.get("max-parallel-subclouds")

            if not max_parallel_subclouds_str:
                max_parallel_subclouds = None
            else:
                max_parallel_subclouds = int(max_parallel_subclouds_str)

        stop_on_failure = payload.get("stop-on-failure") in ["true"]
        force = payload.get(consts.EXTRA_ARGS_FORCE) in ["true"]

        # Has the user specified a specific subcloud?
        cloud_name = payload.get("cloud_name")
        strategy_type = payload.get("type")
        prestage_global_validated = False

        # Has the user specified for_sw_deploy flag for prestage strategy?
        if strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
            for_sw_deploy = payload.get(consts.PRESTAGE_FOR_SW_DEPLOY) in ["true"]

        if cloud_name:
            # Make sure subcloud exists
            try:
                subcloud = db_api.subcloud_get_by_name(context, cloud_name)
            except exceptions.SubcloudNameNotFound:
                msg = f"Subcloud {cloud_name} does not exist"
                LOG.error(
                    "Failed creating software update strategy of type "
                    f"{payload['type']}. {msg}"
                )
                raise exceptions.BadRequest(resource="strategy", msg=msg)

            # TODO(rlima): move prestage to its validator
            if strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
                # Do initial validation for subcloud
                try:
                    prestage.global_prestage_validate(payload)
                    prestage_global_validated = True
                    prestage.initial_subcloud_validate(subcloud)
                except exceptions.PrestagePreCheckFailedException as ex:
                    raise exceptions.BadRequest(resource="strategy", msg=str(ex))
            else:
                self.strategy_validators[strategy_type].validate_strategy_requirements(
                    context, subcloud.id, subcloud.name, force
                )

        extra_args = None
        if strategy_type != consts.SW_UPDATE_TYPE_PRESTAGE:
            extra_args = self.strategy_validators[strategy_type].build_extra_args(
                payload
            )
            # Don't create a strategy if any of the subclouds is online and the
            # relevant sync status is unknown.
            # When the count is greater than 0, that means there are invalid subclouds
            # and the execution should abort.
            count_invalid_subclouds = db_api.subcloud_count_invalid_for_strategy_type(
                context,
                self.strategy_validators[strategy_type].endpoint_type,
                single_group.id if subcloud_group else None,
                cloud_name,
            )
            if count_invalid_subclouds > 0:
                msg = (
                    f"{self.strategy_validators[strategy_type].endpoint_type} "
                    "sync status is unknown for one or more subclouds"
                )
                LOG.error(
                    "Failed creating software update strategy of type "
                    f"{payload['type']}. {msg}"
                )
                raise exceptions.BadRequest(resource="strategy", msg=msg)

        # handle extra_args processing such as staging to the vault
        self._process_extra_args_creation(strategy_type, extra_args)

        if consts.SUBCLOUD_APPLY_TYPE_SERIAL == subcloud_apply_type:
            max_parallel_subclouds = 1

        if max_parallel_subclouds is None:
            max_parallel_subclouds = (
                consts.DEFAULT_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS
            )

        valid_subclouds = db_api.subcloud_get_all_valid_for_strategy_step_creation(
            context,
            self.strategy_validators[strategy_type].endpoint_type,
            single_group.id if subcloud_group else None,
            cloud_name,
            self.strategy_validators[strategy_type].build_availability_status_filter(),
            self.strategy_validators[strategy_type].build_sync_status_filter(force),
        )

        if strategy_type == consts.SW_UPDATE_TYPE_SOFTWARE:
            filtered_valid_subclouds = list()

            for subcloud, sync_status in valid_subclouds:
                if sync_status == dccommon_consts.SYNC_STATUS_OUT_OF_SYNC:
                    filtered_valid_subclouds.append((subcloud, sync_status))

            release_id = extra_args.get(consts.EXTRA_ARGS_RELEASE_ID)
            if filtered_valid_subclouds and release_id:
                software_version = utils.get_major_release(release_id)
                ostree_mount.validate_ostree_iso_mount(software_version)

            valid_subclouds = filtered_valid_subclouds

        elif strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
            if not prestage_global_validated:
                try:
                    prestage.global_prestage_validate(payload)
                except exceptions.PrestagePreCheckFailedException as ex:
                    raise exceptions.BadRequest(resource="strategy", msg=str(ex))

            extra_args = {
                consts.EXTRA_ARGS_SYSADMIN_PASSWORD: payload.get(
                    consts.EXTRA_ARGS_SYSADMIN_PASSWORD
                ),
                consts.EXTRA_ARGS_FORCE: force,
                consts.PRESTAGE_SOFTWARE_VERSION: payload.get(
                    consts.PRESTAGE_REQUEST_RELEASE
                ),
                consts.PRESTAGE_FOR_SW_DEPLOY: for_sw_deploy,
            }

            filtered_valid_subclouds = []
            for subcloud, sync_status in valid_subclouds:
                warn_msg = f"Excluding subcloud from prestage strategy: {subcloud.name}"
                # Do initial validation for subcloud
                try:
                    prestage.initial_subcloud_validate(subcloud)
                    filtered_valid_subclouds.append((subcloud, sync_status))
                except exceptions.PrestagePreCheckFailedException:
                    LOG.warn(warn_msg)
            valid_subclouds = filtered_valid_subclouds

        if not valid_subclouds:
            # handle extra_args processing such as removing from the vault
            self._process_extra_args_deletion(strategy_type, extra_args)
            msg = "Strategy has no steps to apply"
            LOG.error(
                "Failed creating software update strategy of type "
                f"{payload['type']}. {msg}"
            )
            raise exceptions.BadRequest(resource="strategy", msg=msg)

        # Create the strategy
        strategy = db_api.sw_update_strategy_create(
            context,
            strategy_type,
            subcloud_apply_type,
            max_parallel_subclouds,
            stop_on_failure,
            consts.SW_UPDATE_STATE_INITIAL,
            extra_args=extra_args,
        )
        db_api.strategy_step_bulk_create(
            context,
            [subcloud.id for subcloud, _ in valid_subclouds],
            stage=consts.STAGE_SUBCLOUD_ORCHESTRATION_CREATED,
            state=consts.STRATEGY_STATE_INITIAL,
            details="",
        )
        # Clear the error_description field for all subclouds that will
        # perform orchestration.
        update_form = {"error_description": consts.ERROR_DESC_EMPTY}
        db_api.subcloud_bulk_update_by_ids(
            context,
            [subcloud.id for subcloud, _ in valid_subclouds],
            update_form,
        )

        LOG.info(
            f"Finished creating software update strategy of type {payload['type']}."
        )

        return db_api.sw_update_strategy_db_model_to_dict(strategy)

    def delete_sw_update_strategy(self, context, update_type=None):
        """Delete software update strategy.

        :param context: request context object.
        :param update_type: the type to filter on querying
        """
        LOG.info("Deleting software update strategy.")

        # Ensure our read/update of the strategy is done without interference
        # The strategy object is common to all workers (patch, upgrades, etc)
        with self.strategy_lock:
            # Retrieve the existing strategy from the database
            sw_update_strategy = db_api.sw_update_strategy_get(
                context, update_type=update_type
            )

            # Semantic checking
            if sw_update_strategy.state not in [
                consts.SW_UPDATE_STATE_INITIAL,
                consts.SW_UPDATE_STATE_COMPLETE,
                consts.SW_UPDATE_STATE_FAILED,
                consts.SW_UPDATE_STATE_ABORTED,
            ]:
                raise exceptions.BadRequest(
                    resource="strategy",
                    msg="Strategy in state %s cannot be deleted"
                    % sw_update_strategy.state,
                )

            # Set the state to deleting
            sw_update_strategy = db_api.sw_update_strategy_update(
                context, state=consts.SW_UPDATE_STATE_DELETING, update_type=update_type
            )

        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(sw_update_strategy)

        # Because the strategy steps in initial and aborted state does not have a vim
        # strategy created in the subcloud, they can just be deleted from the database
        # directly
        db_api.strategy_step_destroy_all(
            context,
            states=[consts.STRATEGY_STATE_INITIAL, consts.STRATEGY_STATE_ABORTED],
        )

        # Trigger the orchestration for complete and failed steps
        steps = db_api.strategy_step_get_all(
            context, limit=sw_update_strategy.max_parallel_subclouds
        )

        if not steps:
            db_api.sw_update_strategy_destroy(context, sw_update_strategy.type)

            LOG.info(f"({sw_update_strategy.type}) Subcloud orchestration deleted")
            return strategy_dict

        # Set the start time for delete
        self.delete_start_at = timeutils.utcnow()

        # Reduce the sleep time since the deletion is faster than apply
        self.sleep_time = self.sleep_time / 6

        # Send steps to be processed and start monitoring
        self._create_and_send_step_batches(sw_update_strategy.type, steps, True)
        self.thread_group_manager.start(
            self.periodic_strategy_monitoring, sw_update_strategy.type
        )

        LOG.info(f"({sw_update_strategy.type}) Subcloud orchestration delete triggered")

        # handle extra_args processing such as removing from the vault
        self._process_extra_args_deletion(
            sw_update_strategy.type, sw_update_strategy.extra_args
        )

        return strategy_dict

    def apply_sw_update_strategy(self, context, update_type=None):
        """Apply software update strategy.

        :param context: request context object.
        :param update_type: the type to filter on querying
        """
        LOG.info("Applying software update strategy.")

        # Ensure our read/update of the strategy is done without interference
        with self.strategy_lock:
            # Retrieve the existing strategy from the database
            sw_update_strategy = db_api.sw_update_strategy_get(
                context, update_type=update_type
            )

            # Semantic checking
            if sw_update_strategy.state != consts.SW_UPDATE_STATE_INITIAL:
                raise exceptions.BadRequest(
                    resource="strategy",
                    msg="Strategy in state %s cannot be applied"
                    % sw_update_strategy.state,
                )

            # Set the state to applying
            sw_update_strategy = db_api.sw_update_strategy_update(
                context, state=consts.SW_UPDATE_STATE_APPLYING, update_type=update_type
            )

        # Trigger the orchestration
        steps = db_api.strategy_step_get_all(
            context, limit=sw_update_strategy.max_parallel_subclouds
        )
        self._create_and_send_step_batches(sw_update_strategy.type, steps)
        self.thread_group_manager.start(
            self.periodic_strategy_monitoring, sw_update_strategy.type
        )

        LOG.info(f"({sw_update_strategy.type}) Subcloud orchestration apply triggered")

        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(sw_update_strategy)
        return strategy_dict

    def abort_sw_update_strategy(self, context, update_type=None):
        """Abort software update strategy.

        :param context: request context object.
        :param update_type: the type to filter on querying
        """
        LOG.info("Aborting software update strategy.")

        # Ensure our read/update of the strategy is done without interference
        with self.strategy_lock:
            # Retrieve the existing strategy from the database
            sw_update_strategy = db_api.sw_update_strategy_get(
                context, update_type=update_type
            )

            # Semantic checking
            if sw_update_strategy.state != consts.SW_UPDATE_STATE_APPLYING:
                raise exceptions.BadRequest(
                    resource="strategy",
                    msg="Strategy in state %s cannot be aborted"
                    % sw_update_strategy.state,
                )

            # Set the state to abort requested, which will trigger
            # the orchestration to abort...
            sw_update_strategy = db_api.sw_update_strategy_update(
                context, state=consts.SW_UPDATE_STATE_ABORT_REQUESTED
            )

            # Because the workers are only handling the steps up to
            # max_parallel_subclouds, it is necessary to retrieve the remaining
            # steps and set them as aborted, otherwise the strategy will be stuck
            db_api.strategy_step_abort_all_not_processing(
                context, sw_update_strategy.max_parallel_subclouds
            )

            # Reduce the sleep time since the abortion is faster than apply
            self.sleep_time = self.sleep_time / 3

        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(sw_update_strategy)
        return strategy_dict
