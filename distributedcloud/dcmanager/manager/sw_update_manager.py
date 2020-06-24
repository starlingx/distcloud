# Copyright 2017 Ericsson AB.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
import threading

from oslo_log import log as logging

from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import manager
from dcmanager.db import api as db_api
from dcmanager.manager.patch_orch_thread import PatchOrchThread
from dcmanager.manager.sw_upgrade_orch_thread import SwUpgradeOrchThread
from dcorch.common import consts as dcorch_consts

LOG = logging.getLogger(__name__)


class SwUpdateManager(manager.Manager):
    """Manages tasks related to software updates."""

    def __init__(self, *args, **kwargs):
        LOG.debug('SwUpdateManager initialization...')

        super(SwUpdateManager, self).__init__(service_name="sw_update_manager",
                                              *args, **kwargs)
        # Used to protect strategies when an atomic read/update is required.
        self.strategy_lock = threading.Lock()

        # Used to notify dcmanager-audit
        self.audit_rpc_client = dcmanager_audit_rpc_client.ManagerAuditClient()

        # Start worker threads
        # - patch orchestration thread
        self.patch_orch_thread = PatchOrchThread(self.strategy_lock,
                                                 self.audit_rpc_client)
        self.patch_orch_thread.start()
        # - sw upgrade orchestration thread
        self.sw_upgrade_orch_thread = SwUpgradeOrchThread(self.strategy_lock,
                                                          self.audit_rpc_client)
        self.sw_upgrade_orch_thread.start()

    def stop(self):
        # Stop (and join) the worker threads
        # - patch orchestration thread
        self.patch_orch_thread.stop()
        self.patch_orch_thread.join()
        # - sw upgrade orchestration thread
        self.sw_upgrade_orch_thread.stop()
        self.sw_upgrade_orch_thread.join()

    def _validate_subcloud_status_sync(self, strategy_type, subcloud_status):
        """Check the appropriate subcloud_status fields for the strategy_type

           Returns: True if out of sync.
        """
        if strategy_type == consts.SW_UPDATE_TYPE_PATCH:
            return (subcloud_status.endpoint_type ==
                    dcorch_consts.ENDPOINT_TYPE_PATCHING and
                    subcloud_status.sync_status ==
                    consts.SYNC_STATUS_OUT_OF_SYNC)
        elif strategy_type == consts.SW_UPDATE_TYPE_UPGRADE:
            return (subcloud_status.endpoint_type ==
                    dcorch_consts.ENDPOINT_TYPE_LOAD and
                    subcloud_status.sync_status ==
                    consts.SYNC_STATUS_OUT_OF_SYNC)
        # Unimplemented strategy_type status check. Log an error
        LOG.error("_validate_subcloud_status_sync for %s not implemented" %
                  strategy_type)
        return False

    def create_sw_update_strategy(self, context, payload):
        """Create software update strategy.

        :param context: request context object
        :param payload: strategy configuration
        """
        LOG.info("Creating software update strategy of type %s." %
                 payload['type'])

        # Don't create a strategy if one already exists.
        try:
            db_api.sw_update_strategy_get(context)
        except exceptions.NotFound:
            pass
        else:
            raise exceptions.BadRequest(resource='strategy',
                                        msg='Strategy already exists')

        strategy_type = payload.get('type')

        # if use_group_apply_type = True, we use the subcloud_apply_type
        # specified for each subcloud group
        # else we use the subcloud_apply_type specified through CLI
        use_group_apply_type = False
        subcloud_apply_type = payload.get('subcloud-apply-type')
        if not subcloud_apply_type:
            use_group_apply_type = True

        # if use_group_max_parallel = True, we use the max_parallel_subclouds
        # value specified for each subcloud group
        # else we use the max_parallel_subclouds value specified through CLI
        use_group_max_parallel = False
        max_parallel_subclouds_str = payload.get('max-parallel-subclouds')
        if not max_parallel_subclouds_str:
            max_parallel_subclouds = None
            use_group_max_parallel = True
        else:
            max_parallel_subclouds = int(max_parallel_subclouds_str)

        stop_on_failure_str = payload.get('stop-on-failure')
        if not stop_on_failure_str:
            stop_on_failure = False
        else:
            if stop_on_failure_str in ['true']:
                stop_on_failure = True
            else:
                stop_on_failure = False

        # Has the user specified a specific subcloud?
        cloud_name = payload.get('cloud_name')
        if cloud_name and cloud_name != consts.SYSTEM_CONTROLLER_NAME:
            # Make sure subcloud exists
            try:
                subcloud = db_api.subcloud_get_by_name(context, cloud_name)
            except exceptions.SubcloudNameNotFound:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Subcloud %s does not exist' % cloud_name)

            if strategy_type == consts.SW_UPDATE_TYPE_UPGRADE:
                # todo(abailey): Check if subcloud requires upgrade
                LOG.warning("subcloud upgrade in-sync status not implemented")
            elif strategy_type == consts.SW_UPDATE_TYPE_PATCH:
                # Make sure subcloud requires patching
                subcloud_status = db_api.subcloud_status_get(
                    context, subcloud.id, dcorch_consts.ENDPOINT_TYPE_PATCHING)
                if subcloud_status.sync_status == consts.SYNC_STATUS_IN_SYNC:
                    raise exceptions.BadRequest(
                        resource='strategy',
                        msg='Subcloud %s does not require patching' % cloud_name)

        # Don't create a strategy if the strategy sync status is unknown for
        # any subcloud we will be updating that is managed and online.
        subclouds = db_api.subcloud_get_all_with_status(context)
        for subcloud, subcloud_status in subclouds:
            if cloud_name and subcloud.name != cloud_name:
                # We are not updating this subcloud
                continue
            if (subcloud.management_state != consts.MANAGEMENT_MANAGED or
                    subcloud.availability_status !=
                    consts.AVAILABILITY_ONLINE):
                continue

            if strategy_type == consts.SW_UPDATE_TYPE_UPGRADE:
                if (subcloud_status.endpoint_type ==
                    dcorch_consts.ENDPOINT_TYPE_LOAD and
                        subcloud_status.sync_status ==
                        consts.SYNC_STATUS_UNKNOWN):
                    raise exceptions.BadRequest(
                        resource='strategy',
                        msg='Upgrade sync status is unknown for one or more '
                            'subclouds')
            elif strategy_type == consts.SW_UPDATE_TYPE_PATCH:
                if (subcloud_status.endpoint_type ==
                    dcorch_consts.ENDPOINT_TYPE_PATCHING and
                        subcloud_status.sync_status ==
                        consts.SYNC_STATUS_UNKNOWN):
                    raise exceptions.BadRequest(
                        resource='strategy',
                        msg='Patching sync status is unknown for one or more '
                            'subclouds')

        # Create the strategy
        strategy = db_api.sw_update_strategy_create(
            context,
            strategy_type,
            subcloud_apply_type,
            max_parallel_subclouds,
            stop_on_failure,
            consts.SW_UPDATE_STATE_INITIAL)

        # For 'upgrade' do not create a strategy step for the system controller
        # For 'patch', always create a strategy step for the system controller
        if strategy_type == consts.SW_UPDATE_TYPE_PATCH:
            db_api.strategy_step_create(
                context,
                None,  # None means not a subcloud. ie: SystemController
                stage=1,
                state=consts.STRATEGY_STATE_INITIAL,
                details='')

        # Create a strategy step for each subcloud that is managed, online and
        # out of sync
        current_stage = 2
        stage_size = 0
        stage_updated = False

        # Fetch all subcloud groups
        groups = db_api.subcloud_group_get_all(context)

        for group in groups:
            # Fetch subcloud list for each group
            subclouds_list = db_api.subcloud_get_for_group(context, group.id)
            if use_group_max_parallel:
                max_parallel_subclouds = group.max_parallel_subclouds
            if use_group_apply_type:
                subcloud_apply_type = group.update_apply_type
            for subcloud in subclouds_list:
                stage_updated = False
                if cloud_name and subcloud.name != cloud_name:
                    # We are not targeting for update this subcloud
                    continue
                if (subcloud.management_state != consts.MANAGEMENT_MANAGED or
                        subcloud.availability_status !=
                        consts.AVAILABILITY_ONLINE):
                    continue

                subcloud_status = db_api.subcloud_status_get_all(context, subcloud.id)
                for status in subcloud_status:
                    if self._validate_subcloud_status_sync(strategy_type,
                                                           status):
                        LOG.debug("Created for %s" % subcloud.id)
                        db_api.strategy_step_create(
                            context,
                            subcloud.id,
                            stage=current_stage,
                            state=consts.STRATEGY_STATE_INITIAL,
                            details='')

                        # We have added a subcloud to this stage
                        stage_size += 1
                        if consts.SUBCLOUD_APPLY_TYPE_SERIAL in subcloud_apply_type:
                            # For serial apply type always move to next stage
                            stage_updated = True
                            current_stage += 1
                        elif stage_size >= max_parallel_subclouds:
                            # For parallel apply type, move to next stage if we have
                            # reached the maximum subclouds for this stage
                            stage_updated = True
                            current_stage += 1
                            stage_size = 0

            # Reset the stage_size before iterating through a new subcloud group
            stage_size = 0
            # current_stage value is updated only when subcloud_apply_type is serial
            # or the max_parallel_subclouds limit is reached. If the value is updated
            # for either one of these reasons and it also happens to be the last
            # iteration for this particular group, the following check will prevent
            # the current_stage value from being updated twice
            if not stage_updated:
                current_stage += 1

        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
            strategy)
        return strategy_dict

    def delete_sw_update_strategy(self, context):
        """Delete software update strategy.

        :param context: request context object.
        """
        LOG.info("Deleting software update strategy.")

        # Ensure our read/update of the strategy is done without interference
        # The strategy object is common to all workers (patch, upgrades, etc)
        with self.strategy_lock:
            # Retrieve the existing strategy from the database
            sw_update_strategy = db_api.sw_update_strategy_get(context)

            # Semantic checking
            if sw_update_strategy.state not in [
                    consts.SW_UPDATE_STATE_INITIAL,
                    consts.SW_UPDATE_STATE_COMPLETE,
                    consts.SW_UPDATE_STATE_FAILED,
                    consts.SW_UPDATE_STATE_ABORTED]:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Strategy in state %s cannot be deleted' %
                        sw_update_strategy.state)

            # Set the state to deleting, which will trigger the orchestration
            # to delete it...
            sw_update_strategy = db_api.sw_update_strategy_update(
                context, state=consts.SW_UPDATE_STATE_DELETING)

        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
            sw_update_strategy)
        return strategy_dict

    def apply_sw_update_strategy(self, context):
        """Apply software update strategy.

        :param context: request context object.
        """
        LOG.info("Applying software update strategy.")

        # Ensure our read/update of the strategy is done without interference
        with self.strategy_lock:
            # Retrieve the existing strategy from the database
            sw_update_strategy = db_api.sw_update_strategy_get(context)

            # Semantic checking
            if sw_update_strategy.state != consts.SW_UPDATE_STATE_INITIAL:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Strategy in state %s cannot be applied' %
                        sw_update_strategy.state)

            # Set the state to applying, which will trigger the orchestration
            # to begin...
            sw_update_strategy = db_api.sw_update_strategy_update(
                context, state=consts.SW_UPDATE_STATE_APPLYING)
        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
            sw_update_strategy)
        return strategy_dict

    def abort_sw_update_strategy(self, context):
        """Abort software update strategy.

        :param context: request context object.
        """
        LOG.info("Aborting software update strategy.")

        # Ensure our read/update of the strategy is done without interference
        with self.strategy_lock:
            # Retrieve the existing strategy from the database
            sw_update_strategy = db_api.sw_update_strategy_get(context)

            # Semantic checking
            if sw_update_strategy.state != consts.SW_UPDATE_STATE_APPLYING:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Strategy in state %s cannot be aborted' %
                        sw_update_strategy.state)

            # Set the state to abort requested, which will trigger
            # the orchestration to abort...
            sw_update_strategy = db_api.sw_update_strategy_update(
                context, state=consts.SW_UPDATE_STATE_ABORT_REQUESTED)
        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
            sw_update_strategy)
        return strategy_dict
