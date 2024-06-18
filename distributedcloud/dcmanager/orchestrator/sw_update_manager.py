# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2024 Wind River Systems, Inc.
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

import os
import shutil
import threading

from oslo_log import log as logging
from tsconfig.tsconfig import SW_VERSION

from dccommon import consts as dccommon_consts
from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common import manager
from dcmanager.common import prestage
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.orchestrator.fw_update_orch_thread import FwUpdateOrchThread
from dcmanager.orchestrator.kube_rootca_update_orch_thread \
    import KubeRootcaUpdateOrchThread
from dcmanager.orchestrator.kube_upgrade_orch_thread \
    import KubeUpgradeOrchThread
from dcmanager.orchestrator.patch_orch_thread import PatchOrchThread
from dcmanager.orchestrator.prestage_orch_thread import PrestageOrchThread
from dcmanager.orchestrator.software_orch_thread import SoftwareOrchThread
from dcmanager.orchestrator.sw_upgrade_orch_thread import SwUpgradeOrchThread

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

        # todo(abailey): refactor/decouple orch threads into a list
        # Start worker threads

        # - software orchestration thread
        self.software_orch_thread = SoftwareOrchThread(
            self.strategy_lock, self.audit_rpc_client)
        self.software_orch_thread.start()

        # - patch orchestration thread
        self.patch_orch_thread = PatchOrchThread(
            self.strategy_lock, self.audit_rpc_client)
        self.patch_orch_thread.start()

        # - sw upgrade orchestration thread
        self.sw_upgrade_orch_thread = SwUpgradeOrchThread(
            self.strategy_lock, self.audit_rpc_client)
        self.sw_upgrade_orch_thread.start()

        # - fw update orchestration thread
        self.fw_update_orch_thread = FwUpdateOrchThread(
            self.strategy_lock, self.audit_rpc_client)
        self.fw_update_orch_thread.start()

        # - kube upgrade orchestration thread
        self.kube_upgrade_orch_thread = KubeUpgradeOrchThread(
            self.strategy_lock, self.audit_rpc_client)
        self.kube_upgrade_orch_thread.start()

        # - kube rootca update orchestration thread
        self.kube_rootca_update_orch_thread = KubeRootcaUpdateOrchThread(
            self.strategy_lock, self.audit_rpc_client)
        self.kube_rootca_update_orch_thread.start()

        # - prestage orchestration thread
        self.prestage_orch_thread = PrestageOrchThread(
            self.strategy_lock, self.audit_rpc_client)
        self.prestage_orch_thread.start()

    def stop(self):
        # Stop (and join) the worker threads

        # - software orchestration thread
        self.software_orch_thread.stop()
        self.software_orch_thread.join()
        # - patch orchestration thread
        self.patch_orch_thread.stop()
        self.patch_orch_thread.join()
        # - sw upgrade orchestration thread
        self.sw_upgrade_orch_thread.stop()
        self.sw_upgrade_orch_thread.join()
        # - fw update orchestration thread
        self.fw_update_orch_thread.stop()
        self.fw_update_orch_thread.join()
        # - kube upgrade orchestration thread
        self.kube_upgrade_orch_thread.stop()
        self.kube_upgrade_orch_thread.join()
        # - kube rootca update orchestration thread
        self.kube_rootca_update_orch_thread.stop()
        self.kube_rootca_update_orch_thread.join()
        # - prestage orchestration thread
        self.prestage_orch_thread.stop()
        self.prestage_orch_thread.join()

    def _validate_subcloud_status_sync(self, strategy_type,
                                       subcloud_status, force,
                                       subcloud, patch_file):
        """Check the appropriate subcloud_status fields for the strategy_type

           Returns: True if out of sync.
        """
        availability_status = subcloud.availability_status
        if strategy_type == consts.SW_UPDATE_TYPE_PATCH:
            if patch_file:
                # If a patch file is specified, we need to check the software version
                # of the subcloud and the system controller. If the software versions
                # are the same, we cannot apply the patch.
                LOG.warning(
                    f"Patch file: {patch_file} specified for "
                    f"subcloud {subcloud.name}"
                )
                if subcloud.software_version == SW_VERSION:
                    raise exceptions.BadRequest(
                        resource="strategy",
                        msg=(
                            f"Subcloud {subcloud.name} has the same software "
                            "version than the system controller. The --patch "
                            "option only works with n-1 subclouds."
                        ),
                    )
            return (subcloud_status.endpoint_type ==
                    dccommon_consts.ENDPOINT_TYPE_PATCHING and
                    subcloud_status.sync_status ==
                    dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
        elif strategy_type == consts.SW_UPDATE_TYPE_UPGRADE:
            # force option only has an effect in offline case for upgrade
            if force and availability_status != dccommon_consts.AVAILABILITY_ONLINE:
                return (subcloud_status.endpoint_type ==
                        dccommon_consts.ENDPOINT_TYPE_LOAD and
                        subcloud_status.sync_status !=
                        dccommon_consts.SYNC_STATUS_IN_SYNC)
            else:
                return (subcloud_status.endpoint_type ==
                        dccommon_consts.ENDPOINT_TYPE_LOAD and
                        subcloud_status.sync_status ==
                        dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
        elif strategy_type == consts.SW_UPDATE_TYPE_SOFTWARE:
            if force and availability_status != dccommon_consts.AVAILABILITY_ONLINE:
                return (subcloud_status.endpoint_type ==
                        dccommon_consts.ENDPOINT_TYPE_SOFTWARE and
                        subcloud_status.sync_status !=
                        dccommon_consts.SYNC_STATUS_IN_SYNC)
            else:
                return (subcloud_status.endpoint_type ==
                        dccommon_consts.ENDPOINT_TYPE_SOFTWARE and
                        subcloud_status.sync_status ==
                        dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
        elif strategy_type == consts.SW_UPDATE_TYPE_FIRMWARE:
            return (subcloud_status.endpoint_type ==
                    dccommon_consts.ENDPOINT_TYPE_FIRMWARE and
                    subcloud_status.sync_status ==
                    dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
        elif strategy_type == consts.SW_UPDATE_TYPE_KUBERNETES:
            if force:
                # run for in-sync and out-of-sync (but not unknown)
                return (subcloud_status.endpoint_type ==
                        dccommon_consts.ENDPOINT_TYPE_KUBERNETES and
                        subcloud_status.sync_status !=
                        dccommon_consts.SYNC_STATUS_UNKNOWN)
            else:
                return (subcloud_status.endpoint_type ==
                        dccommon_consts.ENDPOINT_TYPE_KUBERNETES and
                        subcloud_status.sync_status ==
                        dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
        elif strategy_type == consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE:
            if force:
                # run for in-sync and out-of-sync (but not unknown)
                return (subcloud_status.endpoint_type ==
                        dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA and
                        subcloud_status.sync_status !=
                        dccommon_consts.SYNC_STATUS_UNKNOWN)
            else:
                return (subcloud_status.endpoint_type ==
                        dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA and
                        subcloud_status.sync_status ==
                        dccommon_consts.SYNC_STATUS_OUT_OF_SYNC)
        elif strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
            # For prestage we reuse the ENDPOINT_TYPE_LOAD.
            # We just need to key off a unique endpoint,
            # so that the strategy is created only once.
            return (subcloud_status.endpoint_type ==
                    dccommon_consts.ENDPOINT_TYPE_LOAD)
        # Unimplemented strategy_type status check. Log an error
        LOG.error("_validate_subcloud_status_sync for %s not implemented" %
                  strategy_type)
        return False

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
                        raise exceptions.BadRequest(resource='strategy',
                                                    msg=reason)
                if subject:
                    is_valid, reason = \
                        utils.validate_certificate_subject(subject)
                    if not is_valid:
                        raise exceptions.BadRequest(resource='strategy',
                                                    msg=reason)
                if cert_file:
                    if expiry_date or subject:
                        raise exceptions.BadRequest(
                            resource='strategy',
                            msg='Invalid extra args.'
                                ' <cert-file> cannot be specified'
                                ' along with <subject> or <expiry-date>.')
                    # copy the cert-file to the vault
                    vault_file = self._vault_upload(consts.CERTS_VAULT_DIR,
                                                    cert_file)
                    # update extra_args with the new path (in the vault)
                    extra_args[consts.EXTRA_ARGS_CERT_FILE] = vault_file

    def _process_extra_args_deletion(self, strategy):
        if strategy.extra_args:
            # cert-file extra_arg needs vault handling for kube rootca update
            if strategy.type == consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE:
                cert_file = strategy.extra_args.get(
                    consts.EXTRA_ARGS_CERT_FILE)
                if cert_file:
                    # remove this cert file from the vault
                    self._vault_remove(consts.CERTS_VAULT_DIR, cert_file)

    def create_sw_update_strategy(self, context, payload):
        """Create software update strategy.

        :param context: request context object
        :param payload: strategy configuration
        """
        LOG.info("Creating software update strategy of type %s." %
                 payload['type'])

        # Don't create a strategy if one exists. No need to filter by type
        try:
            strategy = db_api.sw_update_strategy_get(context, update_type=None)
        except exceptions.NotFound:
            pass
        else:
            raise exceptions.BadRequest(
                resource='strategy',
                msg="Strategy of type: '%s' already exists" % strategy.type)

        strategy_type = payload.get('type')

        single_group = None
        subcloud_group = payload.get('subcloud_group')
        if subcloud_group:
            single_group = utils.subcloud_group_get_by_ref(context,
                                                           subcloud_group)
            subcloud_apply_type = single_group.update_apply_type
            max_parallel_subclouds = single_group.max_parallel_subclouds
        else:
            subcloud_apply_type = payload.get('subcloud-apply-type')
            max_parallel_subclouds_str = payload.get('max-parallel-subclouds')

            if not max_parallel_subclouds_str:
                max_parallel_subclouds = None
            else:
                max_parallel_subclouds = int(max_parallel_subclouds_str)

        # todo(abailey): refactor common code in stop-on-failure and force
        stop_on_failure_str = payload.get('stop-on-failure')

        if not stop_on_failure_str:
            stop_on_failure = False
        else:
            if stop_on_failure_str in ['true']:
                stop_on_failure = True
            else:
                stop_on_failure = False

        force_str = payload.get('force')
        if not force_str:
            force = False
        else:
            if force_str in ['true']:
                force = True
            else:
                force = False

        patch_file = payload.get('patch')
        installed_loads = []
        software_version = None
        if payload.get(consts.PRESTAGE_REQUEST_RELEASE):
            software_version = payload.get(consts.PRESTAGE_REQUEST_RELEASE)
            installed_loads = utils.get_systemcontroller_installed_loads()

        # Has the user specified a specific subcloud?
        # todo(abailey): refactor this code to use classes
        cloud_name = payload.get('cloud_name')
        prestage_global_validated = False
        if cloud_name and cloud_name != dccommon_consts.SYSTEM_CONTROLLER_NAME:
            # Make sure subcloud exists
            try:
                subcloud = db_api.subcloud_get_by_name(context, cloud_name)
            except exceptions.SubcloudNameNotFound:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Subcloud %s does not exist' % cloud_name)

            if strategy_type == consts.SW_UPDATE_TYPE_UPGRADE:
                # Make sure subcloud requires upgrade
                subcloud_status = db_api.subcloud_status_get(
                    context, subcloud.id, dccommon_consts.ENDPOINT_TYPE_LOAD)
                if subcloud_status.sync_status == \
                        dccommon_consts.SYNC_STATUS_IN_SYNC:
                    raise exceptions.BadRequest(
                        resource='strategy',
                        msg='Subcloud %s does not require upgrade' % cloud_name)
            elif strategy_type == consts.SW_UPDATE_TYPE_SOFTWARE:
                subcloud_status = db_api.subcloud_status_get(
                    context, subcloud.id, dccommon_consts.ENDPOINT_TYPE_SOFTWARE)
                if subcloud_status.sync_status == \
                        dccommon_consts.SYNC_STATUS_IN_SYNC:
                    raise exceptions.BadRequest(
                        resource='strategy',
                        msg=f'Subcloud {cloud_name} does not require deploy')
            elif strategy_type == consts.SW_UPDATE_TYPE_FIRMWARE:
                subcloud_status = db_api.subcloud_status_get(
                    context, subcloud.id, dccommon_consts.ENDPOINT_TYPE_FIRMWARE)
                if subcloud_status.sync_status == \
                        dccommon_consts.SYNC_STATUS_IN_SYNC:
                    raise exceptions.BadRequest(
                        resource='strategy',
                        msg='Subcloud %s does not require firmware update'
                            % cloud_name)
            elif strategy_type == consts.SW_UPDATE_TYPE_KUBERNETES:
                if force:
                    # force means we do not care about the status
                    pass
                else:
                    subcloud_status = db_api.subcloud_status_get(
                        context, subcloud.id,
                        dccommon_consts.ENDPOINT_TYPE_KUBERNETES)
                    if subcloud_status.sync_status == \
                            dccommon_consts.SYNC_STATUS_IN_SYNC:
                        raise exceptions.BadRequest(
                            resource='strategy',
                            msg='Subcloud %s does not require kubernetes update'
                                % cloud_name)
            elif strategy_type == consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE:
                if force:
                    # force means we do not care about the status
                    pass
                else:
                    subcloud_status = db_api.subcloud_status_get(
                        context, subcloud.id,
                        dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA)
                    if subcloud_status.sync_status == \
                            dccommon_consts.SYNC_STATUS_IN_SYNC:
                        raise exceptions.BadRequest(
                            resource='strategy',
                            msg='Subcloud %s does not require kube rootca update'
                                % cloud_name)
            elif strategy_type == consts.SW_UPDATE_TYPE_PATCH:
                # Make sure subcloud requires patching
                subcloud_status = db_api.subcloud_status_get(
                    context, subcloud.id, dccommon_consts.ENDPOINT_TYPE_PATCHING)
                if subcloud_status.sync_status == \
                        dccommon_consts.SYNC_STATUS_IN_SYNC:
                    raise exceptions.BadRequest(
                        resource='strategy',
                        msg='Subcloud %s does not require patching' % cloud_name)

            elif strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
                # Do initial validation for subcloud
                try:
                    prestage.global_prestage_validate(payload)
                    prestage_global_validated = True
                    prestage.initial_subcloud_validate(
                        subcloud, installed_loads, software_version)
                except exceptions.PrestagePreCheckFailedException as ex:
                    raise exceptions.BadRequest(resource='strategy',
                                                msg=str(ex))

        extra_args = None
        # kube rootca update orchestration supports extra creation args
        if strategy_type == consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE:
            # payload fields use "-" rather than "_"
            # some of these payloads may be 'None'
            extra_args = {
                consts.EXTRA_ARGS_EXPIRY_DATE:
                    payload.get(consts.EXTRA_ARGS_EXPIRY_DATE),
                consts.EXTRA_ARGS_SUBJECT:
                    payload.get(consts.EXTRA_ARGS_SUBJECT),
                consts.EXTRA_ARGS_CERT_FILE:
                    payload.get(consts.EXTRA_ARGS_CERT_FILE),
            }
        elif strategy_type == consts.SW_UPDATE_TYPE_KUBERNETES:
            extra_args = {
                consts.EXTRA_ARGS_TO_VERSION:
                    payload.get(consts.EXTRA_ARGS_TO_VERSION),
            }
        elif strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
            if not prestage_global_validated:
                try:
                    prestage.global_prestage_validate(payload)
                except exceptions.PrestagePreCheckFailedException as ex:
                    raise exceptions.BadRequest(
                        resource='strategy',
                        msg=str(ex))

            extra_args = {
                consts.EXTRA_ARGS_SYSADMIN_PASSWORD:
                    payload.get(consts.EXTRA_ARGS_SYSADMIN_PASSWORD),
                consts.EXTRA_ARGS_FORCE: force,
                consts.PRESTAGE_SOFTWARE_VERSION:
                    software_version if software_version else SW_VERSION
            }
        elif strategy_type == consts.SW_UPDATE_TYPE_PATCH:
            upload_only_str = payload.get(consts.EXTRA_ARGS_UPLOAD_ONLY)
            upload_only_bool = True if upload_only_str == 'true' else False
            extra_args = {
                consts.EXTRA_ARGS_UPLOAD_ONLY: upload_only_bool,
                consts.EXTRA_ARGS_PATCH: payload.get(consts.EXTRA_ARGS_PATCH)
            }
        elif strategy_type == consts.SW_UPDATE_TYPE_SOFTWARE:
            extra_args = {
                consts.EXTRA_ARGS_RELEASE: payload.get(consts.EXTRA_ARGS_RELEASE)
            }

        # Don't create a strategy if any of the subclouds is online and the
        # relevant sync status is unknown. Offline subcloud is skipped unless
        # --force option is specified and strategy type is upgrade.
        if single_group:
            subclouds = []
            for sb in db_api.subcloud_get_for_group(context, single_group.id):
                statuses = db_api.subcloud_status_get_all(context, sb.id)
                for status in statuses:
                    subclouds.append((sb, status.endpoint_type, status.sync_status))
        else:
            subclouds = db_api.subcloud_get_all_with_status(context)

        subclouds_processed = list()
        for subcloud, endpoint_type, sync_status in subclouds:
            if (
                cloud_name
                and subcloud.name != cloud_name
                or subcloud.management_state != dccommon_consts.MANAGEMENT_MANAGED
            ):
                # We are not updating this subcloud
                continue

            if strategy_type == consts.SW_UPDATE_TYPE_UPGRADE:
                if (
                    subcloud.availability_status !=
                    dccommon_consts.AVAILABILITY_ONLINE
                ):
                    if not force:
                        continue
                elif (
                    endpoint_type == dccommon_consts.ENDPOINT_TYPE_LOAD
                    and sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN
                ):
                    raise exceptions.BadRequest(
                        resource="strategy",
                        msg="Upgrade sync status is unknown for one or more "
                        "subclouds",
                    )
            elif strategy_type == consts.SW_UPDATE_TYPE_SOFTWARE:
                if (
                    subcloud.availability_status !=
                    dccommon_consts.AVAILABILITY_ONLINE
                ):
                    if not force:
                        continue
                if (
                    endpoint_type == dccommon_consts.ENDPOINT_TYPE_SOFTWARE
                    and sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN
                ):
                    raise exceptions.BadRequest(
                        resource="strategy",
                        msg="Software sync status is unknown for one or more "
                        "subclouds",
                    )
            elif strategy_type == consts.SW_UPDATE_TYPE_PATCH:
                if (
                    subcloud.availability_status !=
                    dccommon_consts.AVAILABILITY_ONLINE
                ):
                    continue
                elif (
                    endpoint_type == dccommon_consts.ENDPOINT_TYPE_PATCHING
                    and sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN
                ):
                    raise exceptions.BadRequest(
                        resource="strategy",
                        msg="Patching sync status is unknown for one or more "
                        "subclouds",
                    )
            elif strategy_type == consts.SW_UPDATE_TYPE_FIRMWARE:
                if (
                    subcloud.availability_status !=
                    dccommon_consts.AVAILABILITY_ONLINE
                ):
                    continue
                elif (
                    endpoint_type == dccommon_consts.ENDPOINT_TYPE_FIRMWARE
                    and sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN
                ):
                    raise exceptions.BadRequest(
                        resource="strategy",
                        msg="Firmware sync status is unknown for one or more "
                        "subclouds",
                    )
            elif strategy_type == consts.SW_UPDATE_TYPE_KUBERNETES:
                if (
                    subcloud.availability_status !=
                    dccommon_consts.AVAILABILITY_ONLINE
                ):
                    continue
                elif (
                    endpoint_type == dccommon_consts.ENDPOINT_TYPE_KUBERNETES
                    and sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN
                ):
                    raise exceptions.BadRequest(
                        resource="strategy",
                        msg="Kubernetes sync status is unknown for one or more "
                        "subclouds",
                    )
            elif strategy_type == consts.SW_UPDATE_TYPE_KUBE_ROOTCA_UPDATE:
                if (
                    subcloud.availability_status !=
                    dccommon_consts.AVAILABILITY_ONLINE
                ):
                    continue
                elif (
                    endpoint_type == dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA
                    and sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN
                ):
                    raise exceptions.BadRequest(
                        resource="strategy",
                        msg="Kube rootca update sync status is unknown for "
                        "one or more subclouds",
                    )
            elif strategy_type == consts.SW_UPDATE_TYPE_PRESTAGE:
                if subcloud.name not in subclouds_processed:
                    # Do initial validation for subcloud
                    try:
                        prestage.initial_subcloud_validate(
                            subcloud, installed_loads, software_version)
                    except exceptions.PrestagePreCheckFailedException:
                        LOG.warn("Excluding subcloud from prestage strategy: %s",
                                 subcloud.name)
                        continue
            subclouds_processed.append(subcloud.name)

        # handle extra_args processing such as staging to the vault
        self._process_extra_args_creation(strategy_type, extra_args)

        if consts.SUBCLOUD_APPLY_TYPE_SERIAL == subcloud_apply_type:
            max_parallel_subclouds = 1

        if max_parallel_subclouds is None:
            max_parallel_subclouds = (
                consts.DEFAULT_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS)

        strategy_step_created = False
        # Create the strategy
        strategy = db_api.sw_update_strategy_create(
            context,
            strategy_type,
            subcloud_apply_type,
            max_parallel_subclouds,
            stop_on_failure,
            consts.SW_UPDATE_STATE_INITIAL,
            extra_args=extra_args)

        # Create a strategy step for each subcloud that is managed, online and
        # out of sync
        # special cases:
        #  - kube rootca update: the 'force' option allows in-sync subclouds

        if single_group:
            subclouds_list = db_api.subcloud_get_for_group(context, single_group.id)
        else:
            # Fetch all subclouds
            subclouds_list = db_api.subcloud_get_all_ordered_by_id(context)

        for subcloud in subclouds_list:
            if (cloud_name and subcloud.name != cloud_name or
                    subcloud.management_state != dccommon_consts.MANAGEMENT_MANAGED):
                # We are not targeting for update this subcloud
                continue

            if subcloud.availability_status != dccommon_consts.AVAILABILITY_ONLINE:
                if strategy_type == consts.SW_UPDATE_TYPE_UPGRADE:
                    if not force:
                        continue
                else:
                    continue

            subcloud_status = db_api.subcloud_status_get_all(context,
                                                             subcloud.id)
            for status in subcloud_status:
                if self._validate_subcloud_status_sync(strategy_type,
                                                       status,
                                                       force,
                                                       subcloud,
                                                       patch_file):
                    LOG.debug("Creating strategy_step for endpoint_type: %s, "
                              "sync_status: %s, subcloud: %s, id: %s",
                              status.endpoint_type, status.sync_status,
                              subcloud.name, subcloud.id)
                    db_api.strategy_step_create(
                        context,
                        subcloud.id,
                        stage=consts.STAGE_SUBCLOUD_ORCHESTRATION_CREATED,
                        state=consts.STRATEGY_STATE_INITIAL,
                        details='')
                    strategy_step_created = True

        if strategy_step_created:
            strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
                strategy)
            return strategy_dict
        else:
            # Set the state to deleting, which will trigger the orchestration
            # to delete it...
            strategy = db_api.sw_update_strategy_update(
                context,
                state=consts.SW_UPDATE_STATE_DELETING,
                update_type=strategy_type)
            # handle extra_args processing such as removing from the vault
            self._process_extra_args_deletion(strategy)
            raise exceptions.BadRequest(
                resource='strategy',
                msg='Strategy has no steps to apply')

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
            sw_update_strategy = \
                db_api.sw_update_strategy_get(context, update_type=update_type)

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
                context,
                state=consts.SW_UPDATE_STATE_DELETING,
                update_type=update_type)
            # handle extra_args processing such as removing from the vault
        self._process_extra_args_deletion(sw_update_strategy)

        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
            sw_update_strategy)
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
            sw_update_strategy = \
                db_api.sw_update_strategy_get(context, update_type=update_type)

            # Semantic checking
            if sw_update_strategy.state != consts.SW_UPDATE_STATE_INITIAL:
                raise exceptions.BadRequest(
                    resource='strategy',
                    msg='Strategy in state %s cannot be applied' %
                        sw_update_strategy.state)

            # Set the state to applying, which will trigger the orchestration
            # to begin...
            sw_update_strategy = db_api.sw_update_strategy_update(
                context,
                state=consts.SW_UPDATE_STATE_APPLYING,
                update_type=update_type)
        strategy_dict = db_api.sw_update_strategy_db_model_to_dict(
            sw_update_strategy)
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
            sw_update_strategy = \
                db_api.sw_update_strategy_get(context, update_type=update_type)

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
