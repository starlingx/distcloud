# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2024 Wind River Systems, Inc.
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
import time

import eventlet
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
from tsconfig.tsconfig import CONFIG_PATH

from dccommon import consts as dccommon_consts
from dcmanager.audit import firmware_audit
from dcmanager.audit import kube_rootca_update_audit
from dcmanager.audit import kubernetes_audit
from dcmanager.audit import patch_audit
from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.audit import software_audit
from dcmanager.audit import utils as audit_utils
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.db import api as db_api

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# We will update the state of each subcloud in the dcorch about once per hour.
# Calculate how many iterations that will be.
SUBCLOUD_STATE_UPDATE_ITERATIONS = (
    dccommon_consts.SECONDS_IN_HOUR // CONF.scheduler.subcloud_audit_interval
)

# Time for the periodic audit loop to execute
# It needs to be greater than the subcloud_audit_interval
AUDIT_LOOP_INTERVAL = CONF.scheduler.subcloud_audit_interval + 10

# Name of starlingx openstack helm application
HELM_APP_OPENSTACK = "openstack"

# Every 4 software audits triggers
ONE_HOUR_AUDIT_RATE = 4

# Valid Deploy Status for auditing
VALID_DEPLOY_STATE = [
    consts.DEPLOY_STATE_DONE,
    consts.DEPLOY_STATE_CONFIGURING,
    consts.DEPLOY_STATE_CONFIG_FAILED,
    consts.DEPLOY_STATE_CONFIG_ABORTED,
    consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
    consts.DEPLOY_STATE_INSTALL_FAILED,
    consts.DEPLOY_STATE_INSTALL_ABORTED,
    consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
    consts.DEPLOY_STATE_INSTALLING,
    consts.DEPLOY_STATE_RESTORING,
    consts.DEPLOY_STATE_RESTORE_PREP_FAILED,
    consts.DEPLOY_STATE_RESTORE_FAILED,
    consts.DEPLOY_STATE_REHOME_PENDING,
    consts.DEPLOY_STATE_SW_DEPLOY_IN_PROGRESS,
    consts.DEPLOY_STATE_APPLY_STRATEGY_FAILED,
]


class SubcloudAuditManager(manager.Manager):
    """Manages tasks related to audits."""

    # Used to force patch audit on the next interval
    force_patch_audit = False

    # Used to force firmware audit on the next interval
    force_firmware_audit = False

    # Used to force kube rootca update audit on the next interval
    force_kube_rootca_update_audit = False

    # Used to force kubernetes audit on the next interval
    force_kubernetes_audit = False

    # Used to force patch audit on the next interval
    force_software_audit = False

    def __init__(self, *args, **kwargs):
        LOG.debug(_("SubcloudAuditManager initialization..."))

        super(SubcloudAuditManager, self).__init__(
            service_name="subcloud_audit_manager"
        )
        self.context = context.get_admin_context()
        self.audit_worker_rpc_client = (
            dcmanager_audit_rpc_client.ManagerAuditWorkerClient()
        )
        # Number of audits since last subcloud state update
        self.audit_count = SUBCLOUD_STATE_UPDATE_ITERATIONS - 2
        self.patch_audit = patch_audit.PatchAudit(self.context)
        self.firmware_audit = firmware_audit.FirmwareAudit()
        self.kubernetes_audit = kubernetes_audit.KubernetesAudit()
        self.kube_rootca_update_audit = kube_rootca_update_audit.KubeRootcaUpdateAudit()
        self.software_audit = software_audit.SoftwareAudit()
        # Number of patch audits
        self.patch_audit_count = 0
        # trigger a patch audit on startup
        self.patch_audit_time = 0

    def _add_missing_endpoints(self):
        # Update this flag file based on the most recent new endpoint
        file_path = os.path.join(CONFIG_PATH, ".usm_endpoint_added")
        # If file exists on the controller, all the endpoints have been
        # added to DB since last time an endpoint was added
        if not os.path.isfile(file_path):
            # Ensures all endpoints exist for all subclouds
            # If the endpoint doesn't exist, an entry will be made
            # in endpoint_status table
            for subcloud in db_api.subcloud_get_all(self.context):
                subcloud_statuses = db_api.subcloud_status_get_all(
                    self.context, subcloud.id
                )
                # Use set difference to find missing endpoints
                endpoint_type_set = set(dccommon_consts.AUDIT_TYPES_LIST)
                subcloud_set = set()
                for subcloud_status in subcloud_statuses:
                    subcloud_set.add(subcloud_status.endpoint_type)

                missing_endpoints = list(endpoint_type_set - subcloud_set)

                for endpoint in missing_endpoints:
                    db_api.subcloud_status_create(self.context, subcloud.id, endpoint)
            # Add a flag on a replicated filesystem to avoid re-running
            # the DB checks for missing subcloud endpoints
            open(file_path, "w").close()

    @classmethod
    def trigger_firmware_audit(cls, context):
        """Trigger firmware audit at next interval.

        This can be called from outside the dcmanager audit
        """
        cls.force_firmware_audit = True

    @classmethod
    def reset_force_firmware_audit(cls):
        cls.force_firmware_audit = False

    @classmethod
    def trigger_kubernetes_audit(cls, context):
        """Trigger kubernetes audit at next interval.

        This can be called from outside the dcmanager audit
        """
        cls.force_kubernetes_audit = True

    @classmethod
    def reset_force_kubernetes_audit(cls):
        cls.force_kubernetes_audit = False

    @classmethod
    def trigger_kube_rootca_update_audit(cls, context):
        """Trigger kubernetes rootca update audit at next interval.

        This can be called from outside the dcmanager audit
        """
        cls.force_kube_rootca_update_audit = True

    @classmethod
    def reset_force_kube_rootca_update_audit(cls):
        cls.force_kube_rootca_update_audit = False

    @classmethod
    def trigger_patch_audit(cls, context):
        """Trigger patch audit at next interval.

        This can be called from outside the dcmanager audit
        """
        cls.force_patch_audit = True

    @classmethod
    def trigger_load_audit(cls, context):
        """Trigger load audit of all subclouds at next audit."""
        audit_utils.request_subcloud_audits(context, audit_load=True)

    @classmethod
    def reset_force_patch_audit(cls):
        cls.force_patch_audit = False

    @classmethod
    def trigger_software_audit(cls, context):
        """Trigger software audit at next interval.

        This can be called from outside the dcmanager audit
        """
        cls.force_software_audit = True

    @classmethod
    def reset_force_software_audit(cls):
        cls.force_software_audit = False

    def trigger_subcloud_audits(self, context, subcloud_id, exclude_endpoints):
        """Trigger all subcloud audits for one subcloud."""
        values = {
            "patch_audit_requested": True,
            "firmware_audit_requested": True,
            "load_audit_requested": True,
            "kubernetes_audit_requested": True,
            "kube_rootca_update_audit_requested": True,
            "spare_audit_requested": True,
        }
        # For the endpoints excluded in the audit, set it to False in db
        # to disable the audit explicitly.
        if exclude_endpoints:
            for exclude_endpoint in exclude_endpoints:
                exclude_request = dccommon_consts.ENDPOINT_AUDIT_REQUESTS.get(
                    exclude_endpoint
                )
                if exclude_request:
                    values.update({exclude_request: False})
        db_api.subcloud_audits_update(context, subcloud_id, values)

    def trigger_subcloud_patch_load_audits(self, context, subcloud_id):
        """Trigger subcloud patch and load audits for one subcloud."""
        values = {
            "patch_audit_requested": True,
            "load_audit_requested": True,
        }
        db_api.subcloud_audits_update(context, subcloud_id, values)

    def trigger_subcloud_endpoints_update(self, context, subcloud_name, endpoints):
        """Trigger update endpoints of services for a subcloud region."""
        self.audit_worker_rpc_client.update_subcloud_endpoints(
            context, subcloud_name, endpoints
        )

    def periodic_subcloud_audit(self):
        """Audit availability of subclouds."""

        # Verify subclouds have all the endpoints in DB
        self._add_missing_endpoints()
        # For any subclouds that were in the middle of being audited
        # when dcmanager-audit was shut down, fix up the timestamps so we'll
        # audit them and request all sub-audits.
        # (This is for swact and process restart.)
        db_api.subcloud_audits_fix_expired_audits(
            self.context,
            timeutils.utcnow(),
            trigger_audits=True,
        )
        # Blanket catch all exceptions in the audit so that the audit
        # does not die.
        while True:
            try:
                eventlet.greenthread.sleep(AUDIT_LOOP_INTERVAL)
                self._periodic_subcloud_audit_loop()
            except eventlet.greenlet.GreenletExit:
                # We have been told to exit
                return
            except Exception:
                LOG.exception("Error in periodic subcloud audit loop")

    def _should_use_cache(self):
        # If we are forcing an audit, don't use the cache, get fresh data
        return not any(
            [
                SubcloudAuditManager.force_patch_audit,
                SubcloudAuditManager.force_firmware_audit,
                SubcloudAuditManager.force_kubernetes_audit,
                SubcloudAuditManager.force_kube_rootca_update_audit,
                SubcloudAuditManager.force_software_audit,
            ]
        )

    # TODO(nicodemos): Remove patch/load when no longer supported
    def _get_audits_needed(self):
        """Returns which (if any) extra audits are needed."""
        audit_patch = False
        audit_load = False
        audit_firmware = False
        audit_kube_rootca_updates = False

        # Trigger a software audit
        LOG.info("Trigger software audit")
        audit_software = True
        SubcloudAuditManager.reset_force_software_audit()

        # Trigger a kubernetes audit
        LOG.info("Trigger kubernetes audit")
        audit_kubernetes = True
        SubcloudAuditManager.reset_force_kubernetes_audit()

        current_time = time.time()
        # Determine whether to trigger a patch audit of each subcloud
        if current_time - self.patch_audit_time >= CONF.scheduler.patch_audit_interval:
            LOG.info("Trigger patch audit")
            audit_patch = True

            self.patch_audit_time = current_time
            self.patch_audit_count += 1

            # Every other audit will trigger at a 1-hour rate.
            if self.patch_audit_count % ONE_HOUR_AUDIT_RATE == 1:
                # Triggers following audits (load, firmware and root CA)
                # by setting audit variables to True, then resets the "force_audit"
                # flags to disable forced execution after the audit runs.
                LOG.info("Trigger load audit")
                audit_load = True
                SubcloudAuditManager.reset_force_patch_audit()

                LOG.info("Trigger firmware audit")
                audit_firmware = True
                SubcloudAuditManager.reset_force_firmware_audit()

                LOG.info("Trigger kube rootca update audit")
                audit_kube_rootca_updates = True
                SubcloudAuditManager.reset_force_kube_rootca_update_audit()

        # Trigger a patch/load audit as it is changed through proxy
        if SubcloudAuditManager.force_patch_audit:
            LOG.info("Trigger patch/load audit")
            audit_load = True
            audit_patch = True
            SubcloudAuditManager.reset_force_patch_audit()

        # Trigger a firmware audit as it is changed through proxy
        if SubcloudAuditManager.force_firmware_audit:
            LOG.info("Trigger firmware audit")
            audit_firmware = True
            SubcloudAuditManager.reset_force_firmware_audit()

        # Trigger a kube rootca update audit as it is changed through proxy
        if SubcloudAuditManager.force_kube_rootca_update_audit:
            LOG.info("Trigger kube rootca update audit")
            audit_kube_rootca_updates = True
            SubcloudAuditManager.reset_force_kube_rootca_update_audit()

        return (
            audit_patch,
            audit_load,
            audit_firmware,
            audit_kubernetes,
            audit_kube_rootca_updates,
            audit_software,
        )

    def _get_audit_data(
        self,
        audit_patch,
        audit_firmware,
        audit_kubernetes,
        audit_kube_rootca_updates,
        audit_software,
    ):
        """Return the patch / firmware / kubernetes audit data as needed."""
        patch_audit_data = None
        software_audit_data = None
        firmware_audit_data = None
        kubernetes_audit_data = None
        kube_rootca_update_audit_data = None
        software_audit_data = None

        # TODO(nicodemos): After the integration with VIM the patch audit and patch
        # orchestration will be removed from the dcmanager. The audit_patch will
        # be substituted by the software_audit. The software_audit will be
        # responsible for the patch and load audit.
        if audit_patch:
            # Query RegionOne patches and software version
            patch_audit_data = self.patch_audit.get_regionone_audit_data()
        if audit_software:
            # Query RegionOne releases
            software_audit_data = self.software_audit.get_regionone_audit_data()
        if audit_firmware:
            # Query RegionOne firmware
            firmware_audit_data = self.firmware_audit.get_regionone_audit_data()
        if audit_kubernetes:
            # Query RegionOne kubernetes version info
            kubernetes_audit_data = self.kubernetes_audit.get_regionone_audit_data()
        if audit_kube_rootca_updates:
            # Query RegionOne kube rootca update info
            kube_rootca_update_audit_data = (
                self.kube_rootca_update_audit.get_regionone_audit_data()
            )
        return (
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        )

    def _periodic_subcloud_audit_loop(self):
        """Audit availability of subclouds loop."""

        # We will be running in our own green thread here.
        LOG.debug("Triggered subcloud audit.")
        self.audit_count += 1

        # Determine whether to trigger a state update to each subcloud.
        if self.audit_count >= SUBCLOUD_STATE_UPDATE_ITERATIONS:
            update_subcloud_state = True
            self.audit_count = 0
        else:
            update_subcloud_state = False

        # Determine whether we want to use DCAgent cache for audits
        use_cache = self._should_use_cache()

        # Determine whether we want to trigger specialty audits.
        (
            audit_patch,
            audit_load,
            audit_firmware,
            audit_kubernetes,
            audit_kube_rootca_update,
            audit_software,
        ) = self._get_audits_needed()

        # Set desired audit flags for all subclouds.
        audit_utils.request_subcloud_audits(
            self.context,
            update_subcloud_state,
            audit_patch,
            audit_load,
            audit_firmware,
            audit_kubernetes,
            audit_kube_rootca_update,
            audit_software,
        )

        do_openstack_audit = False

        # The feature of syncing openstack resources to the subclouds was not
        # completed, therefore, auditing the openstack application is disabled
        # Determine whether OpenStack is installed in central cloud
        # os_client = OpenStackDriver(region_name=consts.DEFAULT_REGION_NAME,
        #                            thread_name='dcmanager-audit')
        # sysinv_client = os_client.sysinv_client
        # This could be optimized in the future by attempting to get just the
        # one application. However, sysinv currently treats this as a failure
        # if the application is not installed and generates warning logs, so it
        # would require changes to handle this gracefully.
        # apps = sysinv_client.get_applications()
        # for app in apps:
        #    if app.name.endswith(HELM_APP_OPENSTACK):
        #        do_openstack_audit = True
        #        break

        current_time = timeutils.utcnow()
        last_audit_threshold = current_time - datetime.timedelta(
            seconds=CONF.scheduler.subcloud_audit_interval
        )
        # The sysinv and patching subcloud REST API timeouts are 600 sec,
        # and we need to be greater than that, so lets go with that plus
        # an extra audit interval.
        last_audit_fixup_threshold = current_time - datetime.timedelta(
            seconds=(
                dccommon_consts.SYSINV_CLIENT_REST_DEFAULT_TIMEOUT
                + CONF.scheduler.subcloud_audit_interval
            )
        )

        # Fix up any stale audit timestamps for subclouds that started an
        # audit but never finished it.
        start = timeutils.utcnow()
        num_fixed = db_api.subcloud_audits_fix_expired_audits(
            self.context, last_audit_fixup_threshold
        )
        end = timeutils.utcnow()
        if num_fixed > 0:
            LOG.info("Fixed up subcloud audit timestamp for %s subclouds." % num_fixed)
            LOG.info("Fixup took %s seconds" % (end - start))

        subcloud_ids = []
        skipped_subcloud_ids = []
        pruned_subcloud_audits = []

        subcloud_audits = db_api.subcloud_audits_get_all_need_audit(
            self.context, last_audit_threshold
        )
        LOG.debug(
            f"Number of subclouds need audit based on audit ts: "
            f"{len(subcloud_audits)}"
        )

        # Remove subclouds that don't qualify for this round of audit
        for audit, subcloud_name, deploy_status, availability_status in list(
            subcloud_audits
        ):
            # Include failure deploy status states in the auditable list
            # so that the subcloud can be set as offline
            if deploy_status not in VALID_DEPLOY_STATE or (
                deploy_status
                in [
                    consts.DEPLOY_STATE_INSTALLING,
                    consts.DEPLOY_STATE_REHOME_PENDING,
                ]
                and availability_status == dccommon_consts.AVAILABILITY_OFFLINE
            ):
                LOG.debug(
                    "Skip subcloud %s audit, deploy_status: %s"
                    % (subcloud_name, deploy_status)
                )
                skipped_subcloud_ids.append(audit.subcloud_id)
            else:
                pruned_subcloud_audits.append(audit)

        # Set the audit_finished_at timestamp for non qualified subclouds in bulk
        LOG.debug(
            "Set end audit timestamp for non-qualified subclouds "
            f"({len(skipped_subcloud_ids)}) in bulk"
        )
        db_api.subcloud_audits_bulk_update_audit_finished_at(
            self.context, skipped_subcloud_ids
        )

        LOG.debug(
            f"Number of subclouds qualified for audit: {len(pruned_subcloud_audits)}"
        )

        # Now check whether any of these subclouds need patch audit or firmware
        # audit data and grab it if needed.
        if not audit_patch:
            for audit in pruned_subcloud_audits:
                # Currently the load audit is done as part of the patch audit.
                # It might make sense to split it out.
                if audit.patch_audit_requested or audit.load_audit_requested:
                    audit_patch = True
                    LOG.debug("DB says patch audit needed")
                    break
        if not audit_firmware:
            for audit in pruned_subcloud_audits:
                if audit.firmware_audit_requested:
                    LOG.debug("DB says firmware audit needed")
                    audit_firmware = True
                    break
        if not audit_kube_rootca_update:
            for audit in pruned_subcloud_audits:
                if audit.kube_rootca_update_audit_requested:
                    LOG.debug("DB says kube-rootca-update audit needed")
                    audit_kube_rootca_update = True
                    break
        LOG.info(
            "Triggered subcloud audit: patch=(%s) firmware=(%s) "
            "kube=(%s) kube-rootca=(%s) software=(%s)"
            % (
                audit_patch,
                audit_firmware,
                audit_kubernetes,
                audit_kube_rootca_update,
                audit_software,
            )
        )
        (
            patch_audit_data,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
        ) = self._get_audit_data(
            audit_patch,
            audit_firmware,
            audit_kubernetes,
            audit_kube_rootca_update,
            audit_software,
        )
        LOG.debug(
            "patch_audit_data: %s, "
            "firmware_audit_data: %s, "
            "kubernetes_audit_data: %s, "
            "kube_rootca_update_audit_data: : %s, "
            "software_audit_data: %s"
            % (
                patch_audit_data,
                firmware_audit_data,
                kubernetes_audit_data,
                kube_rootca_update_audit_data,
                software_audit_data,
            )
        )

        # We want a chunksize of at least 1 so add the number of workers.
        chunksize = (len(pruned_subcloud_audits) + CONF.audit_worker_workers) // (
            CONF.audit_worker_workers
        )
        for audit in pruned_subcloud_audits:
            subcloud_ids.append(audit.subcloud_id)
            if len(subcloud_ids) == chunksize:
                # We've gathered a batch of subclouds, send it for processing.
                self.audit_worker_rpc_client.audit_subclouds(
                    self.context,
                    subcloud_ids,
                    patch_audit_data,
                    firmware_audit_data,
                    kubernetes_audit_data,
                    do_openstack_audit,
                    kube_rootca_update_audit_data,
                    software_audit_data,
                    use_cache,
                )
                LOG.info(
                    "Sent subcloud audit request message for subclouds: %s"
                    % subcloud_ids
                )
                subcloud_ids = []
        if len(subcloud_ids) > 0:
            # We've got a partial batch...send it off for processing.
            self.audit_worker_rpc_client.audit_subclouds(
                self.context,
                subcloud_ids,
                patch_audit_data,
                firmware_audit_data,
                kubernetes_audit_data,
                do_openstack_audit,
                kube_rootca_update_audit_data,
                software_audit_data,
                use_cache,
            )
            LOG.info(
                "Sent final subcloud audit request message for subclouds: %s"
                % subcloud_ids
            )
        else:
            LOG.debug("Done sending audit request messages.")
