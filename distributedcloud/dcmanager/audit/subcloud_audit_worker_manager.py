# Copyright 2017 Ericsson AB.
# Copyright (c) 2017-2025 Wind River Systems, Inc.
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

import copy
import json
import os
import threading
import time

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.dcagent_v1 import DcagentClient
from dccommon import endpoint_cache
from dccommon import utils as dccommon_utils
from dcmanager.audit import alarm_aggregation
from dcmanager.audit import firmware_audit
from dcmanager.audit import kube_rootca_update_audit
from dcmanager.audit import kubernetes_audit
from dcmanager.audit import software_audit
from dcmanager.audit import utils as audit_utils
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import scheduler
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy import models
from dcmanager.rpc import client as dcmanager_rpc_client
from dcorch.rpc import client as dcorch_rpc_client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# We will update the state of each subcloud in the dcorch about once per hour.
# Calculate how many iterations that will be.
SUBCLOUD_STATE_UPDATE_ITERATIONS = (
    dccommon_consts.SECONDS_IN_HOUR // CONF.scheduler.subcloud_audit_interval
)


class SubcloudAuditWorkerManager(manager.Manager):
    """Manages tasks related to audits."""

    def __init__(self, *args, **kwargs):
        LOG.debug(_("SubcloudAuditWorkerManager initialization..."))

        super(SubcloudAuditWorkerManager, self).__init__(
            service_name="subcloud_audit_worker_manager"
        )
        self.audit_lock = threading.Lock()
        self.audits_finished = dict()
        self.context = context.get_admin_context()
        self.dcmanager_rpc_client = dcmanager_rpc_client.ManagerClient()
        self.dcorch_client = dcorch_rpc_client.EngineWorkerClient()
        self.state_rpc_client = dcmanager_rpc_client.SubcloudStateClient()
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(thread_pool_size=150)
        self.thread_group_manager.start(self._update_subclouds_end_audit)
        # Track workers created for each subcloud.
        self.subcloud_workers = dict()
        self.alarm_aggr = alarm_aggregation.AlarmAggregation(self.context)
        # todo(abailey): refactor the design pattern for adding new audits
        self.firmware_audit = firmware_audit.FirmwareAudit()
        self.kubernetes_audit = kubernetes_audit.KubernetesAudit()
        self.kube_rootca_update_audit = kube_rootca_update_audit.KubeRootcaUpdateAudit()
        self.software_audit = software_audit.SoftwareAudit()
        self.pid = os.getpid()

    def _update_subclouds_end_audit(self):
        while True:
            audits_to_set_finished = None

            with self.audit_lock:
                if len(self.audits_finished) > 0:
                    audits_to_set_finished = copy.deepcopy(self.audits_finished)
                    self.audits_finished = dict()

            if audits_to_set_finished:
                # Update the audit completion timestamp so it doesn't get
                # audited again for a while.
                try:
                    db_api.subcloud_audits_bulk_end_audit(
                        self.context, audits_to_set_finished
                    )
                except Exception as e:
                    LOG.error(f"An error occurred when updating end audit: {e}")

                    with self.audit_lock:
                        self.audits_finished.update(audits_to_set_finished)

            time.sleep(2)

    def audit_subclouds(
        self,
        context,
        subcloud_ids,
        firmware_audit_data,
        kubernetes_audit_data,
        kube_rootca_update_audit_data,
        software_audit_data,
        use_cache,
    ):
        """Run audits of the specified subcloud(s)"""

        LOG.debug("PID: %s, subclouds to audit: %s" % (self.pid, subcloud_ids))

        for subcloud_id in subcloud_ids:
            # Retrieve the subcloud and subcloud audit info
            try:
                subcloud, subcloud_audits = (
                    db_api.subcloud_audits_subcloud_get_and_start_audit(
                        self.context, subcloud_id
                    )
                )
            except exceptions.SubcloudNotFound:
                # Possibility subcloud could have been deleted since the list of
                # subclouds to audit was created.
                LOG.info(
                    "Ignoring SubcloudNotFound when auditing subcloud %s" % subcloud_id
                )
                continue

            LOG.debug(
                "PID: %s, starting audit of subcloud: %s." % (self.pid, subcloud.name)
            )

            # Check the per-subcloud audit flags
            do_firmware_audit = subcloud_audits.firmware_audit_requested
            do_kubernetes_audit = subcloud_audits.kubernetes_audit_requested
            do_kube_rootca_update_audit = (
                subcloud_audits.kube_rootca_update_audit_requested
            )
            update_subcloud_state = subcloud_audits.state_update_requested
            do_software_audit = subcloud_audits.software_audit_requested

            # Create a new greenthread for each subcloud to allow the audits
            # to be done in parallel. If there are not enough greenthreads
            # in the pool, this will block until one becomes available.
            self.subcloud_workers[subcloud.region_name] = (
                self.thread_group_manager.start(
                    self._do_audit_subcloud,
                    subcloud,
                    update_subcloud_state,
                    firmware_audit_data,
                    kubernetes_audit_data,
                    kube_rootca_update_audit_data,
                    software_audit_data,
                    do_firmware_audit,
                    do_kubernetes_audit,
                    do_kube_rootca_update_audit,
                    do_software_audit,
                    use_cache,
                )
            )

    def update_subcloud_endpoints(self, context, subcloud_name, endpoints):
        LOG.info(
            f"Updating service endpoints for subcloud {subcloud_name} in endpoint cache"
        )
        endpoint_cache.EndpointCache.update_master_service_endpoint_region(
            subcloud_name, endpoints
        )

    def _update_subcloud_audit_fail_count(self, subcloud, audit_fail_count):
        """Update the subcloud's audit_fail_count directly to db.

        It's safe to update audit_fail_count because only the audit actually cares
        about it, dcmanager itself doesn't do anything with the value. If
        audit_fail_count is the only field to update, we want to update the db by
        an audit worker directly to eliminate unnecessary notifications to dcmanager.
        Note: this method should not be used for updating any other data.
        param subcloud: the subcloud object to be updated.
        param audit_fail_count: count of failed audit.
        """
        try:
            db_api.subcloud_update(
                self.context, subcloud.id, audit_fail_count=audit_fail_count
            )
        except exceptions.SubcloudNotFound:
            # Possibly subcloud could have been deleted since we found it in db,
            # ignore this benign error.
            LOG.info(
                "Ignoring SubcloudNotFound when attempting update "
                "audit_fail_count for subcloud: %s" % subcloud.name
            )

    def _do_audit_subcloud(
        self,
        subcloud: models.Subcloud,
        update_subcloud_state: bool,
        firmware_audit_data,
        kubernetes_audit_data,
        kube_rootca_update_audit_data,
        software_audit_data,
        do_firmware_audit: bool,
        do_kubernetes_audit: bool,
        do_kube_rootca_update_audit: bool,
        do_software_audit: bool,
        use_cache: bool,
    ):
        audits_done = list()
        failures = list()
        # Do the actual subcloud audit.
        try:
            audits_done, failures = self._audit_subcloud(
                subcloud,
                update_subcloud_state,
                firmware_audit_data,
                kubernetes_audit_data,
                kube_rootca_update_audit_data,
                software_audit_data,
                do_firmware_audit,
                do_kubernetes_audit,
                do_kube_rootca_update_audit,
                do_software_audit,
                use_cache,
            )
        except Exception:
            LOG.exception("Got exception auditing subcloud: %s" % subcloud.name)

        if failures and len(failures) > 1:
            # extra log for multiple failures:
            LOG.error(
                "Multiple failures auditing subcloud %s: for endpoints: %s",
                subcloud.name,
                ", ".join(sorted(failures)),
            )

        with self.audit_lock:
            self.audits_finished[subcloud.id] = {
                "timestamp": timeutils.utcnow(),
                "audits_finished": audits_done,
            }

        # Remove the worker for this subcloud
        self.subcloud_workers.pop(subcloud.region_name, None)
        LOG.debug("PID: %s, done auditing subcloud: %s." % (self.pid, subcloud.name))

    @staticmethod
    def _should_perform_additional_audit(
        subcloud_management_state, subcloud_avail_status, first_identity_sync_complete
    ):
        return (
            subcloud_management_state == dccommon_consts.MANAGEMENT_MANAGED
            and subcloud_avail_status == dccommon_consts.AVAILABILITY_ONLINE
            and first_identity_sync_complete
        )

    def _build_dcagent_payload(
        self,
        should_perform_additional_audit,
        firmware_audit_data,
        kubernetes_audit_data,
        kube_rootca_update_audit_data,
        software_audit_data,
        do_firmware_audit,
        do_kubernetes_audit,
        do_kube_rootca_update_audit,
        do_software_audit,
        use_cache,
    ):
        audit_payload = {dccommon_consts.BASE_AUDIT: ""}
        if should_perform_additional_audit:
            if do_firmware_audit and firmware_audit_data:
                audit_payload[dccommon_consts.FIRMWARE_AUDIT] = firmware_audit_data
            if do_kubernetes_audit and kubernetes_audit_data:
                audit_payload[dccommon_consts.KUBERNETES_AUDIT] = kubernetes_audit_data
            if do_kube_rootca_update_audit and kube_rootca_update_audit_data:
                audit_payload[dccommon_consts.KUBE_ROOTCA_AUDIT] = (
                    kube_rootca_update_audit_data
                )
            if do_software_audit and software_audit_data:
                audit_payload[dccommon_consts.SOFTWARE_AUDIT] = software_audit_data
        # If the audit was forced, we don't want to use the cache
        if not use_cache:
            audit_payload["use_cache"] = use_cache
        return audit_payload

    def _build_dcagent_request_headers(self, subcloud: models.Subcloud):
        dc_agent_headers = {}
        if subcloud.rehomed:
            dc_agent_headers["rehomed"] = subcloud.rehomed
        header = {"X-DCAGENT-HEADERS": json.dumps(dc_agent_headers)}
        return header

    def _update_sw_sync_status_from_deploy_status(self, subcloud, audit_results):
        # If the subcloud deploy_status is in any of the following states,
        # the sync_status should be set to out-of-sync for software audit.
        # This allows the user to reapply the strategy to resolve the deploy_status.
        if subcloud.deploy_status in [
            consts.DEPLOY_STATE_SW_DEPLOY_APPLY_STRATEGY_FAILED,
            consts.DEPLOY_STATE_SW_DEPLOY_IN_PROGRESS,
        ] and audit_results.get(dccommon_consts.SOFTWARE_AUDIT):
            LOG.info(
                "Setting software sync_status to out-of-sync due to deploy_status. "
                f"subcloud: {subcloud.name} deploy_status: {subcloud.deploy_status}"
            )
            audit_results[dccommon_consts.SOFTWARE_AUDIT][
                "sync_status"
            ] = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC
        return audit_results

    def _audit_subcloud(
        self,
        subcloud: models.Subcloud,
        update_subcloud_state: bool,
        firmware_audit_data,
        kubernetes_audit_data,
        kube_rootca_update_audit_data,
        software_audit_data,
        do_firmware_audit: bool,
        do_kubernetes_audit: bool,
        do_kube_rootca_update_audit: bool,
        do_software_audit: bool,
        use_cache: bool,
    ):
        """Audit a single subcloud."""

        avail_status_current = subcloud.availability_status
        audit_fail_count = subcloud.audit_fail_count
        subcloud_name = subcloud.name
        subcloud_region = subcloud.region_name
        subcloud_management_ip = subcloud.management_start_ip
        audits_done = list()
        failures = list()
        availability_data = dict()
        endpoint_data = dict()
        # Set defaults to None and disabled so we will still set disabled
        # status if we encounter an error.

        dcagent_client = None
        avail_to_set = dccommon_consts.AVAILABILITY_OFFLINE
        failmsg = "Audit failure subcloud: %s, endpoint: %s"
        try:
            subcloud_ks_endpoint = dccommon_utils.build_subcloud_endpoint(
                subcloud_management_ip, dccommon_consts.ENDPOINT_NAME_KEYSTONE
            )
            admin_session = endpoint_cache.EndpointCache.get_admin_session(
                auth_url=subcloud_ks_endpoint
            )
            dcagent_client = DcagentClient(
                subcloud_region,
                admin_session,
                endpoint=dccommon_utils.build_subcloud_endpoint(
                    subcloud_management_ip, dccommon_consts.ENDPOINT_NAME_DCAGENT
                ),
            )
        # TODO(vgluzrom): Revise and improve the debug and error messages
        # as well as the exception causes
        except keystone_exceptions.ConnectTimeout:
            if avail_status_current == dccommon_consts.AVAILABILITY_OFFLINE:
                LOG.debug(
                    "Identity or Platform endpoint for %s not found, ignoring for "
                    "offline subcloud." % subcloud_name
                )
                return audits_done, failures
            else:
                # The subcloud will be marked as offline below.
                LOG.error(
                    "Identity or Platform endpoint for online subcloud: %s not found."
                    % subcloud_name
                )

        except keystone_exceptions.NotFound:
            if (
                subcloud.first_identity_sync_complete
                and avail_status_current == dccommon_consts.AVAILABILITY_ONLINE
            ):
                # The first identity sync is already complete
                # Therefore this is an error
                LOG.error(
                    "Identity or Platform endpoint for online subcloud: %s not found."
                    % subcloud_name
                )
            else:
                LOG.debug(
                    "Identity or Platform endpoint for %s not found, ignoring for "
                    "offline subcloud or identity sync not done." % subcloud_name
                )
                return audits_done, failures

        except (
            keystone_exceptions.EndpointNotFound,
            keystone_exceptions.ConnectFailure,
            IndexError,
        ):
            if avail_status_current == dccommon_consts.AVAILABILITY_OFFLINE:
                LOG.info(
                    "Identity or Platform endpoint for %s not found, ignoring for "
                    "offline subcloud." % subcloud_name
                )
                return audits_done, failures
            # The subcloud will be marked as offline below.
            LOG.error(
                "Identity or Platform endpoint for online subcloud: %s not found."
                % subcloud_name
            )

        except Exception:
            LOG.exception("Failed to create clients for subcloud: %s" % subcloud_name)

        LOG.debug(f"Starting dcagent audit for subcloud: {subcloud_name}")
        # If we don't have the audit data, we won't send the request to the
        # dcagent service, so we set the status to "in sync"
        shoud_perform_additional_audit = self._should_perform_additional_audit(
            subcloud.management_state,
            avail_status_current,
            subcloud.first_identity_sync_complete,
        )
        if shoud_perform_additional_audit:
            if do_firmware_audit and not firmware_audit_data:
                endpoint_data[dccommon_consts.ENDPOINT_TYPE_FIRMWARE] = (
                    dccommon_consts.SYNC_STATUS_IN_SYNC
                )
                audits_done.append(dccommon_consts.ENDPOINT_TYPE_FIRMWARE)
            if do_kubernetes_audit and not kubernetes_audit_data:
                endpoint_data[dccommon_consts.ENDPOINT_TYPE_KUBERNETES] = (
                    dccommon_consts.SYNC_STATUS_IN_SYNC
                )
                audits_done.append(dccommon_consts.ENDPOINT_TYPE_KUBERNETES)
            if do_kube_rootca_update_audit and not kube_rootca_update_audit_data:
                endpoint_data[dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA] = (
                    dccommon_consts.SYNC_STATUS_IN_SYNC
                )
                audits_done.append(dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA)
            if do_software_audit and not software_audit_data:
                endpoint_data[dccommon_consts.AUDIT_TYPE_SOFTWARE] = {
                    "sync_status": dccommon_consts.SYNC_STATUS_IN_SYNC,
                    "software_version": "",
                }
                audits_done.append(dccommon_consts.AUDIT_TYPE_SOFTWARE)
        LOG.debug(
            f"Skipping following audits for subcloud {subcloud_name} because "
            f"RegionOne audit data is not available: {audits_done}"
        )
        audit_payload = self._build_dcagent_payload(
            shoud_perform_additional_audit,
            firmware_audit_data,
            kubernetes_audit_data,
            kube_rootca_update_audit_data,
            software_audit_data,
            do_firmware_audit,
            do_kubernetes_audit,
            do_kube_rootca_update_audit,
            do_software_audit,
            use_cache,
        )
        headers = self._build_dcagent_request_headers(subcloud)
        audit_results = {}
        try:
            audit_results = dcagent_client.audit(audit_payload, headers)
        except Exception:
            LOG.exception(failmsg % (subcloud.name, "dcagent"))
            failures.append("dcagent")
        LOG.debug(f"Audits results for subcloud {subcloud_name}: {audit_results}")
        audit_results = self._update_sw_sync_status_from_deploy_status(
            subcloud, audit_results
        )
        for audit_type, audit_value in audit_results.items():
            if audit_type == dccommon_consts.BASE_AUDIT:
                avail_to_set = audit_value.get("availability")
                if avail_to_set == dccommon_consts.AVAILABILITY_OFFLINE:
                    inactive_sg = audit_value.get("inactive_sg")
                    msg = f"Inactive service groups: {inactive_sg}"
                    dccommon_utils.log_subcloud_msg(
                        LOG.debug, msg, subcloud_name, avail_to_set
                    )
                alarms = audit_value.get("alarms")
                if (
                    alarms
                    and subcloud.management_state == dccommon_consts.MANAGEMENT_MANAGED
                ):
                    self.alarm_aggr.update_alarm_summary(subcloud_name, alarms)
            elif audit_value:
                endpoint_type = dccommon_consts.DCAGENT_ENDPOINT_TYPE_MAP[audit_type]
                endpoint_data[endpoint_type] = audit_value
                audits_done.append(endpoint_type)

        if avail_to_set == dccommon_consts.AVAILABILITY_OFFLINE:
            if audit_fail_count < consts.AVAIL_FAIL_COUNT_MAX:
                audit_fail_count = audit_fail_count + 1
            if (avail_status_current == dccommon_consts.AVAILABILITY_ONLINE) and (
                audit_fail_count < consts.AVAIL_FAIL_COUNT_TO_ALARM
            ):
                # Do not set offline until we have failed audit
                # the requisite number of times
                avail_to_set = dccommon_consts.AVAILABILITY_ONLINE
        else:
            # In the case of a one off blip, we may need to set the
            # fail count back to 0
            audit_fail_count = 0

        if avail_to_set != avail_status_current:
            if avail_to_set == dccommon_consts.AVAILABILITY_ONLINE:
                audit_fail_count = 0

            LOG.debug(
                "Setting new availability status: %s "
                "on subcloud: %s" % (avail_to_set, subcloud_name)
            )
            availability_data.update(
                {
                    "availability_status": avail_to_set,
                    "update_state_only": False,
                    "audit_fail_count": audit_fail_count,
                }
            )
            if avail_to_set == dccommon_consts.AVAILABILITY_OFFLINE:
                utils.clear_subcloud_alarm_summary(self.context, subcloud_name)

        elif audit_fail_count != subcloud.audit_fail_count:
            # The subcloud remains offline, we only need to update
            # the audit_fail_count in db directly by an audit worker
            # to eliminate unnecessary notification to the dcmanager
            self._update_subcloud_audit_fail_count(
                subcloud, audit_fail_count=audit_fail_count
            )

        elif update_subcloud_state:
            # Nothing has changed, but we want to send a state update for this
            # subcloud as an audit.
            LOG.debug(
                "Updating subcloud state unconditionally for subcloud %s"
                % subcloud_name
            )
            availability_data.update(
                {
                    "availability_status": avail_status_current,
                    "update_state_only": True,
                    "audit_fail_count": None,
                }
            )

        # Update the software_version if the software audit detects a different
        # value. This can occur during a manual subcloud upgrade initiated by
        # calling VIM commands directly on the subcloud.
        audit_utils.update_subcloud_software_version(
            self.context, subcloud, endpoint_data, self.dcorch_client
        )

        # Filter the endpoint_data to remove values that did not had any modification
        # from the available data on subcloud table
        audit_utils.filter_endpoint_data(self.context, subcloud, endpoint_data)

        # Create a new variable to store the update method to avoid line too long error
        bulk_update_subcloud_availability_and_endpoint_status = (
            self.state_rpc_client.bulk_update_subcloud_availability_and_endpoint_status
        )

        if availability_data or (endpoint_data and any(endpoint_data.values())):
            try:
                # If a value is not None, an update should be sent to the rpc client
                bulk_update_subcloud_availability_and_endpoint_status(
                    self.context,
                    subcloud.id,
                    subcloud.name,
                    availability_data,
                    endpoint_data,
                )
                LOG.debug(
                    f"Notifying dcmanager-state, subcloud: {subcloud_name}, bulk "
                    "availability and endpoint status update"
                )
            except Exception:
                LOG.exception(
                    "Failed to notify dcmanager-state of subcloud batch "
                    "availability and endpoint status update, "
                    f"subcloud: {subcloud_name}"
                )

        return audits_done, failures
