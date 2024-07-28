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

import os

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_config import cfg
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.dcagent_v1 import DcagentClient
from dccommon.drivers.openstack.fm import FmClient
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import endpoint_cache
from dccommon import utils as dccommon_utils
from dcmanager.audit import alarm_aggregation
from dcmanager.audit import base_audit
from dcmanager.audit import firmware_audit
from dcmanager.audit import kube_rootca_update_audit
from dcmanager.audit import kubernetes_audit
from dcmanager.audit import patch_audit
from dcmanager.audit import software_audit
from dcmanager.audit.subcloud_audit_manager import HELM_APP_OPENSTACK
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
        self.context = context.get_admin_context()
        self.dcmanager_rpc_client = dcmanager_rpc_client.ManagerClient()
        self.state_rpc_client = dcmanager_rpc_client.SubcloudStateClient()
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(thread_pool_size=150)
        # Track workers created for each subcloud.
        self.subcloud_workers = dict()
        self.alarm_aggr = alarm_aggregation.AlarmAggregation(self.context)
        # todo(abailey): refactor the design pattern for adding new audits
        self.patch_audit = patch_audit.PatchAudit(self.context)
        self.firmware_audit = firmware_audit.FirmwareAudit()
        self.kubernetes_audit = kubernetes_audit.KubernetesAudit()
        self.kube_rootca_update_audit = kube_rootca_update_audit.KubeRootcaUpdateAudit()
        self.software_audit = software_audit.SoftwareAudit()
        self.pid = os.getpid()

    def audit_subclouds(
        self,
        context,
        subcloud_ids,
        patch_audit_data,
        firmware_audit_data,
        kubernetes_audit_data,
        do_openstack_audit,
        kube_rootca_update_audit_data,
        software_audit_data,
    ):
        """Run audits of the specified subcloud(s)"""

        LOG.debug(
            "PID: %s, subclouds to audit: %s, do_openstack_audit: %s"
            % (self.pid, subcloud_ids, do_openstack_audit)
        )

        for subcloud_id in subcloud_ids:
            # Retrieve the subcloud and subcloud audit info
            try:
                subcloud = db_api.subcloud_get(self.context, subcloud_id)
                subcloud_audits = db_api.subcloud_audits_get_and_start_audit(
                    self.context, subcloud_id
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
            do_load_audit = subcloud_audits.load_audit_requested
            # Currently we do the load audit as part of the patch audit,
            # so if we want a load audit we need to do a patch audit.
            do_patch_audit = subcloud_audits.patch_audit_requested or do_load_audit
            do_firmware_audit = subcloud_audits.firmware_audit_requested
            do_kubernetes_audit = subcloud_audits.kubernetes_audit_requested
            do_kube_rootca_update_audit = (
                subcloud_audits.kube_rootca_update_audit_requested
            )
            update_subcloud_state = subcloud_audits.state_update_requested
            do_software_audit = subcloud_audits.spare_audit_requested

            # Create a new greenthread for each subcloud to allow the audits
            # to be done in parallel. If there are not enough greenthreads
            # in the pool, this will block until one becomes available.
            self.subcloud_workers[subcloud.region_name] = (
                self.thread_group_manager.start(
                    self._do_audit_subcloud,
                    subcloud,
                    update_subcloud_state,
                    do_openstack_audit,
                    patch_audit_data,
                    firmware_audit_data,
                    kubernetes_audit_data,
                    kube_rootca_update_audit_data,
                    software_audit_data,
                    do_patch_audit,
                    do_load_audit,
                    do_firmware_audit,
                    do_kubernetes_audit,
                    do_kube_rootca_update_audit,
                    do_software_audit,
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

    def _audit_subcloud_openstack_app(
        self, subcloud_name, sysinv_client, openstack_installed
    ):
        openstack_installed_current = False
        # get a list of installed apps in the subcloud
        try:
            apps = sysinv_client.get_applications()
        except Exception:
            LOG.exception(
                "Cannot retrieve installed apps for subcloud: %s" % subcloud_name
            )
            return

        for app in apps:
            if app.name.endswith(HELM_APP_OPENSTACK) and app.active:
                # audit find openstack app is installed and active in
                # the subcloud
                openstack_installed_current = True
                break

        endpoint_type_list = dccommon_consts.ENDPOINT_TYPES_LIST_OS
        if openstack_installed_current and not openstack_installed:
            self.dcmanager_rpc_client.update_subcloud_sync_endpoint_type(
                self.context,
                subcloud_name,
                endpoint_type_list,
                openstack_installed_current,
            )
        elif not openstack_installed_current and openstack_installed:
            self.dcmanager_rpc_client.update_subcloud_sync_endpoint_type(
                self.context,
                subcloud_name,
                endpoint_type_list,
                openstack_installed_current,
            )

    def _do_audit_subcloud(
        self,
        subcloud: models.Subcloud,
        update_subcloud_state: bool,
        do_audit_openstack: bool,
        patch_audit_data,
        firmware_audit_data,
        kubernetes_audit_data,
        kube_rootca_update_audit_data,
        software_audit_data,
        do_patch_audit: bool,
        do_load_audit: bool,
        do_firmware_audit: bool,
        do_kubernetes_audit: bool,
        do_kube_rootca_update_audit: bool,
        do_software_audit: bool,
    ):
        audits_done = list()
        failures = list()
        # Do the actual subcloud audit.
        try:
            audits_done, failures = self._audit_subcloud(
                subcloud,
                update_subcloud_state,
                do_audit_openstack,
                patch_audit_data,
                firmware_audit_data,
                kubernetes_audit_data,
                kube_rootca_update_audit_data,
                software_audit_data,
                do_patch_audit,
                do_load_audit,
                do_firmware_audit,
                do_kubernetes_audit,
                do_kube_rootca_update_audit,
                do_software_audit,
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

        # Update the audit completion timestamp so it doesn't get
        # audited again for a while.
        db_api.subcloud_audits_end_audit(self.context, subcloud.id, audits_done)
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
        subcloud_management_state,
        subcloud_avail_status,
        first_identity_sync_complete,
        firmware_audit_data,
        kubernetes_audit_data,
        kube_rootca_update_audit_data,
        software_audit_data,
        do_firmware_audit,
        do_kubernetes_audit,
        do_kube_rootca_update_audit,
        do_software_audit,
    ):
        audit_payload = {dccommon_consts.BASE_AUDIT: ""}
        if self._should_perform_additional_audit(
            subcloud_management_state,
            subcloud_avail_status,
            first_identity_sync_complete,
        ):
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
        return audit_payload

    def _audit_subcloud(
        self,
        subcloud: models.Subcloud,
        update_subcloud_state: bool,
        do_audit_openstack: bool,
        patch_audit_data,
        firmware_audit_data,
        kubernetes_audit_data,
        kube_rootca_update_audit_data,
        software_audit_data,
        do_patch_audit: bool,
        do_load_audit: bool,
        do_firmware_audit: bool,
        do_kubernetes_audit: bool,
        do_kube_rootca_update_audit: bool,
        do_software_audit: bool,
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
        has_dcagent = dccommon_utils.subcloud_has_dcagent(subcloud.software_version)

        # Set defaults to None and disabled so we will still set disabled
        # status if we encounter an error.

        keystone_client = None
        dcagent_client = None
        sysinv_client = None
        fm_client = None
        avail_to_set = dccommon_consts.AVAILABILITY_OFFLINE
        failmsg = "Audit failure subcloud: %s, endpoint: %s"
        try:
            keystone_client = OpenStackDriver(
                region_name=subcloud_region,
                region_clients=None,
                fetch_subcloud_ips=utils.fetch_subcloud_mgmt_ips,
            ).keystone_client
            admin_session = keystone_client.session
            if has_dcagent:
                dcagent_client = DcagentClient(
                    subcloud_region,
                    admin_session,
                    endpoint=dccommon_utils.build_subcloud_endpoint(
                        subcloud_management_ip, "dcagent"
                    ),
                )
            sysinv_client = SysinvClient(
                subcloud_region,
                admin_session,
                endpoint=keystone_client.endpoint_cache.get_endpoint("sysinv"),
            )
            fm_client = FmClient(
                subcloud_region,
                admin_session,
                endpoint=keystone_client.endpoint_cache.get_endpoint("fm"),
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
            else:
                # The subcloud will be marked as offline below.
                LOG.error(
                    "Identity or Platform endpoint for online subcloud: %s not found."
                    % subcloud_name
                )

        except Exception:
            LOG.exception("Failed to create clients for subcloud: %s" % subcloud_name)

        if has_dcagent and dcagent_client:
            LOG.debug(f"Starting dcagent audit for subcloud: {subcloud_name}")
            # If we don't have the audit data, we won't send the request to the
            # dcagent service, so we set the status to "in sync"
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
                endpoint_data[dccommon_consts.ENDPOINT_TYPE_SOFTWARE] = (
                    dccommon_consts.SYNC_STATUS_IN_SYNC
                )
                audits_done.append(dccommon_consts.ENDPOINT_TYPE_SOFTWARE)
            LOG.debug(
                f"Skipping following audits for subcloud {subcloud_name} because "
                f"RegionOne audit data is not available: {audits_done}"
            )
            audit_payload = self._build_dcagent_payload(
                subcloud.management_state,
                avail_status_current,
                subcloud.first_identity_sync_complete,
                firmware_audit_data,
                kubernetes_audit_data,
                kube_rootca_update_audit_data,
                software_audit_data,
                do_firmware_audit,
                do_kubernetes_audit,
                do_kube_rootca_update_audit,
                do_software_audit,
            )
            audit_results = {}
            try:
                audit_results = dcagent_client.audit(audit_payload)
            except Exception:
                LOG.exception(failmsg % (subcloud.name, "dcagent"))
                failures.append("dcagent")
            LOG.debug(
                f"Audits results for subcloud {subcloud_name}: "
                f"{subcloud_name}: {audit_results}"
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
                    if alarms:
                        self.alarm_aggr.update_alarm_summary(subcloud_name, alarms)
                elif audit_value:
                    endpoint_type = dccommon_consts.DCAGENT_ENDPOINT_TYPE_MAP[
                        audit_type
                    ]
                    endpoint_data[endpoint_type] = audit_value
                    audits_done.append(endpoint_type)
            # Patch and load audits are not done in dcagent,
            # so we need to do it separately
            if self._should_perform_additional_audit(
                subcloud.management_state,
                avail_to_set,
                subcloud.first_identity_sync_complete,
            ):
                if do_patch_audit and patch_audit_data:
                    try:
                        endpoint_data[dccommon_consts.ENDPOINT_TYPE_PATCHING] = (
                            self.patch_audit.subcloud_patch_audit(
                                keystone_client.session,
                                sysinv_client,
                                subcloud_management_ip,
                                subcloud_name,
                                subcloud_region,
                                patch_audit_data,
                            )
                        )
                        audits_done.append(dccommon_consts.ENDPOINT_TYPE_PATCHING)
                    except Exception:
                        LOG.exception(
                            failmsg
                            % (subcloud.name, dccommon_consts.ENDPOINT_TYPE_PATCHING)
                        )
                        failures.append(dccommon_consts.ENDPOINT_TYPE_PATCHING)
                if do_load_audit and patch_audit_data:
                    try:
                        endpoint_data[dccommon_consts.ENDPOINT_TYPE_LOAD] = (
                            self.patch_audit.subcloud_load_audit(
                                sysinv_client, subcloud_name, patch_audit_data
                            )
                        )
                        audits_done.append(dccommon_consts.ENDPOINT_TYPE_LOAD)
                    except Exception:
                        LOG.exception(
                            failmsg
                            % (subcloud.name, dccommon_consts.ENDPOINT_TYPE_LOAD)
                        )
                        failures.append(dccommon_consts.ENDPOINT_TYPE_LOAD)

        # Check availability for subcloud that doesn't have dcagent
        if not has_dcagent and sysinv_client:
            # Avoid a network call to sysinv here if possible:
            # If prestaging is active we can assume that the subcloud
            # is online (otherwise prestaging will fail):
            if subcloud.prestage_status in consts.STATES_FOR_ONGOING_PRESTAGE:
                avail_to_set = dccommon_consts.AVAILABILITY_ONLINE
            else:
                avail_to_set, _ = base_audit.get_subcloud_availability_status(
                    sysinv_client, subcloud_name
                )

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

        # If subcloud is managed, online, the identity was synced once
        # and it doesn't have dcagent, audit additional resources
        if not has_dcagent and self._should_perform_additional_audit(
            subcloud.management_state,
            avail_to_set,
            subcloud.first_identity_sync_complete,
        ):
            # Get alarm summary and store in db,
            if fm_client:
                alarm_updates = self.alarm_aggr.get_alarm_summary(
                    fm_client, subcloud_name
                )
                self.alarm_aggr.update_alarm_summary(subcloud_name, alarm_updates)

            failmsg = "Audit failure subcloud: %s, endpoint: %s"

            # If we have patch audit data, audit the subcloud
            if do_patch_audit and patch_audit_data:
                try:
                    endpoint_data[dccommon_consts.ENDPOINT_TYPE_PATCHING] = (
                        self.patch_audit.subcloud_patch_audit(
                            keystone_client.session,
                            sysinv_client,
                            subcloud_management_ip,
                            subcloud_name,
                            subcloud_region,
                            patch_audit_data,
                        )
                    )
                    audits_done.append(dccommon_consts.ENDPOINT_TYPE_PATCHING)
                except Exception:
                    LOG.exception(
                        failmsg
                        % (subcloud.name, dccommon_consts.ENDPOINT_TYPE_PATCHING)
                    )
                    failures.append(dccommon_consts.ENDPOINT_TYPE_PATCHING)
            # Perform load audit
            if do_load_audit and patch_audit_data:
                try:
                    endpoint_data[dccommon_consts.ENDPOINT_TYPE_LOAD] = (
                        self.patch_audit.subcloud_load_audit(
                            sysinv_client, subcloud_name, patch_audit_data
                        )
                    )
                    audits_done.append(dccommon_consts.ENDPOINT_TYPE_LOAD)
                except Exception:
                    LOG.exception(
                        failmsg % (subcloud.name, dccommon_consts.ENDPOINT_TYPE_LOAD)
                    )
                    failures.append(dccommon_consts.ENDPOINT_TYPE_LOAD)
            # Perform firmware audit
            if do_firmware_audit:
                try:
                    endpoint_data[dccommon_consts.ENDPOINT_TYPE_FIRMWARE] = (
                        self.firmware_audit.subcloud_firmware_audit(
                            sysinv_client, subcloud_name, firmware_audit_data
                        )
                    )
                    audits_done.append(dccommon_consts.ENDPOINT_TYPE_FIRMWARE)
                except Exception:
                    LOG.exception(
                        failmsg
                        % (subcloud.name, dccommon_consts.ENDPOINT_TYPE_FIRMWARE)
                    )
                    failures.append(dccommon_consts.ENDPOINT_TYPE_FIRMWARE)
            # Perform kubernetes audit
            if do_kubernetes_audit:
                try:
                    endpoint_data[dccommon_consts.ENDPOINT_TYPE_KUBERNETES] = (
                        self.kubernetes_audit.subcloud_kubernetes_audit(
                            sysinv_client, subcloud_name, kubernetes_audit_data
                        )
                    )
                    audits_done.append(dccommon_consts.ENDPOINT_TYPE_KUBERNETES)
                except Exception:
                    LOG.exception(
                        failmsg
                        % (subcloud.name, dccommon_consts.ENDPOINT_TYPE_KUBERNETES)
                    )
                    failures.append(dccommon_consts.ENDPOINT_TYPE_KUBERNETES)
            # Perform kube rootca update audit
            if do_kube_rootca_update_audit:
                try:
                    endpoint_data[dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA] = (
                        self.kube_rootca_update_audit.subcloud_kube_rootca_audit(
                            sysinv_client,
                            fm_client,
                            subcloud,
                            kube_rootca_update_audit_data,
                        )
                    )
                    audits_done.append(dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA)
                except Exception:
                    LOG.exception(
                        failmsg
                        % (subcloud.name, dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA)
                    )
                    failures.append(dccommon_consts.ENDPOINT_TYPE_KUBE_ROOTCA)
            # Audit openstack application in the subcloud
            if do_audit_openstack:
                # We don't want an exception here to cause our
                # audits_done to be empty:
                try:
                    self._audit_subcloud_openstack_app(
                        subcloud_region, sysinv_client, subcloud.openstack_installed
                    )
                except Exception:
                    LOG.exception(failmsg % (subcloud.name, "openstack"))
                    failures.append("openstack")
            # Perform software audit
            if do_software_audit:
                try:
                    endpoint_data[dccommon_consts.ENDPOINT_TYPE_SOFTWARE] = (
                        self.software_audit.subcloud_software_audit(
                            keystone_client,
                            subcloud_management_ip,
                            subcloud_name,
                            subcloud_region,
                            software_audit_data,
                        )
                    )
                    audits_done.append(dccommon_consts.ENDPOINT_TYPE_SOFTWARE)
                except Exception:
                    LOG.exception(
                        failmsg
                        % (subcloud.name, dccommon_consts.ENDPOINT_TYPE_SOFTWARE)
                    )
                    failures.append(dccommon_consts.ENDPOINT_TYPE_SOFTWARE)

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
                    subcloud_name,
                    subcloud_region,
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
