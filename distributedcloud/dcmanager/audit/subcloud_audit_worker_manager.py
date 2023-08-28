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
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver
from dcmanager.audit import alarm_aggregation
from dcmanager.audit import firmware_audit
from dcmanager.audit import kube_rootca_update_audit
from dcmanager.audit import kubernetes_audit
from dcmanager.audit import patch_audit
from dcmanager.audit.subcloud_audit_manager import HELM_APP_OPENSTACK
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import prestage
from dcmanager.common import scheduler
from dcmanager.db import api as db_api
from dcmanager.rpc import client as dcmanager_rpc_client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# We will update the state of each subcloud in the dcorch about once per hour.
# Calculate how many iterations that will be.
SUBCLOUD_STATE_UPDATE_ITERATIONS = \
    dccommon_consts.SECONDS_IN_HOUR // CONF.scheduler.subcloud_audit_interval


class SubcloudAuditWorkerManager(manager.Manager):
    """Manages tasks related to audits."""

    def __init__(self, *args, **kwargs):
        LOG.debug(_('SubcloudAuditWorkerManager initialization...'))

        super(SubcloudAuditWorkerManager, self).__init__(
            service_name="subcloud_audit_worker_manager")
        self.context = context.get_admin_context()
        self.dcmanager_rpc_client = dcmanager_rpc_client.ManagerClient()
        self.state_rpc_client = dcmanager_rpc_client.SubcloudStateClient()
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=100)
        # Track workers created for each subcloud.
        self.subcloud_workers = dict()
        self.alarm_aggr = alarm_aggregation.AlarmAggregation(self.context)
        # todo(abailey): refactor the design pattern for adding new audits
        self.patch_audit = patch_audit.PatchAudit(
            self.context, self.state_rpc_client)
        self.firmware_audit = firmware_audit.FirmwareAudit(
            self.context, self.state_rpc_client)
        self.kubernetes_audit = kubernetes_audit.KubernetesAudit(
            self.context, self.state_rpc_client)
        self.kube_rootca_update_audit = \
            kube_rootca_update_audit.KubeRootcaUpdateAudit(
                self.context,
                self.state_rpc_client)
        self.pid = os.getpid()

    def audit_subclouds(self,
                        context,
                        subcloud_ids,
                        patch_audit_data,
                        firmware_audit_data,
                        kubernetes_audit_data,
                        do_openstack_audit,
                        kube_rootca_update_audit_data,
                        software_audit_data):
        """Run audits of the specified subcloud(s)"""

        LOG.debug('PID: %s, subclouds to audit: %s, do_openstack_audit: %s' %
                  (self.pid, subcloud_ids, do_openstack_audit))

        for subcloud_id in subcloud_ids:
            # Retrieve the subcloud and subcloud audit info
            try:
                subcloud = db_api.subcloud_get(self.context, subcloud_id)
                subcloud_audits = db_api.subcloud_audits_get_and_start_audit(
                    self.context, subcloud_id)
            except exceptions.SubcloudNotFound:
                # Possibility subcloud could have been deleted since the list of
                # subclouds to audit was created.
                LOG.info('Ignoring SubcloudNotFound when auditing subcloud %s' %
                         subcloud_id)
                continue

            LOG.debug("PID: %s, starting audit of subcloud: %s." %
                      (self.pid, subcloud.name))

            # Include failure deploy status states in the auditable list
            # so that the subcloud can be set as offline
            if (subcloud.deploy_status not in
                    [consts.DEPLOY_STATE_DONE,
                     consts.DEPLOY_STATE_CONFIGURING,
                     consts.DEPLOY_STATE_CONFIG_FAILED,
                     consts.DEPLOY_STATE_CONFIG_ABORTED,
                     consts.DEPLOY_STATE_PRE_CONFIG_FAILED,
                     consts.DEPLOY_STATE_INSTALL_FAILED,
                     consts.DEPLOY_STATE_INSTALL_ABORTED,
                     consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
                     consts.DEPLOY_STATE_INSTALLING,
                     consts.DEPLOY_STATE_DATA_MIGRATION_FAILED,
                     consts.DEPLOY_STATE_UPGRADE_ACTIVATED,
                     consts.DEPLOY_STATE_RESTORING,
                     consts.DEPLOY_STATE_RESTORE_PREP_FAILED,
                     consts.DEPLOY_STATE_RESTORE_FAILED,
                     consts.DEPLOY_STATE_REHOME_PENDING]
                    and not prestage.is_deploy_status_prestage(
                        subcloud.deploy_status)) or (
                    (subcloud.deploy_status in [
                        consts.DEPLOY_STATE_INSTALLING,
                        consts.DEPLOY_STATE_REHOME_PENDING])
                    and subcloud.availability_status ==
                    dccommon_consts.AVAILABILITY_OFFLINE):
                LOG.debug("Skip subcloud %s audit, deploy_status: %s" %
                          (subcloud.name, subcloud.deploy_status))
                # This DB API call will set the "audit_finished_at" timestamp
                # so it won't get audited again for a while.
                audits_done = []
                db_api.subcloud_audits_end_audit(self.context,
                                                 subcloud_id, audits_done)
                continue

            # Check the per-subcloud audit flags
            do_load_audit = subcloud_audits.load_audit_requested
            # Currently we do the load audit as part of the patch audit,
            # so if we want a load audit we need to do a patch audit.
            do_patch_audit = (subcloud_audits.patch_audit_requested or
                              do_load_audit)
            do_firmware_audit = subcloud_audits.firmware_audit_requested
            do_kubernetes_audit = subcloud_audits.kubernetes_audit_requested
            do_kube_rootca_update_audit = \
                subcloud_audits.kube_rootca_update_audit_requested
            update_subcloud_state = subcloud_audits.state_update_requested

            # Create a new greenthread for each subcloud to allow the audits
            # to be done in parallel. If there are not enough greenthreads
            # in the pool, this will block until one becomes available.
            self.subcloud_workers[subcloud.region_name] = \
                self.thread_group_manager.start(self._do_audit_subcloud,
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
                                                do_kube_rootca_update_audit)

    def update_subcloud_endpoints(self, context, subcloud_name, endpoints):
        try:
            LOG.info("Updating service endpoints for subcloud %s "
                     "in endpoint cache" % subcloud_name)
            endpoint_cache = OpenStackDriver(
                region_name=dccommon_consts.CLOUD_0).keystone_client.endpoint_cache
            endpoint_cache.update_master_service_endpoint_region(
                subcloud_name, endpoints)
        except (keystone_exceptions.EndpointNotFound,
                keystone_exceptions.ConnectFailure,
                IndexError):
            LOG.error("Failed to update the service endpoints "
                      "for subcloud %s." % subcloud_name)

    def _update_subcloud_audit_fail_count(self, subcloud,
                                          audit_fail_count):
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
            db_api.subcloud_update(self.context, subcloud.id,
                                   audit_fail_count=audit_fail_count)
        except exceptions.SubcloudNotFound:
            # Possibly subcloud could have been deleted since we found it in db,
            # ignore this benign error.
            LOG.info('Ignoring SubcloudNotFound when attempting update'
                     'audit_fail_count for subcloud: %s' % subcloud.name)

    def _update_subcloud_availability(self, subcloud_name,
                                      subcloud_region,
                                      availability_status=None,
                                      update_state_only=False,
                                      audit_fail_count=None):
        try:
            self.state_rpc_client.update_subcloud_availability(
                self.context, subcloud_name, subcloud_region, availability_status,
                update_state_only, audit_fail_count)
            LOG.info('Notifying dcmanager-state, subcloud:%s, availability:%s' %
                     (subcloud_name,
                      availability_status))
        except Exception:
            LOG.exception('Problem informing dcmanager-state of subcloud '
                          'availability state change, subcloud: %s'
                          % subcloud_name)

    @staticmethod
    def _get_subcloud_availability_status(subcloud_name, sysinv_client):
        """For each subcloud, if at least one service is active in each

        service of servicegroup-list then declare the subcloud online.
        """
        avail_to_set = dccommon_consts.AVAILABILITY_OFFLINE
        svc_groups = None

        # get a list of service groups in the subcloud
        try:
            svc_groups = sysinv_client.get_service_groups()
        except Exception as e:
            LOG.warn('Cannot retrieve service groups for '
                     'subcloud: %s, %s' % (subcloud_name, e))

        if svc_groups:
            active_sgs = []
            inactive_sgs = []

            # Build 2 lists, 1 of active service groups,
            # one with non-active.
            for sg in svc_groups:
                if sg.state != consts.SERVICE_GROUP_STATUS_ACTIVE:
                    inactive_sgs.append(sg.service_group_name)
                else:
                    active_sgs.append(sg.service_group_name)

            # Create a list of service groups that are only present
            # in non-active list
            inactive_only = [sg for sg in inactive_sgs if
                             sg not in active_sgs]

            # An empty inactive only list and a non-empty active list
            # means we're good to go.
            if not inactive_only and active_sgs:
                avail_to_set = \
                    dccommon_consts.AVAILABILITY_ONLINE
            else:
                LOG.info("Subcloud:%s has non-active "
                         "service groups: %s" %
                         (subcloud_name, inactive_only))
        return avail_to_set

    def _audit_subcloud_openstack_app(self, subcloud_name, sysinv_client,
                                      openstack_installed):
        openstack_installed_current = False
        # get a list of installed apps in the subcloud
        try:
            apps = sysinv_client.get_applications()
        except Exception:
            LOG.exception('Cannot retrieve installed apps for subcloud:%s'
                          % subcloud_name)
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
                openstack_installed_current)
        elif not openstack_installed_current and openstack_installed:
            self.dcmanager_rpc_client.update_subcloud_sync_endpoint_type(
                self.context,
                subcloud_name,
                endpoint_type_list,
                openstack_installed_current)

    def _do_audit_subcloud(self,
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
                           do_kube_rootca_update_audit):
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
                do_kube_rootca_update_audit)
        except Exception:
            LOG.exception("Got exception auditing subcloud: %s" % subcloud.name)

        if failures and len(failures) > 1:
            # extra log for multiple failures:
            LOG.error("Multiple failures auditing subcloud %s: "
                      "for endpoints: %s",
                      subcloud.name, ", ".join(sorted(failures)))

        # Update the audit completion timestamp so it doesn't get
        # audited again for a while.
        db_api.subcloud_audits_end_audit(self.context,
                                         subcloud.id, audits_done)
        # Remove the worker for this subcloud
        self.subcloud_workers.pop(subcloud.region_name, None)
        LOG.debug("PID: %s, done auditing subcloud: %s." %
                  (self.pid, subcloud.name))

    def _audit_subcloud(self,
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
                        do_kube_rootca_update_audit):
        """Audit a single subcloud."""

        avail_status_current = subcloud.availability_status
        audit_fail_count = subcloud.audit_fail_count
        subcloud_name = subcloud.name
        subcloud_region = subcloud.region_name
        audits_done = list()
        failures = list()

        # Set defaults to None and disabled so we will still set disabled
        # status if we encounter an error.

        sysinv_client = None
        fm_client = None
        avail_to_set = dccommon_consts.AVAILABILITY_OFFLINE
        try:
            os_client = OpenStackDriver(region_name=subcloud_region,
                                        thread_name='subcloud-audit',
                                        region_clients=['fm', 'sysinv'])
            sysinv_client = os_client.sysinv_client
            fm_client = os_client.fm_client
        except keystone_exceptions.ConnectTimeout:
            if avail_status_current == dccommon_consts.AVAILABILITY_OFFLINE:
                LOG.debug("Identity or Platform endpoint for %s not "
                          "found, ignoring for offline "
                          "subcloud." % subcloud_name)
                return audits_done, failures
            else:
                # The subcloud will be marked as offline below.
                LOG.error("Identity or Platform endpoint for online "
                          "subcloud: %s not found." % subcloud_name)

        except keystone_exceptions.NotFound:
            if subcloud.first_identity_sync_complete \
                    and avail_status_current == dccommon_consts.AVAILABILITY_ONLINE:
                # The first identity sync is already complete
                # Therefore this is an error
                LOG.error("Identity or Platform endpoint for online "
                          "subcloud: %s not found." % subcloud_name)
            else:
                LOG.debug("Identity or Platform endpoint for %s not "
                          "found, ignoring for offline "
                          "subcloud or identity sync not done." % subcloud_name)
                return audits_done, failures

        except (keystone_exceptions.EndpointNotFound,
                keystone_exceptions.ConnectFailure,
                IndexError):
            if avail_status_current == dccommon_consts.AVAILABILITY_OFFLINE:
                LOG.info("Identity or Platform endpoint for %s not "
                         "found, ignoring for offline "
                         "subcloud." % subcloud_name)
                return audits_done, failures
            else:
                # The subcloud will be marked as offline below.
                LOG.error("Identity or Platform endpoint for online "
                          "subcloud: %s not found." % subcloud_name)

        except Exception:
            LOG.exception("Failed to get OS Client for subcloud: %s"
                          % subcloud_name)

        # Check availability of the subcloud
        if sysinv_client:
            # Avoid a network call to sysinv here if possible:
            # If prestaging is active we can assume that the subcloud
            # is online (otherwise prestaging will fail):
            if subcloud.deploy_status in (consts.PRESTAGE_STATE_PACKAGES,
                                          consts.PRESTAGE_STATE_IMAGES):
                avail_to_set = dccommon_consts.AVAILABILITY_ONLINE
            else:
                avail_to_set = self._get_subcloud_availability_status(
                    subcloud_name, sysinv_client)

        if avail_to_set == dccommon_consts.AVAILABILITY_OFFLINE:
            if audit_fail_count < consts.AVAIL_FAIL_COUNT_MAX:
                audit_fail_count = audit_fail_count + 1
            if (avail_status_current == dccommon_consts.AVAILABILITY_ONLINE) and \
                    (audit_fail_count < consts.AVAIL_FAIL_COUNT_TO_ALARM):
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

            LOG.debug('Setting new availability status: %s '
                      'on subcloud: %s' %
                      (avail_to_set, subcloud_name))
            self._update_subcloud_availability(
                subcloud_name,
                subcloud_region,
                availability_status=avail_to_set,
                audit_fail_count=audit_fail_count)

        elif audit_fail_count != subcloud.audit_fail_count:
            # The subcloud remains offline, we only need to update
            # the audit_fail_count in db directly by an audit worker
            # to eliminate unnecessary notification to the dcmanager
            self._update_subcloud_audit_fail_count(
                subcloud,
                audit_fail_count=audit_fail_count)

        elif update_subcloud_state:
            # Nothing has changed, but we want to send a state update for this
            # subcloud as an audit.
            LOG.debug('Updating subcloud state unconditionally for subcloud %s'
                      % subcloud_name)
            self._update_subcloud_availability(
                subcloud_name,
                subcloud_region,
                availability_status=avail_status_current,
                update_state_only=True)

        # If subcloud is managed and online and the identity was synced once,
        # audit additional resources
        if (subcloud.management_state == dccommon_consts.MANAGEMENT_MANAGED and
                avail_to_set == dccommon_consts.AVAILABILITY_ONLINE and
                subcloud.first_identity_sync_complete):
            # Get alarm summary and store in db,
            if fm_client:
                self.alarm_aggr.update_alarm_summary(subcloud_name, fm_client)

            failmsg = "Audit failure subcloud: %s, endpoint: %s"

            # If we have patch audit data, audit the subcloud
            if do_patch_audit and (patch_audit_data or software_audit_data):
                try:
                    self.patch_audit.subcloud_audit(subcloud_name,
                                                    subcloud_region,
                                                    patch_audit_data,
                                                    software_audit_data,
                                                    do_load_audit)
                    audits_done.append('patch')
                    if do_load_audit:
                        audits_done.append('load')
                except Exception:
                    LOG.exception(failmsg % (subcloud.name, 'patch/load'))
                    failures.append('patch')
                    if do_load_audit:
                        # Currently there's no way to differentiate,
                        # so include same under 'load':
                        failures.append('load')
            # Perform firmware audit
            if do_firmware_audit:
                try:
                    self.firmware_audit.subcloud_firmware_audit(subcloud_name,
                                                                subcloud_region,
                                                                firmware_audit_data)
                    audits_done.append('firmware')
                except Exception:
                    LOG.exception(failmsg % (subcloud.name, 'firmware'))
                    failures.append('firmware')
            # Perform kubernetes audit
            if do_kubernetes_audit:
                try:
                    self.kubernetes_audit.subcloud_kubernetes_audit(
                        subcloud_name,
                        subcloud_region,
                        kubernetes_audit_data)
                    audits_done.append('kubernetes')
                except Exception:
                    LOG.exception(failmsg % (subcloud.name, 'kubernetes'))
                    failures.append('kubernetes')
            # Perform kube rootca update audit
            if do_kube_rootca_update_audit:
                try:
                    self.kube_rootca_update_audit.subcloud_kube_rootca_audit(
                        subcloud, kube_rootca_update_audit_data)
                    audits_done.append('kube-rootca-update')
                except Exception:
                    LOG.exception(failmsg % (subcloud.name,
                                             'kube-rootca-update'))
                    failures.append('kube-rootca-update')
            # Audit openstack application in the subcloud
            if do_audit_openstack and sysinv_client:
                # We don't want an exception here to cause our
                # audits_done to be empty:
                try:
                    self._audit_subcloud_openstack_app(
                        subcloud_region, sysinv_client, subcloud.openstack_installed)
                except Exception:
                    LOG.exception(failmsg % (subcloud.name, 'openstack'))
                    failures.append('openstack')
        return audits_done, failures
