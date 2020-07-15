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

import eventlet
import time

from keystoneauth1 import exceptions as keystone_exceptions
from oslo_config import cfg
from oslo_log import log as logging

from sysinv.common import constants as sysinv_constants

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.sdk_platform import OpenStackDriver

from dcmanager.audit import alarm_aggregation
from dcmanager.audit import patch_audit
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import scheduler
from dcmanager.db import api as db_api
from dcmanager.rpc import client as dcmanager_rpc_client

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

# We will update the state of each subcloud in the dcorch about once per hour.
# Calculate how many iterations that will be.
SUBCLOUD_STATE_UPDATE_ITERATIONS = \
    dccommon_consts.SECONDS_IN_HOUR / CONF.scheduler.subcloud_audit_interval

# Patch audit normally happens every DEFAULT_PATCH_AUDIT_DELAY_SECONDS, but
# can be forced to happen on the next audit interval by calling
# trigger_patch_audit.
DEFAULT_PATCH_AUDIT_DELAY_SECONDS = 900


class SubcloudAuditManager(manager.Manager):
    """Manages tasks related to audits."""

    # Used to force patch audit on the next interval
    force_patch_audit = False

    def __init__(self, *args, **kwargs):
        LOG.debug(_('SubcloudAuditManager initialization...'))

        super(SubcloudAuditManager, self).__init__(
            service_name="subcloud_audit_manager")
        self.context = context.get_admin_context()
        self.dcmanager_rpc_client = dcmanager_rpc_client.ManagerClient()
        # Keeps track of greenthreads we create to do work.
        self.thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=100)
        # Track workers created for each subcloud.
        self.subcloud_workers = dict()
        # Number of audits since last subcloud state update
        self.audit_count = 0
        # Number of patch audits
        self.patch_audit_count = 0
        self.alarm_aggr = alarm_aggregation.AlarmAggregation(self.context)
        self.patch_audit = patch_audit.PatchAudit(
            self.context, self.dcmanager_rpc_client)
        # trigger a patch audit on startup
        self.patch_audit_time = 0

    @classmethod
    def trigger_patch_audit(cls, context):
        """Trigger patch audit at next interval.

        This can be called from outside the dcmanager audit
        """
        cls.force_patch_audit = True

    @classmethod
    def reset_force_patch_audit(cls):
        cls.force_patch_audit = False

    def periodic_subcloud_audit(self):
        """Audit availability of subclouds."""

        # Blanket catch all exceptions in the audit so that the audit
        # does not die.
        while True:
            try:
                eventlet.greenthread.sleep(
                    CONF.scheduler.subcloud_audit_interval)
                self._periodic_subcloud_audit_loop()
            except eventlet.greenlet.GreenletExit:
                # We have been told to exit
                return
            except Exception:
                LOG.exception("Error in periodic subcloud audit loop")

    def _get_patch_audit(self):
        """Return the patch audit data if the patch audit should be triggered.

           Also, returns whether to audit the load.
        """
        patch_audit_data = None
        audit_load = False

        current_time = time.time()
        # Determine whether to trigger a patch audit of each subcloud
        if (SubcloudAuditManager.force_patch_audit or
                (current_time - self.patch_audit_time >=
                    DEFAULT_PATCH_AUDIT_DELAY_SECONDS)):
            LOG.info("Trigger patch audit")
            self.patch_audit_time = current_time
            self.patch_audit_count += 1
            # Query RegionOne patches and software version
            patch_audit_data = self.patch_audit.get_regionone_audit_data()
            # Check subcloud software version every other patch audit cycle
            if (self.patch_audit_count % 2 != 0 or
                    SubcloudAuditManager.force_patch_audit):
                LOG.info("Trigger load audit")
                audit_load = True
            SubcloudAuditManager.reset_force_patch_audit()

        return patch_audit_data, audit_load

    def _periodic_subcloud_audit_loop(self):
        """Audit availability of subclouds loop."""

        # We will be running in our own green thread here.
        LOG.info('Triggered subcloud audit.')
        self.audit_count += 1

        # Determine whether to trigger a state update to each subcloud
        if self.audit_count >= SUBCLOUD_STATE_UPDATE_ITERATIONS:
            update_subcloud_state = True
            self.audit_count = 0
        else:
            update_subcloud_state = False

        patch_audit_data, do_load_audit = self._get_patch_audit()

        openstack_installed = False
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
        #    if app.name == sysinv_constants.HELM_APP_OPENSTACK and app.active:
        #        openstack_installed = True
        #        break

        for subcloud in db_api.subcloud_get_all(self.context):
            # Include failure deploy status states in the auditable list
            # so that the subcloud can be set as offline
            if (subcloud.deploy_status not in
                    [consts.DEPLOY_STATE_DONE,
                     consts.DEPLOY_STATE_DEPLOYING,
                     consts.DEPLOY_STATE_DEPLOY_FAILED,
                     consts.DEPLOY_STATE_INSTALL_FAILED,
                     consts.DEPLOY_STATE_PRE_INSTALL_FAILED,
                     consts.DEPLOY_STATE_DATA_MIGRATION_FAILED]):
                LOG.debug("Skip subcloud %s audit, deploy_status: %s" %
                          (subcloud.name, subcloud.deploy_status))
                continue

            # Create a new greenthread for each subcloud to allow the audits
            # to be done in parallel. If there are not enough greenthreads
            # in the pool, this will block until one becomes available.
            self.subcloud_workers[subcloud.name] = \
                self.thread_group_manager.start(self._audit_subcloud,
                                                subcloud.name,
                                                update_subcloud_state,
                                                openstack_installed,
                                                patch_audit_data,
                                                do_load_audit)

        # Wait for all greenthreads to complete
        LOG.info('Waiting for subcloud audits to complete.')
        for thread in self.subcloud_workers.values():
            thread.wait()

        # Clear the list of workers before next audit
        self.subcloud_workers = dict()
        LOG.info('All subcloud audits have completed.')

    def _update_subcloud_availability(self, subcloud_name,
                                      availability_status=None,
                                      update_state_only=False,
                                      audit_fail_count=None):
        try:
            self.dcmanager_rpc_client.update_subcloud_availability(
                self.context, subcloud_name, availability_status,
                update_state_only, audit_fail_count)
            LOG.info('Notifying dcmanager, subcloud:%s, availability:%s' %
                     (subcloud_name,
                      availability_status))
        except Exception:
            LOG.exception('Problem informing dcmanager of subcloud '
                          'availability state change, subcloud: %s'
                          % subcloud_name)

    @staticmethod
    def _get_subcloud_availability_status(subcloud_name, sysinv_client):
        """For each subcloud, if at least one service is active in each

        service of servicegroup-list then declare the subcloud online.
        """
        avail_to_set = consts.AVAILABILITY_OFFLINE
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
                    consts.AVAILABILITY_ONLINE
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
            if app.name == sysinv_constants.HELM_APP_OPENSTACK \
                    and app.active:
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

    def _audit_subcloud(self, subcloud_name, update_subcloud_state,
                        audit_openstack, patch_audit_data, do_load_audit):
        """Audit a single subcloud."""

        # Retrieve the subcloud
        try:
            subcloud = db_api.subcloud_get_by_name(self.context, subcloud_name)
        except exceptions.SubcloudNotFound:
            # Possibility subcloud could have been deleted since the list of
            # subclouds to audit was created.
            LOG.info('Ignoring SubcloudNotFound when auditing subcloud %s' %
                     subcloud_name)
            return

        avail_status_current = subcloud.availability_status
        audit_fail_count = subcloud.audit_fail_count

        # Set defaults to None and disabled so we will still set disabled
        # status if we encounter an error.

        sysinv_client = None
        fm_client = None
        avail_to_set = consts.AVAILABILITY_OFFLINE

        try:
            os_client = OpenStackDriver(region_name=subcloud_name,
                                        thread_name='subcloud-audit')
            sysinv_client = os_client.sysinv_client
            fm_client = os_client.fm_client
        except (keystone_exceptions.EndpointNotFound,
                keystone_exceptions.ConnectFailure,
                keystone_exceptions.ConnectTimeout,
                IndexError):
            if avail_status_current == consts.AVAILABILITY_OFFLINE:
                LOG.info("Identity or Platform endpoint for %s not "
                         "found, ignoring for offline "
                         "subcloud." % subcloud_name)
                return
            else:
                # The subcloud will be marked as offline below.
                LOG.error("Identity or Platform endpoint for online "
                          "subcloud: %s not found." % subcloud_name)

        except Exception:
            LOG.exception("Failed to get OS Client for subcloud: %s"
                          % subcloud_name)

        # Check availability of the subcloud
        if sysinv_client:
            avail_to_set = self._get_subcloud_availability_status(
                subcloud_name, sysinv_client)

        if avail_to_set == consts.AVAILABILITY_OFFLINE:
            if audit_fail_count < consts.AVAIL_FAIL_COUNT_MAX:
                audit_fail_count = audit_fail_count + 1
            if (avail_status_current == consts.AVAILABILITY_ONLINE) and \
                    (audit_fail_count < consts.AVAIL_FAIL_COUNT_TO_ALARM):
                # Do not set offline until we have failed audit
                # the requisite number of times
                avail_to_set = consts.AVAILABILITY_ONLINE
        else:
            # In the case of a one off blip, we may need to set the
            # fail count back to 0
            audit_fail_count = 0

        if avail_to_set != avail_status_current:

            if avail_to_set == consts.AVAILABILITY_ONLINE:
                audit_fail_count = 0

            LOG.info('Setting new availability status: %s '
                     'on subcloud: %s' %
                     (avail_to_set, subcloud_name))
            self._update_subcloud_availability(
                subcloud_name,
                availability_status=avail_to_set,
                audit_fail_count=audit_fail_count)

        elif audit_fail_count != subcloud.audit_fail_count:
            self._update_subcloud_availability(
                subcloud_name,
                availability_status=None,
                audit_fail_count=audit_fail_count)

        elif update_subcloud_state:
            # Nothing has changed, but we want to send a state update for this
            # subcloud as an audit.
            self._update_subcloud_availability(
                subcloud_name,
                availability_status=avail_status_current,
                update_state_only=True)

        # If subcloud is managed and online, audit additional resources
        if (subcloud.management_state == consts.MANAGEMENT_MANAGED and
                avail_to_set == consts.AVAILABILITY_ONLINE):
            # Get alarm summary and store in db,
            if fm_client:
                self.alarm_aggr.update_alarm_summary(subcloud_name, fm_client)

            # If we have patch audit data, audit the subcloud
            if patch_audit_data:
                self.patch_audit.subcloud_patch_audit(subcloud_name,
                                                      patch_audit_data,
                                                      do_load_audit)

            # Audit openstack application in the subcloud
            if audit_openstack and sysinv_client:
                self._audit_subcloud_openstack_app(
                    subcloud_name, sysinv_client, subcloud.openstack_installed)
