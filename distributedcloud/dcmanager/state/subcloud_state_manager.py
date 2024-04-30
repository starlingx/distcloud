# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2017-2024 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from fm_api import constants as fm_const
from fm_api import fm_api
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import manager
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.rpc import client as rpc_client
from dcorch.rpc import client as dcorch_rpc_client

LOG = logging.getLogger(__name__)
ALARM_OUT_OF_SYNC = fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC


def sync_update_subcloud_endpoint_status(func):
    """Synchronized lock decorator for _update_subcloud_endpoint_status. """

    def _get_lock_and_call(*args, **kwargs):
        """Get a single fair lock per subcloud based on subcloud region. """

        # subcloud region is the 3rd argument to
        # _update_subcloud_endpoint_status()
        @utils.synchronized(args[2], external=True, fair=True)
        def _call_func(*args, **kwargs):
            return func(*args, **kwargs)

        return _call_func(*args, **kwargs)

    return _get_lock_and_call


class SubcloudStateManager(manager.Manager):
    """Manages tasks related to subclouds."""

    def __init__(self, *args, **kwargs):
        LOG.debug('SubcloudStateManager initialization...')

        super(SubcloudStateManager,
              self).__init__(service_name="subcloud_manager", *args, **kwargs)
        self.context = context.get_admin_context()
        self.dcorch_rpc_client = dcorch_rpc_client.EngineWorkerClient()
        self.fm_api = fm_api.FaultAPIs()
        self.audit_rpc_client = dcmanager_audit_rpc_client.ManagerAuditClient()

    def _do_update_subcloud_endpoint_status(self, context, subcloud_id,
                                            endpoint_type, sync_status,
                                            alarmable, ignore_endpoints=None):
        """Update online/managed subcloud endpoint status

        :param context: request context object
        :param subcloud_id: id of subcloud to update
        :param endpoint_type: endpoint type to update
        :param sync_status: sync status to set
        :param alarmable: controls raising an alarm if applicable
        :param ignore_endpoints: list of endpoints to ignore (only used if
               endpoint_type is None)
        """

        if ignore_endpoints is None:
            ignore_endpoints = []

        subcloud_status_list = []
        subcloud = None
        original_identity_status = None
        # retrieve the info from the db for this subcloud.
        # subcloud_id should not be None
        try:
            for subcloud, subcloud_status in db_api. \
                    subcloud_get_with_status(context, subcloud_id):
                if subcloud_status:
                    subcloud_status_list.append(
                        db_api.subcloud_endpoint_status_db_model_to_dict(
                            subcloud_status))
                    if subcloud_status.endpoint_type == \
                            dccommon_consts.ENDPOINT_TYPE_IDENTITY:
                        original_identity_status = subcloud_status.sync_status
        except Exception as e:
            LOG.exception(e)
            raise e

        if subcloud:
            if endpoint_type:
                # updating a single endpoint on a single subcloud
                for subcloud_status in subcloud_status_list:
                    if subcloud_status['endpoint_type'] == endpoint_type:
                        if subcloud_status['sync_status'] == sync_status:
                            # No change in the sync_status
                            LOG.debug("Sync status (%s) for subcloud %s did "
                                      "not change - ignore update" %
                                      (sync_status, subcloud.name))
                            return
                        # We found the endpoint
                        break
                else:
                    # We did not find the endpoint
                    raise exceptions.BadRequest(
                        resource='subcloud',
                        msg='Endpoint %s not found for subcloud' %
                            endpoint_type)

                LOG.info("Updating subcloud:%s endpoint:%s sync:%s" %
                         (subcloud.name, endpoint_type, sync_status))
                db_api.subcloud_status_update(context,
                                              subcloud_id,
                                              endpoint_type,
                                              sync_status)

                # Trigger subcloud audits for the subcloud after
                # its identity endpoint turns to other status from unknown
                is_sync_unknown = sync_status != dccommon_consts.SYNC_STATUS_UNKNOWN
                is_identity_unknown = (
                    original_identity_status == dccommon_consts.SYNC_STATUS_UNKNOWN
                )
                if endpoint_type == dccommon_consts.ENDPOINT_TYPE_IDENTITY \
                        and is_sync_unknown and is_identity_unknown:
                    if not subcloud.first_identity_sync_complete:
                        db_api.subcloud_update(context, subcloud_id,
                                               first_identity_sync_complete=True)
                    LOG.debug('Request for audits for %s after updating '
                              'identity out of unknown' % subcloud.name)
                    self.audit_rpc_client.trigger_subcloud_audits(
                        context, subcloud_id)

                entity_instance_id = "subcloud=%s.resource=%s" % \
                                     (subcloud.name, endpoint_type)
                fault = self.fm_api.get_fault(
                    ALARM_OUT_OF_SYNC,
                    entity_instance_id)

                if (sync_status != dccommon_consts.SYNC_STATUS_OUT_OF_SYNC) \
                        and fault:
                    try:
                        self.fm_api.clear_fault(
                            ALARM_OUT_OF_SYNC,
                            entity_instance_id)
                    except Exception as e:
                        LOG.exception(e)

                elif not fault and alarmable and \
                        (sync_status == dccommon_consts.SYNC_STATUS_OUT_OF_SYNC):
                    entity_type_id = fm_const.FM_ENTITY_TYPE_SUBCLOUD
                    try:

                        fault = fm_api.Fault(
                            alarm_id=ALARM_OUT_OF_SYNC,
                            alarm_state=fm_const.FM_ALARM_STATE_SET,
                            entity_type_id=entity_type_id,
                            entity_instance_id=entity_instance_id,
                            severity=fm_const.FM_ALARM_SEVERITY_MAJOR,
                            reason_text=("%s %s sync_status is "
                                         "out-of-sync" %
                                         (subcloud.name, endpoint_type)),
                            alarm_type=fm_const.FM_ALARM_TYPE_0,
                            probable_cause=fm_const.ALARM_PROBABLE_CAUSE_2,
                            proposed_repair_action="If problem persists "
                                                   "contact next level "
                                                   "of support",
                            service_affecting=False)

                        self.fm_api.set_fault(fault)

                    except Exception as e:
                        LOG.exception(e)

            else:
                # update all endpoints on this subcloud
                LOG.info("Updating all endpoints on subcloud: %s sync: %s "
                         "ignore_endpoints: %s" %
                         (subcloud.name, sync_status, ignore_endpoints))

                # TODO(yuxing): The following code can be further optimized when
                # batch alarm clearance APIs are available, so we don't need to
                # loop over all the endpoints of a given subcloud, e.g.
                # if not ignore_endpoints:
                #    db_api.subcloud_status_update_endpoints_all(...)
                # else:
                #    db_api.subcloud_status_update_endpoints(...)
                endpoint_to_update_list = []
                for entry in subcloud_status_list:
                    endpoint = entry[consts.ENDPOINT_TYPE]
                    if endpoint in ignore_endpoints:
                        # Do not update this endpoint
                        continue
                    endpoint_to_update_list.append(endpoint)

                    entity_instance_id = "subcloud=%s.resource=%s" % \
                                         (subcloud.name, endpoint)

                    fault = self.fm_api.get_fault(
                        ALARM_OUT_OF_SYNC,
                        entity_instance_id)

                    # TODO(yuxing): batch clear all the out-of-sync alarms of a
                    # given subcloud if fm_api support it. Be careful with the
                    # dc-cert endpoint when adding the above; the endpoint
                    # alarm must remain for offline subclouds.
                    if (sync_status != dccommon_consts.SYNC_STATUS_OUT_OF_SYNC) \
                            and fault:
                        try:
                            self.fm_api.clear_fault(
                                ALARM_OUT_OF_SYNC,
                                entity_instance_id)
                        except Exception as e:
                            LOG.exception(e)

                    elif not fault and alarmable and \
                            (sync_status == dccommon_consts.SYNC_STATUS_OUT_OF_SYNC):
                        entity_type_id = fm_const.FM_ENTITY_TYPE_SUBCLOUD
                        try:
                            fault = fm_api.Fault(
                                alarm_id=ALARM_OUT_OF_SYNC,
                                alarm_state=fm_const.FM_ALARM_STATE_SET,
                                entity_type_id=entity_type_id,
                                entity_instance_id=entity_instance_id,
                                severity=fm_const.FM_ALARM_SEVERITY_MAJOR,
                                reason_text=("%s %s sync_status is "
                                             "out-of-sync" %
                                             (subcloud.name, endpoint)),
                                alarm_type=fm_const.FM_ALARM_TYPE_0,
                                probable_cause=fm_const.ALARM_PROBABLE_CAUSE_2,
                                proposed_repair_action="If problem persists "
                                                       "contact next level "
                                                       "of support",
                                service_affecting=False)

                            self.fm_api.set_fault(fault)
                        except Exception as e:
                            LOG.exception(e)

                if endpoint_to_update_list:
                    try:
                        db_api.subcloud_status_update_endpoints(
                            context,
                            subcloud_id,
                            endpoint_to_update_list,
                            sync_status)
                    except Exception as e:
                        LOG.exception(e)

        else:
            LOG.error("Subcloud not found:%s" % subcloud_id)

    @sync_update_subcloud_endpoint_status
    def _update_subcloud_endpoint_status(
            self, context,
            subcloud_region,
            endpoint_type=None,
            sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            alarmable=True,
            ignore_endpoints=None):
        """Update subcloud endpoint status

        :param context: request context object
        :param subcloud_region: name of subcloud region to update
        :param endpoint_type: endpoint type to update
        :param sync_status: sync status to set
        :param alarmable: controls raising an alarm if applicable
        :param ignore_endpoints: list of endpoints to ignore (only used if
               endpoint_type is None)
        """

        if ignore_endpoints is None:
            ignore_endpoints = []

        if not subcloud_region:
            raise exceptions.BadRequest(
                resource='subcloud',
                msg='Subcloud region not provided')

        try:
            subcloud = db_api.subcloud_get_by_region_name(context, subcloud_region)
        except Exception as e:
            LOG.exception(e)
            raise e

        # Rules for updating sync status:
        #
        # For secondary subclouds, only update if the new sync_status is
        # 'unknown'
        #
        # For others, always update if not in-sync.
        #
        # Otherwise, only update the sync status if managed and online
        # (unless dc-cert).
        #
        # Most endpoints are audited only when the subcloud is managed and
        # online. An exception is the dc-cert endpoint, which is audited
        # whenever the subcloud is online (managed or unmanaged).
        #
        # This means if a subcloud is going offline or unmanaged, then
        # the sync status update must be done first.
        #
        is_in_sync = sync_status == dccommon_consts.SYNC_STATUS_IN_SYNC
        is_online = subcloud.availability_status == \
            dccommon_consts.AVAILABILITY_ONLINE
        is_managed = subcloud.management_state == \
            dccommon_consts.MANAGEMENT_MANAGED
        is_endpoint_type_dc_cert = endpoint_type == \
            dccommon_consts.ENDPOINT_TYPE_DC_CERT
        is_secondary = subcloud.deploy_status == consts.DEPLOY_STATE_SECONDARY
        is_sync_unknown = sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN
        is_secondary_and_sync_unknown = is_secondary and is_sync_unknown

        if (
            (not is_in_sync
             or (is_online and (is_managed or is_endpoint_type_dc_cert)))
            and not is_secondary
        ) or is_secondary_and_sync_unknown:
            # update a single subcloud
            try:
                self._do_update_subcloud_endpoint_status(context,
                                                         subcloud.id,
                                                         endpoint_type,
                                                         sync_status,
                                                         alarmable,
                                                         ignore_endpoints)
            except Exception as e:
                LOG.exception(e)
                raise e
        else:
            LOG.info("Ignoring subcloud sync_status update for subcloud:%s "
                     "availability:%s management:%s endpoint:%s sync:%s" %
                     (subcloud.name, subcloud.availability_status,
                      subcloud.management_state, endpoint_type, sync_status))

    def update_subcloud_endpoint_status(
            self, context,
            subcloud_region=None,
            endpoint_type=None,
            sync_status=dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
            alarmable=True,
            ignore_endpoints=None):
        """Update subcloud endpoint status

        :param context: request context object
        :param subcloud_region: region of subcloud to update
        :param endpoint_type: endpoint type to update
        :param sync_status: sync status to set
        :param alarmable: controls raising an alarm if applicable
        :param ignore_endpoints: list of endpoints to ignore (only used if
               endpoint_type is None)
        """

        if ignore_endpoints is None:
            ignore_endpoints = []

        if subcloud_region:
            self._update_subcloud_endpoint_status(
                context, subcloud_region, endpoint_type, sync_status, alarmable,
                ignore_endpoints)
        else:
            # update all subclouds
            for subcloud in db_api.subcloud_get_all(context):
                self._update_subcloud_endpoint_status(
                    context, subcloud.region_name, endpoint_type, sync_status,
                    alarmable, ignore_endpoints)

    def _update_subcloud_state(self, context, subcloud_name, subcloud_region,
                               management_state, availability_status):
        try:
            LOG.info('Notifying dcorch, subcloud:%s management: %s, '
                     'availability:%s' %
                     (subcloud_name,
                      management_state,
                      availability_status))

            self.dcorch_rpc_client.update_subcloud_states(
                context, subcloud_region, management_state, availability_status)

        except Exception:
            LOG.exception('Problem informing dcorch of subcloud state change,'
                          'subcloud: %s' % subcloud_name)

    def _raise_or_clear_subcloud_status_alarm(self, subcloud_name,
                                              availability_status,
                                              deploy_status=None):
        entity_instance_id = "subcloud=%s" % subcloud_name
        fault = self.fm_api.get_fault(
            fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
            entity_instance_id)

        if fault and (availability_status == dccommon_consts.AVAILABILITY_ONLINE):
            try:
                self.fm_api.clear_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
                    entity_instance_id)
            except Exception:
                LOG.exception("Failed to clear offline alarm for subcloud: %s",
                              subcloud_name)

        # Raise the alarm if the subcloud became offline and it's not a
        # secondary subcloud
        elif not fault and \
                (availability_status == dccommon_consts.AVAILABILITY_OFFLINE and
                 deploy_status != consts.DEPLOY_STATE_SECONDARY):
            try:
                fault = fm_api.Fault(
                    alarm_id=fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
                    alarm_state=fm_const.FM_ALARM_STATE_SET,
                    entity_type_id=fm_const.FM_ENTITY_TYPE_SUBCLOUD,
                    entity_instance_id=entity_instance_id,

                    severity=fm_const.FM_ALARM_SEVERITY_CRITICAL,
                    reason_text=('%s is offline' % subcloud_name),
                    alarm_type=fm_const.FM_ALARM_TYPE_0,
                    probable_cause=fm_const.ALARM_PROBABLE_CAUSE_29,
                    proposed_repair_action="Wait for subcloud to "
                                           "become online; if "
                                           "problem persists contact "
                                           "next level of support.",
                    service_affecting=True)

                self.fm_api.set_fault(fault)
            except Exception:
                LOG.exception("Failed to raise offline alarm for subcloud: %s",
                              subcloud_name)

    def update_subcloud_availability(self, context, subcloud_region,
                                     availability_status,
                                     update_state_only=False,
                                     audit_fail_count=None):
        try:
            subcloud = db_api.subcloud_get_by_region_name(context, subcloud_region)
        except Exception:
            LOG.exception(
                "Failed to get subcloud by region name %s" % subcloud_region
            )
            raise

        if update_state_only:
            # Ensure that the status alarm is consistent with the
            # subcloud's availability. This is required to compensate
            # for rare alarm update failures, which may occur during
            # availability updates.
            self._raise_or_clear_subcloud_status_alarm(subcloud.name,
                                                       availability_status)

            # Nothing has changed, but we want to send a state update for this
            # subcloud as an audit. Get the most up-to-date data.
            self._update_subcloud_state(context, subcloud.name,
                                        subcloud.region_name,
                                        subcloud.management_state,
                                        availability_status)
        elif availability_status is None:
            # only update the audit fail count
            try:
                db_api.subcloud_update(self.context, subcloud.id,
                                       audit_fail_count=audit_fail_count)
            except exceptions.SubcloudNotFound:
                # slim possibility subcloud could have been deleted since
                # we found it in db, ignore this benign error.
                LOG.info('Ignoring SubcloudNotFound when attempting '
                         'audit_fail_count update: %s' % subcloud.name)
                return
        else:
            self._raise_or_clear_subcloud_status_alarm(subcloud.name,
                                                       availability_status)

            if availability_status == dccommon_consts.AVAILABILITY_OFFLINE:
                # Subcloud is going offline, set all endpoint statuses to
                # unknown.
                self._update_subcloud_endpoint_status(
                    context, subcloud.region_name, endpoint_type=None,
                    sync_status=dccommon_consts.SYNC_STATUS_UNKNOWN)

            try:
                updated_subcloud = db_api.subcloud_update(
                    context,
                    subcloud.id,
                    availability_status=availability_status,
                    audit_fail_count=audit_fail_count)
            except exceptions.SubcloudNotFound:
                # slim possibility subcloud could have been deleted since
                # we found it in db, ignore this benign error.
                LOG.info('Ignoring SubcloudNotFound when attempting state'
                         ' update: %s' % subcloud.name)
                return

            if availability_status == dccommon_consts.AVAILABILITY_ONLINE:
                # Subcloud is going online
                # Tell cert-mon to audit endpoint certificate.
                LOG.info('Request for online audit for %s' % subcloud.name)
                dc_notification = rpc_client.DCManagerNotifications()
                dc_notification.subcloud_online(context, subcloud.region_name)
                # Trigger all the audits for the subcloud so it can update the
                # sync status ASAP.
                self.audit_rpc_client.trigger_subcloud_audits(context,
                                                              subcloud.id)

            # Send dcorch a state update
            self._update_subcloud_state(context, subcloud.name,
                                        subcloud.region_name,
                                        updated_subcloud.management_state,
                                        availability_status)

    def update_subcloud_sync_endpoint_type(self, context,
                                           subcloud_region,
                                           endpoint_type_list,
                                           openstack_installed):
        operation = 'add' if openstack_installed else 'remove'
        func_switcher = {
            'add': (
                self.dcorch_rpc_client.add_subcloud_sync_endpoint_type,
                db_api.subcloud_status_create
            ),
            'remove': (
                self.dcorch_rpc_client.remove_subcloud_sync_endpoint_type,
                db_api.subcloud_status_delete
            )
        }

        try:
            subcloud = db_api.subcloud_get_by_region_name(context, subcloud_region)
        except Exception:
            LOG.exception(
                "Failed to get subcloud by region name: %s" % subcloud_region
            )
            raise

        try:
            # Notify dcorch to add/remove sync endpoint type list
            func_switcher[operation][0](self.context, subcloud_region,
                                        endpoint_type_list)
            LOG.info('Notifying dcorch, subcloud: %s new sync endpoint: %s' %
                     (subcloud.name, endpoint_type_list))

            # Update subcloud status table by adding/removing openstack sync
            # endpoint types
            for endpoint_type in endpoint_type_list:
                func_switcher[operation][1](self.context, subcloud.id,
                                            endpoint_type)
            # Update openstack_installed of subcloud table
            db_api.subcloud_update(self.context, subcloud.id,
                                   openstack_installed=openstack_installed)
        except Exception:
            LOG.exception('Problem informing dcorch of subcloud sync endpoint'
                          ' type change, subcloud: %s' % subcloud.name)
