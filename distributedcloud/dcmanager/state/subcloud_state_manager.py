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
# Copyright (c) 2017-2022 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from oslo_log import log as logging

from dcorch.common import consts as dcorch_consts
from dcorch.rpc import client as dcorch_rpc_client

from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import manager
from dcmanager.common import utils
from dcmanager.rpc import client as rpc_client

from dcmanager.db import api as db_api

from fm_api import constants as fm_const
from fm_api import fm_api

LOG = logging.getLogger(__name__)


def sync_update_subcloud_endpoint_status(func):
    """Synchronized lock decorator for _update_subcloud_endpoint_status. """

    def _get_lock_and_call(*args, **kwargs):
        """Get a single fair lock per subcloud based on subcloud name. """

        # subcloud name is the 3rd argument to
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
        self.dcorch_rpc_client = dcorch_rpc_client.EngineClient()
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
                        dcorch_consts.ENDPOINT_TYPE_IDENTITY:
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

                # Trigger subcloud patch and load audits for the subcloud after
                # its identity endpoint turns to other status from unknown
                if endpoint_type == dcorch_consts.ENDPOINT_TYPE_IDENTITY \
                    and sync_status != consts.SYNC_STATUS_UNKNOWN \
                    and original_identity_status == consts.SYNC_STATUS_UNKNOWN:
                    LOG.debug('Request for patch and load audit for %s after updating '
                              'identity out of unknown' % subcloud.name)
                    self.audit_rpc_client.trigger_subcloud_patch_load_audits(
                        context, subcloud_id)

                entity_instance_id = "subcloud=%s.resource=%s" % \
                                     (subcloud.name, endpoint_type)
                fault = self.fm_api.get_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,
                    entity_instance_id)

                if (sync_status != consts.SYNC_STATUS_OUT_OF_SYNC) \
                        and fault:
                    try:
                        self.fm_api.clear_fault(
                            fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,  # noqa
                            entity_instance_id)
                    except Exception as e:
                        LOG.exception(e)

                elif not fault and alarmable and \
                        (sync_status == consts.SYNC_STATUS_OUT_OF_SYNC):
                    entity_type_id = fm_const.FM_ENTITY_TYPE_SUBCLOUD
                    try:
                        fault = fm_api.Fault(
                            alarm_id=fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,  # noqa
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
                        fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,
                        entity_instance_id)

                    # TODO(yuxing): batch clear all the out-of-sync alarms of a
                    # given subcloud if fm_api support it. Be careful with the
                    # dc-cert endpoint when adding the above; the endpoint
                    # alarm must remain for offline subclouds.
                    if (sync_status != consts.SYNC_STATUS_OUT_OF_SYNC) \
                            and fault:
                        try:
                            self.fm_api.clear_fault(
                                fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,  # noqa
                                entity_instance_id)
                        except Exception as e:
                            LOG.exception(e)

                    elif not fault and alarmable and \
                            (sync_status == consts.SYNC_STATUS_OUT_OF_SYNC):
                        entity_type_id = fm_const.FM_ENTITY_TYPE_SUBCLOUD
                        try:
                            fault = fm_api.Fault(
                                alarm_id=fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC,  # noqa
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
                        db_api.subcloud_status_update_endpoints(context, subcloud_id,
                                                                endpoint_to_update_list,
                                                                sync_status)
                    except Exception as e:
                        LOG.exception(e)

        else:
            LOG.error("Subcloud not found:%s" % subcloud_id)

    @sync_update_subcloud_endpoint_status
    def _update_subcloud_endpoint_status(
            self, context,
            subcloud_name,
            endpoint_type=None,
            sync_status=consts.SYNC_STATUS_OUT_OF_SYNC,
            alarmable=True,
            ignore_endpoints=None):
        """Update subcloud endpoint status

        :param context: request context object
        :param subcloud_name: name of subcloud to update
        :param endpoint_type: endpoint type to update
        :param sync_status: sync status to set
        :param alarmable: controls raising an alarm if applicable
        :param ignore_endpoints: list of endpoints to ignore (only used if
               endpoint_type is None)
        """

        if ignore_endpoints is None:
            ignore_endpoints = []

        if not subcloud_name:
            raise exceptions.BadRequest(
                resource='subcloud',
                msg='Subcloud name not provided')

        try:
            subcloud = db_api.subcloud_get_by_name(context, subcloud_name)
        except Exception as e:
            LOG.exception(e)
            raise e

        # Rules for updating sync status:
        #
        # Always update if not in-sync.
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
        if (sync_status != consts.SYNC_STATUS_IN_SYNC or
            ((subcloud.availability_status == consts.AVAILABILITY_ONLINE) and
             (subcloud.management_state == consts.MANAGEMENT_MANAGED
              or endpoint_type == dcorch_consts.ENDPOINT_TYPE_DC_CERT))):
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
                     (subcloud_name, subcloud.availability_status,
                      subcloud.management_state, endpoint_type, sync_status))

    def update_subcloud_endpoint_status(
            self, context,
            subcloud_name=None,
            endpoint_type=None,
            sync_status=consts.SYNC_STATUS_OUT_OF_SYNC,
            alarmable=True,
            ignore_endpoints=None):
        """Update subcloud endpoint status

        :param context: request context object
        :param subcloud_name: name of subcloud to update
        :param endpoint_type: endpoint type to update
        :param sync_status: sync status to set
        :param alarmable: controls raising an alarm if applicable
        :param ignore_endpoints: list of endpoints to ignore (only used if
               endpoint_type is None)
        """

        if ignore_endpoints is None:
            ignore_endpoints = []

        if subcloud_name:
            self._update_subcloud_endpoint_status(
                context, subcloud_name, endpoint_type, sync_status, alarmable,
                ignore_endpoints)
        else:
            # update all subclouds
            for subcloud in db_api.subcloud_get_all(context):
                self._update_subcloud_endpoint_status(
                    context, subcloud.name, endpoint_type, sync_status,
                    alarmable, ignore_endpoints)

    def _update_subcloud_state(self, context, subcloud_name,
                               management_state, availability_status):
        try:
            LOG.info('Notifying dcorch, subcloud:%s management: %s, '
                     'availability:%s' %
                     (subcloud_name,
                      management_state,
                      availability_status))

            self.dcorch_rpc_client.update_subcloud_states(
                context, subcloud_name, management_state, availability_status)

        except Exception:
            LOG.exception('Problem informing dcorch of subcloud state change,'
                          'subcloud: %s' % subcloud_name)

    def _raise_or_clear_subcloud_status_alarm(self, subcloud_name,
                                              availability_status):
        entity_instance_id = "subcloud=%s" % subcloud_name
        fault = self.fm_api.get_fault(
            fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
            entity_instance_id)

        if fault and (availability_status == consts.AVAILABILITY_ONLINE):
            try:
                self.fm_api.clear_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
                    entity_instance_id)
            except Exception:
                LOG.exception("Failed to clear offline alarm for subcloud: %s",
                              subcloud_name)

        elif not fault and \
                (availability_status == consts.AVAILABILITY_OFFLINE):
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

    def update_subcloud_availability(self, context, subcloud_name,
                                     availability_status,
                                     update_state_only=False,
                                     audit_fail_count=None):
        try:
            subcloud = db_api.subcloud_get_by_name(context, subcloud_name)
        except Exception:
            LOG.exception("Failed to get subcloud by name: %s" % subcloud_name)
            raise

        if update_state_only:
            # Nothing has changed, but we want to send a state update for this
            # subcloud as an audit. Get the most up-to-date data.
            self._update_subcloud_state(context, subcloud_name,
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
                         'audit_fail_count update: %s' % subcloud_name)
                return
        else:
            self._raise_or_clear_subcloud_status_alarm(subcloud_name,
                                                       availability_status)

            if availability_status == consts.AVAILABILITY_OFFLINE:
                # Subcloud is going offline, set all endpoint statuses to
                # unknown.
                self._update_subcloud_endpoint_status(
                    context, subcloud_name, endpoint_type=None,
                    sync_status=consts.SYNC_STATUS_UNKNOWN)

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
                         ' update: %s' % subcloud_name)
                return

            if availability_status == consts.AVAILABILITY_ONLINE:
                # Subcloud is going online
                # Tell cert-mon to audit endpoint certificate.
                LOG.info('Request for online audit for %s' % subcloud_name)
                dc_notification = rpc_client.DCManagerNotifications()
                dc_notification.subcloud_online(context, subcloud_name)
                # Trigger all the audits for the subcloud so it can update the
                # sync status ASAP.
                self.audit_rpc_client.trigger_subcloud_audits(context,
                                                              subcloud.id)

            # Send dcorch a state update
            self._update_subcloud_state(context, subcloud_name,
                                        updated_subcloud.management_state,
                                        availability_status)

    def update_subcloud_sync_endpoint_type(self, context,
                                           subcloud_name,
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
            subcloud = db_api.subcloud_get_by_name(context, subcloud_name)
        except Exception:
            LOG.exception("Failed to get subcloud by name: %s" % subcloud_name)
            raise

        try:
            # Notify dcorch to add/remove sync endpoint type list
            func_switcher[operation][0](self.context, subcloud_name,
                                        endpoint_type_list)
            LOG.info('Notifying dcorch, subcloud: %s new sync endpoint: %s' %
                     (subcloud_name, endpoint_type_list))

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
                          ' type change, subcloud: %s' % subcloud_name)
