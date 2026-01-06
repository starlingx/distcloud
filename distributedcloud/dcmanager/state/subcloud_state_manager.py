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
# Copyright (c) 2017-2025 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from fm_api import constants as fm_const
from fm_api import fm_api
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dccommon import utils as cutils
from dcmanager.audit import rpcapi as dcmanager_audit_rpc_client
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import exceptions
from dcmanager.common import manager
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy import models
from dcmanager.rpc import client as rpc_client
from dcorch.rpc import client as dcorch_rpc_client

LOG = logging.getLogger(__name__)
ALARM_OUT_OF_SYNC = fm_const.FM_ALARM_ID_DC_SUBCLOUD_RESOURCE_OUT_OF_SYNC


def sync_update_subcloud_endpoint_status(func):
    """Synchronized lock decorator for _update_subcloud_endpoint_status."""

    def _get_lock_and_call(*args, **kwargs):
        """Get a single fair lock per subcloud based on subcloud name/region."""

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
        LOG.debug("SubcloudStateManager initialization...")

        super(SubcloudStateManager, self).__init__(
            service_name="subcloud_manager", *args, **kwargs
        )
        self.context = context.get_admin_context()
        self.dcorch_rpc_client = dcorch_rpc_client.EngineWorkerClient()
        self.fm_api = fm_api.FaultAPIsV2()
        self.audit_rpc_client = dcmanager_audit_rpc_client.ManagerAuditClient()

    def _do_update_subcloud_endpoint_status(
        self,
        context: context.RequestContext,
        subcloud_id: int,
        endpoint_type: str,
        sync_status: str,
        alarmable: bool,
        ignore_endpoints: list[str],
    ) -> None:
        """Update online/managed subcloud endpoint status

        :param context: request context object
        :param subcloud_id: id of subcloud to update
        :param endpoint_type: endpoint type to update
        :param sync_status: sync status to set
        :param alarmable: controls raising an alarm if applicable
        :param ignore_endpoints: list of endpoints to ignore (only used if
               endpoint_type is None)
        """

        endpoint_status_dict = {}
        endpoint_to_update_list = []
        faults_to_raise = []
        faults_to_clear = []

        # The subcloud object will always be the same, so we just keep the last one
        for subcloud, endpoint_status in db_api.subcloud_get_with_status(
            context,
            subcloud_id,
            endpoint_type=endpoint_type,
        ):
            endpoint_status_dict[endpoint_status.endpoint_type] = endpoint_status

        if endpoint_type:
            status = endpoint_status_dict.get(endpoint_type)
            if status and status.sync_status == sync_status:
                msg = f"Sync status ({sync_status}) did not change - ignoring update"
                cutils.log_subcloud_msg(LOG.debug, msg, subcloud.name)
                return
            elif not status:
                msg = f"Subcloud: {subcloud.name}. Endpoint {endpoint_type} not found"
                raise exceptions.BadRequest(
                    resource="subcloud",
                    msg=msg,
                )

            self._trigger_subcloud_audits_after_identity_sync(
                context,
                subcloud_id,
                subcloud,
                sync_status,
                endpoint_type,
                endpoint_status_dict,
            )

        for endpoint in endpoint_status_dict.values():
            if not endpoint_type and endpoint.endpoint_type in ignore_endpoints:
                continue
            endpoint_to_update_list.append(endpoint.endpoint_type)

            entity_instance_id = (
                f"subcloud={subcloud.name}.resource={endpoint.endpoint_type}"
            )
            if sync_status != dccommon_consts.SYNC_STATUS_OUT_OF_SYNC:
                faults_to_clear.append((ALARM_OUT_OF_SYNC, entity_instance_id))
            elif alarmable and (sync_status == dccommon_consts.SYNC_STATUS_OUT_OF_SYNC):
                fault = self._create_fault_out_of_sync(subcloud.name, endpoint_type)
                faults_to_raise.append(fault)

        try:
            # We first want to raise/clear any alarms because in case of an
            # unresponsive FM, like we have during a swact, the operations wont process
            # again if the DB state is already the correct one, leading to a persistent
            # alarm
            self._raise_and_clear_subcloud_alarms_list(
                subcloud.name, faults_to_raise, faults_to_clear
            )
            if endpoint_to_update_list:
                db_api.subcloud_status_update_endpoints(
                    context, subcloud_id, endpoint_to_update_list, sync_status
                )
        except Exception as e:
            msg = f"Failed to update subcloud endpoint status: {e}"
            cutils.log_subcloud_msg(LOG.error, msg, subcloud.name)
            raise e

    def _trigger_subcloud_audits_after_identity_sync(
        self,
        context: context.RequestContext,
        subcloud_id: int,
        subcloud: models.Subcloud,
        sync_status: str,
        endpoint_type: str,
        endpoint_status_dict: dict[str, models.SubcloudStatus],
    ) -> None:
        """Trigger audits for a subcloud after the first identity sync is complete

        :param context: request context object
        :param subcloud_id: id of the subcloud to update
        :param subcloud: subcloud object
        :param sync_status: sync status to set
        :param endpoint_type: endpoint type to update
        :param endpoint_status_dict: dict of endpoint types and their status
        """
        is_sync_not_unknown = sync_status != dccommon_consts.SYNC_STATUS_UNKNOWN
        identity_endpoint = endpoint_status_dict.get(
            dccommon_consts.ENDPOINT_TYPE_IDENTITY
        )
        is_identity_unknown = (
            identity_endpoint
            and identity_endpoint.sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN
        )
        if (
            endpoint_type == dccommon_consts.ENDPOINT_TYPE_IDENTITY
            and is_sync_not_unknown
            and is_identity_unknown
        ):
            if not subcloud.first_identity_sync_complete:
                db_api.subcloud_update(
                    context, subcloud_id, first_identity_sync_complete=True
                )
            msg = "Request for audits after updating identity out of unknown"
            cutils.log_subcloud_msg(LOG.debug, msg, subcloud.name)
            self.audit_rpc_client.trigger_subcloud_audits(context, subcloud_id)

    def _should_update_endpoint_status(
        self, subcloud: models.Subcloud, endpoint_type: str, sync_status: str
    ) -> bool:
        """Verifies if the subcloud's endpoint should have its sync status updated"""

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
        is_online = subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE
        is_managed = subcloud.management_state == dccommon_consts.MANAGEMENT_MANAGED
        is_endpoint_type_dc_cert = (
            endpoint_type == dccommon_consts.ENDPOINT_TYPE_DC_CERT
        )
        is_secondary = subcloud.deploy_status == consts.DEPLOY_STATE_SECONDARY
        is_sync_unknown = sync_status == dccommon_consts.SYNC_STATUS_UNKNOWN
        is_secondary_and_sync_unknown = is_secondary and is_sync_unknown

        return (
            (not is_in_sync or (is_online and (is_managed or is_endpoint_type_dc_cert)))
            and not is_secondary
        ) or is_secondary_and_sync_unknown

    @sync_update_subcloud_endpoint_status
    def _update_subcloud_endpoint_status(
        self,
        context: context.RequestContext,
        subcloud_region: str,
        endpoint_type: str,
        sync_status: str,
        alarmable: bool,
        ignore_endpoints: list[str],
    ) -> None:
        """Update subcloud endpoint status

        :param context: request context object
        :param subcloud_region: name of subcloud region to update
        :param endpoint_type: endpoint type to update
        :param sync_status: sync status to set
        :param alarmable: controls raising an alarm if applicable
        :param ignore_endpoints: list of endpoints to ignore (only used if
               endpoint_type is None)
        """

        if not subcloud_region:
            raise exceptions.BadRequest(
                resource="subcloud", msg="Subcloud region not provided"
            )

        try:
            subcloud = db_api.subcloud_get_by_region_name(context, subcloud_region)
        except Exception as e:
            LOG.exception(e)
            raise e

        if self._should_update_endpoint_status(subcloud, endpoint_type, sync_status):
            # update a single subcloud
            try:
                self._do_update_subcloud_endpoint_status(
                    context,
                    subcloud.id,
                    endpoint_type,
                    sync_status,
                    alarmable,
                    ignore_endpoints,
                )
            except Exception as e:
                LOG.exception(e)
                raise e
        else:
            msg = (
                f"Ignoring subcloud sync_status update. "
                f"Availability: {subcloud.availability_status}; "
                f"Management:{subcloud.management_state}; "
                f"Endpoint:{endpoint_type}; "
                f"sync_status:{sync_status}"
            )
            cutils.log_subcloud_msg(LOG.info, msg, subcloud.name)

    def _create_fault_out_of_sync(
        self, subcloud_name: str, endpoint: str
    ) -> fm_api.Fault:
        """Creates a fault for an endpoint out-of-sync

        :param subcloud_name: subcloud's name
        :param endpoint: the endpoint that is out-of-sync

        :return: an FM fault object
        :rtype: Fault
        """

        return fm_api.Fault(
            alarm_id=ALARM_OUT_OF_SYNC,
            alarm_state=fm_const.FM_ALARM_STATE_SET,
            entity_type_id=fm_const.FM_ENTITY_TYPE_SUBCLOUD,
            entity_instance_id=f"subcloud={subcloud_name}.resource={endpoint}",
            severity=fm_const.FM_ALARM_SEVERITY_MAJOR,
            reason_text=f"{subcloud_name} {endpoint} sync_status is out-of-sync",
            alarm_type=fm_const.FM_ALARM_TYPE_0,
            probable_cause=fm_const.ALARM_PROBABLE_CAUSE_2,
            proposed_repair_action="If problem persists contact next level of support",
            service_affecting=False,
            keep_existing_alarm=True,
        )

    def _create_fault_offline(self, subcloud_name: str) -> fm_api.Fault:
        """Creates a fault for an offline subcloud

        :param subcloud_name: subcloud's name

        :return: an FM fault object
        :rtype: Fault
        """
        entity_instance_id = f"subcloud={subcloud_name}"
        return fm_api.Fault(
            alarm_id=fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE,
            alarm_state=fm_const.FM_ALARM_STATE_SET,
            entity_type_id=fm_const.FM_ENTITY_TYPE_SUBCLOUD,
            entity_instance_id=entity_instance_id,
            severity=fm_const.FM_ALARM_SEVERITY_CRITICAL,
            reason_text=("%s is offline" % subcloud_name),
            alarm_type=fm_const.FM_ALARM_TYPE_0,
            probable_cause=fm_const.ALARM_PROBABLE_CAUSE_29,
            proposed_repair_action=(
                "Wait for subcloud to become online; if problem persists "
                "contact next level of support."
            ),
            service_affecting=True,
            keep_existing_alarm=True,
        )

    def bulk_update_subcloud_availability_and_endpoint_status(
        self,
        context: context.RequestContext,
        subcloud_id: int,
        subcloud_name: str,
        availability_data: dict,
        endpoint_data: dict[str, str],
    ) -> None:
        """Bulk update subcloud availability and endpoint status

        :param context: request context object
        :param subcloud_id: id of the subcloud to update
        :param subcloud_name: name of the subcloud to update
        :param availability_data: a dict containing the availability status,
        update_state_only and audit_fail_count
        :param endpoint_data: a dict containing the endpoint as key and its sync
        status as value
        """
        # This bulk update is executed as part of the audit process in dcmanager and
        # its related endpoints. This method is not used by dcorch and cert-mon.

        # The subcloud object will always be the same, so we just keep the last one
        unchanged_endpoints = []
        for subcloud, endpoint_status in db_api.subcloud_get_with_status(
            context,
            subcloud_id,
        ):
            if (
                endpoint_data.get(endpoint_status.endpoint_type)
                == endpoint_status.sync_status
            ):
                unchanged_endpoints.append(endpoint_status.endpoint_type)
                del endpoint_data[endpoint_status.endpoint_type]
        if unchanged_endpoints:
            msg = (
                "The following endpoints are already set to updated values, "
                f"not updating: {unchanged_endpoints}"
            )
            cutils.log_subcloud_msg(LOG.debug, msg, subcloud_name)

        if availability_data:
            self.update_subcloud_availability(
                context,
                subcloud.name,
                subcloud.region_name,
                availability_data["availability_status"],
                availability_data["update_state_only"],
                availability_data["audit_fail_count"],
                subcloud,
            )
        if endpoint_data:
            self._bulk_update_subcloud_endpoint_status(context, subcloud, endpoint_data)

    @sync_update_subcloud_endpoint_status
    def _do_bulk_update_subcloud_endpoint_status(
        self,
        context: context.RequestContext,
        subcloud_name: str,
        subcloud_id: int,
        endpoint_data: dict[str, str],
    ) -> None:
        """Updates an online and managed subcloud's endpoints sync status

        :param context: request context object
        :param subcloud_name: name of the subcloud to update
        :param subcloud_id: id of the subcloud to update
        :param endpoint_data: a dict containing the endpoint as key and its sync
        status as value
        """

        # This bulk update is executed as part of the audit process and, because of
        # that, the logic is similar to _do_update_subcloud_endpoint_status but with
        # the difference that only the required endpoints will be update and that'll
        # happen at once.
        status_to_set = [f"{key} ({value})" for key, value in endpoint_data.items()]
        msg = f"Updating endpoints: {', '.join(status_to_set)}"
        cutils.log_subcloud_msg(LOG.info, msg, subcloud_name)

        faults_to_set = []
        faults_to_clear = []

        for endpoint, sync_status in endpoint_data.items():
            if sync_status == dccommon_consts.SYNC_STATUS_OUT_OF_SYNC:
                faults_to_set.append(
                    self._create_fault_out_of_sync(subcloud_name, endpoint)
                )
            elif sync_status == dccommon_consts.SYNC_STATUS_IN_SYNC:
                entity_instance_id = f"subcloud={subcloud_name}.resource={endpoint}"
                faults_to_clear.append((ALARM_OUT_OF_SYNC, entity_instance_id))
        self._raise_and_clear_subcloud_alarms_list(
            subcloud_name, faults_to_set, faults_to_clear
        )

        try:
            db_api.subcloud_status_bulk_update_endpoints(
                context,
                subcloud_id,
                endpoint_data,
            )
        except Exception as e:
            msg = f"An error occured when updating the subcloud endpoint status: {e}"
            cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)

    def _bulk_update_subcloud_endpoint_status(
        self,
        context: context.RequestContext,
        subcloud: models.Subcloud,
        endpoint_data: dict[str, str],
    ) -> None:
        """Update the sync status of a list of subcloud endpoints

        :param context: current context object
        :param subcloud: subcloud object
        :param endpoint_data: a dict containing the endpoint as key and its sync
        status as value
        """

        endpoints_to_update = dict()

        for endpoint_type, sync_status in endpoint_data.items():
            if self._should_update_endpoint_status(
                subcloud, endpoint_type, sync_status
            ):
                endpoints_to_update.update({endpoint_type: sync_status})

        # Update all the necessary endpoints for a single subcloud
        if endpoints_to_update:
            try:
                self._do_bulk_update_subcloud_endpoint_status(
                    context,
                    subcloud.name,
                    subcloud.id,
                    endpoints_to_update,
                )
            except Exception as e:
                LOG.exception(e)
                raise e
        else:
            msg = (
                f"No endpoints to update the status; "
                f"Availability: {subcloud.availability_status}; "
                f"Management: {subcloud.management_state};"
                f"Endpoints: {', '.join(endpoint_data.keys())}"
            )
            cutils.log_subcloud_msg(LOG.info, msg, subcloud.name)

    def update_subcloud_endpoint_status(
        self,
        context: context.RequestContext,
        subcloud_region: str = None,
        endpoint_type: str = None,
        sync_status: str = dccommon_consts.SYNC_STATUS_OUT_OF_SYNC,
        alarmable: bool = True,
        ignore_endpoints: list[str] = None,
    ) -> None:
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
                context,
                subcloud_region,
                endpoint_type,
                sync_status,
                alarmable,
                ignore_endpoints,
            )
        else:
            # update all subclouds
            for subcloud in db_api.subcloud_get_all(context):
                self._update_subcloud_endpoint_status(
                    context,
                    subcloud.region_name,
                    endpoint_type,
                    sync_status,
                    alarmable,
                    ignore_endpoints,
                )

    def _update_subcloud_state(
        self,
        context: context.RequestContext,
        subcloud_name: str,
        subcloud_region: str,
        management_state: str,
        availability_status: str,
    ) -> None:
        try:
            msg = (
                f"Notifying dcorch, management: {management_state}, "
                f"availability:{availability_status}"
            )
            cutils.log_subcloud_msg(LOG.info, msg, subcloud_name)

            self.dcorch_rpc_client.update_subcloud_states(
                context, subcloud_region, management_state, availability_status
            )

        except Exception:
            msg = "Problem informing dcorch of subcloud state change"
            cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)

    def _raise_and_clear_subcloud_alarms_list(
        self,
        subcloud_name: str,
        faults_to_raise: list[fm_api.Fault] = None,
        faults_to_clear: list[tuple[str, str]] = None,
    ) -> None:
        """Raise/clear a list of subcloud alarms

        :param faults_to_raise: list of faults to raise
        :param faults_to_clear: list of faults to clear
        """
        if faults_to_clear:
            try:
                self.fm_api.clear_faults_list(faults_to_clear)
            except Exception as e:
                msg = "Failed to clear alarms from list"
                cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
                raise e

        if faults_to_raise:
            try:
                self.fm_api.set_faults(faults_to_raise)
            except Exception as e:
                msg = "Failed to raise alarms from list"
                cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
                raise e

    def _raise_or_clear_subcloud_status_alarm(
        self, subcloud_name: str, availability_status: str, deploy_status: str = None
    ) -> None:
        entity_instance_id = f"subcloud={subcloud_name}"

        if availability_status == dccommon_consts.AVAILABILITY_ONLINE:
            try:
                self.fm_api.clear_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_OFFLINE, entity_instance_id
                )
            except Exception as e:
                msg = "Failed to clear offline alarm"
                cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
                raise e

        elif (
            availability_status == dccommon_consts.AVAILABILITY_OFFLINE
            and deploy_status != consts.DEPLOY_STATE_SECONDARY
        ):
            try:
                fault = self._create_fault_offline(subcloud_name)
                self.fm_api.set_fault(fault)
            except Exception as e:
                msg = "Failed to raise offline alarm"
                cutils.log_subcloud_msg(LOG.info, msg, subcloud_name)
                raise e

    def update_subcloud_availability(
        self,
        context: context.RequestContext,
        subcloud_name: str,
        subcloud_region: str,
        availability_status: str,
        update_state_only: bool = False,
        audit_fail_count: int = None,
        subcloud: models.Subcloud = None,
    ) -> None:
        if subcloud is None:
            try:
                subcloud = db_api.subcloud_get_by_region_name(context, subcloud_region)
            except Exception:
                msg = f"Failed to get subcloud by region name: {subcloud_region}"
                cutils.log_subcloud_msg(LOG.exception, msg, subcloud_name)
                raise

        if update_state_only:
            msg = "Received update_state_only request"
            cutils.log_subcloud_msg(LOG.info, msg, subcloud_name)
            # Ensure that the status alarm is consistent with the
            # subcloud's availability. This is required to compensate
            # for rare alarm update failures, which may occur during
            # availability updates.
            self._raise_or_clear_subcloud_status_alarm(
                subcloud.name, availability_status
            )

            # Nothing has changed, but we want to send a state update for this
            # subcloud as an audit. Get the most up-to-date data.
            self._update_subcloud_state(
                context,
                subcloud.name,
                subcloud.region_name,
                subcloud.management_state,
                availability_status,
            )
        elif availability_status is None:
            # only update the audit fail count
            try:
                db_api.subcloud_update(
                    self.context, subcloud.id, audit_fail_count=audit_fail_count
                )
            except exceptions.SubcloudNotFound:
                # slim possibility subcloud could have been deleted since
                # we found it in db, ignore this benign error.
                msg = (
                    "Ignoring SubcloudNotFound when attempting audit_fail_count update"
                )
                cutils.log_subcloud_msg(LOG.info, msg, subcloud_name)
                return
        else:
            if availability_status == subcloud.availability_status:
                msg = (
                    "Availability status hasn't changed from "
                    f"{availability_status}, not updating"
                )
                cutils.log_subcloud_msg(LOG.info, msg, subcloud_name)
                return
            self._raise_or_clear_subcloud_status_alarm(
                subcloud.name, availability_status
            )

            if availability_status == dccommon_consts.AVAILABILITY_OFFLINE:
                # Subcloud is going offline, set all endpoint statuses to
                # unknown.
                endpoint_data = dict()

                for endpoint in dccommon_consts.AUDIT_TYPES_LIST:
                    endpoint_data[endpoint] = dccommon_consts.SYNC_STATUS_UNKNOWN

                self._bulk_update_subcloud_endpoint_status(
                    context, subcloud, endpoint_data
                )

            try:
                updated_subcloud = db_api.subcloud_update(
                    context,
                    subcloud.id,
                    availability_status=availability_status,
                    audit_fail_count=audit_fail_count,
                )
            except exceptions.SubcloudNotFound:
                # slim possibility subcloud could have been deleted since
                # we found it in db, ignore this benign error.
                msg = "Ignoring SubcloudNotFound when attempting state update"
                cutils.log_subcloud_msg(LOG.info, msg, subcloud_name)
                return

            if availability_status == dccommon_consts.AVAILABILITY_ONLINE:
                # Subcloud is going online
                # Tell cert-mon to audit endpoint certificate.
                msg = "Request for online audit"
                cutils.log_subcloud_msg(LOG.info, msg, subcloud_name)
                dc_notification = rpc_client.DCManagerNotifications()
                dc_notification.subcloud_online(context, subcloud.region_name)
                # Trigger all the audits for the subcloud so it can update the
                # sync status ASAP.
                self.audit_rpc_client.trigger_subcloud_audits(context, subcloud.id)

            # Send dcorch a state update
            self._update_subcloud_state(
                context,
                subcloud.name,
                subcloud.region_name,
                updated_subcloud.management_state,
                availability_status,
            )
