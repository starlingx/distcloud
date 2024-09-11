#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import eventlet
from oslo_log import log as logging

from dccommon import consts as dccommon_consts
from dcorch.common import consts as dco_consts
from dcorch.common import context
from dcorch.common import exceptions
from dcorch.db import api as db_api
from dcorch.engine import scheduler
from dcorch.engine.sync_services.identity import IdentitySyncThread
from dcorch.engine.sync_services.sysinv import SysinvSyncThread
from dcorch.engine.sync_thread import SyncThread
from dcorch.objects import subcloud

LOG = logging.getLogger(__name__)

SYNC_TIMEOUT = 600  # Timeout for subcloud sync

# sync object endpoint type and subclass mappings
sync_object_class_map = {
    dccommon_consts.ENDPOINT_TYPE_PLATFORM: SysinvSyncThread,
    dccommon_consts.ENDPOINT_TYPE_IDENTITY: IdentitySyncThread,
    dccommon_consts.ENDPOINT_TYPE_IDENTITY_OS: IdentitySyncThread,
}


class GenericSyncWorkerManager(object):
    """Manages tasks related to resource management."""

    def __init__(self, engine_id, *args, **kwargs):
        self.context = context.get_admin_context()
        self.engine_id = engine_id
        # Keeps track of greenthreads we create to do the sync work.
        self.sync_thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=100
        )
        # Keeps track of greenthreads we create to do the audit work.
        self.audit_thread_group_manager = scheduler.ThreadGroupManager(
            thread_pool_size=100
        )

    def create_sync_objects(
        self, subcloud_name, capabilities, management_ip, software_version
    ):
        """Create sync object objects for the subcloud

        The objects handle the syncing of the subcloud's endpoint_types
        """
        sync_objs = {}
        endpoint_type_list = capabilities.get("endpoint_types", None)
        if endpoint_type_list:
            for endpoint_type in endpoint_type_list:
                LOG.debug(
                    f"Engine id:({self.engine_id}) create "
                    f"{subcloud_name}/{endpoint_type}/"
                    f"{management_ip}/{software_version} "
                    f"sync obj"
                )
                sync_obj = sync_object_class_map[endpoint_type](
                    subcloud_name, endpoint_type, management_ip, software_version
                )
                sync_objs[endpoint_type] = sync_obj
        return sync_objs

    def sync_subclouds(self, context, subcloud_sync_list):
        LOG.info(
            f"Engine id:({self.engine_id}) Start to sync "
            f"{len(subcloud_sync_list)} (subcloud, endpoint_type) pairs."
        )
        LOG.debug(f"Engine id:({self.engine_id}) Start to sync {subcloud_sync_list}.")

        for sc_region_name, ept, ip, software_version in subcloud_sync_list:
            try:
                self.sync_thread_group_manager.start(
                    self._sync_subcloud,
                    self.context,
                    sc_region_name,
                    ept,
                    ip,
                    software_version,
                )
            except exceptions.SubcloudSyncNotFound:
                # The endpoint in subcloud_sync has been removed
                LOG.debug(
                    f"Engine id:({self.engine_id}/{sc_region_name}/{ept}) "
                    f"SubcloudSyncNotFound: The endpoint in subcloud_sync "
                    f"has been removed"
                )
            except Exception as e:
                LOG.error(
                    f"Exception occurred when running sync {ept} for "
                    f"subcloud {sc_region_name}: {e}"
                )
                db_api.subcloud_sync_update(
                    self.context,
                    sc_region_name,
                    ept,
                    values={"sync_request": dco_consts.SYNC_STATUS_FAILED},
                )

    def _sync_subcloud(
        self, context, subcloud_name, endpoint_type, management_ip, software_version
    ):
        LOG.info(f"Start to sync subcloud {subcloud_name}/{endpoint_type}.")
        sync_obj = sync_object_class_map[endpoint_type](
            subcloud_name, endpoint_type, management_ip, software_version
        )
        new_state = dco_consts.SYNC_STATUS_COMPLETED
        timeout = eventlet.timeout.Timeout(SYNC_TIMEOUT)
        try:
            sync_obj.sync(self.engine_id)
        except eventlet.timeout.Timeout as t:
            if t is not timeout:
                raise  # not my timeout
            LOG.exception(f"Sync timed out for {subcloud_name}/{endpoint_type}.")
            new_state = dco_consts.SYNC_STATUS_FAILED
        except exceptions.ResourceOutOfSync:
            new_state = dco_consts.SYNC_STATUS_FAILED
        except Exception as e:
            LOG.exception(f"Sync failed for {subcloud_name}/{endpoint_type}: {e}")
            new_state = dco_consts.SYNC_STATUS_FAILED
        finally:
            timeout.cancel()

        db_api.subcloud_sync_update(
            context, subcloud_name, endpoint_type, values={"sync_request": new_state}
        )
        LOG.info(f"End of sync_subcloud {subcloud_name}.")

    def add_subcloud(self, context, name, version, management_ip):
        # create subcloud in DB and create the sync objects
        LOG.info(f"adding subcloud {name}")
        endpoint_type_list = dco_consts.SYNC_ENDPOINT_TYPES_LIST[:]
        capabilities = {"endpoint_types": endpoint_type_list}

        sc = subcloud.Subcloud(
            context,
            region_name=name,
            software_version=version,
            capabilities=capabilities,
            management_ip=management_ip,
        )
        sc = sc.create()
        for endpoint_type in endpoint_type_list:
            db_api.subcloud_sync_create(
                context,
                name,
                endpoint_type,
                # pylint: disable-next=no-member
                values={"subcloud_id": sc.id},
            )
        # Create the sync object for this engine
        self.create_sync_objects(name, capabilities, management_ip, version)

    def del_subcloud(self, context, subcloud_name):
        # first update the state of the subcloud
        self.update_subcloud_state(
            context,
            subcloud_name,
            management_state=dccommon_consts.MANAGEMENT_UNMANAGED,
            availability_status=dccommon_consts.AVAILABILITY_OFFLINE,
        )
        try:
            # delete this subcloud
            subcloud.Subcloud.delete_subcloud_by_name(context, subcloud_name)
        except Exception:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def subcloud_state_matches(
        self,
        subcloud_name,
        management_state=None,
        availability_status=None,
        initial_sync_state=None,
    ):
        # compare subcloud states
        match = True
        sc = subcloud.Subcloud.get_by_name(self.context, subcloud_name)
        if management_state is not None and sc.management_state != management_state:
            match = False
        if (
            match
            and availability_status is not None
            and sc.availability_status != availability_status
        ):
            match = False
        if (
            match
            and initial_sync_state is not None
            and sc.initial_sync_state != initial_sync_state
        ):
            match = False
        return match

    def update_subcloud_state(
        self,
        context,
        subcloud_name,
        management_state=None,
        availability_status=None,
        initial_sync_state=None,
        subsequent_sync=None,
    ):
        LOG.info(
            f"updating state for subcloud {subcloud_name} - "
            f"management_state: {management_state} "
            f"availability_status: {availability_status} "
            f"initial_sync_state: {initial_sync_state} "
            f"subsequent_sync: {subsequent_sync}"
        )
        sc = subcloud.Subcloud.get_by_name(context, subcloud_name)
        if management_state is not None:
            sc.management_state = management_state
        if availability_status is not None:
            sc.availability_status = availability_status
        if initial_sync_state is not None:
            sc.initial_sync_state = initial_sync_state
        if subsequent_sync is not None:
            sc.subsequent_sync = subsequent_sync
        sc.save()

    def is_subcloud_managed(self, subcloud_name):
        # is this subcloud managed
        sc = subcloud.Subcloud.get_by_name(self.context, subcloud_name)
        return sc.management_state == dccommon_consts.MANAGEMENT_MANAGED

    def is_subcloud_enabled(self, subcloud_name):
        # is this subcloud enabled
        sc = subcloud.Subcloud.get_by_name(self.context, subcloud_name)
        # We only enable syncing if the subcloud is online and the initial
        # sync has completed.
        return (
            sc.availability_status == dccommon_consts.AVAILABILITY_ONLINE
            and sc.initial_sync_state == dco_consts.INITIAL_SYNC_STATE_COMPLETED
        )

    def is_subcloud_ready(self, subcloud_name):
        # is this subcloud ready for synchronization
        return self.is_subcloud_managed(subcloud_name) and self.is_subcloud_enabled(
            subcloud_name
        )

    def add_subcloud_sync_endpoint_type(
        self, context, subcloud_name, endpoint_type_list=None
    ):

        # TODO(jkung): This method is currently only required by
        # stx-openstack and is to be integrated with stx-openstack when
        # that feature is enabled.

        LOG.info(
            f"add_subcloud_sync_endpoint_type subcloud_name={subcloud_name} "
            f"endpoint_type_list={endpoint_type_list}"
        )

        if endpoint_type_list is None:
            return

        sc = subcloud.Subcloud.get_by_name(context, subcloud_name)
        capabilities = sc.capabilities
        c_endpoint_type_list = capabilities.get("endpoint_types", [])

        # Update the DB first
        for endpoint_type in endpoint_type_list:
            if endpoint_type not in c_endpoint_type_list:
                c_endpoint_type_list.append(endpoint_type)
        if capabilities.get("endpoint_types") is None:
            # assign back if 'endpoint_types' is not in capabilities
            capabilities["endpoint_types"] = c_endpoint_type_list
        sc.capabilities = capabilities
        sc.save()

        # Create objects for the endpoint types
        for endpoint_type in endpoint_type_list:
            # Check whether sync endpoint already exists
            try:
                subcloud_sync = db_api.subcloud_sync_get(
                    context, subcloud_name, endpoint_type
                )

                if subcloud_sync:
                    LOG.info(
                        f"subcloud_sync subcloud={subcloud_name} "
                        f"endpoint_type={endpoint_type} already exists"
                    )
                    continue
            except exceptions.SubcloudSyncNotFound:
                pass

            sync_obj = sync_object_class_map[endpoint_type](
                subcloud_name, endpoint_type, sc.management_ip, sc.software_version
            )

            # create the subcloud_sync !!!
            db_api.subcloud_sync_create(
                context,
                subcloud_name,
                endpoint_type,
                values={"subcloud_id": sc.id},  # pylint: disable=E1101
            )

            if self.is_subcloud_ready(subcloud_name):
                sync_obj.enable()
                sync_obj.initial_sync()

    def remove_subcloud_sync_endpoint_type(
        self, context, subcloud_name, endpoint_type_list=None
    ):

        # TODO(jkung): This method is currently only required by
        # stx-openstack and is to be integrated with stx-openstack when
        # that feature is enabled and remove action performed.
        # The subcloud_sync delete can be more graceful by ensuring the
        # sync object is updated for each engine on delete.

        LOG.info(
            f"remove_subcloud_sync_endpoint_type "
            f"subcloud_name={subcloud_name} "
            f"endpoint_type_list={endpoint_type_list}"
        )

        # Remove sync_objs and subcloud_sync for endpoint types to be removed
        if endpoint_type_list:
            for endpoint_type in endpoint_type_list:
                try:
                    db_api.subcloud_sync_delete(context, subcloud_name, endpoint_type)
                except exceptions.SubcloudSyncNotFound:
                    pass

        # remove the endpoint types from subcloud capabilities
        sc = subcloud.Subcloud.get_by_name(context, subcloud_name)
        c_endpoint_type_list = sc.capabilities.get("endpoint_types", [])

        if endpoint_type_list and c_endpoint_type_list:
            for endpoint_type in endpoint_type_list:
                if endpoint_type in c_endpoint_type_list:
                    c_endpoint_type_list.remove(endpoint_type)
            sc.save()

    def update_subcloud_version(self, context, subcloud_name, sw_version):
        try:
            sc = subcloud.Subcloud.get_by_name(context, subcloud_name)
            sc.software_version = sw_version
            sc.save()
        except KeyError:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def update_subcloud_management_ip(self, context, subcloud_name, management_ip):
        try:
            sc = subcloud.Subcloud.get_by_name(context, subcloud_name)
            sc.management_ip = management_ip
            sc.save()
        except KeyError:
            raise exceptions.SubcloudNotFound(region_name=subcloud_name)

    def _audit_subcloud(self, context, subcloud_name, endpoint_type, sync_obj):
        new_state = dco_consts.AUDIT_STATUS_COMPLETED
        timeout = eventlet.timeout.Timeout(SYNC_TIMEOUT)
        try:
            sync_obj.run_sync_audit(self.engine_id)
        except eventlet.timeout.Timeout as t:
            if t is not timeout:
                raise  # not my timeout
            new_state = dco_consts.AUDIT_STATUS_FAILED
            LOG.exception(f"Audit timed out for {subcloud_name}/{endpoint_type}.")
        except Exception as e:
            LOG.exception(f"Audit failed for {subcloud_name}/{endpoint_type}: {e}")
            new_state = dco_consts.AUDIT_STATUS_FAILED
        finally:
            timeout.cancel()

        db_api.subcloud_sync_update(
            context, subcloud_name, endpoint_type, values={"audit_status": new_state}
        )

    def run_sync_audit(self, context, subcloud_sync_list):
        # Clear the master resource cache
        SyncThread.reset_master_resources_cache()

        LOG.info(
            f"Engine id:({self.engine_id}) Start to audit "
            f"{len(subcloud_sync_list)} (subcloud, endpoint_type) pairs."
        )
        LOG.debug(f"Engine id:({self.engine_id}) Start to audit {subcloud_sync_list}.")

        for sc_region_name, ept, ip, software_version in subcloud_sync_list:
            LOG.debug(
                f"Attempt audit_subcloud: {self.engine_id}/{sc_region_name}/{ept}"
            )
            try:
                sync_obj = sync_object_class_map[ept](
                    sc_region_name, ept, ip, software_version
                )
                self.audit_thread_group_manager.start(
                    self._audit_subcloud, self.context, sc_region_name, ept, sync_obj
                )
            except exceptions.SubcloudSyncNotFound:
                # The endpoint in subcloud_sync has been removed
                LOG.debug(
                    f"Engine id:({self.engine_id}/{sc_region_name}/{ept}) "
                    f"SubcloudSyncNotFound: The endpoint in subcloud_sync "
                    "has been removed"
                )
            except Exception as e:
                LOG.error(
                    f"Exception occurred when running audit {ept} for "
                    f"subcloud {sc_region_name}: {e}"
                )
                db_api.subcloud_sync_update(
                    self.context,
                    sc_region_name,
                    ept,
                    values={"audit_status": dco_consts.AUDIT_STATUS_FAILED},
                )

    def sync_request(self, ctxt, endpoint_type):
        # Someone has enqueued a sync job. set the endpoint sync_request to
        # requested
        db_api.subcloud_sync_update_all_except_in_progress(
            ctxt,
            dccommon_consts.MANAGEMENT_MANAGED,
            endpoint_type,
            values={"sync_request": dco_consts.SYNC_STATUS_REQUESTED},
        )
        LOG.debug(
            f"Updated all managed subclouds ({endpoint_type}) sync status to "
            f"requested except those in_progress."
        )
