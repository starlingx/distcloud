#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import threading

from oslo_config import cfg
from oslo_log import log as logging


from fm_api import constants as fm_const
from fm_api import fm_api

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.manager.system_peer_manager import SystemPeerManager


CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class PeerGroupAuditManager(manager.Manager):
    """Manages audit related tasks."""

    def __init__(self, subcloud_manager, peer_group_id, *args, **kwargs):
        LOG.debug(_('PeerGroupAuditManager initialization...'))
        super().__init__(service_name="peer_group_audit_manager",
                         *args, **kwargs)
        self.context = context.get_admin_context()
        self.fm_api = fm_api.FaultAPIs()
        self.subcloud_manager = subcloud_manager
        self.peer_group_id = peer_group_id
        self.require_audit_flag = True
        self.thread = None
        self.thread_lock = threading.Lock()

    def _get_subclouds_by_peer_group_from_system_peer(self,
                                                      system_peer,
                                                      peer_group_name):
        try:
            dc_client = SystemPeerManager.get_peer_dc_client(system_peer)
            subclouds = dc_client.get_subcloud_list_by_peer_group(
                peer_group_name)
            return subclouds
        except Exception:
            LOG.exception(f"Failed to get subclouds of peer group "
                          f"{peer_group_name} from DC: "
                          f"{system_peer.peer_name}")

    def _update_remote_peer_group_migration_status(self,
                                                   system_peer,
                                                   peer_group_name,
                                                   migration_status):
        dc_client = SystemPeerManager.get_peer_dc_client(system_peer)
        peer_group_kwargs = {
            'migration_status': migration_status
        }
        dc_client.update_subcloud_peer_group(peer_group_name,
                                             **peer_group_kwargs)
        LOG.info(f"Updated Subcloud Peer Group {peer_group_name} on "
                 f"peer site {system_peer.peer_name}, set migration_status "
                 f"to: {migration_status}")

    def _get_local_subclouds_to_update_and_delete(self,
                                                  local_peer_group,
                                                  remote_subclouds):
        local_subclouds_to_update = list()
        local_subclouds_to_delete = list()
        remote_subclouds_dict = {remote_subcloud.get('region-name'):
                                 remote_subcloud for remote_subcloud
                                 in remote_subclouds}
        local_subclouds = db_api.subcloud_get_for_peer_group(
            self.context, local_peer_group.id)

        for local_subcloud in local_subclouds:
            remote_subcloud = remote_subclouds_dict.get(
                local_subcloud.region_name)
            if remote_subcloud:
                # Check if the remote subcloud meets the conditions for update
                # if it is 'managed' and the local subcloud is not
                # in 'secondary' status
                if (remote_subcloud.get('management-state') ==
                    dccommon_consts.MANAGEMENT_MANAGED and
                    not utils.subcloud_is_secondary_state(
                        local_subcloud.deploy_status)):
                    local_subclouds_to_update.append(local_subcloud)
            else:
                local_subclouds_to_delete.append(local_subcloud)

        return local_subclouds_to_update, local_subclouds_to_delete

    def _set_local_subcloud_to_secondary(self, subcloud):
        try:
            LOG.info("Set local subcloud %s to secondary" % subcloud.name)
            # There will be an exception when unmanage
            # a subcloud in 'unamaged' state.
            if subcloud.management_state != \
                    dccommon_consts.MANAGEMENT_UNMANAGED:
                self.subcloud_manager.update_subcloud(
                    self.context,
                    subcloud.id,
                    management_state=dccommon_consts.
                    MANAGEMENT_UNMANAGED)
            self.subcloud_manager.update_subcloud(
                self.context,
                subcloud.id,
                deploy_status=consts.DEPLOY_STATE_SECONDARY)
        except Exception as e:
            LOG.exception(f"Failed to update local non-secondary "
                          f"and offline subcloud [{subcloud.name}], err: {e}")
            raise e

    def audit(self, system_peer, remote_peer_group, local_peer_group):
        if local_peer_group.migration_status == consts.PEER_GROUP_MIGRATING:
            LOG.info("Local peer group in migrating state, quit audit")
            return

        LOG.info("Auditing remote subcloud peer group:[%s] "
                 "migration_status:[%s] group_priority[%s], "
                 "local subcloud peer group:[%s] "
                 "migration_status:[%s] group_priority[%s]" %
                 (remote_peer_group.get("peer_group_name"),
                  remote_peer_group.get("migration_status"),
                  remote_peer_group.get("group_priority"),
                  local_peer_group.peer_group_name,
                  local_peer_group.migration_status,
                  local_peer_group.group_priority))

        # if remote subcloud peer group's migration_status is 'migrating',
        # 'unmanaged' all local subclouds in local peer group and change its
        # deploy status to consts.DEPLOY_STATE_REHOME_PENDING to stop cert-mon
        # audits.
        if remote_peer_group.get("migration_status") == \
                consts.PEER_GROUP_MIGRATING:
            # Unmanaged all local subclouds of peer group
            LOG.info(f"Unmanaged all local subclouds of peer group "
                     f"{local_peer_group.peer_group_name} "
                     f"since remote is in migrating state")
            subclouds = db_api.subcloud_get_for_peer_group(self.context,
                                                           local_peer_group.id)
            for subcloud in subclouds:
                try:
                    # update_subcloud raises an exception when trying to umanage
                    # an already unmanaged subcloud, so the deploy status
                    # update must be done separately
                    if subcloud.management_state != \
                            dccommon_consts.MANAGEMENT_UNMANAGED:
                        # Unmanage and update the deploy-status
                        LOG.info("Unmanaging and setting the local subcloud "
                                 f"{subcloud.name} deploy status to "
                                 f"{consts.DEPLOY_STATE_REHOME_PENDING}")
                        self.subcloud_manager.update_subcloud(
                            self.context,
                            subcloud.id,
                            management_state=dccommon_consts.
                            MANAGEMENT_UNMANAGED,
                            deploy_status=consts.DEPLOY_STATE_REHOME_PENDING)
                    else:
                        # Already unmanaged, just update the deploy-status
                        LOG.info(f"Setting the local subcloud {subcloud.name} "
                                 "deploy status to "
                                 f"{consts.DEPLOY_STATE_REHOME_PENDING}")
                        self.subcloud_manager.update_subcloud(
                            self.context,
                            subcloud.id,
                            deploy_status=consts.DEPLOY_STATE_REHOME_PENDING)
                except Exception as e:
                    LOG.exception(f"Fail to unmanage local subcloud "
                                  f"{subcloud.name}, err: {e}")
                    raise e
            SystemPeerManager.update_sync_status_on_peer_site(
                self.context, system_peer,
                consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
                local_peer_group, remote_peer_group)
            self.require_audit_flag = False

        # if remote subcloud peer group's migration_status is 'complete',
        # get remote subclouds. For 'managed+online' subclouds,
        # set 'unmanaged+secondary' to local on same subclouds
        elif remote_peer_group.get("migration_status") == \
                consts.PEER_GROUP_MIGRATION_COMPLETE:
            remote_subclouds = \
                self._get_subclouds_by_peer_group_from_system_peer(
                    system_peer,
                    remote_peer_group.get("peer_group_name"))

            local_subclouds_to_update, local_subclouds_to_delete = \
                self._get_local_subclouds_to_update_and_delete(
                    local_peer_group, remote_subclouds)

            for subcloud in local_subclouds_to_update:
                self._set_local_subcloud_to_secondary(subcloud)

            # Change the local subcloud not exist on peer site's SPG to
            # secondary status then delete it
            for subcloud in local_subclouds_to_delete:
                self._set_local_subcloud_to_secondary(subcloud)
                try:
                    self.subcloud_manager.delete_subcloud(
                        self.context, subcloud.id)
                    LOG.info(f"Deleted local subcloud {subcloud.name}")
                except Exception as e:
                    SystemPeerManager.update_sync_status_on_peer_site(
                        self.context, system_peer,
                        consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
                        local_peer_group, remote_peer_group)
                    LOG.exception(f"Failed to delete local subcloud "
                                  f"[{subcloud.name}] that does not exist "
                                  f"under the same subcloud_peer_group on "
                                  f"peer site, err: {e}")
                    raise e

            if local_subclouds_to_update or local_subclouds_to_delete:
                self._clear_or_raise_alarm(system_peer,
                                           local_peer_group,
                                           remote_peer_group)
                db_api.subcloud_peer_group_update(
                    self.context,
                    local_peer_group.id,
                    system_leader_id=system_peer.peer_uuid,
                    system_leader_name=system_peer.peer_name)

            self._update_remote_peer_group_migration_status(
                system_peer,
                remote_peer_group.get("peer_group_name"),
                None)
            SystemPeerManager.update_sync_status_on_peer_site(
                self.context, system_peer,
                consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                local_peer_group, remote_peer_group)
            self.require_audit_flag = False
        else:
            # If remote peer group migration_status is 'None'
            self.require_audit_flag = False

    def _clear_or_raise_alarm(self,
                              system_peer,
                              local_peer_group,
                              remote_peer_group):
        # If local subcloud peer group's group_priority is
        # lower than remote subcloud peer group's group_priority,
        # an alarm will be raised.
        # lower number means higher priority
        entity_instance_id = "peer_group=%s,peer=%s" % \
            (local_peer_group.peer_group_name, system_peer.peer_uuid)
        if local_peer_group.group_priority < remote_peer_group.get('group_priority'):
            LOG.warning("Alarm: local subcloud peer group ["
                        f"{local_peer_group.peer_group_name}] "
                        f"is managed by remote system ["
                        f"{system_peer.peer_name}]")
            try:
                fault = fm_api.Fault(
                    alarm_id=fm_const.
                    FM_ALARM_ID_DC_SUBCLOUD_PEER_GROUP_NOT_MANAGED,
                    alarm_state=fm_const.FM_ALARM_STATE_SET,
                    entity_type_id=fm_const.
                    FM_ENTITY_TYPE_SUBCLOUD_PEER_GROUP,
                    entity_instance_id=entity_instance_id,
                    severity=fm_const.FM_ALARM_SEVERITY_MAJOR,
                    reason_text=("Subcloud peer group "
                                 "(peer_group_name=%s) "
                                 "is managed by remote "
                                 "system (peer_uuid=%s) "
                                 "with a lower priority." %
                                 (local_peer_group.peer_group_name,
                                  system_peer.peer_uuid)),
                    alarm_type=fm_const.FM_ALARM_TYPE_0,
                    probable_cause=fm_const.
                    ALARM_PROBABLE_CAUSE_UNKNOWN,
                    proposed_repair_action="Check the reported peer group "
                    "state. Migrate it back to the current system if the "
                    "state is 'rehomed' and the current system is stable. "
                    "Otherwise, wait until these conditions are met.",
                    service_affecting=False)
                self.fm_api.set_fault(fault)
            except Exception as e:
                LOG.exception(e)
        else:
            try:
                fault = self.fm_api.get_fault(
                    fm_const.FM_ALARM_ID_DC_SUBCLOUD_PEER_GROUP_NOT_MANAGED,
                    entity_instance_id)
                if fault:
                    LOG.info(f"Clear alarm: {entity_instance_id}")
                    self.fm_api.clear_fault(
                        fm_const.FM_ALARM_ID_DC_SUBCLOUD_PEER_GROUP_NOT_MANAGED,
                        entity_instance_id)
            except Exception:
                LOG.exception(
                    f"Problem clearing fault [{entity_instance_id}], "
                    f"alarm_id="
                    f"{fm_const.FM_ALARM_ID_DC_SUBCLOUD_PEER_GROUP_NOT_MANAGED}")

    def _do_audit(self, system_peer, remote_peer_group, local_peer_group):
        with self.thread_lock:
            try:
                self.audit(system_peer, remote_peer_group, local_peer_group)
            except Exception as e:
                LOG.exception("audit error occured: %s" % e)

    def stop(self):
        if self.thread:
            self.thread.join()
            LOG.info(f"stopped peer group {self.peer_group_id} audit thread")
        else:
            LOG.info(f"No peer group {self.peer_group_id} audit thread to stop")

    def start(self, system_peer, remote_peer_group, local_peer_group):
        if self.thread_lock.locked():
            LOG.warning(f"Audit thread for {local_peer_group.peer_group_name} "
                        f"has already started")
        else:
            self.thread = threading.Thread(
                target=self._do_audit,
                args=(system_peer, remote_peer_group, local_peer_group))
            self.thread.start()

    def audit_peer_group_from_system(self,
                                     system_peer,
                                     remote_peer_group,
                                     local_peer_group):
        LOG.info(f"Audit peer group [{local_peer_group.peer_group_name}] "
                 f"with remote system {system_peer.peer_name}")
        self.start(system_peer, remote_peer_group, local_peer_group)

    @staticmethod
    def send_audit_peer_group(system_peers, peer_group):
        if not system_peers:
            return
        local_system = utils.get_local_system()
        for system in system_peers:
            try:
                dc_client = SystemPeerManager.get_peer_dc_client(system)
                payload = db_api.subcloud_peer_group_db_model_to_dict(
                    peer_group)
                if 'created-at' in payload:
                    del payload['created-at']
                if 'updated-at' in payload:
                    del payload['updated-at']
                payload['peer_uuid'] = local_system.uuid
                LOG.info("Send audit payload [%s] of peer group %s" %
                         (payload, peer_group.peer_group_name))
                response = dc_client.audit_subcloud_peer_group(
                    peer_group.peer_group_name,
                    **payload)
                if response:
                    return response
            except Exception:
                LOG.exception("Failed to send audit request for peer group "
                              f"{peer_group.peer_group_name} to DC: "
                              f"{system.peer_name}")
