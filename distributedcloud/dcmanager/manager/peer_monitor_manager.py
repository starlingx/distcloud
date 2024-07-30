#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from collections import defaultdict
import threading

from fm_api import constants as fm_const
from fm_api import fm_api
from oslo_config import cfg
from oslo_log import log as logging

from dcmanager.common import consts
from dcmanager.common import context
from dcmanager.common import manager
from dcmanager.db import api as db_api
from dcmanager.manager import peer_group_audit_manager as pgam
from dcmanager.manager.system_peer_manager import SystemPeerManager

CONF = cfg.CONF
LOG = logging.getLogger(__name__)


class PeerMonitor(object):
    def __init__(self, peer, context, subcloud_manager):
        self.peer = peer
        self.thread = None
        self.exit_flag = threading.Event()
        self.fm_api = fm_api.FaultAPIs()
        self.context = context
        self.subcloud_manager = subcloud_manager
        self.peer_group_id_set = set()
        # key: peer_group_id
        # value: PeerGroupAuditManager object
        self.peer_group_audit_obj_map = dict()

    def _clear_failure(self):
        alarm_id = fm_const.FM_ALARM_ID_DC_SYSTEM_PEER_HEARTBEAT_FAILED
        entity_instance_id = "peer=%s" % self.peer.peer_uuid
        try:
            fault = self.fm_api.get_fault(alarm_id, entity_instance_id)
            if fault:
                self.fm_api.clear_fault(alarm_id, entity_instance_id)
        except Exception as e:
            LOG.exception(
                "Problem clearing fault for peer %s, alarm_id=%s error: %s"
                % (self.peer.peer_uuid, alarm_id, e)
            )

    def _raise_failure(self):
        alarm_id = fm_const.FM_ALARM_ID_DC_SYSTEM_PEER_HEARTBEAT_FAILED
        entity_instance_id = "peer=%s" % self.peer.peer_uuid
        reason_text = "Peer %s (peer_uuid=%s) connections in disconnected state." % (
            self.peer.peer_name,
            self.peer.peer_uuid,
        )
        severity = fm_const.FM_ALARM_SEVERITY_MAJOR

        peer_groups = db_api.subcloud_peer_group_get_by_leader_id(
            self.context, self.peer.peer_uuid
        )
        if len(peer_groups) > 0:
            peer_group_names = [
                peer_group.peer_group_name for peer_group in peer_groups
            ]
            reason_text = (
                "Peer %s (peer_uuid=%s) is in disconnected state. The following "
                "subcloud peer groups are impacted: %s."
                % (
                    self.peer.peer_name,
                    self.peer.peer_uuid,
                    ", ".join(peer_group_names),
                )
            )
            severity = fm_const.FM_ALARM_SEVERITY_CRITICAL

        try:
            fault = fm_api.Fault(
                alarm_id=alarm_id,
                alarm_state=fm_const.FM_ALARM_STATE_SET,
                entity_type_id=fm_const.FM_ENTITY_TYPE_SYSTEM_PEER,
                entity_instance_id=entity_instance_id,
                severity=severity,
                reason_text=reason_text,
                alarm_type=fm_const.FM_ALARM_TYPE_1,
                probable_cause=fm_const.ALARM_PROBABLE_CAUSE_UNKNOWN,
                proposed_repair_action=(
                    "Check the connectivity between the current system and the "
                    "reported peer site. If the peer system is down, migrate the "
                    "affected peer group(s) to the current system for continued "
                    "subcloud management."
                ),
                service_affecting=False,
            )

            self.fm_api.set_fault(fault)

        except Exception as e:
            LOG.exception(
                "Problem setting fault for peer %s, alarm_id=%s, error: %s"
                % (self.peer.peer_uuid, alarm_id, e)
            )

    def _heartbeat_check_via_get_peer_group_list(self):
        """Checking the heartbeat of system peer."""
        failed = True
        dc_peer_subcloud_peer_group_list = list()
        try:
            dc_client = SystemPeerManager.get_peer_dc_client(self.peer)
            dc_peer_subcloud_peer_group_list = dc_client.get_subcloud_peer_group_list()
            failed = False

            if not dc_peer_subcloud_peer_group_list:
                LOG.warning(
                    "Resource subcloud peer group of dc:%s not found"
                    % self.peer.manager_endpoint
                )

        except Exception:
            LOG.exception("Failed to access the dc: %s" % self.peer.peer_name)
        return failed, dc_peer_subcloud_peer_group_list

    def _update_sync_status_secondary_site_becomes_unreachable(self):
        # Get associations by system peer
        associations = SystemPeerManager.get_local_associations(self.context, self.peer)
        for association in associations:
            # If the association is not primary, skip it.
            if association.association_type == consts.ASSOCIATION_TYPE_NON_PRIMARY:
                LOG.debug(
                    "Skip update the Association sync_status as it is not primary."
                )
                continue
            # If the secondary site is down, set the association sync status
            #     "in-sync" -> "unknown"
            #     "unknown" -> "unknown"
            #     "out-of-sync" -> "failed"
            #     "syncing" -> "failed"
            #     "failed" -> "failed"
            sync_status = consts.ASSOCIATION_SYNC_STATUS_UNKNOWN
            message = f"Peer site ({self.peer.peer_name}) is unreachable."
            if association.sync_status not in [
                consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                consts.ASSOCIATION_SYNC_STATUS_UNKNOWN,
            ]:
                sync_status = consts.ASSOCIATION_SYNC_STATUS_FAILED
            db_api.peer_group_association_update(
                self.context,
                association.id,
                sync_status=sync_status,
                sync_message=message,
            )

    def _update_sync_status_secondary_site_becomes_reachable(self):
        # Get associations by system peer
        associations = SystemPeerManager.get_local_associations(self.context, self.peer)
        for association in associations:
            # If the association is not primary, skip it.
            if association.association_type == consts.ASSOCIATION_TYPE_NON_PRIMARY:
                LOG.debug(
                    "Skip update Peer Site Association sync_status as "
                    "current site Association is not primary."
                )
                continue
            # Upon detecting that the secondary site is reachable again,
            # the PGA sync_status will be set for both sites by the primary
            # site monitor thread as follows:
            #     "unknown" -> "in-sync"
            #     "failed" -> "out-of-sync"
            sync_status = consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC
            if association.sync_status == consts.ASSOCIATION_SYNC_STATUS_UNKNOWN:
                sync_status = consts.ASSOCIATION_SYNC_STATUS_IN_SYNC
            dc_local_pg = db_api.subcloud_peer_group_get(
                self.context, association.peer_group_id
            )
            SystemPeerManager.update_sync_status(
                self.context,
                self.peer,
                sync_status,
                dc_local_pg,
                association=association,
            )

    def _do_monitor_peer(self):
        failure_count = 0
        LOG.info("Start monitoring thread for peer %s" % self.peer.peer_name)
        UNAVAILABLE_STATE = consts.SYSTEM_PEER_AVAILABILITY_STATE_UNAVAILABLE
        AVAILABLE_STATE = consts.SYSTEM_PEER_AVAILABILITY_STATE_AVAILABLE
        # Do the actual peer monitor.
        while not self.exit_flag.wait(timeout=self.peer.heartbeat_interval):
            try:
                # Get system peer from DB
                self.peer = db_api.system_peer_get(self.context, self.peer.id)
                failed, remote_pg_list = self._heartbeat_check_via_get_peer_group_list()
                if failed:
                    failure_count += 1
                    if failure_count >= self.peer.heartbeat_failure_threshold:
                        # heartbeat_failure_threshold reached.
                        LOG.warning(
                            "DC %s heartbeat failed, Raising alarm"
                            % self.peer.peer_name
                        )
                        self._raise_failure()
                        db_api.system_peer_update(
                            self.context,
                            self.peer.id,
                            availability_state=UNAVAILABLE_STATE,
                        )
                        # pylint: disable=line-too-long
                        self._update_sync_status_secondary_site_becomes_unreachable()
                        failure_count = 0
                        self._set_require_audit_flag_to_associated_peer_groups()
                else:
                    failure_count = 0
                    self._audit_local_peer_groups(remote_pg_list)
                    if self.peer.availability_state != AVAILABLE_STATE:
                        db_api.system_peer_update(
                            self.context,
                            self.peer.id,
                            availability_state=AVAILABLE_STATE,
                        )
                        # pylint: disable=line-too-long
                        self._update_sync_status_secondary_site_becomes_reachable()
                        LOG.info("DC %s back online, clear alarm" % self.peer.peer_name)
                        self._clear_failure()
            except Exception as e:
                LOG.exception(
                    "Got exception monitoring peer %s error: %s"
                    % (self.peer.peer_name, e)
                )
        LOG.info(
            "Caught graceful exit signal for peer monitor %s" % self.peer.peer_name
        )

    def _audit_local_peer_groups(self, remote_pg_list):
        # Generate a dict index by remote peer group name
        remote_pg_dict = {
            remote_peer_group.get("peer_group_name"): remote_peer_group
            for remote_peer_group in remote_pg_list
        }

        # Only audit peer groups existing on both side
        for peer_group_id, pgam_obj in self.peer_group_audit_obj_map.items():
            peer_group = db_api.subcloud_peer_group_get(self.context, peer_group_id)
            if peer_group.peer_group_name in remote_pg_dict:
                remote_peer_group = remote_pg_dict[peer_group.peer_group_name]
                # Audit for require_audit_flag is True or
                # Remote peer group is in 'complete' state.
                if (
                    pgam_obj.require_audit_flag
                    or remote_peer_group.get("migration_status")
                    == consts.PEER_GROUP_MIGRATION_COMPLETE
                ):
                    pgam_obj.audit_peer_group_from_system(
                        self.peer, remote_peer_group, peer_group
                    )
            else:
                LOG.warning(
                    "peer group %s not found on remote DC %s "
                    "nothing to audit, need sync operation"
                    % (peer_group.peer_group_name, self.peer.peer_name)
                )

    def _set_require_audit_flag_to_associated_peer_groups(self):
        for pgam_obj in self.peer_group_audit_obj_map.values():
            pgam_obj.require_audit_flag = True

    def audit_specific_local_peer_group(self, peer_group, remote_peer_group):
        msg = None
        if peer_group.id in self.peer_group_audit_obj_map:
            pgam_obj = self.peer_group_audit_obj_map[peer_group.id]
            pgam_obj.audit(self.peer, remote_peer_group, peer_group)
        else:
            msg = "No peer group id %s found" % peer_group.peer_group_name
        return msg

    def _clean_peer_group_audit_threads(self):
        for pgam_obj in self.peer_group_audit_obj_map.values():
            pgam_obj.stop()
        self.peer_group_audit_obj_map.clear()

    def update_peer_group_id_set(self, peer_group_id_set):
        removed_peer_groups = self.peer_group_id_set - peer_group_id_set
        new_peer_groups = peer_group_id_set - self.peer_group_id_set

        # destroy removed peer_group audit object
        for peer_group_id in removed_peer_groups:
            LOG.info(
                "Peer group [%s] removed from peer [%s]"
                % (peer_group_id, self.peer.peer_name)
            )
            if peer_group_id in self.peer_group_audit_obj_map:
                self.peer_group_audit_obj_map[peer_group_id].stop()
                del self.peer_group_audit_obj_map[peer_group_id]
        # Add new peer_group audit object
        for peer_group_id in new_peer_groups:
            LOG.info(
                "New peer group [%s] found for peer [%s]"
                % (peer_group_id, self.peer.peer_name)
            )
            self.peer_group_audit_obj_map[peer_group_id] = pgam.PeerGroupAuditManager(
                self.subcloud_manager, peer_group_id
            )
        self.peer_group_id_set = peer_group_id_set
        self._set_require_audit_flag_to_associated_peer_groups()

    def start(self):
        if self.thread is not None:
            LOG.error(
                "Peer monitor thread for %s has already started" % self.peer.peer_name
            )
        else:
            self.thread = threading.Thread(target=self._do_monitor_peer)
            self.thread.start()

    def stop(self):
        self.exit_flag.set()
        self.thread.join()
        self._clear_failure()
        self._clean_peer_group_audit_threads()


class PeerMonitorManager(manager.Manager):
    """Manages tasks related to peer monitor."""

    def __init__(self, subcloud_manager):
        LOG.debug("PeerMonitorManager initialization...")

        super(PeerMonitorManager, self).__init__(service_name="peer_monitor_manager")
        self.peer_monitor = dict()
        self.context = context.get_admin_context()
        self.subcloud_manager = subcloud_manager

        # key: system_peer_id
        # value: PeerMonitor object
        self.peer_monitor_thread_map = dict()

    def _remove_peer_monitor_task(self, system_peer_id):
        peer_mon_obj = self.peer_monitor_thread_map[system_peer_id]
        peer_mon_obj.stop()
        del self.peer_monitor_thread_map[system_peer_id]

    def _create_peer_monitor_task(self, system_peer_id):
        peer = db_api.system_peer_get(self.context, system_peer_id)
        LOG.info("Create monitoring thread for peer: %s" % peer.peer_name)
        self.peer_monitor_thread_map[system_peer_id] = PeerMonitor(
            peer, self.context, self.subcloud_manager
        )
        self.peer_monitor_thread_map[system_peer_id].start()

    @staticmethod
    def _diff_dict(dict1, dict2):
        return {key: value for key, value in dict1.items() if key not in dict2}

    def _create_or_destroy_peer_monitor_task(self, peer_system_peer_group_map):
        new_peers = self._diff_dict(
            peer_system_peer_group_map, self.peer_monitor_thread_map
        )
        removed_peers = self._diff_dict(
            self.peer_monitor_thread_map, peer_system_peer_group_map
        )
        for peer_id in new_peers:
            self._create_peer_monitor_task(peer_id)
        for peer_id in removed_peers:
            self._remove_peer_monitor_task(peer_id)

        # Update peer_group_id set
        for peer_id, pm_obj in self.peer_monitor_thread_map.items():
            pm_obj.update_peer_group_id_set(peer_system_peer_group_map[peer_id])

    def peer_monitor_notify(self, context):
        LOG.info("Caught peer monitor notify...")
        peer_system_peer_group_map = defaultdict(set)
        # Get local associations
        associations = db_api.peer_group_association_get_all(context)
        for association in associations:
            peer_system_peer_group_map[association.system_peer_id].add(
                association.peer_group_id
            )

        self._create_or_destroy_peer_monitor_task(peer_system_peer_group_map)

    def peer_group_audit_notify(self, context, peer_group_name, payload):
        LOG.info(
            "Caught peer group audit notification for peer group %s" % peer_group_name
        )
        msg = None
        try:
            peer_group = db_api.subcloud_peer_group_get_by_name(
                context, peer_group_name
            )
            system_uuid = payload.get("peer_uuid")
            system_peer = db_api.system_peer_get_by_uuid(context, system_uuid)
            if system_peer.id in self.peer_monitor_thread_map:
                pmobj = self.peer_monitor_thread_map[system_peer.id]
                msg = pmobj.audit_specific_local_peer_group(peer_group, payload)
            else:
                msg = (
                    "System peer with UUID=%s is not under monitoring. "
                    "Skipping audit for peer group %s" % (system_uuid, peer_group_name)
                )
                LOG.warning(msg)
            return msg
        except Exception as e:
            LOG.exception("Handling peer group audit notify error: %s" % str(e))
            return str(e)
