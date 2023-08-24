#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
import functools
import json
import tempfile

from eventlet import greenpool
from oslo_log import log as logging
import yaml

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.dcmanager_v1 import DcmanagerClient
from dccommon.drivers.openstack.peer_site import PeerSiteDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import exceptions as dccommon_exceptions
from dcmanager.common import consts
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.db import api as db_api

LOG = logging.getLogger(__name__)

TEMP_BOOTSTRAP_PREFIX = 'peer_subcloud_bootstrap_yaml'
MAX_PARALLEL_SUBCLOUD_SYNC = 10
VERIFY_SUBCLOUD_SYNC_VALID = 'valid'
VERIFY_SUBCLOUD_SYNC_IGNORE = 'ignore'


class SystemPeerManager(manager.Manager):
    """Manages tasks related to system peers."""

    def __init__(self, *args, **kwargs):
        LOG.debug(_('SystemPeerManager initialization...'))

        super(SystemPeerManager, self).__init__(
            service_name="system_peer_manager", *args, **kwargs)

    @staticmethod
    def get_peer_ks_client(peer):
        """This will get a new peer keystone client (and new token)"""
        try:
            os_client = PeerSiteDriver(
                auth_url=peer.manager_endpoint,
                username=peer.manager_username,
                password=base64.b64decode(
                    peer.manager_password.encode("utf-8")).decode("utf-8"),
                site_uuid=peer.peer_uuid)
            return os_client.keystone_client
        except Exception:
            LOG.warn('Failure initializing KeystoneClient '
                     f'for system peer {peer.peer_name}')
            raise

    @staticmethod
    def get_peer_sysinv_client(peer):
        p_ks_client = SystemPeerManager.get_peer_ks_client(peer)
        sysinv_endpoint = p_ks_client.session.get_endpoint(
            service_type='platform',
            region_name=dccommon_consts.DEFAULT_REGION_NAME,
            interface=dccommon_consts.KS_ENDPOINT_PUBLIC)
        return SysinvClient(dccommon_consts.DEFAULT_REGION_NAME,
                            p_ks_client.session,
                            endpoint_type=dccommon_consts.
                            KS_ENDPOINT_PUBLIC,
                            endpoint=sysinv_endpoint)

    @staticmethod
    def get_peer_dc_client(peer):
        p_ks_client = SystemPeerManager.get_peer_ks_client(peer)
        dc_endpoint = p_ks_client.session.get_endpoint(
            service_type='dcmanager',
            region_name=dccommon_consts.SYSTEM_CONTROLLER_NAME,
            interface=dccommon_consts.KS_ENDPOINT_PUBLIC)
        return DcmanagerClient(dccommon_consts.SYSTEM_CONTROLLER_NAME,
                               p_ks_client.session,
                               endpoint=dc_endpoint)

    @staticmethod
    def get_peer_subcloud(dc_client, subcloud_name):
        """Get subcloud on peer site if exist.

        :param dc_client: the dcmanager client object
        :param subcloud_ref: subcloud name needs to check
        """
        try:
            peer_subcloud = dc_client.get_subcloud(subcloud_name)
            return peer_subcloud
        except dccommon_exceptions.SubcloudNotFound:
            LOG.warn(f"Subcloud {subcloud_name} does not exist on peer site.")

    @staticmethod
    def is_subcloud_secondary(subcloud):
        """Check if subcloud on peer site is secondary.

        :param subcloud: peer subcloud dictionary
        """
        deploy_status = 'deploy-status' if 'deploy-status' in subcloud else \
            'deploy_status'
        if subcloud.get(deploy_status) not in (
            consts.DEPLOY_STATE_SECONDARY_FAILED,
            consts.DEPLOY_STATE_SECONDARY):
            return False
        return True

    @staticmethod
    def delete_peer_secondary_subcloud(dc_client, subcloud_ref):
        """Delete secondary subcloud on peer site.

        :param dc_client: the dcmanager client object
        :param subcloud_ref: subcloud name to delete
        """
        peer_subcloud = SystemPeerManager.get_peer_subcloud(dc_client,
                                                            subcloud_ref)
        if not peer_subcloud:
            LOG.info(f"Skip delete Peer Site Subcloud {subcloud_ref} cause "
                     f"it doesn't exist.")
            return

        is_secondary = SystemPeerManager.is_subcloud_secondary(peer_subcloud)
        if not is_secondary:
            LOG.info(f"Ignoring delete Peer Site Subcloud {subcloud_ref} "
                     f"as is not in secondary state.")
            return

        dc_client.delete_subcloud(subcloud_ref)
        LOG.info(f"Deleted Subcloud {subcloud_ref} on peer site.")

    @staticmethod
    def _run_parallel_group_operation(op_type, op_function, thread_pool,
                                      subclouds):
        """Run parallel group operation on subclouds."""
        failed_subclouds = []
        processed = 0
        error_msg = {}  # Dictinary to store error message for each subcloud

        for subcloud, success in thread_pool.imap(op_function, subclouds):
            processed += 1

            if not success:
                failed_subclouds.append(subcloud)
                if hasattr(subcloud, 'msg'):
                    error_msg[subcloud.name] = subcloud.msg

            completion = float(processed) / float(len(subclouds)) * 100
            remaining = len(subclouds) - processed
            LOG.info("Processed subcloud %s for %s (operation %.0f%% "
                     "complete, %d subcloud(s) remaining)" %
                     (subcloud.name, op_type, completion, remaining))

        return failed_subclouds, error_msg

    def _add_or_update_subcloud(self, dc_client, peer_controller_gateway_ip,
                                dc_peer_pg_id, subcloud):
        """Add or update subcloud on peer site in parallel."""
        with tempfile.NamedTemporaryFile(prefix=TEMP_BOOTSTRAP_PREFIX,
                                         suffix=".yaml",
                                         mode='w') as temp_file:
            subcloud_name = subcloud.get('name')
            region_name = subcloud.get('region_name')
            rehome_data = json.loads(subcloud.rehome_data)
            subcloud_payload = rehome_data['saved_payload']

            subcloud_payload['systemcontroller_gateway_address'] = \
                peer_controller_gateway_ip

            yaml.dump(subcloud_payload, temp_file)

            files = {"bootstrap_values": temp_file.name}
            data = {
                "bootstrap-address": subcloud_payload['bootstrap-address'],
                "region_name": subcloud.region_name,
                "location": subcloud.location,
                "description": subcloud.description
            }

            try:
                # Sync subcloud information to peer site
                peer_subcloud = self.get_peer_subcloud(dc_client, subcloud_name)
                if peer_subcloud:
                    dc_peer_subcloud = dc_client.update_subcloud(subcloud_name,
                                                                 files, data)
                    LOG.info(f"Updated Subcloud {dc_peer_subcloud.get('name')} "
                             "(region_name: "
                             f"{dc_peer_subcloud.get('region_name')}) on peer "
                             "site.")
                else:
                    # Create subcloud on peer site if not exist
                    dc_peer_subcloud = dc_client. \
                        add_subcloud_with_secondary_status(files, data)
                    LOG.info(f"Created Subcloud {dc_peer_subcloud.get('name')} "
                             "(region_name: "
                             f"{dc_peer_subcloud.get('region_name')}) on peer "
                             "site.")
                LOG.debug(f"Updating subcloud {subcloud_name} (region_name: "
                          f"{region_name}) with subcloud peer group id "
                          f"{dc_peer_pg_id} on peer site.")
                # Update subcloud associated peer group on peer site
                dc_client.update_subcloud(subcloud_name, files=None,
                                          data={"peer_group": str(dc_peer_pg_id)})
                return subcloud, True
            except Exception as e:
                subcloud.msg = str(e)  # Store error message for subcloud
                LOG.error(f"Failed to add/update Subcloud {subcloud_name} "
                          f"(region_name: {region_name}) "
                          f"on peer site: {str(e)}")
                return subcloud, False

    def _is_valid_for_subcloud_sync(self, subcloud):
        """Verify subcloud data for sync."""
        subcloud_name = subcloud.get('name')
        region_name = subcloud.get('region_name')

        # Ignore the secondary subclouds to sync with peer site
        if self.is_subcloud_secondary(subcloud):
            LOG.info(f"Ignoring the Subcloud {subcloud_name} (region_name: "
                     f"{region_name}) in secondary status to sync with "
                     "peer site.")
            return VERIFY_SUBCLOUD_SYNC_IGNORE

        # Verify subcloud payload data
        rehome_json = subcloud.rehome_data
        if not rehome_json:
            msg = f"Subcloud {subcloud_name} (region_name: " + \
                f"{region_name}) does not have rehome_data."
            return msg

        rehome_data = json.loads(rehome_json)
        if 'saved_payload' not in rehome_data:
            msg = f"Subcloud {subcloud_name} (region_name: " + \
                f"{region_name}) does not have saved_payload."
            return msg

        subcloud_payload = rehome_data['saved_payload']
        if not subcloud_payload:
            msg = f"Subcloud {subcloud_name} (region_name: " + \
                f"{region_name}) saved_payload is empty."
            return msg

        if 'bootstrap-address' not in subcloud_payload:
            msg = f"Subcloud {subcloud_name} (region_name: " + \
                f"{region_name}) does not have bootstrap-address in " + \
                "saved_payload."
            return msg

        if 'systemcontroller_gateway_address' not in subcloud_payload:
            msg = f"Subcloud {subcloud_name} (region_name: " + \
                f"{region_name}) does not have systemcontroller_" + \
                "gateway_address in saved_payload."
            return msg

        return VERIFY_SUBCLOUD_SYNC_VALID

    def _validate_subclouds_for_sync(self, subclouds, dc_client):
        """Validate subclouds for sync."""
        valid_subclouds = []
        error_msg = {}  # Dictinary to store error message for each subcloud

        for subcloud in subclouds:
            subcloud_name = subcloud.get('name')
            region_name = subcloud.get('region_name')

            validation = self._is_valid_for_subcloud_sync(subcloud)
            if validation != VERIFY_SUBCLOUD_SYNC_IGNORE and \
                validation != VERIFY_SUBCLOUD_SYNC_VALID:
                LOG.error(validation)
                error_msg[subcloud_name] = validation
                continue

            try:
                peer_subcloud = self.get_peer_subcloud(dc_client, subcloud_name)
                if not peer_subcloud:
                    LOG.info(f"Subcloud {subcloud_name} (region_name: "
                             f"{region_name}) does not exist on peer site.")
                    valid_subclouds.append(subcloud)
                    continue

                if not self.is_subcloud_secondary(peer_subcloud):
                    msg = "Ignoring update Peer Site Subcloud " + \
                          f"{subcloud_name} (region_name: {region_name})" + \
                          " as is not in secondary state."
                    LOG.info(msg)
                    error_msg[subcloud_name] = msg

                valid_subclouds.append(subcloud)

            except Exception as e:
                subcloud.msg = str(e)  # Store error message for subcloud
                LOG.error(f"Failed to validate Subcloud {subcloud_name} "
                          f"(region_name: {region_name}): {str(e)}")
                error_msg[subcloud_name] = str(e)

        return valid_subclouds, error_msg

    def _sync_subclouds(self, context, peer, dc_local_pg_id, dc_peer_pg_id):
        """Sync subclouds of local peer group to peer site.

        :param context: request context object
        :param peer: system peer object of the peer site
        :param dc_local_pg_id: peer group id on local site for sync
        :param dc_peer_pg_id: peer group id on peer site
        """
        dc_client = self.get_peer_dc_client(peer)
        subclouds = db_api.subcloud_get_for_peer_group(context, dc_local_pg_id)

        subclouds_to_sync, error_msg = self._validate_subclouds_for_sync(
            subclouds, dc_client)

        # Use thread pool to limit number of operations in parallel
        sync_pool = greenpool.GreenPool(size=MAX_PARALLEL_SUBCLOUD_SYNC)

        # Spawn threads to sync each applicable subcloud
        sync_function = functools.partial(self._add_or_update_subcloud,
                                          dc_client,
                                          peer.peer_controller_gateway_ip,
                                          dc_peer_pg_id)

        failed_subclouds, sync_error_msg = self._run_parallel_group_operation(
            'peer sync', sync_function, sync_pool, subclouds_to_sync)

        error_msg.update(sync_error_msg)
        LOG.info("Subcloud peer sync operation finished")

        dc_local_region_names = set()
        for subcloud in subclouds:
            # Ignore the secondary subclouds to sync with peer site
            if not self.is_subcloud_secondary(subcloud):
                # Count all subcloud need to be sync
                dc_local_region_names.add(subcloud.get('name'))

        dc_peer_subclouds = dc_client.get_subcloud_list_by_peer_group(
            str(dc_peer_pg_id))
        dc_peer_region_names = set(subcloud.get('name') for subcloud in
                                   dc_peer_subclouds)

        dc_peer_subcloud_diff_names = dc_peer_region_names - \
            dc_local_region_names
        for subcloud_to_delete in dc_peer_subcloud_diff_names:
            try:
                LOG.debug(f"Deleting Subcloud name {subcloud_to_delete} "
                          "on peer site.")
                self.delete_peer_secondary_subcloud(dc_client,
                                                    subcloud_to_delete)
            except Exception as e:
                msg = f"Subcloud delete failed: {str(e)}"
                LOG.error(msg)
                error_msg[subcloud_to_delete] = msg

        return error_msg

    def sync_subcloud_peer_group(self, context, association_id,
                                 sync_subclouds=True, priority=None):
        """Sync subcloud peer group to peer site.

        This function synchronizes subcloud peer groups from current site
        to peer site, supporting two scenarios:

        1. When creating an association between the system peer and a subcloud
        peer group. This function creates the subcloud peer group on the
        peer site and synchronizes the subclouds to it.

        2. When synchronizing a subcloud peer group with the peer site. This
        function syncs both the subcloud peer group and the subclouds
        under it to the peer site.

        :param context: request context object
        :param association_id: id of association to sync
        :param sync_subclouds: Enabled to sync subclouds to peer site
        """
        LOG.info(f"Synchronize the association {association_id} of the "
                 "Subcloud Peer Group with the System Peer pointing to the "
                 "peer site.")

        association = db_api.peer_group_association_get(context,
                                                        association_id)
        peer = db_api.system_peer_get(context, association.system_peer_id)
        dc_local_pg = db_api.subcloud_peer_group_get(context,
                                                     association.peer_group_id)
        peer_group_name = dc_local_pg.peer_group_name

        try:
            sysinv_client = self.get_peer_sysinv_client(peer)

            # Check if the system_uuid of the peer site matches with the
            # peer_uuid
            system = sysinv_client.get_system()
            if system.uuid != peer.peer_uuid:
                LOG.error(f"Peer site system uuid {system.uuid} does not match "
                          f"with the peer_uuid {peer.peer_uuid}")
                raise exceptions.PeerGroupAssociationTargetNotMatch(
                    uuid=system.uuid)

            dc_client = self.get_peer_dc_client(peer)

            peer_group_kwargs = {
                'group-priority': association.peer_group_priority,
                'group-state': dc_local_pg.group_state,
                'system-leader-id': dc_local_pg.system_leader_id,
                'system-leader-name': dc_local_pg.system_leader_name,
                'max-subcloud-rehoming': dc_local_pg.max_subcloud_rehoming
            }
            if priority:
                peer_group_kwargs['group-priority'] = priority
            try:
                dc_peer_pg = dc_client.get_subcloud_peer_group(
                    peer_group_name)
                dc_peer_pg_id = dc_peer_pg.get('id')
                dc_peer_pg_priority = dc_peer_pg.get('group_priority')
                if dc_peer_pg_priority == 0:
                    LOG.error(f"Skip update. Peer Site {peer_group_name} "
                              f"has priority 0.")
                    raise exceptions.SubcloudPeerGroupHasWrongPriority(
                        priority=dc_peer_pg_priority)

                dc_peer_pg = dc_client.update_subcloud_peer_group(
                    peer_group_name, **peer_group_kwargs)
                LOG.info(f"Updated Subcloud Peer Group {peer_group_name} on "
                         f"peer site, ID is {dc_peer_pg.get('id')}.")
            except dccommon_exceptions.SubcloudPeerGroupNotFound:
                peer_group_kwargs['peer-group-name'] = peer_group_name
                dc_peer_pg = dc_client.add_subcloud_peer_group(
                    **peer_group_kwargs)
                dc_peer_pg_id = dc_peer_pg.get('id')
                LOG.info(f"Created Subcloud Peer Group {peer_group_name} on "
                         f"peer site, ID is {dc_peer_pg_id}.")

            association_update = {
                'sync_status': consts.ASSOCIATION_SYNC_STATUS_SYNCED,
                'sync_message': None
            }
            if sync_subclouds:
                error_msg = self._sync_subclouds(context, peer, dc_local_pg.id,
                                                 dc_peer_pg_id)
                if len(error_msg) > 0:
                    association_update['sync_status'] = \
                        consts.ASSOCIATION_SYNC_STATUS_FAILED
                    association_update['sync_message'] = json.dumps(error_msg)
            if priority:
                association_update['peer_group_priority'] = priority
            association = db_api.peer_group_association_update(
                context, association_id, **association_update)

            return db_api.peer_group_association_db_model_to_dict(association)

        except Exception as exception:
            LOG.exception(f"Failed to sync peer group {peer_group_name} to "
                          f"peer site {peer.peer_name}")
            db_api.peer_group_association_update(
                context, association_id,
                sync_status=consts.ASSOCIATION_SYNC_STATUS_FAILED,
                sync_message=str(exception))
            raise exception

    def delete_peer_group_association(self, context, association_id):
        """Delete association and remove related association from peer site.

        :param context: request context object.
        :param association_id: id of association to delete
        """
        LOG.info(f"Deleting association peer group {association_id}.")

        # Retrieve the peer group association details from the database
        association = db_api.peer_group_association_get(context,
                                                        association_id)
        peer = db_api.system_peer_get(context, association.system_peer_id)
        peer_group = db_api.subcloud_peer_group_get(context,
                                                    association.peer_group_id)

        try:
            dc_client = self.get_peer_dc_client(peer)
            dc_peer_pg = dc_client.get_subcloud_peer_group(
                peer_group.peer_group_name)
            dc_peer_pg_priority = dc_peer_pg.get('group_priority')
            if dc_peer_pg_priority == 0:
                LOG.error(f"Failed to delete peer_group_association. "
                          f"Peer Group {peer_group.peer_group_name} "
                          f"has priority 0 on peer site.")
                raise exceptions.SubcloudPeerGroupHasWrongPriority(
                    priority=dc_peer_pg_priority)

            subclouds = db_api.subcloud_get_for_peer_group(context,
                                                           peer_group.id)
            for subcloud in subclouds:
                self.delete_peer_secondary_subcloud(dc_client,
                                                    subcloud.name)
            try:
                dc_client.delete_subcloud_peer_group(peer_group.peer_group_name)
                LOG.info("Deleted Subcloud Peer Group "
                         f"{peer_group.peer_group_name} on peer site.")
            except dccommon_exceptions.SubcloudPeerGroupNotFound:
                LOG.debug(f"Subcloud Peer Group {peer_group.peer_group_name} "
                          "does not exist on peer site.")
            except dccommon_exceptions.SubcloudPeerGroupDeleteFailedAssociated:
                LOG.debug(f"Subcloud Peer Group {peer_group.peer_group_name} "
                          "delete failed as it is associated with system peer "
                          "on peer site.")

            db_api.peer_group_association_destroy(context, association_id)

        except Exception as exception:
            LOG.exception("Failed to delete peer_group_association "
                          f"{association.id}")
            raise exception
