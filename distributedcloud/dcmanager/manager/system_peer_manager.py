#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import base64
from contextlib import nullcontext
import functools
import json
import tempfile
from typing import Optional

from eventlet import greenpool
from oslo_log import log as logging
import yaml

from dccommon import consts as dccommon_consts
from dccommon.drivers.openstack.dcmanager_v1 import DcmanagerClient
from dccommon.drivers.openstack.peer_site import PeerSiteDriver
from dccommon.drivers.openstack.sysinv_v1 import SysinvClient
from dccommon import exceptions as dccommon_exceptions
from dcmanager.common import consts
from dcmanager.common import context as dcmanager_context
from dcmanager.common import exceptions
from dcmanager.common.i18n import _
from dcmanager.common import manager
from dcmanager.common import utils
from dcmanager.db import api as db_api
from dcmanager.db.sqlalchemy import models

LOG = logging.getLogger(__name__)

TEMP_BOOTSTRAP_PREFIX = "peer_subcloud_bootstrap_yaml"
TEMP_INSTALL_PREFIX = "peer_subcloud_install_yaml"
MAX_PARALLEL_SUBCLOUD_SYNC = 10
MAX_PARALLEL_SUBCLOUD_DELETE = 10
VERIFY_SUBCLOUD_SYNC_VALID = "valid"
VERIFY_SUBCLOUD_SYNC_IGNORE = "ignore"

TRANSITORY_STATES = {
    consts.ASSOCIATION_SYNC_STATUS_SYNCING: consts.ASSOCIATION_SYNC_STATUS_FAILED
}


class SystemPeerManager(manager.Manager):
    """Manages tasks related to system peers."""

    def __init__(self, peer_monitor_manager, *args, **kwargs):
        LOG.debug(_("SystemPeerManager initialization..."))
        self.context = dcmanager_context.get_admin_context()
        self.peer_monitor_manager = peer_monitor_manager
        super(SystemPeerManager, self).__init__(
            service_name="system_peer_manager", *args, **kwargs
        )

    @staticmethod
    def get_local_associations(
        ctx, peer: models.SystemPeer, local_pg: models.SubcloudPeerGroup = None
    ) -> list[models.PeerGroupAssociation]:
        if local_pg is None:
            # Get associations by system peer id
            return db_api.peer_group_association_get_by_system_peer_id(ctx, peer.id)
        else:
            # Get association by system peer id and peer group id
            association = (
                db_api.peer_group_association_get_by_peer_group_and_system_peer_id(
                    ctx, local_pg.id, peer.id
                )
            )
            return [association] if association else []

    @staticmethod
    def update_sync_status(
        ctx,
        peer,
        sync_status,
        local_pg=None,
        remote_pg=None,
        message="None",
        association=None,
    ):
        """Update sync status of association.

        This function updates the sync status of the association on the peer
        site and then updates the sync status of the association on the
        primary site.

        :param ctx: request context object
        :param peer: system peer object of the current site
        :param sync_status: sync status to update
        :param local_pg: local peer group object
        :param remote_pg: remote peer group object
        :param message: sync message
        :param association: peer group association object
        """

        def _update_association_on_peer_site(
            peer: models.SystemPeer,
            sync_status: str,
            local_pg: models.SubcloudPeerGroup,
            remote_pg: dict,
            message: str,
        ) -> tuple[str, str]:
            try:
                # Get peer site dcmanager client
                dc_client = SystemPeerManager.get_peer_dc_client(peer)

                # Get peer site peer group if not exist
                remote_pg = (
                    remote_pg
                    if remote_pg is not None
                    else dc_client.get_subcloud_peer_group(local_pg.peer_group_name)
                )
                # Get peer site system peer
                dc_peer_system_peer = dc_client.get_system_peer(
                    utils.get_local_system().uuid
                )
                # Get peer site group association
                dc_peer_association = (
                    dc_client.get_peer_group_association_with_peer_id_and_pg_id(
                        dc_peer_system_peer.get("id"), remote_pg.get("id")
                    )
                )

                # Update peer site association sync_status only if the
                # sync_status is different from the current sync_status
                if dc_peer_association.get("sync-status") != sync_status:
                    # Update peer site association sync_status
                    dc_peer_association_id = dc_peer_association.get("id")
                    dc_client.update_peer_group_association_sync_status(
                        dc_peer_association_id, sync_status
                    )
                    LOG.info(
                        f"Updated peer site '{dc_peer_system_peer.get('peer-name')}' "
                        f"peer group association {dc_peer_association_id} "
                        f"sync_status to '{sync_status}'"
                    )
            except Exception as e:
                message = (
                    f"Failed to update peer site '{peer.peer_name}' "
                    f"association sync_status to '{sync_status}'"
                )
                LOG.exception(f"{message} Error: {e}")
                sync_status = consts.ASSOCIATION_SYNC_STATUS_FAILED

            return sync_status, message

        if association is None:
            associations = SystemPeerManager.get_local_associations(ctx, peer, local_pg)
        else:
            associations = [association]

        for association in associations:
            if association.association_type == consts.ASSOCIATION_TYPE_NON_PRIMARY:
                LOG.info(
                    "Skipping updating peer and local site association "
                    f"sync_status to '{sync_status}' as local site is not primary"
                )
                continue

            local_pg = (
                local_pg
                if local_pg is not None
                else db_api.subcloud_peer_group_get(ctx, association.peer_group_id)
            )
            sync_status, message = _update_association_on_peer_site(
                peer, sync_status, local_pg, remote_pg, message
            )

            if (
                association.sync_status == sync_status
                and sync_status != consts.ASSOCIATION_SYNC_STATUS_FAILED
            ):
                LOG.info(
                    f"Local association {association.id} sync_status "
                    f"already set to '{sync_status}', skipping update"
                )
                continue
            # Update primary site association sync_status
            LOG.info(
                f"Updating local association {association.id} sync_status "
                f"from '{association.sync_status}' to '{sync_status}'"
            )
            db_api.peer_group_association_update(
                ctx, association.id, sync_status=sync_status, sync_message=message
            )

    @staticmethod
    def get_peer_ks_client(peer):
        """This will get a new peer keystone client (and new token)"""
        try:
            os_client = PeerSiteDriver(
                auth_url=peer.manager_endpoint,
                username=peer.manager_username,
                password=base64.b64decode(peer.manager_password.encode("utf-8")).decode(
                    "utf-8"
                ),
                site_uuid=peer.peer_uuid,
            )
            return os_client.keystone_client
        except Exception:
            LOG.warn(
                f"Failure initializing KeystoneClient for system peer {peer.peer_name}"
            )
            raise

    @staticmethod
    def get_peer_sysinv_client(peer):
        p_ks_client = SystemPeerManager.get_peer_ks_client(peer)
        sysinv_endpoint = p_ks_client.session.get_endpoint(
            service_type="platform",
            region_name=p_ks_client.region_name,
            interface=dccommon_consts.KS_ENDPOINT_PUBLIC,
        )
        return SysinvClient(
            p_ks_client.region_name,
            p_ks_client.session,
            endpoint_type=dccommon_consts.KS_ENDPOINT_PUBLIC,
            endpoint=sysinv_endpoint,
        )

    @staticmethod
    def get_peer_dc_client(peer):
        p_ks_client = SystemPeerManager.get_peer_ks_client(peer)
        dc_endpoint = p_ks_client.session.get_endpoint(
            service_type="dcmanager",
            region_name=dccommon_consts.SYSTEM_CONTROLLER_NAME,
            interface=dccommon_consts.KS_ENDPOINT_PUBLIC,
        )
        return DcmanagerClient(
            dccommon_consts.SYSTEM_CONTROLLER_NAME,
            p_ks_client.session,
            endpoint=dc_endpoint,
            peer=peer,
        )

    @staticmethod
    def get_peer_subcloud(dc_client: DcmanagerClient, subcloud_name: str) -> dict:
        """Get subcloud on peer site if exist.

        :param dc_client: the dcmanager client object
        :param subcloud_ref: subcloud name needs to check
        """
        try:
            peer_subcloud = dc_client.get_subcloud(subcloud_name)
            return peer_subcloud
        except dccommon_exceptions.SubcloudNotFound:
            LOG.warn(
                f"Subcloud '{subcloud_name}' does not exist on "
                f"peer site '{dc_client.peer.peer_name}'"
            )

    @staticmethod
    def get_subcloud_deploy_status(subcloud):
        deploy_status = (
            "deploy-status" if "deploy-status" in subcloud else "deploy_status"
        )
        return subcloud.get(deploy_status)

    @staticmethod
    def is_subcloud_secondary(subcloud):
        """Check if subcloud on peer site is secondary.

        :param subcloud: peer subcloud dictionary
        """
        if SystemPeerManager.get_subcloud_deploy_status(subcloud) not in (
            consts.DEPLOY_STATE_SECONDARY_FAILED,
            consts.DEPLOY_STATE_SECONDARY,
        ):
            return False
        return True

    @staticmethod
    def delete_peer_secondary_subcloud(
        dc_client: DcmanagerClient, subcloud_ref: str
    ) -> None:
        """Delete secondary subcloud on peer site.

        :param dc_client: the dcmanager client object
        :param subcloud_ref: subcloud name to delete
        """
        peer_subcloud = SystemPeerManager.get_peer_subcloud(dc_client, subcloud_ref)
        if not peer_subcloud:
            LOG.info(
                f"Skip delete Peer Site Subcloud {subcloud_ref} cause it doesn't exist."
            )
            return

        if SystemPeerManager.get_subcloud_deploy_status(peer_subcloud) not in (
            consts.DEPLOY_STATE_SECONDARY_FAILED,
            consts.DEPLOY_STATE_SECONDARY,
            consts.DEPLOY_STATE_REHOME_FAILED,
            consts.DEPLOY_STATE_REHOME_PREP_FAILED,
        ):
            LOG.info(
                f"Ignoring delete Peer Site Subcloud {subcloud_ref} "
                "as is not in secondary or rehome failed state."
            )
            return

        dc_client.delete_subcloud(subcloud_ref)
        LOG.info(
            f"Deleted subcloud '{subcloud_ref}' on peer site "
            f"'{dc_client.peer.peer_name}'"
        )

    @staticmethod
    def _run_parallel_group_operation(op_type, op_function, thread_pool, subclouds):
        """Run parallel group operation on subclouds."""
        failed_subclouds = []
        processed = 0
        error_msg = {}  # Dictionary to store error message for each subcloud

        for subcloud, success in thread_pool.imap(op_function, subclouds):
            processed += 1

            if not success:
                failed_subclouds.append(subcloud)
                if hasattr(subcloud, "msg"):
                    error_msg[subcloud.name] = subcloud.msg

            completion = float(processed) / float(len(subclouds)) * 100
            remaining = len(subclouds) - processed
            LOG.info(
                "Processed subcloud %s for %s (operation %.0f%% "
                "complete, %d subcloud(s) remaining)"
                % (subcloud.name, op_type, completion, remaining)
            )

        return failed_subclouds, error_msg

    def _add_or_update_subcloud(
        self,
        dc_client: DcmanagerClient,
        peer_controller_gateway_ip: str,
        dc_peer_pg_id: int,
        subcloud: models.Subcloud,
    ):
        """Add or update subcloud on peer site in parallel."""
        with tempfile.NamedTemporaryFile(
            prefix=TEMP_BOOTSTRAP_PREFIX, suffix=".yaml", mode="w"
        ) as temp_bootstrap_file, (
            tempfile.NamedTemporaryFile(
                prefix=TEMP_INSTALL_PREFIX, suffix=".yaml", mode="w"
            )
            if subcloud.data_install
            else nullcontext()
        ) as temp_install_file:
            subcloud_name = subcloud.get("name")
            region_name = subcloud.get("region_name")
            rehome_data = json.loads(subcloud.rehome_data)
            subcloud_payload = rehome_data["saved_payload"]

            # Update bootstrap_values with the peer site
            # systemcontroller_gateway_address
            subcloud_payload["systemcontroller_gateway_address"] = (
                peer_controller_gateway_ip
            )

            yaml.dump(subcloud_payload, temp_bootstrap_file)

            files = {consts.BOOTSTRAP_VALUES: temp_bootstrap_file.name}
            data = {
                consts.BOOTSTRAP_ADDRESS: subcloud_payload[consts.BOOTSTRAP_ADDRESS],
                "region_name": subcloud.region_name,
                "location": subcloud.location,
                "description": subcloud.description,
            }

            if temp_install_file:
                data_install = json.loads(subcloud.data_install)
                yaml.dump(data_install, temp_install_file)
                files[consts.INSTALL_VALUES] = temp_install_file.name

            try:
                # Sync subcloud information to peer site
                peer_subcloud = self.get_peer_subcloud(dc_client, subcloud_name)
                if peer_subcloud:
                    # The subcloud update API expects 'bootstrap_address'
                    # instead of 'bootstrap-address'
                    data["bootstrap_address"] = data.pop(consts.BOOTSTRAP_ADDRESS)
                    dc_peer_subcloud = dc_client.update_subcloud(
                        region_name, files, data, is_region_name=True
                    )
                    LOG.info(
                        f"Updated subcloud '{dc_peer_subcloud.get('name')}' "
                        f"(region_name: {dc_peer_subcloud.get('region-name')}) "
                        f"on peer site '{dc_client.peer.peer_name}'"
                    )
                else:
                    # Create subcloud on peer site if not exist
                    dc_peer_subcloud = dc_client.add_subcloud_with_secondary_status(
                        files, data
                    )
                    LOG.info(
                        f"Created subcloud '{dc_peer_subcloud.get('name')}' "
                        f"(region_name: {dc_peer_subcloud.get('region-name')}) "
                        f"on peer site '{dc_client.peer.peer_name}'"
                    )
                LOG.info(
                    f"Updating subcloud '{subcloud_name}' (region_name: "
                    f"{dc_peer_subcloud.get('region-name')}) with subcloud "
                    f"peer group id {dc_peer_pg_id} on peer site "
                    f"'{dc_client.peer.peer_name}'"
                )
                # Update subcloud associated peer group on peer site.
                # The peer_group update will check the header and should
                # use the region_name as subcloud_ref.
                peer_subcloud = dc_client.update_subcloud(
                    dc_peer_subcloud.get("region-name"),
                    files=None,
                    data={"peer_group": str(dc_peer_pg_id)},
                    is_region_name=True,
                )

                # Need to check the subcloud only in secondary, otherwise it
                # should be recorded as a failure.
                peer_subcloud_deploy_status = self.get_subcloud_deploy_status(
                    peer_subcloud
                )
                if peer_subcloud_deploy_status not in (
                    consts.DEPLOY_STATE_SECONDARY,
                    consts.DEPLOY_STATE_REHOME_FAILED,
                    consts.DEPLOY_STATE_REHOME_PREP_FAILED,
                ):
                    subcloud.msg = (
                        "Subcloud's deploy status not correct: %s"
                        % peer_subcloud_deploy_status
                    )
                    return subcloud, False

                return subcloud, True
            except Exception as e:
                subcloud.msg = str(e)  # Store error message for subcloud
                LOG.error(
                    f"Failed to add/update subcloud '{subcloud_name}' "
                    f"(region_name: {region_name}) on peer site "
                    f"'{dc_client.peer.peer_name}': {str(e)}"
                )
                return subcloud, False

    def _delete_subcloud(
        self, dc_client: DcmanagerClient, subcloud: models.Subcloud
    ) -> tuple[models.Subcloud, bool]:
        """Delete subcloud on peer site in parallel."""
        try:
            subcloud_name = subcloud.get("name")
            self.delete_peer_secondary_subcloud(dc_client, subcloud_name)
            return subcloud, True
        except Exception as e:
            subcloud.msg = str(e)
            LOG.exception(
                f"Failed to delete subcloud '{subcloud_name}' on "
                f"peer site '{dc_client.peer.peer_name}': {str(e)}"
            )
            return subcloud, False

    def _is_valid_for_subcloud_sync(self, subcloud: models.Subcloud) -> str:
        """Verify subcloud data for sync."""
        subcloud_name = subcloud.get("name")
        region_name = subcloud.get("region_name")

        # Ignore the secondary subclouds to sync with peer site
        if self.is_subcloud_secondary(subcloud):
            LOG.info(
                f"Ignoring the Subcloud {subcloud_name} (region_name: "
                f"{region_name}) in secondary status to sync with peer site."
            )
            return VERIFY_SUBCLOUD_SYNC_IGNORE

        # Verify subcloud payload data
        rehome_json = subcloud.rehome_data
        if not rehome_json:
            msg = (
                f"Subcloud {subcloud_name} (region_name: {region_name}) does not "
                "have rehome_data."
            )
            return msg

        rehome_data = json.loads(rehome_json)
        if "saved_payload" not in rehome_data:
            msg = (
                f"Subcloud {subcloud_name} (region_name: {region_name}) does not "
                "have saved_payload."
            )
            return msg

        subcloud_payload = rehome_data["saved_payload"]
        if not subcloud_payload:
            msg = (
                f"Subcloud {subcloud_name} (region_name: {region_name}) saved_payload "
                "is empty."
            )
            return msg

        if "bootstrap-address" not in subcloud_payload:
            msg = (
                f"Subcloud {subcloud_name} (region_name: {region_name}) does not "
                "have bootstrap-address in saved_payload."
            )
            return msg

        if "systemcontroller_gateway_address" not in subcloud_payload:
            msg = (
                f"Subcloud {subcloud_name} (region_name: {region_name}) does not "
                "have systemcontroller_gateway_address in saved_payload."
            )
            return msg

        return VERIFY_SUBCLOUD_SYNC_VALID

    def _validate_subclouds_for_sync(
        self, subclouds: list[models.Subcloud], dc_client: DcmanagerClient
    ) -> tuple[list[models.Subcloud], dict[str, str]]:
        """Validate subclouds for sync."""
        valid_subclouds = []
        error_msg = {}  # Dictionary to store error message for each subcloud

        for subcloud in subclouds:
            subcloud_name = subcloud.get("name")
            region_name = subcloud.get("region_name")

            validation = self._is_valid_for_subcloud_sync(subcloud)
            if (
                validation != VERIFY_SUBCLOUD_SYNC_IGNORE
                and validation != VERIFY_SUBCLOUD_SYNC_VALID
            ):
                LOG.error(validation)
                error_msg[subcloud_name] = validation
                continue

            try:
                # TODO(lzhu1): Sending requests to fetch the subcloud one by one
                #  should be optimized to fetch them all with one request by calling
                #  the "get_subcloud_list_by_peer_group" method
                peer_subcloud = self.get_peer_subcloud(dc_client, subcloud_name)
                if not peer_subcloud:
                    LOG.info(
                        f"Subcloud '{subcloud_name}' (region_name: {region_name}) does "
                        f"not exist on peer site '{dc_client.peer.peer_name}'"
                    )
                    valid_subclouds.append(subcloud)
                    continue

                if not self.is_subcloud_secondary(
                    peer_subcloud
                ) and self.get_subcloud_deploy_status(peer_subcloud) not in (
                    consts.DEPLOY_STATE_REHOME_FAILED,
                    consts.DEPLOY_STATE_REHOME_PREP_FAILED,
                ):
                    msg = (
                        f"Subcloud {subcloud_name} is not in the right state for sync."
                    )
                    LOG.info(msg)
                    error_msg[subcloud_name] = msg
                    continue

                valid_subclouds.append(subcloud)

            except Exception as e:
                subcloud.msg = str(e)  # Store error message for subcloud
                LOG.error(
                    f"Failed to validate Subcloud {subcloud_name} "
                    f"(region_name: {region_name}): {str(e)}"
                )
                error_msg[subcloud_name] = str(e)

        return valid_subclouds, error_msg

    def _sync_subclouds(
        self, context, peer: models.SystemPeer, dc_local_pg_id: int, dc_peer_pg_id: int
    ) -> dict[str, str]:
        """Sync subclouds of local peer group to peer site.

        :param context: request context object
        :param peer: system peer object of the peer site
        :param dc_local_pg_id: peer group id on local site for sync
        :param dc_peer_pg_id: peer group id on peer site
        """
        dc_client = self.get_peer_dc_client(peer)
        subclouds = db_api.subcloud_get_for_peer_group(context, dc_local_pg_id)

        subclouds_to_sync, error_msg = self._validate_subclouds_for_sync(
            subclouds, dc_client
        )

        # Use thread pool to limit number of operations in parallel
        sync_pool = greenpool.GreenPool(size=MAX_PARALLEL_SUBCLOUD_SYNC)

        # Spawn threads to sync each applicable subcloud
        sync_function = functools.partial(
            self._add_or_update_subcloud,
            dc_client,
            peer.peer_controller_gateway_ip,
            dc_peer_pg_id,
        )

        failed_subclouds, sync_error_msg = self._run_parallel_group_operation(
            "peer sync", sync_function, sync_pool, subclouds_to_sync
        )

        error_msg.update(sync_error_msg)
        LOG.info(
            f"Completed subcloud peer sync with peer '{peer.peer_name}': processed "
            f"{len(subclouds_to_sync)} subclouds, {len(failed_subclouds)} failed"
        )

        dc_local_region_names = set()
        for subcloud in subclouds:
            # Ignore the secondary subclouds to sync with peer site
            if not self.is_subcloud_secondary(subcloud):
                # Count all subcloud need to be sync
                dc_local_region_names.add(subcloud.get("name"))

        dc_peer_subclouds = dc_client.get_subcloud_list_by_peer_group(
            str(dc_peer_pg_id)
        )
        dc_peer_region_names = set(
            subcloud.get("name") for subcloud in dc_peer_subclouds
        )

        dc_peer_subcloud_diff_names = dc_peer_region_names - dc_local_region_names
        for subcloud_to_delete in dc_peer_subcloud_diff_names:
            try:
                LOG.info(
                    f"Deleting subcloud '{subcloud_to_delete}' on "
                    f"peer site '{dc_client.peer.peer_name}'"
                )
                self.delete_peer_secondary_subcloud(dc_client, subcloud_to_delete)
            except Exception as e:
                msg = f"Subcloud delete failed: {str(e)}"
                LOG.error(msg)
                error_msg[subcloud_to_delete] = msg

        return error_msg

    def _update_sync_status(
        self,
        context,
        association_id,
        sync_status,
        sync_message,
        dc_peer_association_id=None,
        dc_client=None,
        **kwargs,
    ):
        """Update sync status of association."""
        if dc_peer_association_id is not None:
            if dc_client is None:
                association = db_api.peer_group_association_get(context, association_id)
                peer = db_api.system_peer_get(context, association.system_peer_id)
                dc_client = self.get_peer_dc_client(peer)
            dc_client.update_peer_group_association_sync_status(
                dc_peer_association_id, sync_status
            )
            LOG.info(
                "Updated non-primary Peer Group Association "
                f"{dc_peer_association_id} sync_status to {sync_status}."
            )
        return db_api.peer_group_association_update(
            context,
            association_id,
            sync_status=sync_status,
            sync_message=sync_message,
            **kwargs,
        )

    def _update_sync_status_to_failed(
        self, context, association_id, failed_message, dc_peer_association_id=None
    ):
        """Update sync status to failed."""
        return self._update_sync_status(
            context,
            association_id,
            consts.ASSOCIATION_SYNC_STATUS_FAILED,
            failed_message,
            dc_peer_association_id,
        )

    def update_association_sync_status(
        self, context, peer_group_id, sync_status, sync_message=None
    ):
        """Update PGA sync status on primary and peer site(s).

        The update of PGA sync status is always triggered on the primary site,
        therefore, this method can only be called on the primary site.

        :param context: request context object
        :param peer_group_id: id of the peer group used to fetch corresponding PGA
        :param sync_status: the sync status to be updated to
        :param sync_message: The sync message to be updated to
        """
        # Collect the association IDs to be synced.
        out_of_sync_associations_ids = set()
        local_peer_gp = db_api.subcloud_peer_group_get(self.context, peer_group_id)
        # Get associations by peer group id
        associations = db_api.peer_group_association_get_by_peer_group_id(
            context, peer_group_id
        )
        if not associations:
            LOG.info(f"No association found for peer group '{peer_group_id}'")
        else:
            for association in associations:
                if sync_status == consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC:
                    out_of_sync_associations_ids.add(association.id)

                pre_sync_status = association.sync_status
                new_sync_status = sync_status
                new_sync_message = sync_message
                if sync_status in (
                    consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                    consts.ASSOCIATION_SYNC_STATUS_OUT_OF_SYNC,
                ):
                    # We don't need sync_message for in-sync and out-of-sync
                    # status, so clear the previous remained message for these
                    # two status.
                    new_sync_message = "None"

                # If the local sync_status already set to unknown, indicating
                # that the peer site is unreachable, we'll change the sync_status
                # to failed directly on the local site without trying to sync
                # the status to the peer site. When the peer site becomes
                # reachable, the primary site monitor will update the failed
                # status to out-of-sync on both sites.
                if pre_sync_status == consts.ASSOCIATION_SYNC_STATUS_UNKNOWN:
                    if sync_status != consts.ASSOCIATION_SYNC_STATUS_IN_SYNC:
                        new_sync_status = consts.ASSOCIATION_SYNC_STATUS_FAILED
                        new_sync_message = (
                            "Failed to update sync_status, "
                            "because the peer site is unreachable."
                        )
                # Update peer site peer association sync_status
                else:
                    # Get system peer by peer id from the association
                    system_peer = db_api.system_peer_get(
                        context, association.system_peer_id
                    )
                    if pre_sync_status != sync_status:
                        SystemPeerManager.update_sync_status(
                            context,
                            system_peer,
                            sync_status,
                            local_peer_gp,
                            None,
                            new_sync_message,
                            association,
                        )
                        # Already update sync_status on both peer and local sites
                        continue

                if pre_sync_status != new_sync_status:
                    # Update local site peer association sync_status
                    db_api.peer_group_association_update(
                        context,
                        association.id,
                        sync_status=new_sync_status,
                        sync_message=new_sync_message,
                    )
                    LOG.info(
                        f"Updated Local Peer Group Association {association.id} "
                        f"sync_status to {new_sync_status}."
                    )

        return out_of_sync_associations_ids

    def update_subcloud_peer_group(
        self,
        context,
        peer_group_id,
        group_state,
        max_subcloud_rehoming,
        group_name,
        new_group_name=None,
    ):
        # Collect the success and failed peer ids.
        success_peer_ids = set()
        failed_peer_ids = set()

        # Get associations by peer group id
        associations = db_api.peer_group_association_get_by_peer_group_id(
            context, peer_group_id
        )
        if not associations:
            LOG.info("No association found for peer group %s" % peer_group_id)
        else:
            for association in associations:
                # Get system peer by peer id from the association
                system_peer = db_api.system_peer_get(
                    context, association.system_peer_id
                )
                # Get 'available' system peer
                if (
                    system_peer.availability_state
                    != consts.SYSTEM_PEER_AVAILABILITY_STATE_AVAILABLE
                ):
                    LOG.warning("Peer system %s offline" % system_peer.id)
                    failed_peer_ids.add(system_peer.id)
                else:
                    try:
                        # Get a client for sending request to this system peer
                        dc_client = self.get_peer_dc_client(system_peer)
                        peer_group_kwargs = {
                            "peer-group-name": new_group_name,
                            "group-state": group_state,
                            "max-subcloud-rehoming": max_subcloud_rehoming,
                        }
                        # Make an API call to update peer group on peer site
                        dc_client.update_subcloud_peer_group(
                            group_name, **peer_group_kwargs
                        )
                        success_peer_ids.add(system_peer.id)
                    except Exception:
                        LOG.error(
                            f"Failed to update Subcloud Peer Group {group_name} on "
                            f"peer site {system_peer.id} with the values: "
                            f"{peer_group_kwargs}"
                        )
                        failed_peer_ids.add(system_peer.id)

        return success_peer_ids, failed_peer_ids

    def _get_non_primary_association(
        self,
        dc_client: DcmanagerClient,
        dc_peer_system_peer_id: int,
        dc_peer_pg_id: int,
    ) -> Optional[dict]:
        """Get non-primary Association from peer site."""
        try:
            return dc_client.get_peer_group_association_with_peer_id_and_pg_id(
                dc_peer_system_peer_id, dc_peer_pg_id
            )
        except dccommon_exceptions.PeerGroupAssociationNotFound:
            LOG.error(
                "Peer group association does not exist on peer site "
                f"'{dc_client.peer.peer_name}'. Peer group ID: {dc_peer_pg_id}, "
                f"peer system peer ID: {dc_peer_system_peer_id}"
            )
            return None

    def _get_peer_site_pg_by_name(
        self, dc_client: DcmanagerClient, peer_group_name: str
    ) -> Optional[dict]:
        """Get remote Peer Group from peer site by name."""
        try:
            return dc_client.get_subcloud_peer_group(peer_group_name)
        except dccommon_exceptions.SubcloudPeerGroupNotFound:
            LOG.error(
                f"Peer group '{peer_group_name}' does not exist on "
                f"peer site '{dc_client.peer.peer_name}'"
            )
            return None

    def _get_peer_site_system_peer(self, dc_client, peer_uuid=None):
        """Get System Peer from peer site."""
        try:
            peer_uuid = (
                peer_uuid if peer_uuid is not None else utils.get_local_system().uuid
            )
            return dc_client.get_system_peer(peer_uuid)
        except dccommon_exceptions.SystemPeerNotFound:
            LOG.error(f"Peer Site System Peer {peer_uuid} does not exist.")
            return None

    def sync_subcloud_peer_group(self, context, association_id, sync_subclouds=True):
        """Sync subcloud peer group to peer site.

        This function synchronizes subcloud peer groups from current site
        to peer site, supporting two scenarios:

        1. When creating the association between the system peer and a subcloud
        peer group. This function creates the subcloud peer group on the
        peer site and synchronizes the subclouds to it.

        2. When synchronizing a subcloud peer group with the peer site. This
        function syncs both the subcloud peer group and the subclouds
        under it to the peer site.

        :param context: request context object
        :param association_id: id of association to sync
        :param sync_subclouds: Enabled to sync subclouds to peer site
        """

        association = db_api.peer_group_association_get(context, association_id)
        peer = db_api.system_peer_get(context, association.system_peer_id)
        dc_local_pg = db_api.subcloud_peer_group_get(context, association.peer_group_id)
        peer_group_name = dc_local_pg.peer_group_name
        dc_peer_association_id = None

        LOG.info(
            f"Syncing peer group association {association_id} that links subcloud "
            f"peer group '{peer_group_name}' with system peer '{peer.peer_name}'"
        )

        try:
            # Check if the system_uuid of the peer site matches with the
            # peer_uuid
            system = self.get_peer_sysinv_client(peer).get_system()
            if system.uuid != peer.peer_uuid:
                LOG.error(
                    f"Peer site '{peer.peer_name}' system uuid {system.uuid} does "
                    f"not match the configured peer_uuid: {peer.peer_uuid}"
                )
                raise exceptions.PeerGroupAssociationTargetNotMatch(uuid=system.uuid)

            dc_client = self.get_peer_dc_client(peer)

            # Get current site system information
            local_system_uuid = utils.get_local_system().uuid

            # Get peer site system peer
            dc_peer_system_peer = self._get_peer_site_system_peer(
                dc_client, local_system_uuid
            )

            if dc_peer_system_peer is None:
                failed_message = (
                    f"A system peer with UUID of {local_system_uuid} "
                    f"does not exist on peer site '{peer.peer_name}'"
                )
                return db_api.peer_group_association_db_model_to_dict(
                    self._update_sync_status_to_failed(
                        context, association_id, failed_message
                    )
                )
            dc_peer_system_peer_id = dc_peer_system_peer.get("id")

            # Get peer site peer group, create if not exist
            dc_peer_pg = self._get_peer_site_pg_by_name(dc_client, peer_group_name)
            if dc_peer_pg is None:
                peer_group_kwargs = {
                    "group-priority": association.peer_group_priority,
                    "group-state": dc_local_pg.group_state,
                    "system-leader-id": dc_local_pg.system_leader_id,
                    "system-leader-name": dc_local_pg.system_leader_name,
                    "max-subcloud-rehoming": dc_local_pg.max_subcloud_rehoming,
                }
                peer_group_kwargs["peer-group-name"] = peer_group_name
                dc_peer_pg = dc_client.add_subcloud_peer_group(**peer_group_kwargs)
                LOG.info(
                    f"Created Subcloud Peer Group {peer_group_name} on "
                    f"peer site '{peer.peer_name}'. ID is {dc_peer_pg.get('id')}."
                )
            dc_peer_pg_id = dc_peer_pg.get("id")
            dc_peer_pg_priority = dc_peer_pg.get("group_priority")
            # Check if the peer group priority is 0, if so, raise exception
            if dc_peer_pg_priority == 0:
                LOG.error(f"Skip update. Peer Site {peer_group_name} has priority 0.")
                raise exceptions.SubcloudPeerGroupHasWrongPriority(
                    priority=dc_peer_pg_priority
                )

            # Get peer site non-primary association, create if not exist
            dc_peer_association = self._get_non_primary_association(
                dc_client, dc_peer_system_peer_id, dc_peer_pg_id
            )
            if dc_peer_association is None:
                non_primary_association_kwargs = {
                    "peer_group_id": dc_peer_pg_id,
                    "system_peer_id": dc_peer_system_peer_id,
                }
                dc_peer_association = dc_client.add_peer_group_association(
                    **non_primary_association_kwargs
                )
                LOG.info(
                    "Created 'non-primary' Peer Group Association "
                    f"{dc_peer_association.get('id')} on peer site '{peer.peer_name}'"
                )
            dc_peer_association_id = dc_peer_association.get("id")

            # Update peer group association sync status to syncing
            dc_client.update_peer_group_association_sync_status(
                dc_peer_association_id, consts.ASSOCIATION_SYNC_STATUS_SYNCING
            )

            # Update peer group on peer site
            peer_group_kwargs = {
                "group-priority": association.peer_group_priority,
                "group-state": dc_local_pg.group_state,
                "system-leader-id": dc_local_pg.system_leader_id,
                "system-leader-name": dc_local_pg.system_leader_name,
                "max-subcloud-rehoming": dc_local_pg.max_subcloud_rehoming,
            }
            dc_peer_pg = dc_client.update_subcloud_peer_group(
                peer_group_name, **peer_group_kwargs
            )
            LOG.info(
                f"Updated Subcloud Peer Group {peer_group_name} on "
                f"peer site '{peer.peer_name}', ID is {dc_peer_pg.get('id')}"
            )

            association_update = {
                "sync_status": consts.ASSOCIATION_SYNC_STATUS_IN_SYNC,
                "sync_message": "None",
                "dc_peer_association_id": dc_peer_association_id,
                "dc_client": dc_client,
            }
            if sync_subclouds:
                error_msg = self._sync_subclouds(
                    context, peer, dc_local_pg.id, dc_peer_pg_id
                )
                if len(error_msg) > 0:
                    LOG.error(
                        f"Failed to sync subcloud(s) in the Subcloud "
                        f"Peer Group {peer_group_name}: {json.dumps(error_msg)}"
                    )
                    association_update["sync_status"] = (
                        consts.ASSOCIATION_SYNC_STATUS_FAILED
                    )
                    association_update["sync_message"] = (
                        f"Failed to sync {list(error_msg.keys())} in the "
                        f"Subcloud Peer Group {peer_group_name}."
                    )
            association = self._update_sync_status(
                context, association_id, **association_update
            )

            self.peer_monitor_manager.peer_monitor_notify(context)

            return db_api.peer_group_association_db_model_to_dict(association)

        except Exception as exception:
            LOG.exception(
                f"Failed to sync peer group {peer_group_name} to "
                f"peer site {peer.peer_name}"
            )
            self._update_sync_status_to_failed(
                context, association_id, str(exception), dc_peer_association_id
            )
            raise exception

    def _delete_primary_association(self, context, association_id):
        """Delete primary peer group association."""
        result = db_api.peer_group_association_destroy(context, association_id)
        self.peer_monitor_manager.peer_monitor_notify(context)
        return result

    def delete_peer_group_association(self, context, association_id):
        """Delete association and remove related association from peer site.

        :param context: request context object.
        :param association_id: id of association to delete
        """

        # Retrieve the peer group association details from the database
        association = db_api.peer_group_association_get(context, association_id)
        peer = db_api.system_peer_get(context, association.system_peer_id)
        dc_local_pg = db_api.subcloud_peer_group_get(context, association.peer_group_id)
        peer_group_name = dc_local_pg.peer_group_name

        LOG.info(
            f"Deleting peer group association ({association_id=}, "
            f"peer={peer.peer_name}, peer_group_id={dc_local_pg.id})"
        )

        try:
            # Check if the system_uuid of the peer site matches with the
            # peer_uuid
            system = self.get_peer_sysinv_client(peer).get_system()
            if system.uuid != peer.peer_uuid:
                LOG.warning(
                    f"Peer site system uuid {system.uuid} does not "
                    f"match with the peer_uuid {peer.peer_uuid}"
                )
                return self._delete_primary_association(context, association_id)

            dc_client = self.get_peer_dc_client(peer)

            # Get current site system information
            local_system_uuid = utils.get_local_system().uuid

            # Get peer site system peer
            dc_peer_system_peer = self._get_peer_site_system_peer(
                dc_client, local_system_uuid
            )

            # Get peer site peer group
            dc_peer_pg = self._get_peer_site_pg_by_name(dc_client, peer_group_name)

            if dc_peer_pg is None:
                # peer group does not exist on peer site, the association should
                # be deleted
                LOG.warning(
                    f"Subcloud Peer Group {peer_group_name} does "
                    f"not exist on peer site '{peer.peer_name}'"
                )
                return self._delete_primary_association(context, association_id)

            dc_peer_pg_id = dc_peer_pg.get("id")
            dc_peer_pg_priority = dc_peer_pg.get("group_priority")
            # Check if the peer group priority is 0, if so, raise exception
            if dc_peer_pg_priority == 0:
                LOG.error(
                    f"Failed to delete peer_group_association. Peer Group: "
                    f"{peer_group_name} has priority 0 on peer site '{peer.peer_name}'"
                )
                raise exceptions.SubcloudPeerGroupHasWrongPriority(
                    priority=dc_peer_pg_priority
                )

            # Use thread pool to limit number of operations in parallel
            delete_pool = greenpool.GreenPool(size=MAX_PARALLEL_SUBCLOUD_DELETE)
            subclouds = db_api.subcloud_get_for_peer_group(context, dc_local_pg.id)
            # Spawn threads to delete each subcloud
            clean_function = functools.partial(self._delete_subcloud, dc_client)

            _, delete_error_msg = self._run_parallel_group_operation(
                "peer subcloud clean", clean_function, delete_pool, subclouds
            )

            if delete_error_msg:
                LOG.error(
                    "Failed to delete subcloud(s) from the Subcloud Peer Group "
                    f"'{peer_group_name}' on peer site '{peer.peer_name}': "
                    f"{json.dumps(delete_error_msg)}"
                )
                sync_message = (
                    f"Deletion of {list(delete_error_msg.keys())} from the "
                    f"Subcloud Peer Group: {peer_group_name} on the peer site "
                    f"'{peer.peer_name}' failed."
                )
                self._update_sync_status_to_failed(
                    context, association_id, sync_message
                )
                return

            # System Peer does not exist on peer site, delete peer group
            if dc_peer_system_peer is None:
                try:
                    dc_client.delete_subcloud_peer_group(peer_group_name)
                    LOG.info(
                        f"Deleted Subcloud Peer Group {peer_group_name} on "
                        f"peer site '{peer.peer_name}'"
                    )
                except dccommon_exceptions.SubcloudPeerGroupDeleteFailedAssociated:
                    LOG.error(
                        f"Subcloud Peer Group {peer_group_name} delete failed "
                        f"as it is associated with System Peer on peer site "
                        f"'{peer.peer_name}'"
                    )
                return self._delete_primary_association(context, association_id)
            dc_peer_system_peer_id = dc_peer_system_peer.get("id")

            # Get peer site non-primary association
            dc_peer_association = self._get_non_primary_association(
                dc_client, dc_peer_system_peer_id, dc_peer_pg_id
            )
            # Delete peer group association on peer site if exist
            if dc_peer_association is not None:
                dc_peer_association_id = dc_peer_association.get("id")
                dc_client.delete_peer_group_association(dc_peer_association_id)
            elif dc_peer_association is None:
                LOG.warning(
                    f"PeerGroupAssociation does not exist on peer site "
                    f"'{peer.peer_name}'. Peer Group ID: {dc_peer_pg_id}, "
                    f"peer site System Peer ID: {dc_peer_system_peer_id}"
                )

            try:
                dc_client.delete_subcloud_peer_group(peer_group_name)
                LOG.info(
                    f"Deleted Subcloud Peer Group {peer_group_name} on "
                    f"peer site '{peer.peer_name}'"
                )
            except dccommon_exceptions.SubcloudPeerGroupDeleteFailedAssociated:
                failed_message = (
                    f"Subcloud Peer Group {peer_group_name} delete failed as it "
                    f"is associated with system peer on peer site '{peer.peer_name}'"
                )
                self._update_sync_status_to_failed(
                    context, association_id, failed_message
                )
                LOG.error(failed_message)
                raise

            return self._delete_primary_association(context, association_id)

        except Exception as exception:
            LOG.exception(f"Failed to delete peer_group_association {association.id}")
            raise exception

    def handle_association_operations_in_progress(self):
        """Identify associations in transitory stages and update association

        state to failure.
        """

        LOG.info("Identifying associations in transitory stages.")

        associations = db_api.peer_group_association_get_all(self.context)

        for association in associations:
            # Identify associations in transitory states
            new_sync_status = TRANSITORY_STATES.get(association.sync_status)

            # update syncing states to the corresponding failure states
            if new_sync_status:
                LOG.info(
                    f"Changing association {association.id} sync status "
                    f"from {association.sync_status} to {new_sync_status}"
                )

                db_api.peer_group_association_update(
                    self.context,
                    association.id,
                    sync_status=new_sync_status or association.sync_status,
                    sync_message="Service restart during syncing",
                )
