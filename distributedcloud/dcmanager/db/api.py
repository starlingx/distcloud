# Copyright (c) 2015 Ericsson AB.
# Copyright (c) 2017-2024 Wind River Systems, Inc.
# All Rights Reserved.
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

"""
Interface for database access.

SQLAlchemy is currently the only supported backend.
"""

from oslo_config import cfg
from oslo_db import api

from dccommon import consts as dccommon_consts
from dcmanager.db.sqlalchemy import models

CONF = cfg.CONF

_BACKEND_MAPPING = {"sqlalchemy": "dcmanager.db.sqlalchemy.api"}

IMPL = api.DBAPI.from_config(CONF, backend_mapping=_BACKEND_MAPPING)


def get_engine():
    return IMPL.get_engine()


def get_session():
    return IMPL.get_session()


# subcloud audit db methods

##########################


def subcloud_audits_get(context, subcloud_id):
    """Get subcloud_audits info for a subcloud."""
    return IMPL.subcloud_audits_get(context, subcloud_id)


def subcloud_audits_get_all(context, subcloud_ids=None):
    """Get subcloud_audits info for  subclouds."""
    return IMPL.subcloud_audits_get_all(context, subcloud_ids)


def subcloud_audits_update_all(context, values):
    """Mark sub-audits as needed for all subclouds."""
    return IMPL.subcloud_audits_update_all(context, values)


def subcloud_audits_create(context, subcloud_id):
    """Create subcloud_audits info for a subcloud."""
    return IMPL.subcloud_audits_create(context, subcloud_id)


def subcloud_audits_update(context, subcloud_id, values):
    """Get all subcloud_audits that need auditing."""
    return IMPL.subcloud_audits_update(context, subcloud_id, values)


def subcloud_audits_get_all_need_audit(context, last_audit_threshold):
    """Get all subcloud_audits that need auditing."""
    return IMPL.subcloud_audits_get_all_need_audit(context, last_audit_threshold)


# In the functions below it would be cleaner if the timestamp were calculated
# by the DB server.  If server time is in UTC func.now() might work.


def subcloud_audits_get_and_start_audit(context, subcloud_id):
    """Set the 'audit started' timestamp for the main audit."""
    return IMPL.subcloud_audits_get_and_start_audit(context, subcloud_id)


def subcloud_audits_bulk_end_audit(context, audits_finished):
    """Update the subcloud's audit end status in a bulk request"""
    return IMPL.subcloud_audits_bulk_end_audit(context, audits_finished)


def subcloud_audits_bulk_update_audit_finished_at(context, subcloud_ids):
    """Set the 'audit finished' timestamp for the main audit in bulk."""
    return IMPL.subcloud_audits_bulk_update_audit_finished_at(context, subcloud_ids)


def subcloud_audits_fix_expired_audits(
    context, last_audit_threshold, trigger_audits=False
):
    return IMPL.subcloud_audits_fix_expired_audits(
        context, last_audit_threshold, trigger_audits
    )


# subcloud db methods

###################


def subcloud_db_model_to_dict(subcloud):
    """Convert subcloud db model to dictionary."""
    result = {
        "id": subcloud.id,
        "name": subcloud.name,
        "description": subcloud.description,
        "location": subcloud.location,
        "software-version": subcloud.software_version,
        "management-state": subcloud.management_state,
        "availability-status": subcloud.availability_status,
        "deploy-status": subcloud.deploy_status,
        "backup-status": subcloud.backup_status,
        "backup-datetime": subcloud.backup_datetime,
        "error-description": subcloud.error_description,
        "region-name": subcloud.region_name,
        "management-subnet": subcloud.management_subnet,
        "management-start-ip": subcloud.management_start_ip,
        "management-end-ip": subcloud.management_end_ip,
        "management-gateway-ip": subcloud.management_gateway_ip,
        "openstack-installed": subcloud.openstack_installed,
        "prestage-status": subcloud.prestage_status,
        "prestage-versions": subcloud.prestage_versions,
        "systemcontroller-gateway-ip": subcloud.systemcontroller_gateway_ip,
        "data_install": subcloud.data_install,
        "data_upgrade": subcloud.data_upgrade,
        "created-at": subcloud.created_at,
        "updated-at": subcloud.updated_at,
        "group_id": subcloud.group_id,
        "peer_group_id": subcloud.peer_group_id,
        "rehome_data": subcloud.rehome_data,
    }
    return result


def subcloud_create(
    context,
    name,
    description,
    location,
    software_version,
    management_subnet,
    management_gateway_ip,
    management_start_ip,
    management_end_ip,
    systemcontroller_gateway_ip,
    external_oam_subnet_ip_family,
    deploy_status,
    error_description,
    region_name,
    openstack_installed,
    group_id,
    data_install=None,
):
    """Create a subcloud."""
    return IMPL.subcloud_create(
        context,
        name,
        description,
        location,
        software_version,
        management_subnet,
        management_gateway_ip,
        management_start_ip,
        management_end_ip,
        systemcontroller_gateway_ip,
        external_oam_subnet_ip_family,
        deploy_status,
        error_description,
        region_name,
        openstack_installed,
        group_id,
        data_install,
    )


def subcloud_get(context, subcloud_id):
    """Retrieve a subcloud or raise if it does not exist."""
    return IMPL.subcloud_get(context, subcloud_id)


def subcloud_get_with_status(context, subcloud_id):
    """Retrieve a subcloud and all endpoint sync statuses."""
    return IMPL.subcloud_get_with_status(context, subcloud_id)


def subcloud_get_by_name(context, name) -> models.Subcloud:
    """Retrieve a subcloud by name or raise if it does not exist."""
    return IMPL.subcloud_get_by_name(context, name)


def subcloud_get_by_region_name(context, region_name):
    """Retrieve a subcloud by region name or raise if it does not exist."""
    return IMPL.subcloud_get_by_region_name(context, region_name)


def subcloud_get_by_name_or_region_name(context, name):
    """Retrieve a subcloud by name or region name or raise if it does not exist."""
    return IMPL.subcloud_get_by_name_or_region_name(context, name)


def subcloud_get_all(context):
    """Retrieve all subclouds."""
    return IMPL.subcloud_get_all(context)


def subcloud_get_all_by_group_id(context, group_id):
    """Retrieve all subclouds that belong to the specified group id"""
    return IMPL.subcloud_get_all_by_group_id(context, group_id)


def subcloud_get_all_ordered_by_id(context):
    """Retrieve all subclouds ordered by id."""
    return IMPL.subcloud_get_all_ordered_by_id(context)


def subcloud_get_all_with_status(context):
    """Retrieve all subclouds and sync statuses."""
    return IMPL.subcloud_get_all_with_status(context)


def subcloud_get_all_valid_for_strategy_step_creation(
    context,
    endpoint_type,
    group_id=None,
    subcloud_name=None,
    availability_status=None,
    sync_status=None,
):
    """Queries all the subclouds that are valid for the strategy step to create"""
    return IMPL.subcloud_get_all_valid_for_strategy_step_creation(
        context,
        endpoint_type,
        group_id,
        subcloud_name,
        availability_status,
        sync_status,
    )


def subcloud_count_invalid_for_strategy_type(
    context, endpoint_type, group_id=None, subcloud_name=None
):
    """Queries the count of invalid subclouds for a strategy's creation"""
    return IMPL.subcloud_count_invalid_for_strategy_type(
        context, endpoint_type, group_id, subcloud_name
    )


def subcloud_update(
    context,
    subcloud_id,
    management_state=None,
    availability_status=None,
    software_version=None,
    name=None,
    description=None,
    management_subnet=None,
    management_gateway_ip=None,
    management_start_ip=None,
    management_end_ip=None,
    location=None,
    audit_fail_count=None,
    deploy_status=None,
    backup_status=None,
    backup_datetime=None,
    error_description=None,
    openstack_installed=None,
    group_id=None,
    data_install=None,
    data_upgrade=None,
    first_identity_sync_complete=None,
    systemcontroller_gateway_ip=None,
    external_oam_subnet_ip_family=None,
    peer_group_id=None,
    rehome_data=None,
    rehomed=None,
    prestage_status=None,
    prestage_versions=None,
    region_name=None,
):
    """Update a subcloud or raise if it does not exist."""
    return IMPL.subcloud_update(
        context,
        subcloud_id,
        management_state,
        availability_status,
        software_version,
        name,
        description,
        management_subnet,
        management_gateway_ip,
        management_start_ip,
        management_end_ip,
        location,
        audit_fail_count,
        deploy_status,
        backup_status,
        backup_datetime,
        error_description,
        openstack_installed,
        group_id,
        data_install,
        data_upgrade,
        first_identity_sync_complete,
        systemcontroller_gateway_ip,
        external_oam_subnet_ip_family,
        peer_group_id,
        rehome_data,
        rehomed,
        prestage_status,
        prestage_versions,
        region_name,
    )


def subcloud_bulk_update_by_ids(context, subcloud_ids, update_form):
    """Update subclouds in bulk using a set of subcloud IDs."""
    return IMPL.subcloud_bulk_update_by_ids(context, subcloud_ids, update_form)


def subcloud_destroy(context, subcloud_id):
    """Destroy the subcloud or raise if it does not exist."""
    return IMPL.subcloud_destroy(context, subcloud_id)


def subcloud_status_create(context, subcloud_id, endpoint_type):
    """Create a subcloud status for an endpoint_type."""
    return IMPL.subcloud_status_create(context, subcloud_id, endpoint_type)


def subcloud_status_create_all(context, subcloud_id):
    """Create a subcloud status for all endpoint_types."""
    return IMPL.subcloud_status_create_all(context, subcloud_id)


def subcloud_status_delete(context, subcloud_id, endpoint_type):
    """Delete a subcloud status for an endpoint_type."""
    return IMPL.subcloud_status_delete(context, subcloud_id, endpoint_type)


def subcloud_status_db_model_to_dict(subcloud_status):
    """Convert subcloud status db model to dictionary."""
    if subcloud_status:
        result = {
            "subcloud_id": subcloud_status.subcloud_id,
            "sync_status": subcloud_status.sync_status,
        }
    else:
        result = {"subcloud_id": 0, "sync_status": "unknown"}

    return result


def subcloud_endpoint_status_db_model_to_dict(subcloud_status):
    """Convert endpoint subcloud db model to dictionary."""
    if subcloud_status:
        result = {
            "endpoint_type": subcloud_status.endpoint_type,
            "sync_status": subcloud_status.sync_status,
        }
    else:
        result = {}

    return result


def subcloud_status_get(context, subcloud_id, endpoint_type):
    """Retrieve the subcloud status for an endpoint

    Will raise if subcloud does not exist.
    """

    return IMPL.subcloud_status_get(context, subcloud_id, endpoint_type)


def subcloud_status_get_all(context, subcloud_id):
    """Retrieve all statuses for a subcloud."""
    return IMPL.subcloud_status_get_all(context, subcloud_id)


def subcloud_status_get_all_by_name(context, name):
    """Retrieve all statuses for a subcloud by name."""
    return IMPL.subcloud_status_get_all_by_name(context, name)


def subcloud_status_update(context, subcloud_id, endpoint_type, sync_status):
    """Update the status of a subcloud or raise if it does not exist."""
    return IMPL.subcloud_status_update(context, subcloud_id, endpoint_type, sync_status)


def subcloud_status_update_endpoints(
    context, subcloud_id, endpoint_type_list, sync_status
):
    """Update all statuses of the endpoints in endpoint_type_list of a subcloud."""

    return IMPL.subcloud_status_update_endpoints(
        context, subcloud_id, endpoint_type_list, sync_status
    )


def subcloud_status_bulk_update_endpoints(context, subcloud_id, endpoint_list):
    """Update the status of the specified endpoints for a subcloud"""

    return IMPL.subcloud_status_bulk_update_endpoints(
        context, subcloud_id, endpoint_list
    )


def subcloud_status_destroy_all(context, subcloud_id):
    """Destroy all the statuses for a subcloud

    Will raise if subcloud does not exist.
    """

    return IMPL.subcloud_status_destroy_all(context, subcloud_id)


###################
# subcloud_group


def subcloud_group_db_model_to_dict(subcloud_group):
    """Convert subcloud_group db model to dictionary."""
    result = {
        "id": subcloud_group.id,
        "name": subcloud_group.name,
        "description": subcloud_group.description,
        "update_apply_type": subcloud_group.update_apply_type,
        "max_parallel_subclouds": subcloud_group.max_parallel_subclouds,
        "created-at": subcloud_group.created_at,
        "updated-at": subcloud_group.updated_at,
    }
    return result


def subcloud_group_create(
    context, name, description, update_apply_type, max_parallel_subclouds
):
    """Create a subcloud_group."""
    return IMPL.subcloud_group_create(
        context, name, description, update_apply_type, max_parallel_subclouds
    )


def subcloud_group_get(context, group_id):
    """Retrieve a subcloud_group or raise if it does not exist."""
    return IMPL.subcloud_group_get(context, group_id)


def subcloud_group_get_by_name(context, name):
    """Retrieve a subcloud_group b name or raise if it does not exist."""
    return IMPL.subcloud_group_get_by_name(context, name)


def subcloud_group_get_all(context):
    """Retrieve all subcloud groups."""
    return IMPL.subcloud_group_get_all(context)


def subcloud_get_for_group(context, group_id):
    """Retrieve a subcloud_group or raise if it does not exist."""
    return IMPL.subcloud_get_for_group(context, group_id)


def subcloud_group_update(
    context, group_id, name, description, update_apply_type, max_parallel_subclouds
):
    """Update the subcloud group or raise if it does not exist."""
    return IMPL.subcloud_group_update(
        context, group_id, name, description, update_apply_type, max_parallel_subclouds
    )


def subcloud_group_destroy(context, group_id):
    """Destroy the subcloud group or raise if it does not exist."""
    return IMPL.subcloud_group_destroy(context, group_id)


###################
# system_peer
def system_peer_db_model_to_dict(system_peer):
    """Convert system_peer db model to dictionary."""
    result = {
        "id": system_peer.id,
        "peer-uuid": system_peer.peer_uuid,
        "peer-name": system_peer.peer_name,
        "manager-endpoint": system_peer.manager_endpoint,
        "manager-username": system_peer.manager_username,
        "peer-controller-gateway-address": system_peer.peer_controller_gateway_ip,
        "administrative-state": system_peer.administrative_state,
        "heartbeat-interval": system_peer.heartbeat_interval,
        "heartbeat-failure-threshold": system_peer.heartbeat_failure_threshold,
        "heartbeat-failure-policy": system_peer.heartbeat_failure_policy,
        "heartbeat-maintenance-timeout": system_peer.heartbeat_maintenance_timeout,
        "availability-state": system_peer.availability_state,
        "created-at": system_peer.created_at,
        "updated-at": system_peer.updated_at,
    }
    return result


def system_peer_create(
    context,
    peer_uuid,
    peer_name,
    endpoint,
    username,
    password,
    gateway_ip,
    administrative_state,
    heartbeat_interval,
    heartbeat_failure_threshold,
    heartbeat_failure_policy,
    heartbeat_maintenance_timeout,
):
    """Create a system_peer."""
    return IMPL.system_peer_create(
        context,
        peer_uuid,
        peer_name,
        endpoint,
        username,
        password,
        gateway_ip,
        administrative_state,
        heartbeat_interval,
        heartbeat_failure_threshold,
        heartbeat_failure_policy,
        heartbeat_maintenance_timeout,
    )


def system_peer_get(context, peer_id) -> models.SystemPeer:
    """Retrieve a system_peer or raise if it does not exist."""
    return IMPL.system_peer_get(context, peer_id)


def system_peer_get_by_uuid(context, uuid) -> models.SystemPeer:
    """Retrieve a system_peer by uuid or raise if it does not exist."""
    return IMPL.system_peer_get_by_uuid(context, uuid)


def system_peer_get_by_name(context, uuid) -> models.SystemPeer:
    """Retrieve a system_peer by name or raise if it does not exist."""
    return IMPL.system_peer_get_by_name(context, uuid)


def system_peer_get_all(context) -> list[models.SystemPeer]:
    """Retrieve all system peers."""
    return IMPL.system_peer_get_all(context)


def peer_group_get_for_system_peer(context, peer_id) -> list[models.SubcloudPeerGroup]:
    """Get subcloud peer groups associated with a system peer."""
    return IMPL.peer_group_get_for_system_peer(context, peer_id)


def system_peer_update(
    context,
    peer_id,
    peer_uuid=None,
    peer_name=None,
    endpoint=None,
    username=None,
    password=None,
    gateway_ip=None,
    administrative_state=None,
    heartbeat_interval=None,
    heartbeat_failure_threshold=None,
    heartbeat_failure_policy=None,
    heartbeat_maintenance_timeout=None,
    availability_state=None,
):
    """Update the system peer or raise if it does not exist."""
    return IMPL.system_peer_update(
        context,
        peer_id,
        peer_uuid,
        peer_name,
        endpoint,
        username,
        password,
        gateway_ip,
        administrative_state,
        heartbeat_interval,
        heartbeat_failure_threshold,
        heartbeat_failure_policy,
        heartbeat_maintenance_timeout,
        availability_state,
    )


def system_peer_destroy(context, peer_id):
    """Destroy the system peer or raise if it does not exist."""
    return IMPL.system_peer_destroy(context, peer_id)


###################


###################
# subcloud_peer_group
def subcloud_peer_group_db_model_to_dict(subcloud_peer_group):
    """Convert subcloud_peer_group db model to dictionary."""
    result = {
        "id": subcloud_peer_group.id,
        "peer_group_name": subcloud_peer_group.peer_group_name,
        "group_priority": subcloud_peer_group.group_priority,
        "group_state": subcloud_peer_group.group_state,
        "max_subcloud_rehoming": subcloud_peer_group.max_subcloud_rehoming,
        "system_leader_id": subcloud_peer_group.system_leader_id,
        "system_leader_name": subcloud_peer_group.system_leader_name,
        "migration_status": subcloud_peer_group.migration_status,
        "created-at": subcloud_peer_group.created_at,
        "updated-at": subcloud_peer_group.updated_at,
    }
    return result


def subcloud_peer_group_create(
    context,
    peer_group_name,
    group_priority,
    group_state,
    max_subcloud_rehoming,
    system_leader_id,
    system_leader_name,
    migration_status=None,
):
    """Create a subcloud_peer_group."""
    return IMPL.subcloud_peer_group_create(
        context,
        peer_group_name,
        group_priority,
        group_state,
        max_subcloud_rehoming,
        system_leader_id,
        system_leader_name,
        migration_status,
    )


def subcloud_peer_group_destroy(context, group_id):
    """Destroy the subcloud peer group or raise if it does not exist."""
    return IMPL.subcloud_peer_group_destroy(context, group_id)


def subcloud_peer_group_get(context, group_id) -> models.SubcloudPeerGroup:
    """Retrieve a subcloud_peer_group or raise if it does not exist."""
    return IMPL.subcloud_peer_group_get(context, group_id)


def subcloud_peer_group_get_by_name(context, name) -> models.SubcloudPeerGroup:
    """Retrieve a subcloud_peer_group by name or raise if it does not exist."""
    return IMPL.subcloud_peer_group_get_by_name(context, name)


def subcloud_peer_group_get_by_leader_id(
    context, system_leader_id
) -> list[models.SubcloudPeerGroup]:
    """Retrieve subcloud peer groups by system_leader_id."""
    return IMPL.subcloud_peer_group_get_by_leader_id(context, system_leader_id)


def subcloud_get_for_peer_group(context, group_id) -> list[models.Subcloud]:
    """Retrieve all subclouds belonging to a subcloud_peer_group

    or raise if it does not exist.
    """
    return IMPL.subcloud_get_for_peer_group(context, group_id)


def subcloud_peer_group_get_all(context) -> list[models.SubcloudPeerGroup]:
    """Retrieve all subcloud peer groups."""
    return IMPL.subcloud_peer_group_get_all(context)


def subcloud_peer_group_update(
    context,
    group_id,
    peer_group_name=None,
    group_priority=None,
    group_state=None,
    max_subcloud_rehoming=None,
    system_leader_id=None,
    system_leader_name=None,
    migration_status=None,
):
    """Update the subcloud peer group or raise if it does not exist."""
    return IMPL.subcloud_peer_group_update(
        context,
        group_id,
        peer_group_name,
        group_priority,
        group_state,
        max_subcloud_rehoming,
        system_leader_id,
        system_leader_name,
        migration_status,
    )


###################


###################
# peer_group_association
def peer_group_association_db_model_to_dict(peer_group_association):
    """Convert peer_group_association db model to dictionary."""
    result = {
        "id": peer_group_association.id,
        "peer-group-id": peer_group_association.peer_group_id,
        "system-peer-id": peer_group_association.system_peer_id,
        "peer-group-priority": peer_group_association.peer_group_priority,
        "association-type": peer_group_association.association_type,
        "sync-status": peer_group_association.sync_status,
        "sync-message": peer_group_association.sync_message,
        "created-at": peer_group_association.created_at,
        "updated-at": peer_group_association.updated_at,
    }
    return result


def peer_group_association_create(
    context,
    peer_group_id,
    system_peer_id,
    peer_group_priority,
    association_type=None,
    sync_status=None,
    sync_message=None,
):
    """Create a peer_group_association."""
    return IMPL.peer_group_association_create(
        context,
        peer_group_id,
        system_peer_id,
        peer_group_priority,
        association_type,
        sync_status,
        sync_message,
    )


def peer_group_association_update(
    context, id, peer_group_priority=None, sync_status=None, sync_message=None
):
    """Update the system peer or raise if it does not exist."""
    return IMPL.peer_group_association_update(
        context, id, peer_group_priority, sync_status, sync_message
    )


def peer_group_association_destroy(context, id):
    """Destroy the peer_group_association or raise if it does not exist."""
    return IMPL.peer_group_association_destroy(context, id)


def peer_group_association_get(context, id) -> models.PeerGroupAssociation:
    """Retrieve a peer_group_association or raise if it does not exist."""
    return IMPL.peer_group_association_get(context, id)


def peer_group_association_get_all(context) -> list[models.PeerGroupAssociation]:
    """Retrieve all peer_group_associations."""
    return IMPL.peer_group_association_get_all(context)


def peer_group_association_get_by_peer_group_and_system_peer_id(
    context, peer_group_id, system_peer_id
) -> list[models.PeerGroupAssociation]:
    """Get peer group associations by peer_group_id and system_peer_id."""
    return IMPL.peer_group_association_get_by_peer_group_and_system_peer_id(
        context, peer_group_id, system_peer_id
    )


def peer_group_association_get_by_peer_group_id(
    context, peer_group_id
) -> list[models.PeerGroupAssociation]:
    """Get the peer_group_association list by peer_group_id"""
    return IMPL.peer_group_association_get_by_peer_group_id(context, peer_group_id)


def peer_group_association_get_by_system_peer_id(
    context, system_peer_id
) -> list[models.PeerGroupAssociation]:
    """Get the peer_group_association list by system_peer_id"""
    return IMPL.peer_group_association_get_by_system_peer_id(context, system_peer_id)


###################


def sw_update_strategy_db_model_to_dict(sw_update_strategy):
    """Convert sw update db model to dictionary."""
    result = {
        "id": sw_update_strategy.id,
        "type": sw_update_strategy.type,
        "subcloud-apply-type": sw_update_strategy.subcloud_apply_type,
        "max-parallel-subclouds": sw_update_strategy.max_parallel_subclouds,
        "stop-on-failure": sw_update_strategy.stop_on_failure,
        "state": sw_update_strategy.state,
        "created-at": sw_update_strategy.created_at,
        "updated-at": sw_update_strategy.updated_at,
        "extra-args": sw_update_strategy.extra_args,
    }
    return result


def sw_update_strategy_create(
    context,
    type,
    subcloud_apply_type,
    max_parallel_subclouds,
    stop_on_failure,
    state,
    extra_args=None,
):
    """Create a sw update."""
    return IMPL.sw_update_strategy_create(
        context,
        type,
        subcloud_apply_type,
        max_parallel_subclouds,
        stop_on_failure,
        state,
        extra_args=extra_args,
    )


def sw_update_strategy_get(context, update_type=None):
    """Retrieve a sw update or raise if it does not exist."""
    return IMPL.sw_update_strategy_get(context, update_type=update_type)


def sw_update_strategy_update(
    context, state=None, update_type=None, additional_args=None
):
    """Update a sw update or raise if it does not exist."""
    return IMPL.sw_update_strategy_update(
        context, state, update_type=update_type, additional_args=additional_args
    )


def sw_update_strategy_destroy(context, update_type=None):
    """Destroy the sw update or raise if it does not exist."""
    return IMPL.sw_update_strategy_destroy(context, update_type=update_type)


###################


def strategy_step_db_model_to_dict(strategy_step):
    """Convert patch strategy db model to dictionary."""
    if strategy_step.subcloud is not None:
        cloud = strategy_step.subcloud.name
    else:
        cloud = dccommon_consts.SYSTEM_CONTROLLER_NAME
    result = {
        "id": strategy_step.id,
        "cloud": cloud,
        "stage": strategy_step.stage,
        "state": strategy_step.state,
        "details": strategy_step.details,
        "started-at": strategy_step.started_at,
        "finished-at": strategy_step.finished_at,
        "created-at": strategy_step.created_at,
        "updated-at": strategy_step.updated_at,
    }
    return result


def strategy_step_get(context, subcloud_id):
    """Retrieve the patch strategy step for a subcloud ID.

    Will raise if subcloud does not exist.
    """

    return IMPL.strategy_step_get(context, subcloud_id)


def strategy_step_get_by_name(context, name):
    """Retrieve the patch strategy step for a subcloud name."""
    return IMPL.strategy_step_get_by_name(context, name)


def strategy_step_get_all(context):
    """Retrieve all patch strategy steps."""
    return IMPL.strategy_step_get_all(context)


def strategy_step_bulk_create(context, subcloud_ids, stage, state, details):
    """Creates the strategy step for a list of subclouds"""
    return IMPL.strategy_step_bulk_create(context, subcloud_ids, stage, state, details)


def strategy_step_create(context, subcloud_id, stage, state, details):
    """Create a patch strategy step."""
    return IMPL.strategy_step_create(context, subcloud_id, stage, state, details)


def strategy_step_update(
    context,
    subcloud_id,
    stage=None,
    state=None,
    details=None,
    started_at=None,
    finished_at=None,
):
    """Update a patch strategy step or raise if it does not exist."""
    return IMPL.strategy_step_update(
        context, subcloud_id, stage, state, details, started_at, finished_at
    )


def strategy_step_destroy_all(context):
    """Destroy all the patch strategy steps."""
    return IMPL.strategy_step_destroy_all(context)


###################


def sw_update_opts_w_name_db_model_to_dict(sw_update_opts, subcloud_name):
    """Convert sw update options db model plus subcloud name to dictionary."""
    result = {
        "id": sw_update_opts.id,
        "name": subcloud_name,
        "subcloud-id": sw_update_opts.subcloud_id,
        "storage-apply-type": sw_update_opts.storage_apply_type,
        "worker-apply-type": sw_update_opts.worker_apply_type,
        "max-parallel-workers": sw_update_opts.max_parallel_workers,
        "alarm-restriction-type": sw_update_opts.alarm_restriction_type,
        "default-instance-action": sw_update_opts.default_instance_action,
        "created-at": sw_update_opts.created_at,
        "updated-at": sw_update_opts.updated_at,
    }
    return result


def sw_update_opts_create(
    context,
    subcloud_id,
    storage_apply_type,
    worker_apply_type,
    max_parallel_workers,
    alarm_restriction_type,
    default_instance_action,
):
    """Create sw update options."""
    return IMPL.sw_update_opts_create(
        context,
        subcloud_id,
        storage_apply_type,
        worker_apply_type,
        max_parallel_workers,
        alarm_restriction_type,
        default_instance_action,
    )


def sw_update_opts_get(context, subcloud_id):
    """Retrieve sw update options."""
    return IMPL.sw_update_opts_get(context, subcloud_id)


def sw_update_opts_get_all_plus_subcloud_info(context):
    """Retrieve sw update options plus subcloud info."""
    return IMPL.sw_update_opts_get_all_plus_subcloud_info(context)


def sw_update_opts_update(
    context,
    subcloud_id,
    storage_apply_type=None,
    worker_apply_type=None,
    max_parallel_workers=None,
    alarm_restriction_type=None,
    default_instance_action=None,
):
    """Update sw update options or raise if it does not exist."""
    return IMPL.sw_update_opts_update(
        context,
        subcloud_id,
        storage_apply_type,
        worker_apply_type,
        max_parallel_workers,
        alarm_restriction_type,
        default_instance_action,
    )


def sw_update_opts_destroy(context, subcloud_id):
    """Destroy sw update options or raise if it does not exist."""
    return IMPL.sw_update_opts_destroy(context, subcloud_id)


###################
def sw_update_opts_default_create(
    context,
    storage_apply_type,
    worker_apply_type,
    max_parallel_workers,
    alarm_restriction_type,
    default_instance_action,
):
    """Create default sw update options."""
    return IMPL.sw_update_opts_default_create(
        context,
        storage_apply_type,
        worker_apply_type,
        max_parallel_workers,
        alarm_restriction_type,
        default_instance_action,
    )


def sw_update_opts_default_get(context):
    """Retrieve default sw update options."""
    return IMPL.sw_update_opts_default_get(context)


def sw_update_opts_default_update(
    context,
    storage_apply_type=None,
    worker_apply_type=None,
    max_parallel_workers=None,
    alarm_restriction_type=None,
    default_instance_action=None,
):
    """Update default sw update options."""
    return IMPL.sw_update_opts_default_update(
        context,
        storage_apply_type,
        worker_apply_type,
        max_parallel_workers,
        alarm_restriction_type,
        default_instance_action,
    )


def sw_update_opts_default_destroy(context):
    """Destroy the default sw update options or raise if it does not exist."""
    return IMPL.sw_update_opts_default_destroy(context)


###################


def db_sync(engine, version=None):
    """Migrate the database to `version` or the most recent version."""
    return IMPL.db_sync(engine, version=version)


def db_version(engine):
    """Display the current database version."""
    return IMPL.db_version(engine)


# Alarm Resources
###################
def subcloud_alarms_get(context, name):
    return IMPL.subcloud_alarms_get(context, name)


def subcloud_alarms_get_all(context, name=None):
    return IMPL.subcloud_alarms_get_all(context, name=name)


def subcloud_alarms_create(context, name, values):
    return IMPL.subcloud_alarms_create(context, name, values)


def subcloud_alarms_update(context, name, values):
    return IMPL.subcloud_alarms_update(context, name, values)


def subcloud_alarms_delete(context, name):
    return IMPL.subcloud_alarms_delete(context, name)


def subcloud_rename_alarms(context, subcloud_name, new_name):
    return IMPL.subcloud_rename_alarms(context, subcloud_name, new_name)
