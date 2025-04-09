# Copyright (c) 2015 Ericsson AB.
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
# Copyright (c) 2018-2020, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Interface for database access.

SQLAlchemy is currently the only supported backend.
"""

from oslo_config import cfg
from oslo_db import api

CONF = cfg.CONF

_BACKEND_MAPPING = {"sqlalchemy": "dcorch.db.sqlalchemy.api"}

IMPL = api.DBAPI.from_config(CONF, backend_mapping=_BACKEND_MAPPING)


def get_engine():
    return IMPL.get_engine()


def get_session():
    return IMPL.get_session()


# quota usage db methods

###################


def quota_create(context, project_id, resource, limit):
    """Create a quota for the given project and resource."""
    return IMPL.Connection(context).quota_create(project_id, resource, limit)


def quota_get(context, project_id, resource):
    """Retrieve a quota or raise if it does not exist."""
    return IMPL.Connection(context).quota_get(project_id, resource)


def quota_get_all_by_project(context, project_id):
    """Retrieve all quotas associated with a given project."""
    return IMPL.Connection(context).quota_get_all_by_project(project_id)


def quota_update(context, project_id, resource, limit):
    """Update a quota or raise if it does not exist."""
    return IMPL.Connection(context).quota_update(project_id, resource, limit)


def quota_destroy(context, project_id, resource):
    """Destroy the quota or raise if it does not exist."""
    return IMPL.Connection(context).quota_destroy(project_id, resource)


def quota_destroy_all(context, project_id):
    """Destroy the quota or raise if it does not exist."""
    return IMPL.Connection(context).quota_destroy(project_id)


def quota_class_get(context, class_name, resource):
    """Retrieve quota from the given quota class."""
    return IMPL.Connection(context).quota_class_get(class_name, resource)


def quota_class_get_default(context):
    """Get default class quotas."""
    return IMPL.Connection(context).quota_class_get_default()


def quota_class_get_all_by_name(context, class_name):
    """Get all quota limits for a specified class."""
    return IMPL.Connection(context).quota_class_get_all_by_name(class_name)


def quota_class_create(context, class_name, resource, limit):
    """Create a new quota limit in a specified class."""
    return IMPL.Connection(context).quota_class_create(class_name, resource, limit)


def quota_class_destroy_all(context, class_name):
    """Destroy all quotas for class."""
    return IMPL.Connection(context).quota_class_destroy_all(class_name)


def quota_class_update(context, class_name, resource, limit):
    """Update a quota or raise if it doesn't exist."""
    return IMPL.Connection(context).quota_class_update(class_name, resource, limit)


def db_sync(engine, version=None):
    """Migrate the database to `version` or the most recent version."""
    return IMPL.Connection.db_sync(engine, version=version)


def db_version(engine):
    """Display the current database version."""
    return IMPL.Connection.db_version(engine)


def service_create(context, service_id, host=None, binary=None, topic=None):
    return IMPL.Connection(context).service_create(
        service_id=service_id, host=host, binary=binary, topic=topic
    )


def service_update(context, service_id, values=None):
    return IMPL.Connection(context).service_update(service_id, values=values)


def service_delete(context, service_id):
    return IMPL.Connection(context).service_delete(service_id)


def service_get(context, service_id):
    return IMPL.Connection(context).service_get(service_id)


def service_get_all(context):
    return IMPL.Connection(context).service_get_all()


def subcloud_get(context, region_id):
    return IMPL.Connection(context).subcloud_get(region_id)


def subcloud_get_all(
    context,
    region_name=None,
    management_state=None,
    availability_status=None,
    initial_sync_state=None,
):
    return IMPL.Connection(context).subcloud_get_all(
        region_name=region_name,
        management_state=management_state,
        availability_status=availability_status,
        initial_sync_state=initial_sync_state,
    )


def subcloud_capabilities_get_all(
    context,
    region_name=None,
    management_state=None,
    availability_status=None,
    initial_sync_state=None,
):
    return IMPL.Connection(context).subcloud_capabilities_get_all(
        region_name=region_name,
        management_state=management_state,
        availability_status=availability_status,
        initial_sync_state=initial_sync_state,
    )


def subcloud_sync_update_all_to_in_progress(
    context, management_state, availability_status, initial_sync_state, sync_requests
):
    return IMPL.Connection(context).subcloud_sync_update_all_to_in_progress(
        management_state=management_state,
        availability_status=availability_status,
        initial_sync_state=initial_sync_state,
        sync_requests=sync_requests,
    )


def subcloud_audit_update_last_audit_time(context, subcloud_name):
    """Updates the last audit time for all rows of a subcloud"""
    return IMPL.Connection(context).subcloud_audit_update_last_audit_time(subcloud_name)


def subcloud_audit_update_all_to_in_progress(
    context, management_state, availability_status, initial_sync_state, audit_interval
):
    return IMPL.Connection(context).subcloud_audit_update_all_to_in_progress(
        management_state=management_state,
        availability_status=availability_status,
        initial_sync_state=initial_sync_state,
        audit_interval=audit_interval,
    )


def subcloud_create(context, region_name, values):
    return IMPL.Connection(context).subcloud_create(region_name, values)


def subcloud_update(context, region_name, values):
    return IMPL.Connection(context).subcloud_update(region_name, values)


def subcloud_delete(context, region_name):
    return IMPL.Connection(context).subcloud_delete(region_name)


def subcloud_update_initial_state(
    context, subcloud_name, pre_initial_sync_state, initial_sync_state
):
    return IMPL.Connection(context).subcloud_update_initial_state(
        subcloud_name, pre_initial_sync_state, initial_sync_state
    )


def subcloud_update_all_initial_state(
    context, pre_initial_sync_state, initial_sync_state
):
    return IMPL.Connection(context).subcloud_update_all_initial_state(
        pre_initial_sync_state, initial_sync_state
    )


def resource_get_by_type_and_master_id(context, resource_type, master_id):
    return IMPL.Connection(context).resource_get_by_type_and_master_id(
        resource_type, master_id
    )


def resource_get_by_id(context, id):
    return IMPL.Connection(context).resource_get_by_id(id)


def resource_get_all(context, resource_type=None):
    return IMPL.Connection(context).resource_get_all(resource_type=resource_type)


def resource_create(context, resource_type, values):
    return IMPL.Connection(context).resource_create(resource_type, values)


def resource_update(context, resource_type, values):
    return IMPL.Connection(context).resource_update(resource_type, values)


def resource_delete(context, resource_type, master_id):
    return IMPL.Connection(context).resource_delete(resource_type, master_id)


def subcloud_resource_get(context, subcloud_resource_id):
    return IMPL.Connection(context).subcloud_resource_get(subcloud_resource_id)


def subcloud_resources_get_by_subcloud(context, subcloud_id):
    return IMPL.Connection(context).subcloud_resources_get_by_subcloud(subcloud_id)


def subcloud_resources_get_by_resource(context, resource_id):
    return IMPL.Connection(context).subcloud_resources_get_by_resource(resource_id)


def subcloud_resource_get_by_resource_and_subcloud(context, resource_id, subcloud_id):
    return IMPL.Connection(context).subcloud_resource_get_by_resource_and_subcloud(
        resource_id, subcloud_id
    )


def subcloud_resources_get_all(context):
    return IMPL.Connection(context).subcloud_resources_get_all()


def subcloud_resource_create(context, subcloud_id, resource_id, values):
    return IMPL.Connection(context).subcloud_resource_create(
        subcloud_id, resource_id, values
    )


def subcloud_resource_update(context, subcloud_resource_id, values):
    return IMPL.Connection(context).subcloud_resource_update(
        subcloud_resource_id, values
    )


def subcloud_resource_delete(context, subcloud_resource_id):
    return IMPL.Connection(context).subcloud_resource_delete(subcloud_resource_id)


def orch_job_get(context, orch_job_id):
    return IMPL.Connection(context).orch_job_get(orch_job_id)


def orch_job_get_all(context, resource_id=None):
    return IMPL.Connection(context).orch_job_get_all(resource_id=resource_id)


def orch_job_create(context, resource_id, endpoint_type, operation_type, values):
    return IMPL.Connection(context).orch_job_create(
        resource_id, endpoint_type, operation_type, values
    )


def orch_job_update(context, orch_job_id, values):
    return IMPL.Connection(context).orch_job_update(orch_job_id, values)


def orch_job_delete(context, orch_job_id):
    return IMPL.Connection(context).orch_job_delete(orch_job_id)


def orch_request_get(context, orch_request_id):
    return IMPL.Connection(context).orch_request_get(orch_request_id)


def orch_request_get_most_recent_failed_request(context):
    return IMPL.Connection(context).orch_request_get_most_recent_failed_request()


def orch_request_get_all(context, orch_job_id=None):
    return IMPL.Connection(context).orch_request_get_all(orch_job_id=orch_job_id)


def orch_request_get_by_attrs(
    context, endpoint_type, resource_type=None, target_region_name=None, states=None
):
    """Query OrchRequests by attributes.

    :param context:  authorization context
    :param endpoint_type: OrchJob.endpoint_type
    :param resource_type: Resource.resource_type
    :param target_region_name: OrchRequest target_region_name
    :param states: [OrchRequest.state] must be a list
    :return: [OrchRequests] sorted by OrchRequest.id
    """
    return IMPL.Connection(context).orch_request_get_by_attrs(
        endpoint_type,
        resource_type=resource_type,
        target_region_name=target_region_name,
        states=states,
    )


def orch_request_create(context, orch_job_id, target_region_name, values):
    return IMPL.Connection(context).orch_request_create(
        orch_job_id, target_region_name, values
    )


def orch_request_create_bulk(context, orch_requests):
    return IMPL.Connection(context).orch_request_create_bulk(orch_requests)


def orch_request_update(context, orch_request_id, values):
    return IMPL.Connection(context).orch_request_update(orch_request_id, values)


def orch_request_destroy(context, orch_request_id):
    return IMPL.Connection(context).orch_request_destroy(orch_request_id)


def orch_request_delete_by_subcloud(context, region_name):
    return IMPL.Connection(context).orch_request_delete_by_subcloud(region_name)


def orch_request_delete_previous_failed_requests(context, delete_timestamp):
    return IMPL.Connection(context).orch_request_delete_previous_failed_requests(
        delete_timestamp
    )


# Periodic cleanup
def purge_deleted_records(context, age_in_days=1):
    return IMPL.Connection(context).purge_deleted_records(age_in_days)


def subcloud_sync_get(context, subcloud_name, endpoint_type):
    return IMPL.Connection(context).subcloud_sync_get(subcloud_name, endpoint_type)


def subcloud_sync_update(context, subcloud_name, endpoint_type, values):
    return IMPL.Connection(context).subcloud_sync_update(
        subcloud_name, endpoint_type, values
    )


def subcloud_sync_update_all_except_in_progress(
    context, management_state, endpoint_type, values
):
    return IMPL.Connection(context).subcloud_sync_update_all_except_in_progress(
        management_state, endpoint_type, values
    )


def subcloud_sync_create(context, subcloud_name, endpoint_type, values):
    return IMPL.Connection(context).subcloud_sync_create(
        subcloud_name, endpoint_type, values
    )


def subcloud_sync_delete(context, subcloud_name, endpoint_type):
    return IMPL.Connection(context).subcloud_sync_delete(subcloud_name, endpoint_type)
