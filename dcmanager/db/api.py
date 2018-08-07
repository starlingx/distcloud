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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
'''
Interface for database access.

SQLAlchemy is currently the only supported backend.
'''

from oslo_config import cfg
from oslo_db import api

from dcmanager.common import consts

CONF = cfg.CONF

_BACKEND_MAPPING = {'sqlalchemy': 'dcmanager.db.sqlalchemy.api'}

IMPL = api.DBAPI.from_config(CONF, backend_mapping=_BACKEND_MAPPING)


def get_engine():
    return IMPL.get_engine()


def get_session():
    return IMPL.get_session()


# subcloud db methods

###################

def subcloud_db_model_to_dict(subcloud):
    """Convert subcloud db model to dictionary."""
    result = {"id": subcloud.id,
              "name": subcloud.name,
              "description": subcloud.description,
              "location": subcloud.location,
              "software-version": subcloud.software_version,
              "management-state": subcloud.management_state,
              "availability-status": subcloud.availability_status,
              "management-subnet": subcloud.management_subnet,
              "management-start-ip": subcloud.management_start_ip,
              "management-end-ip": subcloud.management_end_ip,
              "management-gateway-ip": subcloud.management_gateway_ip,
              "systemcontroller-gateway-ip":
                  subcloud.systemcontroller_gateway_ip,
              "created-at": subcloud.created_at,
              "updated-at": subcloud.updated_at}
    return result


def subcloud_create(context, name, description, location, software_version,
                    management_subnet, management_gateway_ip,
                    management_start_ip, management_end_ip,
                    systemcontroller_gateway_ip):
    """Create a subcloud."""
    return IMPL.subcloud_create(context, name, description, location,
                                software_version,
                                management_subnet, management_gateway_ip,
                                management_start_ip, management_end_ip,
                                systemcontroller_gateway_ip)


def subcloud_get(context, subcloud_id):
    """Retrieve a subcloud or raise if it does not exist."""
    return IMPL.subcloud_get(context, subcloud_id)


def subcloud_get_with_status(context, subcloud_id):
    """Retrieve a subcloud and all endpoint sync statuses."""
    return IMPL.subcloud_get_with_status(context, subcloud_id)


def subcloud_get_by_name(context, name):
    """Retrieve a subcloud by name or raise if it does not exist."""
    return IMPL.subcloud_get_by_name(context, name)


def subcloud_get_all(context):
    """Retrieve all subclouds."""
    return IMPL.subcloud_get_all(context)


def subcloud_get_all_with_status(context):
    """Retrieve all subclouds and sync statuses."""
    return IMPL.subcloud_get_all_with_status(context)


def subcloud_update(context, subcloud_id, management_state=None,
                    availability_status=None, software_version=None,
                    description=None, location=None, audit_fail_count=None):
    """Update a subcloud or raise if it does not exist."""
    return IMPL.subcloud_update(context, subcloud_id, management_state,
                                availability_status, software_version,
                                description, location, audit_fail_count)


def subcloud_destroy(context, subcloud_id):
    """Destroy the subcloud or raise if it does not exist."""
    return IMPL.subcloud_destroy(context, subcloud_id)


###################

def subcloud_status_create(context, subcloud_id, endpoint_type):
    """Create a subcloud status for an endpoint_type."""
    return IMPL.subcloud_status_create(context, subcloud_id, endpoint_type)


def subcloud_status_db_model_to_dict(subcloud_status):
    """Convert subcloud status db model to dictionary."""
    if subcloud_status:
        result = {"subcloud_id": subcloud_status.subcloud_id,
                  "sync_status": subcloud_status.sync_status}
    else:
        result = {"subcloud_id": 0,
                  "sync_status": "unknown"}

    return result


def subcloud_endpoint_status_db_model_to_dict(subcloud_status):
    """Convert endpoint subcloud db model to dictionary."""
    if subcloud_status:
        result = {"endpoint_type": subcloud_status.endpoint_type,
                  "sync_status": subcloud_status.sync_status}
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
    return IMPL.subcloud_status_update(context, subcloud_id, endpoint_type,
                                       sync_status)


def subcloud_status_destroy_all(context, subcloud_id):
    """Destroy all the statuses for a subcloud

    Will raise if subcloud does not exist.
    """

    return IMPL.subcloud_status_destroy_all(context, subcloud_id)


###################

def sw_update_strategy_db_model_to_dict(sw_update_strategy):
    """Convert sw update db model to dictionary."""
    result = {"id": sw_update_strategy.id,
              "type": sw_update_strategy.type,
              "subcloud-apply-type": sw_update_strategy.subcloud_apply_type,
              "max-parallel-subclouds":
                  sw_update_strategy.max_parallel_subclouds,
              "stop-on-failure": sw_update_strategy.stop_on_failure,
              "state": sw_update_strategy.state,
              "created-at": sw_update_strategy.created_at,
              "updated-at": sw_update_strategy.updated_at}
    return result


def sw_update_strategy_create(context, type, subcloud_apply_type,
                              max_parallel_subclouds, stop_on_failure, state):
    """Create a sw update."""
    return IMPL.sw_update_strategy_create(context, type, subcloud_apply_type,
                                          max_parallel_subclouds,
                                          stop_on_failure, state)


def sw_update_strategy_get(context):
    """Retrieve a sw update or raise if it does not exist."""
    return IMPL.sw_update_strategy_get(context)


def sw_update_strategy_update(context, state=None):
    """Update a sw update or raise if it does not exist."""
    return IMPL.sw_update_strategy_update(context, state)


def sw_update_strategy_destroy(context):
    """Destroy the sw update or raise if it does not exist."""
    return IMPL.sw_update_strategy_destroy(context)


###################

def strategy_step_db_model_to_dict(strategy_step):
    """Convert patch strategy db model to dictionary."""
    if strategy_step.subcloud is not None:
        cloud = strategy_step.subcloud.name
    else:
        cloud = consts.SYSTEM_CONTROLLER_NAME
    result = {"id": strategy_step.id,
              "cloud": cloud,
              "stage": strategy_step.stage,
              "state": strategy_step.state,
              "details": strategy_step.details,
              "started-at": strategy_step.started_at,
              "finished-at": strategy_step.finished_at,
              "created-at": strategy_step.created_at,
              "updated-at": strategy_step.updated_at}
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


def strategy_step_create(context, subcloud_id, stage, state, details):
    """Create a patch strategy step."""
    return IMPL.strategy_step_create(context, subcloud_id, stage, state,
                                     details)


def strategy_step_update(context, subcloud_id, stage=None, state=None,
                         details=None, started_at=None, finished_at=None):
    """Update a patch strategy step or raise if it does not exist."""
    return IMPL.strategy_step_update(context, subcloud_id, stage, state,
                                     details, started_at, finished_at)


def strategy_step_destroy_all(context):
    """Destroy all the patch strategy steps."""
    return IMPL.strategy_step_destroy_all(context)


###################

def sw_update_opts_w_name_db_model_to_dict(sw_update_opts, subcloud_name):
    """Convert sw update options db model plus subcloud name to dictionary."""
    result = {"id": sw_update_opts.id,
              "name": subcloud_name,
              "subcloud-id": sw_update_opts.subcloud_id,
              "storage-apply-type": sw_update_opts.storage_apply_type,
              "compute-apply-type": sw_update_opts.compute_apply_type,
              "max-parallel-computes": sw_update_opts.max_parallel_computes,
              "alarm-restriction-type": sw_update_opts.alarm_restriction_type,
              "default-instance-action":
                  sw_update_opts.default_instance_action,
              "created-at": sw_update_opts.created_at,
              "updated-at": sw_update_opts.updated_at}
    return result


def sw_update_opts_create(context, subcloud_id, storage_apply_type,
                          compute_apply_type, max_parallel_computes,
                          alarm_restriction_type, default_instance_action):
    """Create sw update options."""
    return IMPL.sw_update_opts_create(context, subcloud_id,
                                      storage_apply_type,
                                      compute_apply_type,
                                      max_parallel_computes,
                                      alarm_restriction_type,
                                      default_instance_action)


def sw_update_opts_get(context, subcloud_id):
    """Retrieve sw update options."""
    return IMPL.sw_update_opts_get(context, subcloud_id)


def sw_update_opts_get_all_plus_subcloud_info(context):
    """Retrieve sw update options plus subcloud info."""
    return IMPL.sw_update_opts_get_all_plus_subcloud_info(context)


def sw_update_opts_update(context, subcloud_id,
                          storage_apply_type=None,
                          compute_apply_type=None,
                          max_parallel_computes=None,
                          alarm_restriction_type=None,
                          default_instance_action=None):

    """Update sw update options or raise if it does not exist."""
    return IMPL.sw_update_opts_update(context, subcloud_id,
                                      storage_apply_type,
                                      compute_apply_type,
                                      max_parallel_computes,
                                      alarm_restriction_type,
                                      default_instance_action)


def sw_update_opts_destroy(context, subcloud_id):
    """Destroy sw update options or raise if it does not exist."""
    return IMPL.sw_update_opts_destroy(context, subcloud_id)


###################
def sw_update_opts_default_create(context, storage_apply_type,
                                  compute_apply_type, max_parallel_computes,
                                  alarm_restriction_type,
                                  default_instance_action):
    """Create default sw update options."""
    return IMPL.sw_update_opts_default_create(context,
                                              storage_apply_type,
                                              compute_apply_type,
                                              max_parallel_computes,
                                              alarm_restriction_type,
                                              default_instance_action)


def sw_update_opts_default_get(context):
    """Retrieve default sw update options."""
    return IMPL.sw_update_opts_default_get(context)


def sw_update_opts_default_update(context,
                                  storage_apply_type=None,
                                  compute_apply_type=None,
                                  max_parallel_computes=None,
                                  alarm_restriction_type=None,
                                  default_instance_action=None):

    """Update default sw update options."""
    return IMPL.sw_update_opts_default_update(context,
                                              storage_apply_type,
                                              compute_apply_type,
                                              max_parallel_computes,
                                              alarm_restriction_type,
                                              default_instance_action)


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
