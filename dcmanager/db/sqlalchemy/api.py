# Copyright (c) 2015 Ericsson AB.
# All Rights Reserved.
#
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
# Copyright (c) 2017 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

"""
Implementation of SQLAlchemy backend.
"""

import sys
import threading

from oslo_db.sqlalchemy import enginefacade

from oslo_log import log as logging

from sqlalchemy.orm import joinedload_all

from dcmanager.common import consts
from dcmanager.common import exceptions as exception
from dcmanager.common.i18n import _
from dcmanager.db.sqlalchemy import migration
from dcmanager.db.sqlalchemy import models

LOG = logging.getLogger(__name__)

_facade = None

_main_context_manager = None
_CONTEXT = threading.local()


def _get_main_context_manager():
    global _main_context_manager
    if not _main_context_manager:
        _main_context_manager = enginefacade.transaction_context()
    return _main_context_manager


def get_engine():
    return _get_main_context_manager().get_legacy_facade().get_engine()


def get_session():
    return _get_main_context_manager().get_legacy_facade().get_session()


def read_session():
    return _get_main_context_manager().reader.using(_CONTEXT)


def write_session():
    return _get_main_context_manager().writer.using(_CONTEXT)


def get_backend():
    """The backend is this module itself."""
    return sys.modules[__name__]


def model_query(context, *args):
    with read_session() as session:
        query = session.query(*args).options(joinedload_all('*'))
        return query


def _session(context):
    return get_session()


def is_admin_context(context):
    """Indicate if the request context is an administrator."""
    if not context:
        LOG.warning(_('Use of empty request context is deprecated'),
                    DeprecationWarning)
        raise Exception('die')
    return context.is_admin


def is_user_context(context):
    """Indicate if the request context is a normal user."""
    if not context:
        return False
    if context.is_admin:
        return False
    if not context.user or not context.project:
        return False
    return True


def require_admin_context(f):
    """Decorator to require admin request context.

    The first argument to the wrapped function must be the context.
    """
    def wrapper(*args, **kwargs):
        if not is_admin_context(args[0]):
            raise exception.AdminRequired()
        return f(*args, **kwargs)

    return wrapper


def require_context(f):
    """Decorator to require *any* user or admin context.

    This does no authorization for user or project access matching, see
    :py:func:`authorize_project_context` and
    :py:func:`authorize_user_context`.
    The first argument to the wrapped function must be the context.

    """
    def wrapper(*args, **kwargs):
        if not is_admin_context(args[0]) and not is_user_context(args[0]):
            raise exception.NotAuthorized()
        return f(*args, **kwargs)

    return wrapper


###################


@require_context
def subcloud_get(context, subcloud_id):
    result = model_query(context, models.Subcloud). \
        filter_by(deleted=0). \
        filter_by(id=subcloud_id). \
        first()

    if not result:
        raise exception.SubcloudNotFound(subcloud_id=subcloud_id)

    return result


@require_context
def subcloud_get_with_status(context, subcloud_id):
    result = model_query(context, models.Subcloud, models.SubcloudStatus). \
        outerjoin(models.SubcloudStatus,
                  (models.Subcloud.id == models.SubcloudStatus.subcloud_id) |
                  (not models.SubcloudStatus.subcloud_id)). \
        filter(models.Subcloud.id == subcloud_id). \
        filter(models.Subcloud.deleted == 0). \
        order_by(models.SubcloudStatus.endpoint_type). \
        all()

    if not result:
        raise exception.SubcloudNotFound(subcloud_id=subcloud_id)

    return result


@require_context
def subcloud_get_by_name(context, name):
    result = model_query(context, models.Subcloud). \
        filter_by(deleted=0). \
        filter_by(name=name). \
        first()

    if not result:
        raise exception.SubcloudNameNotFound(name=name)

    return result


@require_context
def subcloud_get_all(context):
    return model_query(context, models.Subcloud). \
        filter_by(deleted=0). \
        all()


@require_context
def subcloud_get_all_with_status(context):
    result = model_query(context, models.Subcloud, models.SubcloudStatus). \
        outerjoin(models.SubcloudStatus,
                  (models.Subcloud.id == models.SubcloudStatus.subcloud_id) |
                  (not models.SubcloudStatus.subcloud_id)). \
        filter(models.Subcloud.deleted == 0). \
        order_by(models.Subcloud.id). \
        all()

    return result


@require_admin_context
def subcloud_create(context, name, description, location, software_version,
                    management_subnet, management_gateway_ip,
                    management_start_ip, management_end_ip,
                    systemcontroller_gateway_ip):
    with write_session() as session:
        subcloud_ref = models.Subcloud()
        subcloud_ref.name = name
        subcloud_ref.description = description
        subcloud_ref.location = location
        subcloud_ref.software_version = software_version
        subcloud_ref.management_state = consts.MANAGEMENT_UNMANAGED
        subcloud_ref.availability_status = consts.AVAILABILITY_OFFLINE
        subcloud_ref.management_subnet = management_subnet
        subcloud_ref.management_gateway_ip = management_gateway_ip
        subcloud_ref.management_start_ip = management_start_ip
        subcloud_ref.management_end_ip = management_end_ip
        subcloud_ref.systemcontroller_gateway_ip = systemcontroller_gateway_ip
        subcloud_ref.audit_fail_count = 0
        session.add(subcloud_ref)
        return subcloud_ref


@require_admin_context
def subcloud_update(context, subcloud_id, management_state=None,
                    availability_status=None, software_version=None,
                    description=None, location=None, audit_fail_count=None):
    with write_session() as session:
        subcloud_ref = subcloud_get(context, subcloud_id)
        if management_state is not None:
            subcloud_ref.management_state = management_state
        if availability_status is not None:
            subcloud_ref.availability_status = availability_status
        if software_version is not None:
            subcloud_ref.software_version = software_version
        if description is not None:
            subcloud_ref.description = description
        if location is not None:
            subcloud_ref.location = location
        if audit_fail_count is not None:
            subcloud_ref.audit_fail_count = audit_fail_count
        subcloud_ref.save(session)
        return subcloud_ref


@require_admin_context
def subcloud_destroy(context, subcloud_id):
    with write_session() as session:
        subcloud_ref = subcloud_get(context, subcloud_id)
        session.delete(subcloud_ref)


##########################


@require_context
def subcloud_status_get(context, subcloud_id, endpoint_type):
    result = model_query(context, models.SubcloudStatus). \
        filter_by(deleted=0). \
        filter_by(subcloud_id=subcloud_id). \
        filter_by(endpoint_type=endpoint_type). \
        first()

    if not result:
        raise exception.SubcloudStatusNotFound(subcloud_id=subcloud_id,
                                               endpoint_type=endpoint_type)

    return result


@require_context
def subcloud_status_get_all(context, subcloud_id):
    return model_query(context, models.SubcloudStatus). \
        filter_by(deleted=0). \
        join(models.Subcloud,
             models.SubcloudStatus.subcloud_id == models.Subcloud.id). \
        filter(models.Subcloud.id == subcloud_id).all()


@require_context
def subcloud_status_get_all_by_name(context, name):
    return model_query(context, models.SubcloudStatus). \
        filter_by(deleted=0). \
        join(models.Subcloud,
             models.SubcloudStatus.subcloud_id == models.Subcloud.id). \
        filter(models.Subcloud.name == name).all()


@require_admin_context
def subcloud_status_create(context, subcloud_id, endpoint_type):
    with write_session() as session:
        subcloud_status_ref = models.SubcloudStatus()
        subcloud_status_ref.subcloud_id = subcloud_id
        subcloud_status_ref.endpoint_type = endpoint_type
        subcloud_status_ref.sync_status = consts.SYNC_STATUS_UNKNOWN
        session.add(subcloud_status_ref)
        return subcloud_status_ref


@require_admin_context
def subcloud_status_update(context, subcloud_id, endpoint_type, sync_status):
    with write_session() as session:
        subcloud_status_ref = subcloud_status_get(context, subcloud_id,
                                                  endpoint_type)
        subcloud_status_ref.sync_status = sync_status
        subcloud_status_ref.save(session)
        return subcloud_status_ref


@require_admin_context
def subcloud_status_destroy_all(context, subcloud_id):
    with write_session() as session:
        subcloud_statuses = subcloud_status_get_all(context, subcloud_id)
        if subcloud_statuses:
            for subcloud_status_ref in subcloud_statuses:
                session.delete(subcloud_status_ref)
        else:
            raise exception.SubcloudStatusNotFound(subcloud_id=subcloud_id,
                                                   endpoint_type="any")


###################


@require_context
def sw_update_strategy_get(context):
    result = model_query(context, models.SwUpdateStrategy). \
        filter_by(deleted=0). \
        first()

    if not result:
        raise exception.NotFound()

    return result


@require_admin_context
def sw_update_strategy_create(context, type, subcloud_apply_type,
                              max_parallel_subclouds, stop_on_failure, state):
    with write_session() as session:
        sw_update_strategy_ref = models.SwUpdateStrategy()
        sw_update_strategy_ref.type = type
        sw_update_strategy_ref.subcloud_apply_type = subcloud_apply_type
        sw_update_strategy_ref.max_parallel_subclouds = max_parallel_subclouds
        sw_update_strategy_ref.stop_on_failure = stop_on_failure
        sw_update_strategy_ref.state = state

        session.add(sw_update_strategy_ref)
        return sw_update_strategy_ref


@require_admin_context
def sw_update_strategy_update(context, state=None):
    with write_session() as session:
        sw_update_strategy_ref = sw_update_strategy_get(context)
        if state is not None:
            sw_update_strategy_ref.state = state
        sw_update_strategy_ref.save(session)
        return sw_update_strategy_ref


@require_admin_context
def sw_update_strategy_destroy(context):
    with write_session() as session:
        sw_update_strategy_ref = sw_update_strategy_get(context)
        session.delete(sw_update_strategy_ref)


##########################


@require_context
def sw_update_opts_get(context, subcloud_id):
    result = model_query(context, models.SwUpdateOpts). \
        filter_by(deleted=0). \
        filter_by(subcloud_id=subcloud_id). \
        first()

    # Note we will return None if not found
    return result


@require_context
def sw_update_opts_get_all_plus_subcloud_info(context):
    result = model_query(context, models.Subcloud, models.SwUpdateOpts). \
        outerjoin(models.SwUpdateOpts,
                  (models.Subcloud.id == models.SwUpdateOpts.subcloud_id) |
                  (not models.SubcloudStatus.subcloud_id)). \
        filter(models.Subcloud.deleted == 0). \
        order_by(models.Subcloud.id). \
        all()

    return result


@require_admin_context
def sw_update_opts_create(context, subcloud_id, storage_apply_type,
                          worker_apply_type,
                          max_parallel_workers,
                          alarm_restriction_type,
                          default_instance_action):
    with write_session() as session:
        sw_update_opts_ref = models.SwUpdateOpts()
        sw_update_opts_ref.subcloud_id = subcloud_id
        sw_update_opts_ref.storage_apply_type = storage_apply_type
        sw_update_opts_ref.worker_apply_type = worker_apply_type
        sw_update_opts_ref.max_parallel_workers = max_parallel_workers
        sw_update_opts_ref.alarm_restriction_type = alarm_restriction_type
        sw_update_opts_ref.default_instance_action = default_instance_action
        session.add(sw_update_opts_ref)
        return sw_update_opts_ref


@require_admin_context
def sw_update_opts_update(context, subcloud_id, storage_apply_type=None,
                          worker_apply_type=None, max_parallel_workers=None,
                          alarm_restriction_type=None,
                          default_instance_action=None):
    with write_session() as session:
        sw_update_opts_ref = sw_update_opts_get(context, subcloud_id)
        if storage_apply_type is not None:
            sw_update_opts_ref.storage_apply_type = storage_apply_type
        if worker_apply_type is not None:
            sw_update_opts_ref.worker_apply_type = worker_apply_type
        if max_parallel_workers is not None:
            sw_update_opts_ref.max_parallel_workers = max_parallel_workers
        if alarm_restriction_type is not None:
            sw_update_opts_ref.alarm_restriction_type = alarm_restriction_type
        if default_instance_action is not None:
            sw_update_opts_ref.default_instance_action = \
                default_instance_action
        sw_update_opts_ref.save(session)
        return sw_update_opts_ref


@require_admin_context
def sw_update_opts_destroy(context, subcloud_id):
    with write_session() as session:
        sw_update_opts_ref = sw_update_opts_get(context, subcloud_id)
        session.delete(sw_update_opts_ref)


##########################


@require_context
def sw_update_opts_default_get(context):
    result = model_query(context, models.SwUpdateOptsDefault). \
        filter_by(deleted=0). \
        first()

    # Note we will return None if not found
    return result


@require_admin_context
def sw_update_opts_default_create(context, storage_apply_type,
                                  worker_apply_type,
                                  max_parallel_workers,
                                  alarm_restriction_type,
                                  default_instance_action):
    with write_session() as session:
        sw_update_opts_default_ref = models.SwUpdateOptsDefault()
        sw_update_opts_default_ref.subcloud_id = 0
        sw_update_opts_default_ref.storage_apply_type = storage_apply_type
        sw_update_opts_default_ref.worker_apply_type = worker_apply_type
        sw_update_opts_default_ref.max_parallel_workers = \
            max_parallel_workers
        sw_update_opts_default_ref.alarm_restriction_type = \
            alarm_restriction_type
        sw_update_opts_default_ref.default_instance_action = \
            default_instance_action
        session.add(sw_update_opts_default_ref)
        return sw_update_opts_default_ref


@require_admin_context
def sw_update_opts_default_update(context, storage_apply_type=None,
                                  worker_apply_type=None,
                                  max_parallel_workers=None,
                                  alarm_restriction_type=None,
                                  default_instance_action=None):
    with write_session() as session:
        sw_update_opts_default_ref = sw_update_opts_default_get(context)
        if storage_apply_type is not None:
            sw_update_opts_default_ref.storage_apply_type = storage_apply_type
        if worker_apply_type is not None:
            sw_update_opts_default_ref.worker_apply_type = worker_apply_type
        if max_parallel_workers is not None:
            sw_update_opts_default_ref.max_parallel_workers = \
                max_parallel_workers
        if alarm_restriction_type is not None:
            sw_update_opts_default_ref.alarm_restriction_type = \
                alarm_restriction_type
        if default_instance_action is not None:
            sw_update_opts_default_ref.default_instance_action = \
                default_instance_action
        sw_update_opts_default_ref.save(session)
        return sw_update_opts_default_ref


@require_admin_context
def sw_update_opts_default_destroy(context):
    with write_session() as session:
        sw_update_opts_default_ref = sw_update_opts_default_get(context)
        session.delete(sw_update_opts_default_ref)


##########################


@require_context
def strategy_step_get(context, subcloud_id):
    result = model_query(context, models.StrategyStep). \
        filter_by(deleted=0). \
        filter_by(subcloud_id=subcloud_id). \
        first()

    if not result:
        raise exception.StrategyStepNotFound(subcloud_id=subcloud_id)

    return result


@require_context
def strategy_step_get_by_name(context, name):
    result = model_query(context, models.StrategyStep). \
        filter_by(deleted=0). \
        join(models.Subcloud,
             models.StrategyStep.subcloud_id == models.Subcloud.id). \
        filter(models.Subcloud.name == name).first()

    if not result:
        raise exception.StrategyStepNameNotFound(name=name)

    return result


@require_context
def strategy_step_get_all(context):
    result = model_query(context, models.StrategyStep). \
        filter_by(deleted=0). \
        order_by(models.StrategyStep.id). \
        all()

    return result


@require_admin_context
def strategy_step_create(context, subcloud_id, stage, state, details):
    with write_session() as session:
        strategy_step_ref = models.StrategyStep()
        strategy_step_ref.subcloud_id = subcloud_id
        strategy_step_ref.stage = stage
        strategy_step_ref.state = state
        strategy_step_ref.details = details
        session.add(strategy_step_ref)
        return strategy_step_ref


@require_admin_context
def strategy_step_update(context, subcloud_id, stage=None, state=None,
                         details=None, started_at=None, finished_at=None):
    with write_session() as session:
        strategy_step_ref = strategy_step_get(context, subcloud_id)
        if stage is not None:
            strategy_step_ref.stage = stage
        if state is not None:
            strategy_step_ref.state = state
        if details is not None:
            strategy_step_ref.details = details
        if started_at is not None:
            strategy_step_ref.started_at = started_at
        if finished_at is not None:
            strategy_step_ref.finished_at = finished_at
        strategy_step_ref.save(session)
        return strategy_step_ref


@require_admin_context
def strategy_step_destroy_all(context):
    with write_session() as session:
        strategy_step_stages = strategy_step_get_all(context)
        if strategy_step_stages:
            for strategy_step_ref in strategy_step_stages:
                session.delete(strategy_step_ref)


##########################


def db_sync(engine, version=None):
    """Migrate the database to `version` or the most recent version."""
    return migration.db_sync(engine, version=version)


def db_version(engine):
    """Display the current database version."""
    return migration.db_version(engine)
