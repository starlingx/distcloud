# Copyright (c) 2015 Ericsson AB.
# Copyright (c) 2017-2021, 2023-2025 Wind River Systems, Inc.
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


"""
Implementation of SQLAlchemy backend.
"""

import datetime
import functools
import sys

import eventlet
from oslo_db import exception as db_exc
from oslo_db.sqlalchemy import enginefacade
from oslo_log import log as logging
from oslo_utils import strutils
from oslo_utils import timeutils
from oslo_utils import uuidutils
from sqlalchemy import and_
from sqlalchemy import asc
from sqlalchemy import desc
from sqlalchemy import or_
from sqlalchemy.orm.exc import MultipleResultsFound
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import joinedload
from sqlalchemy import select
from sqlalchemy import update

from dccommon import consts as dccommon_consts
from dcorch.common import consts
from dcorch.common import exceptions as exception
from dcorch.common.i18n import _
from dcorch.db.sqlalchemy import migration
from dcorch.db.sqlalchemy import models

LOG = logging.getLogger(__name__)

_facade = None

_main_context_manager = None


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
    _context = eventlet.greenthread.getcurrent()
    return _get_main_context_manager().reader.using(_context)


def write_session():
    _context = eventlet.greenthread.getcurrent()
    return _get_main_context_manager().writer.using(_context)


_DEFAULT_QUOTA_NAME = "default"


def get_backend():
    """The backend is this module itself."""
    return sys.modules[__name__]


def db_session_cleanup(cls):
    """Class decorator that adds session cleanup to all non-special methods."""

    def method_decorator(method):
        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            _context = eventlet.greenthread.getcurrent()
            exc_info = (None, None, None)

            try:
                return method(self, *args, **kwargs)
            except Exception:
                exc_info = sys.exc_info()
                raise
            finally:
                if (
                    hasattr(_context, "_db_session_context")
                    and _context._db_session_context is not None
                ):
                    try:
                        _context._db_session_context.__exit__(*exc_info)
                    except Exception as e:
                        LOG.warning(f"Error closing database session: {e}")

                    # Clear the session
                    _context._db_session = None
                    _context._db_session_context = None

        return wrapper

    for attr_name in dir(cls):
        # Skip special methods
        if not attr_name.startswith("__"):
            attr = getattr(cls, attr_name)
            if callable(attr):
                setattr(cls, attr_name, method_decorator(attr))

    return cls


def model_query(context, *args, **kwargs):
    """Query helper for simpler session usage.

    If the session is already provided in the kwargs, use it. Otherwise,
    try to get it from thread context. If it's not there, create a new one.

    Note: If not providing a session, the calling function need to have
    the db_session_cleanup decorator to clean up the session.

    :param session: if present, the session to use
    """
    session = kwargs.get("session")
    if not session:
        _context = eventlet.greenthread.getcurrent()
        if hasattr(_context, "_db_session") and _context._db_session is not None:
            session = _context._db_session
        else:
            session_context = read_session()
            session = session_context.__enter__()  # pylint: disable=no-member
            _context._db_session = session
            # Need to store the session context to call __exit__ method later
            _context._db_session_context = session_context

    return session.query(*args).options(joinedload("*"))


def _session(context):
    return get_session()


def is_admin_context(context):
    """Indicate if the request context is an administrator."""
    if not context:
        LOG.warning(_("Use of empty request context is deprecated"), DeprecationWarning)
        raise Exception("die")
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


def require_context(admin=False):
    """Decorator to require user or admin request context.

    When called with admin=True, only admin context is accepted.
    When called without arguments, any user or admin context is accepted.
    """

    def decorator(f):
        def wrapper(self, *args, **kwargs):

            if admin:
                if not is_admin_context(self.context):
                    raise exception.AdminRequired()
            else:
                if not is_admin_context(self.context) and not is_user_context(
                    self.context
                ):
                    raise exception.NotAuthorized()

            return f(self, *args, **kwargs)

        return wrapper

    return decorator


def add_identity_filter(query, value, use_region_name=None, use_resource_type=None):
    """Adds an identity filter to a query.

    Filters results by 'id', if supplied value is a valid integer.
    then attempts to filter results by 'uuid';
    otherwise filters by name

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :param use_region_name: Use region_name in filter
    :param use_resource_type: Use resource_type in filter

    :return: Modified query.
    """
    if use_region_name:
        return query.filter_by(region_name=value)
    elif strutils.is_int_like(value):
        return query.filter_by(id=value)
    elif uuidutils.is_uuid_like(value):
        return query.filter_by(uuid=value)
    elif use_resource_type:
        return query.filter_by(resource_type=value)
    else:
        return query.filter_by(name=value)


def add_filter_by_many_identities(query, model, values):
    """Adds an identity filter to a query for values list.

    Filters results by ID, if supplied values contain a valid integer.
    Otherwise attempts to filter results by UUID.

    :param query: Initial query to add filter to.
    :param model: Model for filter.
    :param values: Values for filtering results by.
    :return: tuple (Modified query, filter field name).
    """
    if not values:
        raise exception.Invalid()
    value = values[0]
    if strutils.is_int_like(value):
        return query.filter(getattr(model, "id").in_(values)), "id"
    elif uuidutils.is_uuid_like(value):
        return query.filter(getattr(model, "uuid").in_(values)), "uuid"
    else:
        raise exception.InvalidParameterValue(
            err="Invalid identity filter value %s" % value
        )


def add_subcloud_resource_filter_by_subcloud(query, value):
    if strutils.is_int_like(value):
        return query.filter(models.Subcloud.id == value)
    elif uuidutils.is_uuid_like(value):
        return query.filter(models.Subcloud.uuid == value)


def add_orch_job_filter_by_resource(query, value):
    if strutils.is_int_like(value):
        return query.filter(models.OrchJob.id == value)
    elif uuidutils.is_uuid_like(value):
        return query.filter(models.OrchJob.uuid == value)


def add_orch_request_filter_by_resource(query, value):
    if strutils.is_int_like(value):
        return query.filter(models.OrchRequest.id == value)
    elif uuidutils.is_uuid_like(value):
        return query.filter(models.OrchRequest.uuid == value)


@db_session_cleanup
class Connection(object):

    def __init__(self, context):
        self.context = context

    @staticmethod
    def db_sync(engine, version=None):
        """Migrate the database to `version` or the most recent version."""
        return migration.db_sync(engine, version=version)

    @staticmethod
    def db_version(engine):
        """Display the current database version."""
        return migration.db_version(engine)

    @require_context(admin=True)
    def purge_deleted_records(self, age_in_days):
        deleted_age = timeutils.utcnow() - datetime.timedelta(days=age_in_days)

        LOG.info("Purging deleted records older than %s", deleted_age)

        with write_session() as session:
            # Purging orch_request table
            count = (
                session.query(models.OrchRequest)
                .filter_by(deleted=1)
                .filter(models.OrchRequest.deleted_at < deleted_age)
                .delete()
            )
            LOG.info("%d records were purged from orch_request table.", count)

            # Purging orch_job table
            subquery = model_query(
                self.context, models.OrchRequest.orch_job_id
            ).group_by(models.OrchRequest.orch_job_id)

            count = (
                session.query(models.OrchJob)
                .filter(~models.OrchJob.id.in_(subquery))
                .delete(synchronize_session="fetch")
            )
            LOG.info("%d records were purged from orch_job table.", count)

            # Purging resource table
            orchjob_subquery = model_query(
                self.context, models.OrchJob.resource_id
            ).group_by(models.OrchJob.resource_id)

            subcloud_resource_subquery = model_query(
                self.context, models.SubcloudResource.resource_id
            ).group_by(models.SubcloudResource.resource_id)

            count = (
                session.query(models.Resource)
                .filter(~models.Resource.id.in_(orchjob_subquery))
                .filter(~models.Resource.id.in_(subcloud_resource_subquery))
                .delete(synchronize_session="fetch")
            )
            LOG.info("%d records were purged from resource table.", count)

    def _quota_get(self, project_id, resource, session=None):
        result = (
            model_query(self.context, models.Quota, session=session)
            .filter_by(project_id=project_id)
            .filter_by(resource=resource)
            .first()
        )

        if not result:
            raise exception.ProjectQuotaNotFound(project_id=project_id)

        return result

    @require_context()
    def quota_get(self, project_id, resource):
        return self._quota_get(project_id, resource)

    @require_context()
    def quota_get_all_by_project(self, project_id):
        rows = (
            model_query(self.context, models.Quota)
            .filter_by(project_id=project_id)
            .all()
        )
        result = {"project_id": project_id}
        for row in rows:
            result[row.resource] = row.hard_limit
        return result

    @require_context(admin=True)
    def quota_create(self, project_id, resource, limit):
        with write_session() as session:
            quota_ref = models.Quota()
            quota_ref.project_id = project_id
            quota_ref.resource = resource
            quota_ref.hard_limit = limit
            session.add(quota_ref)
            return quota_ref

    @require_context(admin=True)
    def quota_update(self, project_id, resource, limit):
        with write_session() as session:
            quota_ref = self._quota_get(project_id, resource, session=session)
            if not quota_ref:
                raise exception.ProjectQuotaNotFound(project_id=project_id)
            quota_ref.hard_limit = limit
            quota_ref.save(session)
            return quota_ref

    @require_context(admin=True)
    def quota_destroy(self, project_id, resource):
        with write_session() as session:
            quota_ref = self._quota_get(project_id, resource, session=session)
            if not quota_ref:
                raise exception.ProjectQuotaNotFound(project_id=project_id)
            session.delete(quota_ref)

    @require_context(admin=True)
    def quota_destroy_all(self, project_id):
        with write_session() as session:

            quotas = (
                model_query(self.context, models.Quota, session=session)
                .filter_by(project_id=project_id)
                .all()
            )

            if not quotas:
                raise exception.ProjectQuotaNotFound(project_id=project_id)

            for quota_ref in quotas:
                session.delete(quota_ref)

    def _quota_class_get(self, class_name, resource):
        result = (
            model_query(self.context, models.QuotaClass)
            .filter_by(deleted=0)
            .filter_by(class_name=class_name)
            .filter_by(resource=resource)
            .first()
        )

        if not result:
            raise exception.QuotaClassNotFound(class_name=class_name)

        return result

    @require_context()
    def quota_class_get(self, class_name, resource):
        return self._quota_class_get(class_name, resource)

    @require_context()
    def quota_class_get_default(self):
        return self.quota_class_get_all_by_name(_DEFAULT_QUOTA_NAME)

    @require_context()
    def quota_class_get_all_by_name(self, class_name):
        rows = (
            model_query(self.context, models.QuotaClass)
            .filter_by(deleted=0)
            .filter_by(class_name=class_name)
            .all()
        )

        result = {"class_name": class_name}
        for row in rows:
            result[row.resource] = row.hard_limit

        return result

    @require_context(admin=True)
    def quota_class_create(self, class_name, resource, limit):
        with write_session() as session:
            quota_class_ref = models.QuotaClass()
            quota_class_ref.class_name = class_name
            quota_class_ref.resource = resource
            quota_class_ref.hard_limit = limit
            session.add(quota_class_ref)
            return quota_class_ref

    @require_context(admin=True)
    def quota_class_update(self, class_name, resource, limit):
        with write_session() as session:
            quota_class_ref = (
                session.query(models.QuotaClass)
                .filter_by(deleted=0)
                .filter_by(class_name=class_name)
                .filter_by(resource=resource)
                .first()
            )
            if not quota_class_ref:
                raise exception.QuotaClassNotFound(class_name=class_name)
            quota_class_ref.hard_limit = limit
            quota_class_ref.save(session)
            return quota_class_ref

    @require_context(admin=True)
    def quota_class_destroy_all(self, class_name):
        with write_session() as session:
            quota_classes = (
                session.query(models.QuotaClass)
                .filter_by(deleted=0)
                .filter_by(class_name=class_name)
                .all()
            )
            if quota_classes:
                for quota_class_ref in quota_classes:
                    session.delete(quota_class_ref)
            else:
                raise exception.QuotaClassNotFound()

    def service_create(self, service_id, host=None, binary=None, topic=None):
        with write_session() as session:
            time_now = timeutils.utcnow()
            svc = models.Service(
                id=service_id,
                host=host,
                binary=binary,
                topic=topic,
                created_at=time_now,
                updated_at=time_now,
            )
            session.add(svc)
            return svc

    def service_update(self, service_id, values=None):
        with write_session() as session:
            service = session.query(models.Service).get(service_id)
            if not service:
                return

            if values is None:
                values = {}

            values.update({"updated_at": timeutils.utcnow()})
            service.update(values)
            service.save(session)
            return service

    def service_delete(self, service_id):
        with write_session() as session:
            session.query(models.Service).filter_by(id=service_id).delete(
                synchronize_session="fetch"
            )

    def service_get(self, service_id):
        return model_query(self.context, models.Service).get(service_id)

    def service_get_all(self):
        return model_query(self.context, models.Service).all()

    def _subcloud_get(self, region_id, session=None):
        query = model_query(self.context, models.Subcloud, session=session).filter_by(
            deleted=0
        )
        query = add_identity_filter(query, region_id, use_region_name=True)

        try:
            return query.one()
        except NoResultFound:
            raise exception.SubcloudNotFound(region_name=region_id)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for subcloud %s" % region_id
            )

    @require_context()
    def subcloud_get(self, region_id):
        return self._subcloud_get(region_id)

    @require_context()
    def subcloud_get_all(
        self,
        region_name=None,
        management_state=None,
        availability_status=None,
        initial_sync_state=None,
    ):
        query = model_query(self.context, models.Subcloud).filter_by(deleted=0)

        if region_name:
            query = add_identity_filter(query, region_name, use_region_name=True)
        if management_state:
            query = query.filter_by(management_state=management_state)
        if availability_status:
            query = query.filter_by(availability_status=availability_status)
        if initial_sync_state:
            query = query.filter_by(initial_sync_state=initial_sync_state)
        return query.all()

    @require_context()
    def subcloud_capabilities_get_all(
        self,
        region_name=None,
        management_state=None,
        availability_status=None,
        initial_sync_state=None,
    ):
        results = self.subcloud_get_all(
            region_name,
            management_state,
            availability_status,
            initial_sync_state,
        )
        return {
            result["region_name"]: (
                result["capabilities"],
                result["management_ip"],
                result["software_version"],
                result["id"],
                result["subsequent_sync"],
            )
            for result in results
        }

    @require_context()
    def subcloud_sync_update_all_to_in_progress(
        self,
        management_state,
        availability_status,
        initial_sync_state,
        sync_requests,
    ):
        with write_session() as session:
            # Fetch the records of subcloud_sync that meet the update criteria
            subcloud_sync_rows = (
                session.query(
                    models.SubcloudSync,
                    models.Subcloud.management_ip,
                    models.Subcloud.software_version,
                    models.Subcloud.id,
                )
                .join(
                    models.Subcloud,
                    models.Subcloud.region_name == models.SubcloudSync.subcloud_name,
                )
                .filter(
                    models.Subcloud.management_state == management_state,
                    models.Subcloud.availability_status == availability_status,
                    models.Subcloud.initial_sync_state == initial_sync_state,
                    models.SubcloudSync.sync_request.in_(sync_requests),
                )
                .all()
            )

            # Update the sync status to in-progress for the selected subcloud_sync
            # records
            updated_rows = []
            for (
                subcloud_sync,
                management_ip,
                software_version,
                subcloud_id,
            ) in subcloud_sync_rows:
                subcloud_sync.sync_request = consts.SYNC_STATUS_IN_PROGRESS
                updated_rows.append(
                    (
                        subcloud_sync.subcloud_name,
                        subcloud_sync.endpoint_type,
                        management_ip,
                        software_version,
                        subcloud_id,
                    )
                )

            return updated_rows

    @require_context()
    def subcloud_audit_update_last_audit_time(self, subcloud_name):
        """Updates the last audit time for all rows of a subcloud"""

        with write_session() as session:
            session.query(models.SubcloudSync).filter(
                models.SubcloudSync.subcloud_name == subcloud_name
            ).update({models.SubcloudSync.last_audit_time: timeutils.utcnow()})

    @require_context()
    def subcloud_audit_update_all_to_in_progress(
        self,
        management_state,
        availability_status,
        initial_sync_state,
        audit_interval,
    ):
        threshold_time = timeutils.utcnow() - datetime.timedelta(seconds=audit_interval)

        with write_session() as session:
            # Fetch the records of subcloud_sync that meet the update criteria
            subcloud_sync_rows = (
                session.query(
                    models.SubcloudSync,
                    models.Subcloud.management_ip,
                    models.Subcloud.software_version,
                    models.Subcloud.id,
                )
                .join(
                    models.Subcloud,
                    models.Subcloud.region_name == models.SubcloudSync.subcloud_name,
                )
                .filter(
                    models.Subcloud.management_state == management_state,
                    models.Subcloud.availability_status == availability_status,
                    models.Subcloud.initial_sync_state == initial_sync_state,
                    models.SubcloudSync.last_audit_time is not None,
                    or_(
                        # Search those with conditional audit status
                        # (completed/in-progress) and the last audit time is equal
                        # or greater than the audit interval
                        and_(
                            models.SubcloudSync.audit_status.in_(
                                consts.AUDIT_CONDITIONAL_STATUS
                            ),
                            models.SubcloudSync.last_audit_time <= threshold_time,
                        ),
                        models.SubcloudSync.audit_status.in_(
                            consts.AUDIT_QUALIFIED_STATUS
                        ),
                    ),
                )
                .all()
            )

            # Update the audit status to in-progress for the selected subcloud_sync
            # records
            updated_rows = []
            for (
                subcloud_sync,
                management_ip,
                software_version,
                subcloud_id,
            ) in subcloud_sync_rows:
                subcloud_sync.audit_status = consts.AUDIT_STATUS_IN_PROGRESS
                subcloud_sync.last_audit_time = timeutils.utcnow()
                updated_rows.append(
                    (
                        subcloud_sync.subcloud_name,
                        subcloud_sync.endpoint_type,
                        management_ip,
                        software_version,
                        subcloud_id,
                    )
                )

            return updated_rows

    @require_context(admin=True)
    def subcloud_create(self, region_name, values):
        with write_session() as session:
            result = models.Subcloud()
            result.region_name = region_name
            if not values.get("uuid"):
                values["uuid"] = uuidutils.generate_uuid()
            result.update(values)
            try:
                session.add(result)
            except db_exc.DBDuplicateEntry:
                raise exception.SubcloudAlreadyExists(region_name=region_name)
            return result

    @require_context(admin=True)
    def subcloud_update(self, region_name, values):
        with write_session() as session:
            result = self._subcloud_get(region_name, session)
            result.update(values)
            result.save(session)
            return result

    @require_context(admin=True)
    def subcloud_delete(self, region_name):
        with write_session() as session:
            subclouds = (
                session.query(models.Subcloud)
                .filter_by(deleted=0)
                .filter_by(region_name=region_name)
                .all()
            )
            if subclouds:
                for subcloud_ref in subclouds:
                    session.delete(subcloud_ref)
            else:
                raise exception.SubcloudNotFound(region_name=region_name)

    @require_context(admin=True)
    def subcloud_update_initial_state(
        self, region_name, pre_initial_sync_state, initial_sync_state
    ):
        with write_session() as session:
            result = (
                session.query(models.Subcloud)
                .filter_by(region_name=region_name)
                .filter_by(initial_sync_state=pre_initial_sync_state)
                .update({models.Subcloud.initial_sync_state: initial_sync_state})
            )
            return result

    @require_context(admin=True)
    def subcloud_update_all_initial_state(
        self, pre_initial_sync_state, initial_sync_state
    ):
        with write_session() as session:
            updated_count = (
                session.query(models.Subcloud)
                .filter_by(deleted=0)
                .filter_by(initial_sync_state=pre_initial_sync_state)
                .update({models.Subcloud.initial_sync_state: initial_sync_state})
            )
            return updated_count

    def _resource_get(self, resource_type, master_id, session):
        query = model_query(self.context, models.Resource, session=session).filter_by(
            deleted=0
        )
        query = query.filter_by(resource_type=resource_type)
        query = query.filter_by(master_id=master_id)
        try:
            return query.one()
        except NoResultFound:
            raise exception.ResourceNotFound(resource_type=resource_type)
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err=(
                    "Multiple entries found for resource %(id)s of type %(type)s",
                    {"id": master_id, "type": resource_type},
                )
            )

    @require_context()
    def resource_get_by_type_and_master_id(self, resource_type, master_id):
        with read_session() as session:
            return self._resource_get(resource_type, master_id, session)

    @require_context()
    def resource_get_by_id(self, resource_id, session=None):
        query = model_query(self.context, models.Resource, session=session).filter_by(
            deleted=0
        )
        query = query.filter_by(id=resource_id)
        try:
            return query.one()
        except NoResultFound:
            raise exception.ResourceNotFound(id=resource_id)

    @require_context()
    def resource_get_all(self, resource_type=None):
        query = model_query(self.context, models.Resource).filter_by(deleted=0)

        if resource_type:
            query = add_identity_filter(query, resource_type, use_resource_type=True)

        return query.all()

    @require_context(admin=True)
    def resource_create(self, resource_type, values):
        with write_session() as session:
            result = models.Resource()
            result.resource_type = resource_type
            if not values.get("uuid"):
                values["uuid"] = uuidutils.generate_uuid()
            result.update(values)
            session.add(result)
            return result

    @require_context(admin=True)
    def resource_update(self, resource_id, values):
        with write_session() as session:
            result = self.resource_get_by_id(resource_id, session=session)
            result.update(values)
            result.save(session)
            return result

    @require_context(admin=True)
    def resource_delete(self, resource_type, master_id):
        with write_session() as session:
            resources = (
                session.query(models.Resource)
                .filter_by(deleted=0)
                .filter_by(resource_type=resource_type)
                .filter_by(master_id=master_id)
                .all()
            )
            if resources:
                for resource_ref in resources:
                    session.delete(resource_ref)
            else:
                raise exception.ResourceNotFound(resource_type=resource_type)

    def _subcloud_resource_get(self, subcloud_resource_id, session=None):
        query = model_query(
            self.context, models.SubcloudResource, session=session
        ).filter_by(deleted=0)
        query = add_identity_filter(query, subcloud_resource_id)
        try:
            return query.one()
        except NoResultFound:
            raise exception.SubcloudResourceNotFound(resource=subcloud_resource_id)

    @require_context()
    def subcloud_resource_get(self, subcloud_resource_id):
        return self._subcloud_resource_get(subcloud_resource_id)

    @require_context()
    def subcloud_resources_get_by_subcloud(self, subcloud_id):
        query = model_query(self.context, models.SubcloudResource).filter_by(deleted=0)
        if subcloud_id:
            query = query.join(
                models.Subcloud,
                models.Subcloud.id == models.SubcloudResource.subcloud_id,
            )
            query, field = add_filter_by_many_identities(
                query, models.Subcloud, [subcloud_id]
            )
        return query.all()

    @require_context()
    def subcloud_resources_get_by_resource(self, resource_id):
        # query by resource id or uuid, not resource master uuid.
        query = model_query(self.context, models.SubcloudResource).filter_by(deleted=0)
        if resource_id:
            query = query.join(
                models.Resource,
                models.Resource.id == models.SubcloudResource.resource_id,
            )
            query, field = add_filter_by_many_identities(
                query, models.Resource, [resource_id]
            )
        return query.all()

    def subcloud_resources_get_all(self):
        query = model_query(self.context, models.SubcloudResource).filter_by(deleted=0)
        return query.all()

    @require_context()
    def subcloud_resource_get_by_resource_and_subcloud(self, resource_id, subcloud_id):
        query = (
            model_query(self.context, models.SubcloudResource)
            .filter_by(deleted=0)
            .filter_by(resource_id=resource_id)
            .filter_by(subcloud_id=subcloud_id)
        )
        try:
            return query.one()
        except NoResultFound:
            raise exception.SubcloudResourceNotFound()
        except MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err=(
                    "Multiple entries found for resource %(rid)d subcloud %(sid)d",
                    {"rid": resource_id, "sid": subcloud_id},
                )
            )

    @require_context(admin=True)
    def subcloud_resource_create(self, subcloud_id, resource_id, values):
        with write_session() as session:
            result = models.SubcloudResource()
            result.subcloud_id = subcloud_id
            result.resource_id = resource_id
            if not values.get("uuid"):
                values["uuid"] = uuidutils.generate_uuid()
            result.update(values)
            try:
                session.add(result)
            except db_exc.DBDuplicateEntry:
                raise exception.SubcloudResourceAlreadyExists(
                    subcloud_id=subcloud_id, resource_id=resource_id
                )
            return result

    @require_context(admin=True)
    def subcloud_resource_update(self, subcloud_resource_id, values):
        with write_session() as session:
            result = self._subcloud_resource_get(subcloud_resource_id, session)
            result.update(values)
            result.save(session)
            return result

    @require_context(admin=True)
    def subcloud_resource_delete(self, subcloud_resource_id):
        with write_session() as session:
            query = session.query(models.SubcloudResource).filter_by(deleted=0)
            query = add_identity_filter(query, subcloud_resource_id)
            try:
                subcloud_resource_ref = query.one()
            except NoResultFound:
                raise exception.SubcloudResourceNotFound(resource=subcloud_resource_id)
            session.delete(subcloud_resource_ref)

    def _orch_job_get(self, orch_job_id, session=None):
        query = model_query(self.context, models.OrchJob, session=session).filter_by(
            deleted=0
        )
        query = add_identity_filter(query, orch_job_id)
        try:
            return query.one()
        except NoResultFound:
            raise exception.OrchJobNotFound(orch_job=orch_job_id)

    @require_context()
    def orch_job_get(self, orch_job_id):
        return self._orch_job_get(orch_job_id)

    @require_context()
    def orch_job_get_all(self, resource_id=None):
        query = model_query(self.context, models.OrchJob).filter_by(deleted=0)
        if resource_id:
            query = query.join(
                models.Resource, models.Resource.id == models.OrchJob.resource_id
            )
            query, field = add_filter_by_many_identities(
                query, models.Resource, [resource_id]
            )
        return query.all()

    @require_context(admin=True)
    def orch_job_create(self, resource_id, endpoint_type, operation_type, values):
        with write_session() as session:
            result = models.OrchJob()
            result.resource_id = resource_id
            result.endpoint_type = endpoint_type
            result.operation_type = operation_type
            if not values.get("uuid"):
                values["uuid"] = uuidutils.generate_uuid()
            result.update(values)
            try:
                session.add(result)
            except db_exc.DBDuplicateEntry:
                raise exception.OrchJobAlreadyExists(
                    resource_id=resource_id,
                    endpoint_type=endpoint_type,
                    operation_type=operation_type,
                )
            return result

    @require_context(admin=True)
    def orch_job_update(self, context, orch_job_id, values):
        with write_session() as session:
            result = self._orch_job_get(orch_job_id, session)
            result.update(values)
            result.save(session)
            return result

    @require_context(admin=True)
    def orch_job_delete(self, orch_job_id):
        with write_session() as session:
            query = session.query(models.OrchJob).filter_by(deleted=0)
            query = add_identity_filter(query, orch_job_id)
            try:
                orch_job_ref = query.one()
            except NoResultFound:
                raise exception.OrchJobNotFound(orch_job=orch_job_id)
            session.delete(orch_job_ref)

    def _orch_request_get(self, orch_request_id, session=None):
        query = model_query(
            self.context, models.OrchRequest, session=session
        ).filter_by(deleted=0)
        query = add_identity_filter(query, orch_request_id)
        try:
            return query.one()
        except NoResultFound:
            raise exception.OrchRequestNotFound(orch_request=orch_request_id)

    @require_context()
    def orch_request_get(self, orch_request_id):
        return self._orch_request_get(orch_request_id)

    @require_context()
    def orch_request_get_most_recent_failed_request(self):
        query = (
            model_query(self.context, models.OrchRequest)
            .filter_by(deleted=0)
            .filter_by(state=consts.ORCH_REQUEST_STATE_FAILED)
        )

        try:
            return query.order_by(desc(models.OrchRequest.updated_at)).first()
        except NoResultFound:
            return None

    @require_context()
    def orch_request_get_all(self, orch_job_id=None):
        query = model_query(self.context, models.OrchRequest).filter_by(deleted=0)
        if orch_job_id:
            query = query.join(
                models.OrchJob, models.OrchJob.id == models.OrchRequest.orch_job_id
            )
            query, field = add_filter_by_many_identities(
                query, models.OrchJob, [orch_job_id]
            )
        return query.all()

    @require_context()
    def orch_request_get_by_attrs(
        self,
        endpoint_type,
        resource_type=None,
        target_region_name=None,
        states=None,
    ):
        """Query OrchRequests by attributes.

        :param endpoint_type: OrchJob.endpoint_type
        :param resource_type: Resource.resource_type
        :param target_region_name: OrchRequest target_region_name
        :param states: [OrchRequest.state] note: must be a list
        :return: [OrchRequests] sorted by OrchRequest.id
        """
        query = model_query(self.context, models.OrchRequest).filter_by(deleted=0)

        if target_region_name:
            query = query.filter_by(target_region_name=target_region_name)

        if states:
            states = set(states)
            query = query.filter(models.OrchRequest.state.in_(states))

        query = query.join(
            models.OrchJob, models.OrchJob.id == models.OrchRequest.orch_job_id
        ).filter_by(endpoint_type=endpoint_type)

        if resource_type is not None:
            query = query.join(
                models.Resource, models.Resource.id == models.OrchJob.resource_id
            ).filter_by(resource_type=resource_type)

        # sort by orch_request id
        query = query.order_by(asc(models.OrchRequest.id)).all()

        return query

    @require_context(admin=True)
    def orch_request_create(self, orch_job_id, target_region_name, values):
        with write_session() as session:
            result = models.OrchRequest()
            result.orch_job_id = orch_job_id
            result.target_region_name = target_region_name
            if not values.get("uuid"):
                values["uuid"] = uuidutils.generate_uuid()
            result.update(values)
            try:
                session.add(result)
            except db_exc.DBDuplicateEntry:
                raise exception.OrchRequestAlreadyExists(
                    orch_request=orch_job_id, target_region_name=target_region_name
                )
            return result

    def orch_request_create_bulk(self, orch_requests):
        for request in orch_requests:
            if "orch_job_id" not in request:
                msg = "cannot create an OrchRequest object without a orch_job_id set"
                raise exception.ObjectActionError(
                    action="create_bulk",
                    reason=msg,
                )
            if "target_region_name" not in request:
                raise exception.ObjectActionError(
                    action="create_bulk",
                    reason="cannot create an OrchRequest object without a "
                    "target_region_name set",
                )
        with write_session() as session:
            session.bulk_insert_mappings(models.OrchRequest, orch_requests)

    @require_context(admin=True)
    def orch_request_update(self, orch_request_id, values):
        with write_session() as session:
            result = self._orch_request_get(orch_request_id, session)
            result.update(values)
            result.save(session)
            return result

    @require_context(admin=True)
    def orch_request_destroy(self, orch_request_id):
        with write_session() as session:
            query = session.query(models.OrchRequest).filter_by(deleted=0)
            query = add_identity_filter(query, orch_request_id)
            try:
                orch_request_ref = query.one()
            except NoResultFound:
                raise exception.OrchRequestNotFound(orch_request=orch_request_id)
            session.delete(orch_request_ref)

    @require_context(admin=True)
    def orch_request_delete_by_subcloud(self, region_name):
        """Delete all orch_request entries for a given subcloud.

        This is used primarily when deleting a subcloud.
        In particular, it is not a bug if there are no entries to delete.
        """
        with write_session() as session:
            session.query(models.OrchRequest).filter_by(
                target_region_name=region_name
            ).delete()

    @require_context(admin=True)
    def orch_request_delete_previous_failed_requests(self, delete_timestamp):
        """Soft delete orch_request entries.

        This is used to soft delete all previously failed requests at
        the end of each audit cycle.
        """
        LOG.info(
            "Soft deleting failed orch requests at and before %s", delete_timestamp
        )
        with write_session() as session:
            query = (
                session.query(models.OrchRequest)
                .filter_by(deleted=0)
                .filter_by(state=consts.ORCH_REQUEST_STATE_FAILED)
                .filter(models.OrchRequest.updated_at <= delete_timestamp)
            )

            count = query.update({"deleted": 1, "deleted_at": timeutils.utcnow()})
        LOG.info("%d previously failed sync requests soft deleted", count)

    def _subcloud_sync_get(self, subcloud_name, endpoint_type, session=None):
        query = (
            model_query(self.context, models.SubcloudSync, session=session)
            .filter_by(subcloud_name=subcloud_name)
            .filter_by(endpoint_type=endpoint_type)
        )
        try:
            return query.one()
        except NoResultFound:
            raise exception.SubcloudSyncNotFound(
                subcloud_name=subcloud_name, endpoint_type=endpoint_type
            )
        except MultipleResultsFound:
            err = "Multiple entries found for subcloud %s endpoint_type %s" % (
                subcloud_name,
                endpoint_type,
            )
            raise exception.InvalidParameterValue(err=err)

    def subcloud_sync_get(self, subcloud_name, endpoint_type):
        return self._subcloud_sync_get(subcloud_name, endpoint_type)

    def subcloud_sync_create(self, subcloud_name, endpoint_type, values):
        with write_session() as session:
            result = models.SubcloudSync()
            result.subcloud_name = subcloud_name
            result.endpoint_type = endpoint_type
            result.update(values)
            try:
                session.add(result)
            except db_exc.DBDuplicateEntry:
                raise exception.SubcloudSyncAlreadyExists(
                    subcloud_name=subcloud_name, endpoint_type=endpoint_type
                )
            return result

    def subcloud_sync_update(self, subcloud_name, endpoint_type, values):
        with write_session() as session:
            result = self._subcloud_sync_get(subcloud_name, endpoint_type, session)
            result.update(values)
            result.save(session)
            return result

    def subcloud_sync_update_all_except_in_progress(
        self, management_state, endpoint_type, values
    ):
        with write_session() as session:
            subquery = (
                select([models.SubcloudSync.id])
                .where(models.SubcloudSync.subcloud_name == models.Subcloud.region_name)
                .where(models.Subcloud.management_state == management_state)
                .where(models.SubcloudSync.endpoint_type == endpoint_type)
                .where(
                    models.SubcloudSync.sync_request != consts.SYNC_STATUS_IN_PROGRESS
                )
                .where(models.SubcloudSync.deleted == 0)
                .correlate(models.SubcloudSync)
            )

            stmt = (
                update(models.SubcloudSync)
                .where(models.SubcloudSync.id.in_(subquery))
                .values(values)
            )

            result = session.execute(stmt)

            return result.rowcount

    def subcloud_sync_delete(self, subcloud_name, endpoint_type):
        with write_session() as session:
            results = (
                session.query(models.SubcloudSync)
                .filter_by(subcloud_name=subcloud_name)
                .filter_by(endpoint_type=endpoint_type)
                .all()
            )
            for result in results:
                session.delete(result)

    @require_context()
    def should_stop_subcloud_sync(self, subcloud_name, endpoint_type):
        with read_session() as session:
            try:
                # Get minimal subcloud columns
                subcloud = (
                    session.query(
                        models.Subcloud.availability_status,
                        models.Subcloud.initial_sync_state,
                    )
                    .filter_by(deleted=0)
                    .filter_by(region_name=subcloud_name)
                    .one()
                )
            except NoResultFound:
                raise exception.SubcloudNotFound(region_name=subcloud_name)
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err="Multiple entries found for subcloud %s" % subcloud_name
                )

            try:
                # Verify sync exists
                session.query(models.SubcloudSync).filter_by(
                    subcloud_name=subcloud_name, endpoint_type=endpoint_type
                ).one()

            except NoResultFound:
                return True
            except MultipleResultsFound:
                raise exception.InvalidParameterValue(
                    err=f"Multiple entries found for subcloud {subcloud_name}"
                )

            return not (
                subcloud.availability_status == dccommon_consts.AVAILABILITY_ONLINE
                and subcloud.initial_sync_state == consts.INITIAL_SYNC_STATE_COMPLETED
            )
