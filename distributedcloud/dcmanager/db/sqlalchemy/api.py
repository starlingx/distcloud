# Copyright (c) 2015 Ericsson AB.
# Copyright (c) 2017-2025 Wind River Systems, Inc.
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
Implementation of SQLAlchemy backend.
"""

import functools
import sys

import eventlet
from oslo_db import exception as db_exc
from oslo_db.exception import DBDuplicateEntry
from oslo_db.sqlalchemy import enginefacade
from oslo_log import log as logging
from oslo_utils import strutils
from oslo_utils import timeutils
from oslo_utils import uuidutils
import sqlalchemy
from sqlalchemy import bindparam
from sqlalchemy import desc
from sqlalchemy import func
from sqlalchemy import insert
from sqlalchemy import or_
from sqlalchemy.orm import exc
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import load_only
from sqlalchemy.sql.expression import true
from sqlalchemy import update

from dccommon import consts as dccommon_consts
from dcmanager.common import consts
from dcmanager.common import exceptions as exception
from dcmanager.common.i18n import _
from dcmanager.db.sqlalchemy import migration
from dcmanager.db.sqlalchemy import models

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


@db_session_cleanup
class Connection(object):

    def __init__(self, context):
        self.context = context

    @staticmethod
    def db_sync(engine, version=None):
        """Migrate the database to `version` or the most recent version."""
        retVal = migration.db_sync(engine, version=version)
        # returns None if migration has completed
        if retVal is None:
            initialize_db_defaults(engine)
        return retVal

    @staticmethod
    def db_version(engine):
        """Display the current database version."""
        return migration.db_version(engine)

    @require_context()
    def subcloud_audits_get(self, subcloud_id):
        result = (
            model_query(self.context, models.SubcloudAudits)
            .filter_by(deleted=0)
            .filter_by(subcloud_id=subcloud_id)
            .first()
        )

        if not result:
            raise exception.SubcloudNotFound(subcloud_id=subcloud_id)

        return result

    @require_context()
    def subcloud_audits_get_all(self, subcloud_ids=None):
        """Get subcloud_audits info for subclouds

        :param subcloud_ids: if specified, return only the subclouds with specified ids
        """

        with read_session() as session:
            query = session.query(models.SubcloudAudits).filter_by(deleted=0)

            if subcloud_ids:
                query = query.filter(
                    models.SubcloudAudits.subcloud_id.in_(subcloud_ids)
                )

            return query.all()

    @require_context()
    def subcloud_audits_update_all(self, values):
        with write_session() as session:
            result = (
                session.query(models.SubcloudAudits).filter_by(deleted=0).update(values)
            )
            return result

    @require_context(admin=True)
    def subcloud_audits_create(self, subcloud_id):
        with write_session() as session:
            subcloud_audits_ref = models.SubcloudAudits()
            subcloud_audits_ref.subcloud_id = subcloud_id
            session.add(subcloud_audits_ref)
            return subcloud_audits_ref

    @require_context(admin=True)
    def subcloud_audits_update(self, subcloud_id, values):
        with write_session() as session:
            subcloud_audits_ref = self.subcloud_audits_get(subcloud_id)
            subcloud_audits_ref.update(values)
            subcloud_audits_ref.save(session)
            return subcloud_audits_ref

    @require_context()
    def subcloud_audits_get_all_need_audit(self, last_audit_threshold):
        with read_session() as session:
            result = (
                session.query(
                    models.SubcloudAudits,
                    models.Subcloud.name,
                    models.Subcloud.deploy_status,
                    models.Subcloud.availability_status,
                )
                .join(
                    models.Subcloud,
                    models.Subcloud.id == models.SubcloudAudits.subcloud_id,
                )
                .filter_by(deleted=0)
                .filter(
                    models.SubcloudAudits.audit_started_at
                    <= models.SubcloudAudits.audit_finished_at
                )
                .filter(
                    (models.SubcloudAudits.audit_finished_at < last_audit_threshold)
                    | (models.SubcloudAudits.patch_audit_requested == true())
                    | (models.SubcloudAudits.firmware_audit_requested == true())
                    | (models.SubcloudAudits.load_audit_requested == true())
                    | (
                        models.SubcloudAudits.kube_rootca_update_audit_requested
                        == true()
                    )
                    | (models.SubcloudAudits.kubernetes_audit_requested == true())
                    | (models.SubcloudAudits.spare_audit_requested == true())
                )
                .all()
            )
        return result

    # In the functions below it would be cleaner if the timestamp were calculated
    # by the DB server.  If server time is in UTC func.now() might work.

    @require_context()
    def subcloud_audits_subcloud_get_and_start_audit(self, subcloud_id):
        with write_session() as session:
            result = (
                session.query(models.Subcloud, models.SubcloudAudits)
                .join(
                    models.SubcloudAudits,
                    models.Subcloud.id == models.SubcloudAudits.subcloud_id,
                )
                .filter(models.Subcloud.id == subcloud_id)
                .filter(models.SubcloudAudits.deleted == 0)
                .first()
            )

            if not result:
                raise exception.SubcloudNotFound(subcloud_id=subcloud_id)

            subcloud, subcloud_audit = result

            # Start the new audit
            subcloud_audit.audit_started_at = timeutils.utcnow()
            subcloud_audit.save(session)

            return subcloud, subcloud_audit

    @require_context()
    def subcloud_audits_bulk_end_audit(self, audits_finished):
        """Update the subcloud's audit end status in a bulk request

        :param audits_finished: audits finished dict object that contains the subcloud's
        id as the key and its timestamp and audits finished as values
        """

        # audits_finished structure:
        # "subcloud's id": {
        #   "timestamp": "2024-08-15 17:56:00",
        #   "audits_finished": ["patching", "firmware"]
        # }

        update_list = list()
        subcloud_audits = self.subcloud_audits_get_all(audits_finished.keys())

        for subcloud_audit in subcloud_audits:
            audit_finished = audits_finished[subcloud_audit.subcloud_id]
            entry = {
                "id": subcloud_audit.id,
                "audit_finished_at": audit_finished["timestamp"],
                "state_update_requested": False,
                **{
                    dccommon_consts.ENDPOINT_AUDIT_REQUESTS[endpoint]: False
                    for endpoint in audit_finished["audits_finished"]
                },
            }
            update_list.append(entry)

        with write_session() as session:
            return session.bulk_update_mappings(models.SubcloudAudits, update_list)

    @require_context()
    def subcloud_audits_bulk_update_audit_finished_at(self, subcloud_ids):
        values = {"audit_finished_at": timeutils.utcnow()}
        with write_session() as session:
            model_query(self.context, models.SubcloudAudits, session=session).filter_by(
                deleted=0
            ).filter(models.SubcloudAudits.subcloud_id.in_(subcloud_ids)).update(
                values, synchronize_session="fetch"
            )

    # Find and fix up subcloud audits where the audit has taken too long.
    # We want to find subclouds that started an audit but never finished
    # it and update the "finished at" timestamp to be the same as
    # the "started at" timestamp.  Returns the number of rows updated.
    @require_context()
    def subcloud_audits_fix_expired_audits(
        self, last_audit_threshold, trigger_audits=False
    ):
        values = {"audit_finished_at": models.SubcloudAudits.audit_started_at}
        if trigger_audits:
            # request all the special audits
            values["patch_audit_requested"] = True
            values["firmware_audit_requested"] = True
            values["load_audit_requested"] = True
            values["kubernetes_audit_requested"] = True
            values["kube_rootca_update_audit_requested"] = True
            values["spare_audit_requested"] = True
        with write_session() as session:
            result = (
                session.query(models.SubcloudAudits)
                .options(load_only("deleted", "audit_started_at", "audit_finished_at"))
                .filter_by(deleted=0)
                .filter(models.SubcloudAudits.audit_finished_at < last_audit_threshold)
                .filter(
                    models.SubcloudAudits.audit_started_at
                    > models.SubcloudAudits.audit_finished_at
                )
                .update(values, synchronize_session=False)
            )
        return result

    @require_context()
    def subcloud_get(self, subcloud_id):
        result = model_query(self.context, models.Subcloud).get(subcloud_id)

        if not result:
            raise exception.SubcloudNotFound(subcloud_id=subcloud_id)

        return result

    @require_context()
    def subcloud_get_with_status(self, subcloud_id):
        result = (
            model_query(self.context, models.Subcloud, models.SubcloudStatus)
            .outerjoin(
                models.SubcloudStatus,
                (models.Subcloud.id == models.SubcloudStatus.subcloud_id)
                | (not models.SubcloudStatus.subcloud_id),
            )
            .filter(models.Subcloud.id == subcloud_id)
            .filter(models.Subcloud.deleted == 0)
            .order_by(models.SubcloudStatus.endpoint_type)
            .all()
        )

        if not result:
            raise exception.SubcloudNotFound(subcloud_id=subcloud_id)

        return result

    @require_context()
    def subcloud_get_by_name(self, name):
        result = (
            model_query(self.context, models.Subcloud)
            .filter_by(deleted=0)
            .filter_by(name=name)
            .first()
        )

        if not result:
            raise exception.SubcloudNameNotFound(name=name)

        return result

    @require_context()
    def subcloud_get_by_region_name(self, region_name):
        result = (
            model_query(self.context, models.Subcloud)
            .filter_by(deleted=0)
            .filter_by(region_name=region_name)
            .first()
        )

        if not result:
            raise exception.SubcloudRegionNameNotFound(region_name=region_name)

        return result

    @require_context()
    def subcloud_get_by_name_or_region_name(self, name):
        result = (
            model_query(self.context, models.Subcloud)
            .filter_by(deleted=0)
            .filter(
                or_(models.Subcloud.name == name, models.Subcloud.region_name == name)
            )
            .first()
        )

        if not result:
            raise exception.SubcloudNameOrRegionNameNotFound(name=name)

        return result

    @require_context()
    def subcloud_get_all(self):
        return model_query(self.context, models.Subcloud).filter_by(deleted=0).all()

    @require_context()
    def subcloud_get_all_by_group_id(self, group_id):
        """Retrieve all subclouds that belong to the specified group id"""

        return (
            model_query(self.context, models.Subcloud)
            .filter_by(deleted=0)
            .filter_by(group_id=group_id)
            .all()
        )

    @require_context()
    def subcloud_get_all_ordered_by_id(self):
        return (
            model_query(self.context, models.Subcloud)
            .filter_by(deleted=0)
            .order_by(models.Subcloud.id)
            .all()
        )

    @require_context()
    def subcloud_get_all_with_status(self):
        result = (
            model_query(
                self.context,
                models.Subcloud,
                models.SubcloudStatus.endpoint_type,
                models.SubcloudStatus.sync_status,
            )
            .join(
                models.SubcloudStatus,
                models.Subcloud.id == models.SubcloudStatus.subcloud_id,
            )
            .filter(models.Subcloud.deleted == 0)
            .order_by(models.Subcloud.id)
            .all()
        )

        return result

    @require_context()
    def subcloud_get_all_valid_for_strategy_step_creation(
        self,
        endpoint_type,
        group_id=None,
        subcloud_name=None,
        availability_status=None,
        sync_status=None,
    ):
        """Queries all the subclouds that are valid for the strategy step to create

        :param endpoint_type: type of endpoint
        :param group_id: if specified, filter the subclouds by their group id
        :param subcloud_name: if specified, retrieve only a single subcloud
        :param availability_status: availability status to filter
        :param sync_status: list of sync status to filter

        :return: subclouds' object and the associated endpoint's sync status
        :rtype: list
        """

        with read_session() as session:
            query = session.query(
                models.Subcloud, models.SubcloudStatus.sync_status
            ).filter(
                models.Subcloud.deleted == 0,
                models.Subcloud.management_state == dccommon_consts.MANAGEMENT_MANAGED,
            )

            if group_id:
                query = query.filter(models.Subcloud.group_id == group_id)
            elif subcloud_name:
                query = query.filter(models.Subcloud.name == subcloud_name)

            if availability_status:
                query = query.filter(
                    models.Subcloud.availability_status == availability_status
                )

            query = query.join(
                models.SubcloudStatus,
                models.Subcloud.id == models.SubcloudStatus.subcloud_id,
            ).filter(
                models.SubcloudStatus.endpoint_type == endpoint_type,
            )

            if sync_status:
                query = query.filter(models.SubcloudStatus.sync_status.in_(sync_status))

            return query.all()

    @require_context()
    def subcloud_count_invalid_for_strategy_type(
        self, endpoint_type, group_id=None, subcloud_name=None, force=False
    ):
        """Queries the count of invalid subclouds for a strategy's creation

        :param endpoint_type: type of endpoint
        :param group_id: if specified, filter the subclouds by their group id
        :param subcloud_name: if specified, retrieve only a single subcloud
        :param force: whether all subclouds should be evaluated or only online ones

        :return: number of invalid subclouds for the specified endpoint type
        :rtype: int
        """

        with read_session() as session:
            query = session.query(models.Subcloud).filter(
                models.Subcloud.deleted == 0,
                models.Subcloud.management_state == dccommon_consts.MANAGEMENT_MANAGED,
            )

            if group_id:
                query = query.filter(models.Subcloud.group_id == group_id)
            elif subcloud_name:
                query = query.filter(models.Subcloud.name == subcloud_name)

            if not force:
                query = query.filter(
                    models.Subcloud.availability_status
                    == dccommon_consts.AVAILABILITY_ONLINE
                )

            query = query.join(
                models.SubcloudStatus,
                models.Subcloud.id == models.SubcloudStatus.subcloud_id,
            ).filter(
                models.SubcloudStatus.endpoint_type == endpoint_type,
                models.SubcloudStatus.sync_status
                == dccommon_consts.SYNC_STATUS_UNKNOWN,
            )

            return query.count()

    @require_context(admin=True)
    def subcloud_create(
        self,
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
        with write_session() as session:
            subcloud_ref = models.Subcloud()
            subcloud_ref.name = name
            subcloud_ref.description = description
            subcloud_ref.location = location
            subcloud_ref.software_version = software_version
            subcloud_ref.management_state = dccommon_consts.MANAGEMENT_UNMANAGED
            subcloud_ref.availability_status = dccommon_consts.AVAILABILITY_OFFLINE
            subcloud_ref.management_subnet = management_subnet
            subcloud_ref.management_gateway_ip = management_gateway_ip
            subcloud_ref.management_start_ip = management_start_ip
            subcloud_ref.management_end_ip = management_end_ip
            subcloud_ref.systemcontroller_gateway_ip = systemcontroller_gateway_ip
            subcloud_ref.external_oam_subnet_ip_family = external_oam_subnet_ip_family
            subcloud_ref.deploy_status = deploy_status
            subcloud_ref.error_description = error_description
            subcloud_ref.region_name = region_name
            subcloud_ref.audit_fail_count = 0
            subcloud_ref.openstack_installed = openstack_installed
            subcloud_ref.group_id = group_id
            if data_install is not None:
                subcloud_ref.data_install = data_install
            session.add(subcloud_ref)
            session.flush()
            self.subcloud_status_create_all(subcloud_ref.id)
            self.subcloud_audits_create(subcloud_ref.id)
            return subcloud_ref

    @require_context(admin=True)
    def subcloud_update(
        self,
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
        with write_session() as session:
            subcloud_ref = self.subcloud_get(subcloud_id)
            if management_state is not None:
                subcloud_ref.management_state = management_state
            if availability_status is not None:
                subcloud_ref.availability_status = availability_status
            if software_version is not None:
                subcloud_ref.software_version = software_version
            if name is not None:
                subcloud_ref.name = name
            if description is not None:
                subcloud_ref.description = description
            if management_subnet is not None:
                subcloud_ref.management_subnet = management_subnet
            if management_gateway_ip is not None:
                subcloud_ref.management_gateway_ip = management_gateway_ip
            if management_start_ip is not None:
                subcloud_ref.management_start_ip = management_start_ip
            if management_end_ip is not None:
                subcloud_ref.management_end_ip = management_end_ip
            if location is not None:
                subcloud_ref.location = location
            if audit_fail_count is not None:
                subcloud_ref.audit_fail_count = audit_fail_count
            if data_install is not None:
                subcloud_ref.data_install = data_install
            if deploy_status is not None:
                subcloud_ref.deploy_status = deploy_status
            if backup_status is not None:
                subcloud_ref.backup_status = backup_status
            if backup_datetime is not None:
                subcloud_ref.backup_datetime = backup_datetime
            if error_description is not None:
                subcloud_ref.error_description = error_description
            if data_upgrade is not None:
                subcloud_ref.data_upgrade = data_upgrade
            if openstack_installed is not None:
                subcloud_ref.openstack_installed = openstack_installed
            if group_id is not None:
                subcloud_ref.group_id = group_id
            if first_identity_sync_complete is not None:
                subcloud_ref.first_identity_sync_complete = first_identity_sync_complete
            if systemcontroller_gateway_ip is not None:
                subcloud_ref.systemcontroller_gateway_ip = systemcontroller_gateway_ip
            if external_oam_subnet_ip_family is not None:
                subcloud_ref.external_oam_subnet_ip_family = (
                    external_oam_subnet_ip_family
                )
            if peer_group_id is not None:
                if str(peer_group_id).lower() == "none":
                    subcloud_ref.peer_group_id = None
                else:
                    subcloud_ref.peer_group_id = peer_group_id
            if rehome_data is not None:
                subcloud_ref.rehome_data = rehome_data
            if rehomed is not None:
                subcloud_ref.rehomed = rehomed
            if prestage_status is not None:
                subcloud_ref.prestage_status = prestage_status
            if prestage_versions is not None:
                subcloud_ref.prestage_versions = prestage_versions
            if region_name is not None:
                subcloud_ref.region_name = region_name
            subcloud_ref.save(session)
            return subcloud_ref

    @require_context(admin=True)
    def subcloud_bulk_update_by_ids(self, subcloud_ids, update_form):
        with write_session() as session:
            model_query(self.context, models.Subcloud, session=session).filter_by(
                deleted=0
            ).filter(models.Subcloud.id.in_(subcloud_ids)).update(
                update_form, synchronize_session="fetch"
            )

    @require_context(admin=True)
    def subcloud_destroy(self, subcloud_id):
        with write_session() as session:
            subcloud_ref = self.subcloud_get(subcloud_id)
            session.delete(subcloud_ref)

    @require_context()
    def subcloud_status_get(self, subcloud_id, endpoint_type):
        result = (
            model_query(self.context, models.SubcloudStatus)
            .filter_by(deleted=0)
            .filter_by(subcloud_id=subcloud_id)
            .filter_by(endpoint_type=endpoint_type)
            .first()
        )

        if not result:
            raise exception.SubcloudStatusNotFound(
                subcloud_id=subcloud_id, endpoint_type=endpoint_type
            )

        return result

    @require_context()
    def subcloud_status_get_all(self, subcloud_id):
        return (
            model_query(self.context, models.SubcloudStatus)
            .filter_by(deleted=0)
            .join(
                models.Subcloud, models.SubcloudStatus.subcloud_id == models.Subcloud.id
            )
            .filter(models.Subcloud.id == subcloud_id)
            .all()
        )

    @require_context()
    def _subcloud_status_get_by_endpoint_types(self, subcloud_id, endpoint_types):
        return (
            model_query(self.context, models.SubcloudStatus)
            .filter_by(deleted=0)
            .filter(models.SubcloudStatus.subcloud_id == subcloud_id)
            .filter(models.SubcloudStatus.endpoint_type.in_(endpoint_types))
            .all()
        )

    @require_context()
    def subcloud_status_get_all_by_name(self, name):
        return (
            model_query(self.context, models.SubcloudStatus)
            .filter_by(deleted=0)
            .join(
                models.Subcloud, models.SubcloudStatus.subcloud_id == models.Subcloud.id
            )
            .filter(models.Subcloud.name == name)
            .all()
        )

    @require_context(admin=True)
    def subcloud_status_create(self, subcloud_id, endpoint_type):
        with write_session() as session:
            subcloud_status_ref = models.SubcloudStatus()
            subcloud_status_ref.subcloud_id = subcloud_id
            subcloud_status_ref.endpoint_type = endpoint_type
            subcloud_status_ref.sync_status = dccommon_consts.SYNC_STATUS_UNKNOWN
            session.add(subcloud_status_ref)
            return subcloud_status_ref

    @require_context(admin=True)
    def subcloud_status_create_all(self, subcloud_id):
        with write_session() as session:
            for endpoint_type in dccommon_consts.AUDIT_TYPES_LIST:
                subcloud_status_ref = models.SubcloudStatus()
                subcloud_status_ref.subcloud_id = subcloud_id
                subcloud_status_ref.endpoint_type = endpoint_type
                subcloud_status_ref.sync_status = dccommon_consts.SYNC_STATUS_UNKNOWN
                session.add(subcloud_status_ref)

    @require_context(admin=True)
    def subcloud_status_delete(self, subcloud_id, endpoint_type):
        with write_session() as session:
            subcloud_status_ref = self.subcloud_status_get(subcloud_id, endpoint_type)
            session.delete(subcloud_status_ref)

    @require_context(admin=True)
    def subcloud_status_update(self, subcloud_id, endpoint_type, sync_status):
        with write_session() as session:
            subcloud_status_ref = self.subcloud_status_get(subcloud_id, endpoint_type)
            subcloud_status_ref.sync_status = sync_status
            subcloud_status_ref.save(session)
            return subcloud_status_ref

    @require_context(admin=True)
    def subcloud_status_update_endpoints(
        self, subcloud_id, endpoint_type_list, sync_status
    ):
        """Update all statuses of endpoints in endpoint_type_list of a subcloud.

        Will raise if subcloud status does not exist.
        """
        value = {"sync_status": sync_status}
        with write_session() as session:
            result = (
                session.query(models.SubcloudStatus)
                .filter_by(subcloud_id=subcloud_id)
                .filter(models.SubcloudStatus.endpoint_type.in_(endpoint_type_list))
                .update(value, synchronize_session=False)
            )
        if not result:
            raise exception.SubcloudStatusNotFound(
                subcloud_id=subcloud_id, endpoint_type="any"
            )

        return result

    @require_context(admin=True)
    def subcloud_status_bulk_update_endpoints(self, subcloud_id, endpoint_list):
        """Update the status of the specified endpoints for a subcloud

        Will raise if subcloud status does not exist.
        """

        # Retrieves the subcloud status' data for all of the endpoints in endpoint_lst
        subcloud_statuses = self._subcloud_status_get_by_endpoint_types(
            subcloud_id, endpoint_list.keys()
        )

        # Create a list with the id of each subcloud status that needs to be updated and
        # its respective sync_status
        update_list = list()
        for subcloud_status in subcloud_statuses:
            update_list.append(
                {
                    "_id": subcloud_status.id,
                    "sync_status": endpoint_list[subcloud_status.endpoint_type],
                }
            )

        # Bindparam associates keys from update_list to columns in the database
        # query. This way, for each of the items that needs update, it's possible to
        # set a specific sync_status, i.e. the query is capable of updating many
        # endpoints with each of them having one of three values:
        # in-sync, out-of-sync and unknown.
        with write_session() as session:
            statement = (
                update(models.SubcloudStatus)
                .where(models.SubcloudStatus.id == bindparam("_id"))
                .values(sync_status=bindparam("sync_status"))
            )

            result = session.execute(statement, update_list)
        if not result:
            raise exception.SubcloudStatusNotFound(
                subcloud_id=subcloud_id, endpoint_type="any"
            )

        return result

    @require_context(admin=True)
    def subcloud_status_destroy_all(self, subcloud_id):
        with write_session() as session:
            subcloud_statuses = self.subcloud_status_get_all(subcloud_id)
            if subcloud_statuses:
                for subcloud_status_ref in subcloud_statuses:
                    session.delete(subcloud_status_ref)
            else:
                raise exception.SubcloudStatusNotFound(
                    subcloud_id=subcloud_id, endpoint_type="any"
                )

    @require_context()
    def sw_update_strategy_get(self, update_type=None):
        query = model_query(self.context, models.SwUpdateStrategy).filter_by(deleted=0)
        if update_type is not None:
            query = query.filter_by(type=update_type)
        result = query.first()
        if not result:
            raise exception.StrategyNotFound(strategy_type=update_type)

        return result

    @require_context(admin=True)
    def sw_update_strategy_create(
        self,
        type,
        subcloud_apply_type,
        max_parallel_subclouds,
        stop_on_failure,
        state,
        extra_args=None,
    ):
        with write_session() as session:
            sw_update_strategy_ref = models.SwUpdateStrategy()
            sw_update_strategy_ref.type = type
            sw_update_strategy_ref.subcloud_apply_type = subcloud_apply_type
            sw_update_strategy_ref.max_parallel_subclouds = max_parallel_subclouds
            sw_update_strategy_ref.stop_on_failure = stop_on_failure
            sw_update_strategy_ref.state = state
            sw_update_strategy_ref.extra_args = extra_args

            session.add(sw_update_strategy_ref)
            return sw_update_strategy_ref

    @require_context(admin=True)
    def sw_update_strategy_update(
        self, state=None, update_type=None, additional_args=None
    ):
        with write_session() as session:
            sw_update_strategy_ref = self.sw_update_strategy_get(
                update_type=update_type
            )
            if state is not None:
                sw_update_strategy_ref.state = state
            if additional_args is not None:
                if sw_update_strategy_ref.extra_args is None:
                    sw_update_strategy_ref.extra_args = additional_args
                else:
                    # extend the existing dictionary
                    sw_update_strategy_ref.extra_args = dict(
                        sw_update_strategy_ref.extra_args, **additional_args
                    )
            sw_update_strategy_ref.save(session)
            return sw_update_strategy_ref

    @require_context(admin=True)
    def sw_update_strategy_destroy(self, update_type=None):
        with write_session() as session:
            sw_update_strategy_ref = self.sw_update_strategy_get(
                update_type=update_type
            )
            session.delete(sw_update_strategy_ref)

    @require_context()
    def sw_update_opts_get(self, subcloud_id):
        result = (
            model_query(self.context, models.SwUpdateOpts)
            .filter_by(deleted=0)
            .filter_by(subcloud_id=subcloud_id)
            .first()
        )

        # Note we will return None if not found
        return result

    @require_context()
    def sw_update_opts_get_all_plus_subcloud_info(self):
        result = (
            model_query(self.context, models.Subcloud, models.SwUpdateOpts)
            .outerjoin(
                models.SwUpdateOpts,
                (models.Subcloud.id == models.SwUpdateOpts.subcloud_id)
                | (not models.SubcloudStatus.subcloud_id),
            )
            .filter(models.Subcloud.deleted == 0)
            .order_by(models.Subcloud.id)
            .all()
        )

        return result

    @require_context(admin=True)
    def sw_update_opts_create(
        self,
        subcloud_id,
        storage_apply_type,
        worker_apply_type,
        max_parallel_workers,
        alarm_restriction_type,
        default_instance_action,
    ):
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

    @require_context(admin=True)
    def sw_update_opts_update(
        self,
        subcloud_id,
        storage_apply_type=None,
        worker_apply_type=None,
        max_parallel_workers=None,
        alarm_restriction_type=None,
        default_instance_action=None,
    ):
        with write_session() as session:
            sw_update_opts_ref = self.sw_update_opts_get(subcloud_id)
            if storage_apply_type is not None:
                sw_update_opts_ref.storage_apply_type = storage_apply_type
            if worker_apply_type is not None:
                sw_update_opts_ref.worker_apply_type = worker_apply_type
            if max_parallel_workers is not None:
                sw_update_opts_ref.max_parallel_workers = max_parallel_workers
            if alarm_restriction_type is not None:
                sw_update_opts_ref.alarm_restriction_type = alarm_restriction_type
            if default_instance_action is not None:
                sw_update_opts_ref.default_instance_action = default_instance_action
            sw_update_opts_ref.save(session)
            return sw_update_opts_ref

    @require_context(admin=True)
    def sw_update_opts_destroy(self, subcloud_id):
        with write_session() as session:
            sw_update_opts_ref = self.sw_update_opts_get(subcloud_id)
            session.delete(sw_update_opts_ref)

    @require_context()
    def sw_update_opts_default_get(self):
        result = (
            model_query(self.context, models.SwUpdateOptsDefault)
            .filter_by(deleted=0)
            .first()
        )

        # Note we will return None if not found
        return result

    @require_context(admin=True)
    def sw_update_opts_default_create(
        self,
        storage_apply_type,
        worker_apply_type,
        max_parallel_workers,
        alarm_restriction_type,
        default_instance_action,
    ):
        with write_session() as session:
            sw_update_opts_default_ref = models.SwUpdateOptsDefault()
            sw_update_opts_default_ref.subcloud_id = 0
            sw_update_opts_default_ref.storage_apply_type = storage_apply_type
            sw_update_opts_default_ref.worker_apply_type = worker_apply_type
            sw_update_opts_default_ref.max_parallel_workers = max_parallel_workers
            sw_update_opts_default_ref.alarm_restriction_type = alarm_restriction_type
            sw_update_opts_default_ref.default_instance_action = default_instance_action
            session.add(sw_update_opts_default_ref)
            return sw_update_opts_default_ref

    @require_context(admin=True)
    def sw_update_opts_default_update(
        self,
        storage_apply_type=None,
        worker_apply_type=None,
        max_parallel_workers=None,
        alarm_restriction_type=None,
        default_instance_action=None,
    ):
        with write_session() as session:
            sw_update_opts_default_ref = self.sw_update_opts_default_get()
            if storage_apply_type is not None:
                sw_update_opts_default_ref.storage_apply_type = storage_apply_type
            if worker_apply_type is not None:
                sw_update_opts_default_ref.worker_apply_type = worker_apply_type
            if max_parallel_workers is not None:
                sw_update_opts_default_ref.max_parallel_workers = max_parallel_workers
            if alarm_restriction_type is not None:
                sw_update_opts_default_ref.alarm_restriction_type = (
                    alarm_restriction_type
                )
            if default_instance_action is not None:
                sw_update_opts_default_ref.default_instance_action = (
                    default_instance_action
                )
            sw_update_opts_default_ref.save(session)
            return sw_update_opts_default_ref

    @require_context(admin=True)
    def sw_update_opts_default_destroy(self):
        with write_session() as session:
            sw_update_opts_default_ref = self.sw_update_opts_default_get()
            session.delete(sw_update_opts_default_ref)

    @require_context()
    def system_peer_get(self, peer_id):
        try:
            result = (
                model_query(self.context, models.SystemPeer)
                .filter_by(deleted=0)
                .filter_by(id=peer_id)
                .one()
            )
        except exc.NoResultFound:
            raise exception.SystemPeerNotFound(peer_id=peer_id)
        except exc.MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for system peer %s" % peer_id
            )

        return result

    @require_context()
    def system_peer_get_by_name(self, name):
        try:
            result = (
                model_query(self.context, models.SystemPeer)
                .filter_by(deleted=0)
                .filter_by(peer_name=name)
                .one()
            )
        except exc.NoResultFound:
            raise exception.SystemPeerNameNotFound(name=name)
        except exc.MultipleResultsFound:
            # This exception should never happen due to the UNIQUE setting for name
            raise exception.InvalidParameterValue(
                err="Multiple entries found for system peer %s" % name
            )

        return result

    @require_context()
    def system_peer_get_by_uuid(self, uuid):
        try:
            result = (
                model_query(self.context, models.SystemPeer)
                .filter_by(deleted=0)
                .filter_by(peer_uuid=uuid)
                .one()
            )
        except exc.NoResultFound:
            raise exception.SystemPeerUUIDNotFound(uuid=uuid)
        except exc.MultipleResultsFound:
            # This exception should never happen due to the UNIQUE setting for uuid
            raise exception.InvalidParameterValue(
                err="Multiple entries found for system peer %s" % uuid
            )

        return result

    @require_context()
    def system_peer_get_all(self):
        result = (
            model_query(self.context, models.SystemPeer)
            .filter_by(deleted=0)
            .order_by(models.SystemPeer.id)
            .all()
        )

        return result

    # This method returns all subcloud peer groups for a particular system peer
    @require_context()
    def peer_group_get_for_system_peer(self, peer_id):
        return (
            model_query(self.context, models.SubcloudPeerGroup)
            .join(
                models.PeerGroupAssociation,
                models.SubcloudPeerGroup.id
                == models.PeerGroupAssociation.peer_group_id,
            )
            .filter(models.SubcloudPeerGroup.deleted == 0)
            .filter(models.PeerGroupAssociation.system_peer_id == peer_id)
            .order_by(models.SubcloudPeerGroup.id)
            .all()
        )

    @require_context(admin=True)
    def system_peer_create(
        self,
        peer_uuid,
        peer_name,
        endpoint,
        username,
        password,
        gateway_ip,
        administrative_state="enabled",
        heartbeat_interval=60,
        heartbeat_failure_threshold=3,
        heartbeat_failure_policy="alarm",
        heartbeat_maintenance_timeout=600,
        availability_state="created",
    ):
        with write_session() as session:
            system_peer_ref = models.SystemPeer()
            system_peer_ref.peer_uuid = peer_uuid
            system_peer_ref.peer_name = peer_name
            system_peer_ref.manager_endpoint = endpoint
            system_peer_ref.manager_username = username
            system_peer_ref.manager_password = password
            system_peer_ref.peer_controller_gateway_ip = gateway_ip
            system_peer_ref.administrative_state = administrative_state
            system_peer_ref.heartbeat_interval = heartbeat_interval
            system_peer_ref.heartbeat_failure_threshold = heartbeat_failure_threshold
            system_peer_ref.heartbeat_failure_policy = heartbeat_failure_policy
            system_peer_ref.heartbeat_maintenance_timeout = (
                heartbeat_maintenance_timeout
            )
            system_peer_ref.availability_state = availability_state
            session.add(system_peer_ref)
            return system_peer_ref

    @require_context(admin=True)
    def system_peer_update(
        self,
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
        with write_session() as session:
            system_peer_ref = self.system_peer_get(peer_id)
            if peer_uuid is not None:
                system_peer_ref.peer_uuid = peer_uuid
            if peer_name is not None:
                system_peer_ref.peer_name = peer_name
            if endpoint is not None:
                system_peer_ref.manager_endpoint = endpoint
            if username is not None:
                system_peer_ref.manager_username = username
            if password is not None:
                system_peer_ref.manager_password = password
            if gateway_ip is not None:
                system_peer_ref.peer_controller_gateway_ip = gateway_ip
            if administrative_state is not None:
                system_peer_ref.administrative_state = administrative_state
            if heartbeat_interval is not None:
                system_peer_ref.heartbeat_interval = heartbeat_interval
            if heartbeat_failure_threshold is not None:
                system_peer_ref.heartbeat_failure_threshold = (
                    heartbeat_failure_threshold
                )
            if heartbeat_failure_policy is not None:
                system_peer_ref.heartbeat_failure_policy = heartbeat_failure_policy
            if heartbeat_maintenance_timeout is not None:
                system_peer_ref.heartbeat_maintenance_timeout = (
                    heartbeat_maintenance_timeout
                )
            if availability_state is not None:
                system_peer_ref.availability_state = availability_state
            system_peer_ref.save(session)
            return system_peer_ref

    @require_context(admin=True)
    def system_peer_destroy(self, peer_id):
        with write_session() as session:
            system_peer_ref = self.system_peer_get(peer_id)
            session.delete(system_peer_ref)

    @require_context()
    def subcloud_group_get(self, group_id):
        try:
            result = (
                model_query(self.context, models.SubcloudGroup)
                .filter_by(deleted=0)
                .filter_by(id=group_id)
                .one()
            )
        except exc.NoResultFound:
            raise exception.SubcloudGroupNotFound(group_id=group_id)
        except exc.MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for subcloud group %s" % group_id
            )

        return result

    @require_context()
    def subcloud_group_get_by_name(self, name):
        try:
            result = (
                model_query(self.context, models.SubcloudGroup)
                .filter_by(deleted=0)
                .filter_by(name=name)
                .one()
            )
        except exc.NoResultFound:
            raise exception.SubcloudGroupNameNotFound(name=name)
        except exc.MultipleResultsFound:
            # This exception should never happen due to the UNIQUE setting for name
            raise exception.InvalidParameterValue(
                err="Multiple entries found for subcloud group %s" % name
            )

        return result

    # This method returns all subclouds for a particular subcloud group
    @require_context()
    def subcloud_get_for_group(self, group_id):
        return (
            model_query(self.context, models.Subcloud)
            .filter_by(deleted=0)
            .filter_by(group_id=group_id)
            .order_by(models.Subcloud.id)
            .all()
        )

    @require_context()
    def subcloud_group_get_all(self):
        result = (
            model_query(self.context, models.SubcloudGroup)
            .filter_by(deleted=0)
            .order_by(models.SubcloudGroup.id)
            .all()
        )

        return result

    @require_context(admin=True)
    def subcloud_group_create(
        self, name, description, update_apply_type, max_parallel_subclouds
    ):
        with write_session() as session:
            subcloud_group_ref = models.SubcloudGroup()
            subcloud_group_ref.name = name
            subcloud_group_ref.description = description
            subcloud_group_ref.update_apply_type = update_apply_type
            subcloud_group_ref.max_parallel_subclouds = max_parallel_subclouds
            session.add(subcloud_group_ref)
            return subcloud_group_ref

    @require_context(admin=True)
    def subcloud_group_update(
        self,
        group_id,
        name=None,
        description=None,
        update_apply_type=None,
        max_parallel_subclouds=None,
    ):
        with write_session() as session:
            subcloud_group_ref = self.subcloud_group_get(group_id)
            if name is not None:
                # Do not allow the name of the default group to be edited
                if subcloud_group_ref.id == consts.DEFAULT_SUBCLOUD_GROUP_ID:
                    raise exception.SubcloudGroupNameViolation()
                # do not allow another group to use the default group name
                if name == consts.DEFAULT_SUBCLOUD_GROUP_NAME:
                    raise exception.SubcloudGroupNameViolation()
                subcloud_group_ref.name = name
            if description is not None:
                subcloud_group_ref.description = description
            if update_apply_type is not None:
                subcloud_group_ref.update_apply_type = update_apply_type
            if max_parallel_subclouds is not None:
                subcloud_group_ref.max_parallel_subclouds = max_parallel_subclouds
            subcloud_group_ref.save(session)
            return subcloud_group_ref

    @require_context(admin=True)
    def subcloud_group_destroy(self, group_id):
        with write_session() as session:
            subcloud_group_ref = self.subcloud_group_get(group_id)
            if subcloud_group_ref.id == consts.DEFAULT_SUBCLOUD_GROUP_ID:
                raise exception.SubcloudGroupDefaultNotDeletable(group_id=group_id)
            session.delete(subcloud_group_ref)

    @require_context()
    def subcloud_peer_group_get(self, group_id):
        try:
            result = (
                model_query(self.context, models.SubcloudPeerGroup)
                .filter_by(deleted=0)
                .filter_by(id=group_id)
                .one()
            )
        except exc.NoResultFound:
            raise exception.SubcloudPeerGroupNotFound(group_id=group_id)
        except exc.MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for subcloud peer group %s" % group_id
            )

        return result

    @require_context()
    def subcloud_get_for_peer_group(self, peer_group_id):
        """Get all subclouds for a subcloud peer group.

        :param peer_group_id: ID of the subcloud peer group
        """
        return (
            model_query(self.context, models.Subcloud)
            .filter_by(deleted=0)
            .filter_by(peer_group_id=peer_group_id)
            .order_by(models.Subcloud.id)
            .all()
        )

    @require_context()
    def subcloud_peer_group_get_all(self):
        result = (
            model_query(self.context, models.SubcloudPeerGroup)
            .filter_by(deleted=0)
            .order_by(models.SubcloudPeerGroup.id)
            .all()
        )

        return result

    @require_context()
    def subcloud_peer_group_get_by_name(self, name):
        try:
            result = (
                model_query(self.context, models.SubcloudPeerGroup)
                .filter_by(deleted=0)
                .filter_by(peer_group_name=name)
                .one()
            )
        except exc.NoResultFound:
            raise exception.SubcloudPeerGroupNameNotFound(name=name)
        except exc.MultipleResultsFound:
            # This exception should never happen due to the UNIQUE setting for name
            raise exception.InvalidParameterValue(
                err="Multiple entries found for subcloud peer group %s" % name
            )

        return result

    @require_context()
    def subcloud_peer_group_get_by_leader_id(self, system_leader_id):
        result = (
            model_query(self.context, models.SubcloudPeerGroup)
            .filter_by(deleted=0)
            .filter_by(system_leader_id=system_leader_id)
            .order_by(models.SubcloudPeerGroup.id)
            .all()
        )

        return result

    @require_context(admin=True)
    def subcloud_peer_group_create(
        self,
        peer_group_name,
        group_priority,
        group_state,
        max_subcloud_rehoming,
        system_leader_id,
        system_leader_name,
        migration_status,
    ):
        with write_session() as session:
            subcloud_peer_group_ref = models.SubcloudPeerGroup()
            subcloud_peer_group_ref.peer_group_name = peer_group_name
            subcloud_peer_group_ref.group_priority = group_priority
            subcloud_peer_group_ref.group_state = group_state
            subcloud_peer_group_ref.max_subcloud_rehoming = max_subcloud_rehoming
            subcloud_peer_group_ref.system_leader_id = system_leader_id
            subcloud_peer_group_ref.system_leader_name = system_leader_name
            subcloud_peer_group_ref.migration_status = migration_status
            session.add(subcloud_peer_group_ref)
            return subcloud_peer_group_ref

    @require_context(admin=True)
    def subcloud_peer_group_destroy(self, group_id):
        with write_session() as session:
            subcloud_peer_group_ref = self.subcloud_peer_group_get(group_id)
            session.delete(subcloud_peer_group_ref)

    @require_context(admin=True)
    def subcloud_peer_group_update(
        self,
        group_id,
        peer_group_name=None,
        group_priority=None,
        group_state=None,
        max_subcloud_rehoming=None,
        system_leader_id=None,
        system_leader_name=None,
        migration_status=None,
    ):
        with write_session() as session:
            subcloud_peer_group_ref = self.subcloud_peer_group_get(group_id)
            if peer_group_name is not None:
                subcloud_peer_group_ref.peer_group_name = peer_group_name
            if group_priority is not None:
                subcloud_peer_group_ref.group_priority = group_priority
            if group_state is not None:
                subcloud_peer_group_ref.group_state = group_state
            if max_subcloud_rehoming is not None:
                subcloud_peer_group_ref.max_subcloud_rehoming = max_subcloud_rehoming
            if system_leader_id is not None:
                subcloud_peer_group_ref.system_leader_id = system_leader_id
            if system_leader_name is not None:
                subcloud_peer_group_ref.system_leader_name = system_leader_name
            if migration_status is not None:
                if str(migration_status).lower() == "none":
                    subcloud_peer_group_ref.migration_status = None
                else:
                    subcloud_peer_group_ref.migration_status = migration_status
            subcloud_peer_group_ref.save(session)
            return subcloud_peer_group_ref

    @require_context(admin=True)
    def peer_group_association_create(
        self,
        peer_group_id,
        system_peer_id,
        peer_group_priority,
        association_type,
        sync_status,
        sync_message,
    ):
        with write_session() as session:
            peer_group_association_ref = models.PeerGroupAssociation()
            peer_group_association_ref.peer_group_id = peer_group_id
            peer_group_association_ref.system_peer_id = system_peer_id
            peer_group_association_ref.peer_group_priority = peer_group_priority
            peer_group_association_ref.association_type = association_type
            peer_group_association_ref.sync_status = sync_status
            peer_group_association_ref.sync_message = sync_message
            session.add(peer_group_association_ref)
            return peer_group_association_ref

    @require_context(admin=True)
    def peer_group_association_update(
        self,
        associate_id,
        peer_group_priority=None,
        sync_status=None,
        sync_message=None,
    ):
        with write_session() as session:
            association_ref = self.peer_group_association_get(associate_id)
            if peer_group_priority is not None:
                association_ref.peer_group_priority = peer_group_priority
            if sync_status is not None:
                association_ref.sync_status = sync_status
            if sync_message is not None:
                if str(sync_message).lower() == "none":
                    association_ref.sync_message = None
                else:
                    association_ref.sync_message = sync_message
            association_ref.save(session)
            return association_ref

    @require_context(admin=True)
    def peer_group_association_destroy(self, association_id):
        with write_session() as session:
            association_ref = self.peer_group_association_get(association_id)
            session.delete(association_ref)

    @require_context()
    def peer_group_association_get(self, association_id) -> models.PeerGroupAssociation:
        try:
            result = (
                model_query(self.context, models.PeerGroupAssociation)
                .filter_by(deleted=0)
                .filter_by(id=association_id)
                .one()
            )
        except exc.NoResultFound:
            raise exception.PeerGroupAssociationNotFound(association_id=association_id)
        except exc.MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for peer group association %s"
                % association_id
            )

        return result

    @require_context()
    def peer_group_association_get_all(
        self,
    ) -> list[models.PeerGroupAssociation]:
        result = (
            model_query(self.context, models.PeerGroupAssociation)
            .filter_by(deleted=0)
            .order_by(models.PeerGroupAssociation.id)
            .all()
        )

        return result

    # Each combination of 'peer_group_id' and 'system_peer_id' is unique
    # and appears only once in the entries.
    @require_context()
    def peer_group_association_get_by_peer_group_and_system_peer_id(
        self, peer_group_id, system_peer_id
    ) -> models.PeerGroupAssociation:
        try:
            result = (
                model_query(self.context, models.PeerGroupAssociation)
                .filter_by(deleted=0)
                .filter_by(peer_group_id=peer_group_id)
                .filter_by(system_peer_id=system_peer_id)
                .one()
            )
        except exc.NoResultFound:
            raise exception.PeerGroupAssociationCombinationNotFound(
                peer_group_id=peer_group_id, system_peer_id=system_peer_id
            )
        except exc.MultipleResultsFound:
            # This exception should never happen due to the UNIQUE setting for name
            raise exception.InvalidParameterValue(
                err="Multiple entries found for peer group association %s,%s"
                % (peer_group_id, system_peer_id)
            )
        return result

    @require_context()
    def peer_group_association_get_by_peer_group_id(
        self, peer_group_id
    ) -> models.PeerGroupAssociation:
        result = (
            model_query(self.context, models.PeerGroupAssociation)
            .filter_by(deleted=0)
            .filter_by(peer_group_id=peer_group_id)
            .order_by(models.PeerGroupAssociation.id)
            .all()
        )

        return result

    @require_context()
    def peer_group_association_get_by_system_peer_id(
        self, system_peer_id
    ) -> models.PeerGroupAssociation:
        result = (
            model_query(self.context, models.PeerGroupAssociation)
            .filter_by(deleted=0)
            .filter_by(system_peer_id=system_peer_id)
            .order_by(models.PeerGroupAssociation.id)
            .all()
        )

        return result

    @require_context()
    def strategy_step_get(self, subcloud_id):
        result = (
            model_query(self.context, models.StrategyStep)
            .filter_by(deleted=0)
            .filter_by(subcloud_id=subcloud_id)
            .first()
        )

        if not result:
            raise exception.StrategyStepNotFound(subcloud_id=subcloud_id)

        return result

    @require_context()
    def strategy_step_get_by_name(self, name):
        result = (
            model_query(self.context, models.StrategyStep)
            .filter_by(deleted=0)
            .join(
                models.Subcloud, models.StrategyStep.subcloud_id == models.Subcloud.id
            )
            .filter(models.Subcloud.name == name)
            .first()
        )

        if not result:
            raise exception.StrategyStepNameNotFound(name=name)

        return result

    @require_context()
    def strategy_step_get_all(self, steps_id=None, limit=None):
        with read_session() as session:
            query = model_query(
                self.context, models.StrategyStep, session=session
            ).filter_by(deleted=0)

            if steps_id:
                query = query.filter(models.StrategyStep.id.in_(steps_id))

            query = query.order_by(models.StrategyStep.id)

            if limit:
                query = query.limit(limit)

            return query.all()

    def _strategy_step_get_all_processing(self, session, max_parallel_subclouds):
        # Acquire all subclouds up to max_parallel_subclouds that have not reached
        # a final state yet. That is, the ones that are either processing or waiting
        # to be processed
        return (
            session.query(models.StrategyStep.id)
            .filter_by(deleted=0)
            .filter(
                models.StrategyStep.state.notin_(
                    [
                        consts.STRATEGY_STATE_ABORTED,
                        consts.STRATEGY_STATE_COMPLETE,
                        consts.STRATEGY_STATE_FAILED,
                    ]
                )
            )
            .order_by(models.StrategyStep.id)
            .limit(max_parallel_subclouds)
        )

    @require_context()
    def strategy_step_get_all_to_process(
        self, last_update_threshold, max_parallel_subclouds
    ):
        with read_session() as session:
            subquery = self._strategy_step_get_all_processing(
                session, max_parallel_subclouds
            )

            # Besides acquiring the steps based on the last updated time, it is
            # also necessary to get all steps that might be in initial state as
            # those won't have the updated_at field set
            return (
                model_query(self.context, models.StrategyStep, session=session)
                .filter(models.StrategyStep.id.in_(subquery))
                .filter(
                    or_(
                        models.StrategyStep.updated_at < last_update_threshold,
                        models.StrategyStep.state == consts.STRATEGY_STATE_INITIAL,
                    )
                )
            ).all()

    @require_context()
    def strategy_step_count_all_states(self):
        with read_session() as session:
            return (
                session.query(
                    models.StrategyStep.state, func.count(models.StrategyStep.id)
                )
                .filter_by(deleted=0)
                .group_by(models.StrategyStep.state)
            ).all()

    @require_context(admin=True)
    def strategy_step_bulk_create(self, subcloud_ids, stage, state, details):
        """Creates the strategy step for a list of subclouds

        :param subcloud_ids: list of subcloud ids
        :param stage: stretegy's step stage
        :param state: strategy's step state
        :param details: additional information for the strategy step
        """

        strategy_steps = list()

        for subcloud_id in subcloud_ids:
            strategy_steps.append(
                {
                    "subcloud_id": subcloud_id,
                    "stage": stage,
                    "state": state,
                    "details": details,
                }
            )

        with write_session() as session:
            return session.execute(insert(models.StrategyStep), strategy_steps)

    @require_context(admin=True)
    def strategy_step_create(self, subcloud_id, stage, state, details):
        with write_session() as session:
            strategy_step_ref = models.StrategyStep()
            strategy_step_ref.subcloud_id = subcloud_id
            strategy_step_ref.stage = stage
            strategy_step_ref.state = state
            strategy_step_ref.details = details
            session.add(strategy_step_ref)
            return strategy_step_ref

    @require_context(admin=True)
    def strategy_step_update(
        self,
        subcloud_id,
        stage=None,
        state=None,
        details=None,
        started_at=None,
        finished_at=None,
        updated_at=None,
    ):
        with write_session() as session:
            strategy_step_ref = self.strategy_step_get(subcloud_id)
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
            if updated_at is not None:
                strategy_step_ref.updated_at = updated_at
            strategy_step_ref.save(session)
            return strategy_step_ref

    @require_context(admin=True)
    def strategy_step_update_all(self, filters, values, steps_id=None):
        """Updates all strategy steps

        :param filters: filters to be applied in the query
        :param values: values to be set for the specified strategies
        :param steps_id: list of strategy steps to update
        """
        with write_session() as session:
            query = session.query(models.StrategyStep).filter_by(deleted=0)

            if steps_id:
                query = query.filter(models.StrategyStep.id.in_(steps_id))

            for key, value in filters.items():
                attribute = getattr(models.StrategyStep, key, None)

                if attribute:
                    query = query.filter(attribute == value)

            query.update(values, synchronize_session="fetch")

    @require_context(admin=True)
    def strategy_step_update_reset_updated_at(self, steps_id, last_update_threshold):
        with write_session() as session:
            model_query(self.context, models.StrategyStep, session=session).filter(
                models.StrategyStep.id.in_(steps_id)
            ).filter(models.StrategyStep.updated_at < last_update_threshold).update(
                {"updated_at": timeutils.utcnow()}, synchronize_session="fetch"
            )

    @require_context(admin=True)
    def strategy_step_abort_all_not_processing(self, max_parallel_subclouds):
        with write_session() as session:
            subquery = self._strategy_step_get_all_processing(
                session, max_parallel_subclouds
            )

            session.query(models.StrategyStep).filter(
                models.StrategyStep.id.notin_(subquery)
            ).update(
                {"state": consts.STRATEGY_STATE_ABORTED}, synchronize_session="fetch"
            )

    @require_context(admin=True)
    def strategy_step_destroy_all(self, steps_id=None, states=None):
        with write_session() as session:
            query = session.query(models.StrategyStep).filter_by(deleted=0)

            if steps_id:
                query = query.filter(models.StrategyStep.id.in_(steps_id))

            if states:
                query = query.filter(models.StrategyStep.state.in_(states))

            query.delete(synchronize_session="fetch")

    @require_context()
    def _subcloud_alarms_get(self, name):
        query = model_query(self.context, models.SubcloudAlarmSummary).filter_by(
            deleted=0
        )
        query = add_identity_filter(query, name, use_name=True)

        try:
            return query.one()
        except exc.NoResultFound:
            raise exception.SubcloudNameNotFound(name=name)
        except exc.MultipleResultsFound:
            raise exception.InvalidParameterValue(
                err="Multiple entries found for subcloud %s" % name
            )

    @require_context()
    def subcloud_alarms_get(self, name):
        return self._subcloud_alarms_get(name)

    @require_context()
    def subcloud_alarms_get_all(self, name=None):
        query = model_query(self.context, models.SubcloudAlarmSummary).filter_by(
            deleted=0
        )

        if name:
            query = add_identity_filter(query, name, use_name=True)

        return query.order_by(desc(models.SubcloudAlarmSummary.id)).all()

    @require_context(admin=True)
    def subcloud_alarms_create(self, name, values):
        with write_session() as session:
            result = models.SubcloudAlarmSummary()
            result.name = name
            if not values.get("uuid"):
                values["uuid"] = uuidutils.generate_uuid()
            result.update(values)
            try:
                session.add(result)
            except db_exc.DBDuplicateEntry:
                raise exception.SubcloudAlreadyExists(region_name=name)
            return result

    @require_context(admin=True)
    def subcloud_alarms_update(self, name, values):
        with write_session() as session:
            result = self._subcloud_alarms_get(name)
            result.update(values)
            result.save(session)
            return result

    @require_context(admin=True)
    def subcloud_alarms_delete(self, name):
        with write_session() as session:
            session.query(models.SubcloudAlarmSummary).filter_by(name=name).delete()

    @require_context(admin=True)
    def subcloud_rename_alarms(self, subcloud_name, new_name):
        with write_session() as session:
            result = self._subcloud_alarms_get(subcloud_name)
            result.name = new_name
            result.save(session)
            return result


def initialize_subcloud_group_default(engine):
    try:
        # Assign a constant to avoid line too long
        default_sc_group_max_parallel_subclouds = (
            consts.DEFAULT_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS
        )
        default_group = {
            "id": consts.DEFAULT_SUBCLOUD_GROUP_ID,
            "name": consts.DEFAULT_SUBCLOUD_GROUP_NAME,
            "description": consts.DEFAULT_SUBCLOUD_GROUP_DESCRIPTION,
            "update_apply_type": consts.DEFAULT_SUBCLOUD_GROUP_UPDATE_APPLY_TYPE,
            "max_parallel_subclouds": default_sc_group_max_parallel_subclouds,
            "deleted": 0,
        }
        meta = sqlalchemy.MetaData(bind=engine)
        subcloud_group = sqlalchemy.Table("subcloud_group", meta, autoload=True)
        try:
            with engine.begin() as conn:
                conn.execute(
                    subcloud_group.insert(), default_group  # pylint: disable=E1120
                )
            LOG.info("Default Subcloud Group created")
        except DBDuplicateEntry:
            # The default already exists.
            pass
    except Exception as ex:
        LOG.error("Exception occurred setting up default subcloud group", ex)


def initialize_db_defaults(engine):
    # a default value may already exist. If it does not, create it
    initialize_subcloud_group_default(engine)


def add_identity_filter(query, value, use_name=None):
    """Adds an identity filter to a query.

    Filters results by 'id', if supplied value is a valid integer.
    then attempts to filter results by 'uuid';
    otherwise filters by name

    :param query: Initial query to add filter to.
    :param value: Value for filtering results by.
    :param use_name: Use name in filter

    :return: Modified query.
    """
    if strutils.is_int_like(value):
        return query.filter_by(id=value)
    elif uuidutils.is_uuid_like(value):
        return query.filter_by(uuid=value)
    elif use_name:
        return query.filter_by(name=value)
    else:
        return query.filter_by(name=value)
