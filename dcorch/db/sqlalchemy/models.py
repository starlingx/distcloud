# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
#
# Copyright (c) 2015 Ericsson AB
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
"""
SQLAlchemy models for dcorch data.
"""

import json
from oslo_db.sqlalchemy import models

from sqlalchemy.orm import session as orm_session
from sqlalchemy import (Column, Integer, String, Boolean, Index, schema)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.types import TypeDecorator, VARCHAR
from sqlalchemy.orm import relationship

from dcmanager.common import consts as dcm_consts
from dcorch.common import consts

BASE = declarative_base()


def get_session():
    from dcorch.db.sqlalchemy import api as db_api

    return db_api.get_session()


class JSONEncodedDict(TypeDecorator):
    """Represents an immutable structure as a json-encoded string."""

    impl = VARCHAR

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


class OrchestratorBase(models.ModelBase,
                       models.SoftDeleteMixin,
                       models.TimestampMixin):
    """Base class for Orchestrator Models."""

    __table_args__ = {'mysql_engine': 'InnoDB'}

    def expire(self, session=None, attrs=None):
        if not session:
            session = orm_session.Session.object_session(self)
            if not session:
                session = get_session()
        session.expire(self, attrs)

    def refresh(self, session=None, attrs=None):
        """Refresh this object."""
        if not session:
            session = orm_session.Session.object_session(self)
            if not session:
                session = get_session()
        session.refresh(self, attrs)

    def delete(self, session=None):
        """Delete this object."""
        if not session:
            session = orm_session.Session.object_session(self)
            if not session:
                session = get_session()
        session.begin()
        session.delete(self)
        session.commit()


class Quota(BASE, OrchestratorBase):
    """Represents a single quota override for a project.

    If there is no row for a given project id and resource, then the
    default for the quota class is used.  If there is no row for a
    given quota class and resource, then the default for the
    deployment is used. If the row is present but the hard limit is
    Null, then the resource is unlimited.
    """

    __tablename__ = 'quotas'

    __table_args__ = (
        schema.UniqueConstraint("project_id", "resource", "deleted",
                                name="uniq_quotas0project_id0resource0deleted"
                                ),)

    id = Column(Integer, primary_key=True)

    project_id = Column(String(255), index=True)

    resource = Column(String(255), nullable=False)

    hard_limit = Column(Integer, nullable=True)

    capabilities = Column(JSONEncodedDict)


class QuotaClass(BASE, OrchestratorBase):
    """Represents a single quota override for a quota class.

    If there is no row for a given quota class and resource, then the
    default for the deployment is used.  If the row is present but the
    hard limit is Null, then the resource is unlimited.
    """

    __tablename__ = "quota_classes"

    id = Column(Integer, primary_key=True)

    class_name = Column(String(255), index=True)

    resource = Column(String(255))

    hard_limit = Column(Integer, nullable=True)

    capabilities = Column(JSONEncodedDict)


class Service(BASE, OrchestratorBase):
    """"Orchestrator service engine registry"""

    __tablename__ = 'service'

    id = Column('id', String(36), primary_key=True, nullable=False)

    host = Column(String(255))

    binary = Column(String(255))

    topic = Column(String(255))

    disabled = Column(Boolean, default=False)

    disabled_reason = Column(String(255))

    capabilities = Column(JSONEncodedDict)


# Distributed Cloud Orchestrator Data Base Models
class Subcloud(BASE, OrchestratorBase):
    """Represents a Distributed Cloud subcloud"""

    __tablename__ = 'subcloud'
    __table_args__ = (
        Index('subcloud_region_name_idx', 'region_name'),
    )
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), unique=True)
    region_name = Column('region_name', String(255), unique=True)  # keystone
    software_version = Column('software_version', String(255))

    # dc manager updates the management and availability
    # default management_state is None; could be set to 'deleting'
    management_state = Column('management_state', String(64))
    availability_status = Column('availability_status', String(64),
                                 default=dcm_consts.AVAILABILITY_OFFLINE)
    capabilities = Column(JSONEncodedDict)


class SubcloudAlarmSummary(BASE, OrchestratorBase):
    """Represents a Distributed Cloud subcloud alarm aggregate"""
    __tablename__ = 'subcloud_alarms'
    __table_args__ = (
        Index('subcloud_alarm_region_name_idx', 'region_name'),
    )
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), unique=True)
    region_name = Column('region_name', String(255), unique=True)  # keystone
    critical_alarms = Column('critical_alarms', Integer)
    major_alarms = Column('major_alarms', Integer)
    minor_alarms = Column('minor_alarms', Integer)
    warnings = Column('warnings', Integer)
    cloud_status = Column('cloud_status', String(64))
    capabilities = Column(JSONEncodedDict)


class Resource(BASE, OrchestratorBase):
    """Represents a Distributed Cloud Orchestrator Resource"""

    __tablename__ = 'resource'
    __table_args__ = (
        Index('resource_resource_type_idx', 'resource_type'),
        Index('resource_master_id_idx', 'master_id'),
        UniqueConstraint(
            'resource_type', 'master_id', 'deleted',
            name='uniq_resource0resource_type0master_id0deleted'),
    )
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), unique=True)
    capabilities = Column(JSONEncodedDict)

    resource_type = Column(String(128))  # e.g. quota_x,flavor_extra_spec,dns..
    master_id = Column(String(255))     # id/uuid of resource in central region


class SubcloudResource(BASE, OrchestratorBase):
    """Represents a Distributed Cloud Orchestrator Subcloud Resource"""

    __tablename__ = 'subcloud_resource'
    __table_args__ = (
        Index('subcloud_resource_resource_id_idx', 'resource_id'),
        UniqueConstraint(
            'resource_id', 'subcloud_id',
            name='uniq_subcloud_resource0resource_id0subcloud_id'),
    )

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), unique=True)

    # Could get subcloud_name (or target_region) from subcloud.region_name
    # subcloud_name = Column('subcloud_name', String(255))
    # Is this resource managed or unmanaged: e.g. ntp may not be managed
    # by orchestrator for some subcloud
    shared_config_state = Column('shared_config_state', String(255),
                                 default="managed")
    capabilities = Column(JSONEncodedDict)

    subcloud_resource_id = Column(String(255))  # usually uuid, sometimes id
    # if either resource_id or subcloud_id is set as primary key, id does not
    # autoincrement
    resource_id = Column('resource_id', Integer,
                         ForeignKey('resource.id', ondelete='CASCADE'))

    subcloud_id = Column('subcloud_id', Integer,
                         ForeignKey('subcloud.id', ondelete='CASCADE'))
    # todo: we shouldn't allow more than one row to have the same
    # resource_id/subcloud_id tuple


class OrchJob(BASE, OrchestratorBase):
    """Orchestrator Job registry"""

    __tablename__ = 'orch_job'
    __table_args__ = (
        Index('orch_job_endpoint_type_idx', 'endpoint_type'),
    )

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), unique=True)

    user_id = Column('user_id', String(128))
    project_id = Column('project_id', String(128))

    # Filled in by x_orch_api e.g. platform, volumev2, compute, network
    endpoint_type = Column(String(255), nullable=False)
    # e.g. quota_x, flavors, flavor_extra_spec, idns
    # resource_type = Column(String(255), nullable=False)
    source_resource_id = Column(String(255))  # for debugging
    operation_type = Column(String(255))  # http type: post/put/patch/delete
    capabilities = Column(JSONEncodedDict)

    resource_id = Column('resource_id', Integer,
                         ForeignKey('resource.id'))  # nullable=False?

    # resource_info cannot be derived from  resource.master_values
    # Represents resource info for a specific API call.  In case of update, it
    # may only be adding a specific k/v pair to an existing resource.  Also, we
    # need to ensure order of operations in the subcloud matches order of
    # operations in the master cloud.  This is a string representing a JSON-
    # formatted dict.  The exact contents will vary depending on resource.
    resource_info = Column(String())

    orchrequests = relationship('OrchRequest', backref='orch_job')
    # orch_status can be derived from the underlying OrchRequests state


class OrchRequest(BASE, OrchestratorBase):
    __tablename__ = 'orch_request'
    __table_args__ = (
        Index('orch_request_state_idx', 'state'),
        UniqueConstraint(
            'target_region_name', 'orch_job_id', 'deleted',
            name='uniq_orchreq0target_region_name0orch_job_id0deleted'),
    )

    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), unique=True)

    # state updated by engine one of: "in-progress", "completed", "failed",
    # "timed-out", "aborted"
    state = Column(String(128), default=consts.ORCH_REQUEST_NONE)
    try_count = Column(Integer, default=0)
    api_version = Column(String(128))

    target_region_name = Column(String(255))
    capabilities = Column(JSONEncodedDict)

    orch_job_id = Column('orch_job_id', Integer,
                         ForeignKey('orch_job.id'), primary_key=True)
