# Copyright (c) 2015 Ericsson AB
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
SQLAlchemy models for dcmanager data.
"""

import datetime
import json

from oslo_db.sqlalchemy import models
from sqlalchemy import Boolean
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy.orm import backref
from sqlalchemy.orm import relationship
from sqlalchemy.orm import session as orm_session
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator
from sqlalchemy.types import VARCHAR

BASE = declarative_base()


def get_session():
    from dcmanager.db.sqlalchemy import api as db_api

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


class DCManagerBase(models.ModelBase, models.SoftDeleteMixin, models.TimestampMixin):
    """Base class for DC Manager Models."""

    # __table_args__ = {'mysql_engine': 'InnoDB'}

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


class SystemPeer(BASE, DCManagerBase):
    """Represents a system peer"""

    __tablename__ = "system_peer"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    peer_uuid = Column(String(36), unique=True)
    peer_name = Column(String(255), unique=True)
    manager_endpoint = Column(String(255))
    manager_username = Column(String(255))
    manager_password = Column(String(255))
    peer_controller_gateway_ip = Column(String(255))
    administrative_state = Column(String(255))
    heartbeat_interval = Column(Integer)
    heartbeat_failure_threshold = Column(Integer)
    heartbeat_failure_policy = Column(String(255))
    heartbeat_maintenance_timeout = Column(Integer)
    availability_state = Column(String(255))


class SubcloudGroup(BASE, DCManagerBase):
    """Represents a subcloud group"""

    __tablename__ = "subcloud_group"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    name = Column(String(255), unique=True)
    description = Column(String(255))
    update_apply_type = Column(String(255))
    max_parallel_subclouds = Column(Integer)


class SubcloudPeerGroup(BASE, DCManagerBase):
    """Represents a subcloud group"""

    __tablename__ = "subcloud_peer_group"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    peer_group_name = Column(String(255), unique=True)
    group_priority = Column(Integer)
    group_state = Column(String(255))
    max_subcloud_rehoming = Column(Integer)
    system_leader_id = Column(String(255))
    system_leader_name = Column(String(255))
    migration_status = Column(String(255))


class PeerGroupAssociation(BASE, DCManagerBase):
    """Represents a Peer Group Association"""

    __tablename__ = "peer_group_association"

    id = Column(Integer, primary_key=True, autoincrement=True, nullable=False)
    peer_group_id = Column(Integer)
    system_peer_id = Column(Integer)
    association_type = Column(String(255))
    peer_group_priority = Column(Integer)
    sync_status = Column(String(255))
    sync_message = Column(Text())


class Subcloud(BASE, DCManagerBase):
    """Represents a subcloud"""

    __tablename__ = "subclouds"

    id = Column(Integer, primary_key=True, nullable=False)
    name = Column(String(255), unique=True)
    description = Column(String(255))
    location = Column(String(255))
    software_version = Column(String(255))
    management_state = Column(String(255))
    availability_status = Column(String(255))
    data_install = Column(String())
    deploy_status = Column(String(255))
    backup_status = Column(String(255))
    backup_datetime = Column(DateTime(timezone=False))
    error_description = Column(String(2048))
    region_name = Column(String(255), unique=True)
    data_upgrade = Column(String())
    management_subnet = Column(String(255))
    management_gateway_ip = Column(String(255))
    management_start_ip = Column(String(255), unique=True)
    management_end_ip = Column(String(255), unique=True)
    openstack_installed = Column(Boolean, nullable=False, default=False)
    systemcontroller_gateway_ip = Column(String(255))
    external_oam_subnet_ip_family = Column(String(255))
    audit_fail_count = Column(Integer)
    first_identity_sync_complete = Column(Boolean, default=False)
    peer_group_id = Column(Integer, ForeignKey("subcloud_peer_group.id"))
    rehome_data = Column(Text())
    prestage_status = Column(String(255))
    prestage_versions = Column(String(255))

    # multiple subclouds can be in a particular group
    group_id = Column(Integer, ForeignKey("subcloud_group.id"))
    group = relationship(SubcloudGroup, backref=backref("subcloud"))
    rehomed = Column(Boolean, default=False)


class SubcloudAudits(BASE, DCManagerBase):
    """Represents the various audits for a subcloud"""

    __tablename__ = "subcloud_audits"

    id = Column(Integer, primary_key=True, nullable=False)
    subcloud_id = Column(
        Integer, ForeignKey("subclouds.id", ondelete="CASCADE"), unique=True
    )
    audit_started_at = Column(DateTime(timezone=False), default=datetime.datetime.min)
    audit_finished_at = Column(DateTime(timezone=False), default=datetime.datetime.min)
    state_update_requested = Column(Boolean, nullable=False, default=False)
    firmware_audit_requested = Column(Boolean, nullable=False, default=False)
    kubernetes_audit_requested = Column(Boolean, nullable=False, default=False)
    kube_rootca_update_audit_requested = Column(Boolean, nullable=False, default=False)
    software_audit_requested = Column(Boolean, nullable=False, default=False)
    spare_audit_requested = Column(Boolean, nullable=False, default=False)
    spare2_audit_requested = Column(Boolean, nullable=False, default=False)
    reserved = Column(Text)


class SubcloudStatus(BASE, DCManagerBase):
    """Represents the status of an endpoint in a subcloud"""

    __tablename__ = "subcloud_status"

    id = Column(Integer, primary_key=True, nullable=False)
    subcloud_id = Column(Integer, ForeignKey("subclouds.id", ondelete="CASCADE"))
    endpoint_type = Column(String(255))
    sync_status = Column(String(255))


class SwUpdateStrategy(BASE, DCManagerBase):
    """Represents a software update for subclouds"""

    __tablename__ = "sw_update_strategy"

    id = Column(Integer, primary_key=True, nullable=False)
    type = Column(String(255), unique=True)
    subcloud_apply_type = Column(String(255))
    max_parallel_subclouds = Column(Integer)
    stop_on_failure = Column(Boolean)
    state = Column(String(255))
    extra_args = Column(JSONEncodedDict)


class SwUpdateOpts(BASE, DCManagerBase):
    """Represents software update options for a subcloud"""

    __tablename__ = "sw_update_opts"

    id = Column(Integer, primary_key=True, nullable=False)
    subcloud_id = Column(Integer, ForeignKey("subclouds.id", ondelete="CASCADE"))

    storage_apply_type = Column(String(255))
    worker_apply_type = Column(String(255))
    max_parallel_workers = Column(Integer)
    alarm_restriction_type = Column(String(255))
    default_instance_action = Column(String(255))


class SwUpdateOptsDefault(BASE, DCManagerBase):
    """Represents default software update options for subclouds"""

    __tablename__ = "sw_update_opts_default"

    id = Column(Integer, primary_key=True, nullable=False)

    subcloud_id = Column(Integer)
    storage_apply_type = Column(String(255))
    worker_apply_type = Column(String(255))
    max_parallel_workers = Column(Integer)
    alarm_restriction_type = Column(String(255))
    default_instance_action = Column(String(255))


class StrategyStep(BASE, DCManagerBase):
    """Represents a step for a strategy application"""

    __tablename__ = "strategy_steps"

    id = Column(Integer, primary_key=True, nullable=False)
    subcloud_id = Column(
        Integer, ForeignKey("subclouds.id", ondelete="CASCADE"), unique=True
    )
    stage = Column(Integer)
    state = Column(String(255))
    details = Column(String(1000))
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    subcloud = relationship(
        "Subcloud", backref=backref("strategy_steps", cascade="all,delete")
    )


class SubcloudAlarmSummary(BASE, DCManagerBase):
    """Represents a Distributed Cloud subcloud alarm aggregate"""

    __tablename__ = "subcloud_alarms"
    id = Column(Integer, primary_key=True, nullable=False, autoincrement=True)
    uuid = Column(String(36), unique=True)
    name = Column("name", String(255), unique=True)
    critical_alarms = Column("critical_alarms", Integer)
    major_alarms = Column("major_alarms", Integer)
    minor_alarms = Column("minor_alarms", Integer)
    warnings = Column("warnings", Integer)
    cloud_status = Column("cloud_status", String(64))
