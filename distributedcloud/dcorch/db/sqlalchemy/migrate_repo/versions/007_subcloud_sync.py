# Copyright (c) 2020, 2024 Wind River Inc.
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


import sqlalchemy


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    sqlalchemy.Table("subcloud", meta, autoload=True)

    subcloud_sync = sqlalchemy.Table(
        "subcloud_sync",
        meta,
        sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, nullable=False),
        sqlalchemy.Column(
            "subcloud_id",
            sqlalchemy.Integer,
            sqlalchemy.ForeignKey("subcloud.id", ondelete="CASCADE"),
        ),
        sqlalchemy.Column("subcloud_name", sqlalchemy.String(255)),
        sqlalchemy.Column("endpoint_type", sqlalchemy.String(255), default="none"),
        sqlalchemy.Column("sync_request", sqlalchemy.String(64), default="none"),
        sqlalchemy.Column(
            "sync_status_reported", sqlalchemy.String(64), default="none"
        ),
        sqlalchemy.Column("sync_status_report_time", sqlalchemy.DateTime),
        sqlalchemy.Column("audit_status", sqlalchemy.String(64), default="none"),
        sqlalchemy.Column("last_audit_time", sqlalchemy.DateTime),
        sqlalchemy.Column("created_at", sqlalchemy.DateTime),
        sqlalchemy.Column("updated_at", sqlalchemy.DateTime),
        sqlalchemy.Column("deleted_at", sqlalchemy.DateTime),
        sqlalchemy.Column("deleted", sqlalchemy.Integer),
        sqlalchemy.Index(
            "subcloud_sync_subcloud_name_endpoint_type_idx",
            "subcloud_name",
            "endpoint_type",
        ),
        sqlalchemy.UniqueConstraint(
            "subcloud_name",
            "endpoint_type",
            name="uniq_subcloud_sync0subcloud_name0endpoint_type",
        ),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )
    subcloud_sync.create()
