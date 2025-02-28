# Copyright (c) 2017-2018, 2024-2025 Wind River Inc.
# All Rights Reserved.
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

import datetime
from oslo_config import cfg
import sqlalchemy


QUOTA_CLASS_NAME_DEFAULT = "default"
CONF = cfg.CONF
CONF.import_group("dc_orch_global_limit", "dcorch.common.config")


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData()
    meta.bind = migrate_engine

    quotas = sqlalchemy.Table(
        "quotas",
        meta,
        sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, nullable=False),
        sqlalchemy.Column("project_id", sqlalchemy.String(36)),
        sqlalchemy.Column("resource", sqlalchemy.String(255), nullable=False),
        sqlalchemy.Column("hard_limit", sqlalchemy.Integer, nullable=False),
        sqlalchemy.Column("capabilities", sqlalchemy.Text),
        sqlalchemy.Column("created_at", sqlalchemy.DateTime),
        sqlalchemy.Column("updated_at", sqlalchemy.DateTime),
        sqlalchemy.Column("deleted_at", sqlalchemy.DateTime),
        sqlalchemy.Column("deleted", sqlalchemy.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    quota_classes = sqlalchemy.Table(
        "quota_classes",
        meta,
        sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True, nullable=False),
        sqlalchemy.Column("class_name", sqlalchemy.String(length=255), index=True),
        sqlalchemy.Column("capabilities", sqlalchemy.Text),
        sqlalchemy.Column("created_at", sqlalchemy.DateTime),
        sqlalchemy.Column("updated_at", sqlalchemy.DateTime),
        sqlalchemy.Column("deleted_at", sqlalchemy.DateTime),
        sqlalchemy.Column("deleted", sqlalchemy.Integer),
        sqlalchemy.Column("resource", sqlalchemy.String(length=255)),
        sqlalchemy.Column("hard_limit", sqlalchemy.Integer, nullable=True),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    service = sqlalchemy.Table(
        "service",
        meta,
        sqlalchemy.Column(
            "id", sqlalchemy.String(36), primary_key=True, nullable=False
        ),
        sqlalchemy.Column("host", sqlalchemy.String(length=255)),
        sqlalchemy.Column("binary", sqlalchemy.String(length=255)),
        sqlalchemy.Column("topic", sqlalchemy.String(length=255)),
        sqlalchemy.Column("disabled", sqlalchemy.Boolean, default=False),
        sqlalchemy.Column("disabled_reason", sqlalchemy.String(length=255)),
        sqlalchemy.Column("capabilities", sqlalchemy.Text),
        sqlalchemy.Column("created_at", sqlalchemy.DateTime),
        sqlalchemy.Column("updated_at", sqlalchemy.DateTime),
        sqlalchemy.Column("deleted_at", sqlalchemy.DateTime),
        sqlalchemy.Column("deleted", sqlalchemy.Integer),
        mysql_engine="InnoDB",
        mysql_charset="utf8",
    )

    tables = (
        quotas,
        quota_classes,
        service,
    )

    for index, table in enumerate(tables):
        try:
            table.create()
        except Exception:
            # If an error occurs, drop all tables created so far to return
            # to the previously existing state.
            meta.drop_all(tables=tables[:index])
            raise

    rows = (
        sqlalchemy.select([sqlalchemy.func.count()])
        .select_from(quota_classes)
        .where(quota_classes.c.class_name == "default")
        .execute()
        .scalar()
    )

    # Do not add entries if there are already 'default' entries. We don't want to write
    # over something the user added.
    if not rows:
        created_at = datetime.datetime.now()

        # Set default quota limits
        qci = quota_classes.insert()  # pylint: disable=no-value-for-parameter
        for resource, default in CONF.dc_orch_global_limit.items():
            qci.execute(
                {
                    "created_at": created_at,
                    "class_name": QUOTA_CLASS_NAME_DEFAULT,
                    "resource": resource[6:],
                    "hard_limit": default,
                    "deleted": 0,
                }
            )


def downgrade(migrate_engine):
    raise NotImplementedError(
        "Database downgrade not supported - would drop all tables"
    )
