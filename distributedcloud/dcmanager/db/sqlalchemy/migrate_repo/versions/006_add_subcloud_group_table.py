# Copyright (c) 2020-2021 Wind River Systems, Inc.
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

from migrate.changeset import constraint
import sqlalchemy

from dcmanager.common import consts

ENGINE = 'InnoDB',
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = sqlalchemy.MetaData(bind=migrate_engine)

    # Declare the new subcloud_group table
    subcloud_group = sqlalchemy.Table(
        'subcloud_group', meta,
        sqlalchemy.Column('id', sqlalchemy.Integer,
                          primary_key=True,
                          autoincrement=True,
                          nullable=False),
        sqlalchemy.Column('name', sqlalchemy.String(255), unique=True),
        sqlalchemy.Column('description', sqlalchemy.String(255)),
        sqlalchemy.Column('update_apply_type', sqlalchemy.String(255)),
        sqlalchemy.Column('max_parallel_subclouds', sqlalchemy.Integer),
        sqlalchemy.Column('reserved_1', sqlalchemy.Text),
        sqlalchemy.Column('reserved_2', sqlalchemy.Text),
        sqlalchemy.Column('created_at', sqlalchemy.DateTime),
        sqlalchemy.Column('updated_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted_at', sqlalchemy.DateTime),
        sqlalchemy.Column('deleted', sqlalchemy.Integer, default=0),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET
    )
    subcloud_group.create()

    subclouds = sqlalchemy.Table('subclouds', meta, autoload=True)

    # TODO(abailey) do we want to fix the missing constraint for strategy_steps
    # strat_steps = sqlalchemy.Table('strategy_steps', meta, autoload=True)
    # strat_fkey = constraint.ForeignKeyConstraint(
    #    columns=[strat_steps.c.subcloud_id],
    #    refcolumns=[subclouds.c.id],
    #    name='strat_subcloud_ref')
    # strat_steps.append_constraint(strat_fkey)

    # Create a default subcloud group
    default_group = {
        "id": consts.DEFAULT_SUBCLOUD_GROUP_ID,
        "name": consts.DEFAULT_SUBCLOUD_GROUP_NAME,
        "description": consts.DEFAULT_SUBCLOUD_GROUP_DESCRIPTION,
        "update_apply_type": consts.DEFAULT_SUBCLOUD_GROUP_UPDATE_APPLY_TYPE,
        "max_parallel_subclouds":
            consts.DEFAULT_SUBCLOUD_GROUP_MAX_PARALLEL_SUBCLOUDS,
        "deleted": 0
    }
    # Inserting the GROUP as ID 1,
    # This should increment the pkey to 2
    with migrate_engine.begin() as conn:
        conn.execute(
            subcloud_group.insert(),  # pylint: disable=E1120
            default_group)

    # postgres does not increment the subcloud group id sequence
    # after the insert above as part of the migrate.
    # Note: use different SQL syntax if using mysql or sqlite
    if migrate_engine.name == 'postgresql':
        with migrate_engine.begin() as conn:
            conn.execute("ALTER SEQUENCE subcloud_group_id_seq RESTART WITH 2")

    # Add group_id column to subclouds table
    group_id = \
        sqlalchemy.Column('group_id',
                          sqlalchemy.Integer,
                          server_default=str(consts.DEFAULT_SUBCLOUD_GROUP_ID))
    group_id.create(subclouds)

    subcloud_fkey = constraint.ForeignKeyConstraint(
        columns=[subclouds.c.group_id],
        refcolumns=[subcloud_group.c.id],
        name='subclouds_group_ref')
    subclouds.append_constraint(subcloud_fkey)


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade is unsupported.')
