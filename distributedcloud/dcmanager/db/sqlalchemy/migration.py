#
# Copyright (c) 2015 Ericsson AB.
# Copyright (c) 2017, 2019, 2021, 2024, 2026 Wind River Systems, Inc.
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

import os
import sqlalchemy

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext

from oslo_db.sqlalchemy import enginefacade

# Minimum legacy sqlalchemy-migrate version required for upgrade.
# 22 is the last version in both stx11 (N-2) and stx12 (N-1).
LEGACY_MIN_VERSION = 22
LEGACY_ALEMBIC_REVISION = "65c98c626672"


def get_engine():
    return enginefacade.get_legacy_facade().get_engine()


def db_sync(engine, version=None):
    """Upgrade database to the specified version using Alembic."""
    with engine.begin() as connection:
        config = _get_alembic_config(engine, connection)

        # Ensure database is under Alembic control, or bridge from migrate_version
        _ensure_alembic_control(connection, config)

        if version is None:
            command.upgrade(config, "head")
        else:
            command.upgrade(config, version)


def db_version(engine):
    """Get current database version using Alembic."""
    with engine.connect() as connection:
        context = MigrationContext.configure(connection)
        return context.get_current_revision()


def db_version_control(engine, version=None):
    """Initialize database version control using Alembic."""
    with engine.begin() as connection:
        config = _get_alembic_config(engine, connection)
        revision = "base" if version is None else version
        command.stamp(config, revision)
        return revision


def _ensure_alembic_control(connection, config):
    """Ensure the database is under Alembic version control.

    If the database has no alembic_version table:
    - Empty database: stamp as 'base' for fresh install
    - Has migrate_version table: bridge from legacy version
    - Unknown legacy version: reject with upgrade requirement
    """
    context = MigrationContext.configure(connection)
    current_rev = context.get_current_revision()

    if current_rev is not None:
        return current_rev

    inspector = sqlalchemy.inspect(connection)
    tables = [t for t in inspector.get_table_names() if t != "alembic_version"]

    if len(tables) == 0:
        command.stamp(config, "base")
        return "base"

    if "migrate_version" not in tables:
        raise Exception("Upgrade to 25.09 or 26.03 first")

    legacy_version = connection.execute(
        sqlalchemy.text("SELECT version FROM migrate_version")
    ).scalar()

    if legacy_version < LEGACY_MIN_VERSION:
        raise Exception(
            f"Unsupported legacy version {legacy_version}. "
            "Upgrade to 25.09 or 26.03 first"
        )

    command.stamp(config, LEGACY_ALEMBIC_REVISION)
    return LEGACY_ALEMBIC_REVISION


def _get_alembic_config(engine, connection=None):
    """Get Alembic configuration."""
    config_path = os.path.join(os.path.dirname(__file__), "alembic.ini")
    config = Config(config_path)
    config.set_main_option(
        "script_location",
        os.path.join(os.path.dirname(__file__), "migrations"),
    )
    config.set_main_option("sqlalchemy.url", str(engine.url))
    if connection is not None:
        config.attributes["connection"] = connection  # pylint: disable=E1137
    return config
