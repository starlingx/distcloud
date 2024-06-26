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

from sqlalchemy import MetaData, Table, Index

ORCH_JOB_ID_INDEX_NAME = "orch_request_orch_job_id_idx"
UPDATED_AT_STATE_INDEX_NAME = "orch_request_updated_at_state_idx"
DELETED_AT_INDEX_NAME = "orch_request_deleted_at_idx"


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    orch_request = Table("orch_request", meta, autoload=True)

    index = Index(
        UPDATED_AT_STATE_INDEX_NAME, orch_request.c.updated_at, orch_request.c.state
    )
    index.create(migrate_engine)

    index = Index(DELETED_AT_INDEX_NAME, orch_request.c.deleted_at)
    index.create(migrate_engine)

    index = Index(ORCH_JOB_ID_INDEX_NAME, orch_request.c.orch_job_id)
    index.create(migrate_engine)


def downgrade(migrate_engine):
    raise NotImplementedError(
        "Database downgrade not supported - would drop all tables"
    )
