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
# Copyright (c) 2019 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from sqlalchemy import MetaData
from sqlalchemy import Table


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    sw_update_opts_default = Table('sw_update_opts_default', meta,
                                   autoload=True)
    sw_update_opts = Table('sw_update_opts', meta, autoload=True)

    columns_to_rename = {'compute_apply_type': 'worker_apply_type',
                         'max_parallel_computes': 'max_parallel_workers'}
    for k, v in columns_to_rename.items():
        getattr(sw_update_opts_default.c, k).alter(name=v)
        getattr(sw_update_opts.c, k).alter(name=v)

    return True


def downgrade(migrate_engine):
    raise NotImplementedError('Database downgrade is unsupported.')
