# Copyright 2016 Ericsson AB
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

from oslo_config import cfg
from oslo_log import log as logging

from dcorch.common.i18n import _
from dcorch.engine import scheduler


LOG = logging.getLogger(__name__)

lock_opts = [
    cfg.IntOpt('lock_retry_times',
               default=3,
               help=_('Number of times trying to grab a lock.')),
    cfg.IntOpt('lock_retry_interval',
               default=10,
               help=_('Number of seconds between lock retries.'))
]

lock_opts_group = cfg.OptGroup('locks')
cfg.CONF.register_group(lock_opts_group)
cfg.CONF.register_opts(lock_opts, group=lock_opts_group)


def sync_lock_acquire(engine_id, task_type, lock):
    """Try to lock with specified engine_id.

    :param engine: ID of the engine which wants to lock the projects.
    :param lock: the lock object owned by the caller
    :returns: True if lock is acquired, or False otherwise.
    """

    # Step 1: try lock the projects- if it returns True then success
    LOG.info('Trying to acquire lock with %(engId)s for Task: %(task)s',
             {'engId': engine_id,
              'task': task_type
              }
             )
    lock_status = lock.acquire(False)
    if lock_status:
        return True

    # Step 2: retry using global configuration options
    retries = cfg.CONF.locks.lock_retry_times
    retry_interval = cfg.CONF.locks.lock_retry_interval

    while retries > 0:
        scheduler.sleep(retry_interval)
        LOG.info('Retry acquire lock with %(engId)s for Task: %(task)s',
                 {'engId': engine_id,
                  'task': task_type
                  }
                 )
        lock_status = lock.acquire(False)
        if lock_status:
            return True
        retries = retries - 1

    # Will reach here only when not able to acquire locks with retry

    LOG.error('Not able to acquire lock  for %(task)s with retry'
              ' with engineId %(engId)s',
              {'engId': engine_id,
               'task': task_type
               }
              )
    return False


def sync_lock_release(engine_id, task_type, lock):
    """Release the lock for the projects"""

    LOG.info('Releasing acquired lock with %(engId)s for Task: %(task)s',
             {'engId': engine_id,
              'task': task_type
              }
             )
    return lock.release()


def list_opts():
    yield lock_opts_group.name, lock_opts
