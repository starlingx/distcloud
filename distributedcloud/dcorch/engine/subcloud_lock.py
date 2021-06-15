# Copyright 2020  Wind River Inc.
# All Rights Reserved.
#
# Copyright 2016 Ericsson AB
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

from oslo_db import exception as db_exc
from oslo_log import log as logging

from dcorch.db import api as db_api


LOG = logging.getLogger(__name__)


def sync_subcloud(func):
    """Synchronized lock decorator for _update_subcloud_endpoint_status. """

    def _get_lock_and_call(*args, **kwargs):
        """Get a single fair lock per subcloud based on subcloud name. """

        # context is the 2nd argument
        # engine_id is the 3rd argument
        # subcloud name is the 4rd argument
        # endpoint_type is the 5th argument
        # action is the 6th argument
        def _call_func(*args, **kwargs):
            if sync_lock_acquire(args[1], args[2], args[3], args[4], args[5]):
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    sync_lock_release(args[1], args[2], args[3], args[4],
                                      args[5])

        return _call_func(*args, **kwargs)

    return _get_lock_and_call


def sync_lock_acquire(context, engine_id, name, endpoint_type, action):
    """Try to lock with specified engine_id.

    :param context: the security context
    :param engine_id: ID of the engine which wants to lock the projects.
    :param name: the name of the resource to lock
    :param endpoint_type: service type of a subcloud
    :param action: action to be performed (i.e. audit or sync)
    :returns: True if lock is acquired, or False otherwise.
    """

    LOG.debug('Trying to acquire lock with %(engId)s for Resource: %(name)s '
              'Type: %(type)s, action: %(action)s',
              {'engId': engine_id,
               'name': name,
               'type': endpoint_type,
               'action': action
               }
              )
    try:
        lock_status = db_api.sync_lock_acquire(context, engine_id, name,
                                               endpoint_type, action)
    except db_exc.DBDuplicateEntry:
        return False

    if lock_status:
        return True

    return False


def sync_lock_release(context, engine_id, name, endpoint_type, action):
    """Release the lock for the projects"""

    LOG.debug('Releasing acquired lock with %(engId)s for subcloud: %(name)s '
              '%(type)s, %(action)s',
              {'engId': engine_id,
               'name': name,
               'type': endpoint_type,
               'action': action
               }
              )
    return db_api.sync_lock_release(context, name, endpoint_type, action)
