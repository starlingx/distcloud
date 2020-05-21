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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

import time

import eventlet
from oslo_log import log as logging

from oslo_service import threadgroup

LOG = logging.getLogger(__name__)

wallclock = time.time


class ThreadGroupManager(object):
    """Thread group manager."""

    def __init__(self, *args, **kwargs):
        super(ThreadGroupManager, self).__init__()
        self.threads = {}
        self.group = threadgroup.ThreadGroup(*args, **kwargs)

    def start(self, func, *args, **kwargs):
        """Run the given method in a sub-thread."""

        return self.group.add_thread(func, *args, **kwargs)

    def add_timer(self, interval, func, *args, **kwargs):
        """Define a periodic task to be run in the thread group.

        The task will be executed in a separate green thread.
        """

        self.group.add_timer(interval, func, *args, **kwargs)

    def stop_timers(self):
        self.group.stop_timers()

    def stop(self, graceful=False):
        """Stop any active threads belong to this threadgroup."""
        # Try to stop all threads gracefully
        self.group.stop(graceful)
        self.group.wait()

        # Wait for link()ed functions (i.e. lock release)
        threads = self.group.threads[:]
        links_done = dict((th, False) for th in threads)

        def mark_done(gt, th):
            links_done[th] = True

        for th in threads:
            th.link(mark_done, th)

        while not all(links_done.values()):
            eventlet.sleep()


def reschedule(action, sleep_time=1):
    """Eventlet Sleep for the specified number of seconds.

    :param sleep_time: seconds to sleep; if None, no sleep;
    """

    if sleep_time is not None:
        LOG.debug('Action %s sleep for %s seconds' % (
            action.id, sleep_time))
        eventlet.sleep(sleep_time)


def sleep(sleep_time):
    """Interface for sleeping."""

    eventlet.sleep(sleep_time)
