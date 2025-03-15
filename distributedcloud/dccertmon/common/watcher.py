#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time

from oslo_log import log

LOG = log.getLogger(__name__)


class DC_CertWatcher(object):
    def __init__(self):
        pass

    def initialize(self):
        LOG.info("initialize DC_CertWatcher")

    def start_watch(self, on_success, on_error):
        LOG.info("DC_CertWatcher start_watch")
        time.sleep(60)
