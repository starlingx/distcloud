#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log as logging

from dccommon.drivers.openstack import vim
from dcmanager.common import consts
from dcmanager.db import api as db_api
from dcmanager.orchestrator.orch_thread import OrchThread

LOG = logging.getLogger(__name__)


class SoftwareOrchThread(OrchThread):
    """Software Orchestration Thread

    This thread is responsible for executing the software orchestration strategy.
    Here is how it works:
    - The user creates an update strategy from CLI (or REST API) of 'usm'
    - This ends up being handled by the SwUpdateManager class, which
      runs under the main dcmanager thread. The strategy is created and stored
      in the database.
    - The user then applies the strategy from the CLI (or REST API). The
      SwUpdateManager code updates the state of the strategy in the database.
    - The SoftwareOrchThread wakes up periodically and checks the database for
      a strategy that is in an active state (applying, aborting, etc...). If
      so, it executes the strategy, updating the strategy and steps in the
      database as it goes, with state and progress information.
    """

    def __init__(self, strategy_lock, audit_rpc_client):
        super(SoftwareOrchThread, self).__init__(
            strategy_lock,
            audit_rpc_client,
            consts.SW_UPDATE_TYPE_UPGRADE,    # software update strategy type
            vim.STRATEGY_NAME_SW_UPGRADE,     # strategy type used by vim
            consts.STRATEGY_STATE_COMPLETE)   # starting state

    def trigger_audit(self):
        """Trigger an audit for upgrade (which is combined with patch audit)"""
        self.audit_rpc_client.trigger_patch_audit(self.context)

    def delete(self, sw_update_strategy):
        super(SoftwareOrchThread, self).delete(sw_update_strategy)

    def apply(self, sw_update_strategy):
        LOG.info("(%s) Applying update strategy" % self.update_type)

        LOG.info("(%s) Strategy application is complete."
                 % self.update_type)
        with self.strategy_lock:
            db_api.sw_update_strategy_update(
                self.context,
                state=consts.SW_UPDATE_STATE_COMPLETE,
                update_type=self.update_type)

        self.subcloud_workers.clear()
        # Trigger audit to update the sync status for each subcloud.
        self.trigger_audit()
        return
