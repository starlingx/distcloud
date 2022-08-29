#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import itertools

from dcmanager.api.policies import alarm_manager
from dcmanager.api.policies import base
from dcmanager.api.policies import subcloud_backup
from dcmanager.api.policies import subcloud_deploy
from dcmanager.api.policies import subcloud_group
from dcmanager.api.policies import subclouds
from dcmanager.api.policies import sw_update_options
from dcmanager.api.policies import sw_update_strategy


def list_rules():
    return itertools.chain(
        base.list_rules(),
        subclouds.list_rules(),
        subcloud_deploy.list_rules(),
        alarm_manager.list_rules(),
        sw_update_strategy.list_rules(),
        sw_update_options.list_rules(),
        subcloud_group.list_rules(),
        subcloud_backup.list_rules()
    )
