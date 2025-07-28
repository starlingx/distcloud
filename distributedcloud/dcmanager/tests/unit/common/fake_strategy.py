#
# Copyright (c) 2020, 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from dcmanager.common import consts
from dcmanager.db import api as db_api


def create_fake_strategy(
    ctxt,
    strategy_type,
    state=consts.SW_UPDATE_STATE_INITIAL,
    subcloud_apply_type=consts.SUBCLOUD_APPLY_TYPE_PARALLEL,
    max_parallel_subclouds=2,
    stop_on_failure=True,
    extra_args=None,
):
    values = {
        "type": strategy_type,
        "subcloud_apply_type": subcloud_apply_type,
        "max_parallel_subclouds": max_parallel_subclouds,
        "stop_on_failure": stop_on_failure,
        "state": state,
        "extra_args": extra_args,
    }
    return db_api.sw_update_strategy_create(ctxt, **values)


def create_fake_strategy_step(
    ctxt,
    subcloud_id=1,
    state=consts.STRATEGY_STATE_INITIAL,
    stage=1,
    details="Dummy details",
):
    values = {
        "subcloud_id": subcloud_id,
        "stage": stage,
        "state": state,
        "details": details,
    }
    return db_api.strategy_step_create(ctxt, **values)
