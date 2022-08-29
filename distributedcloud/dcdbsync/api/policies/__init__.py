#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import itertools

from dcdbsync.api.policies import base


def list_rules():
    return itertools.chain(
        base.list_rules()
    )
