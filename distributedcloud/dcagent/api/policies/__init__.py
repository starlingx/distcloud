#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import itertools

from dcagent.api.policies import base


def list_rules():
    return itertools.chain(base.list_rules())
