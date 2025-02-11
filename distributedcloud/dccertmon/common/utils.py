#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# TODO(srana): Refactor DC role usage due to deprecation.
DC_ROLE_UNDETECTED = "unknown"
DC_ROLE_SUBCLOUD = "subcloud"
DC_ROLE_SYSTEMCONTROLLER = "systemcontroller"

DC_ROLE_TIMEOUT_SECONDS = 180
DC_ROLE_DELAY_SECONDS = 5

INVALID_SUBCLOUD_AUDIT_DEPLOY_STATES = [
    # Secondary subclouds should not be audited as they are expected
    # to be managed by a peer system controller (geo-redundancy feat.)
    "create-complete",
    "create-failed",
    "pre-rehome",
    "rehome-failed",
    "rehome-pending",
    "rehoming",
    "secondary",
    "secondary-failed",
]
