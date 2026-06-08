#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Shared utilities for distributedcloud scripts."""

import logging

PLATFORM_CONF_PATH = "/etc/platform/platform.conf"

LOG = logging.getLogger(__name__)


def get_sw_version() -> str:
    """Get sw_version from /etc/platform/platform.conf.

    Raises RuntimeError if sw_version is not found or the file
    cannot be read.
    """
    try:
        with open(PLATFORM_CONF_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("sw_version="):
                    version = line.strip().split("=", 1)[1]
                    if version:
                        return version
        raise RuntimeError(f"sw_version not found in {PLATFORM_CONF_PATH}")
    except IOError as e:
        raise RuntimeError(f"Failed to read {PLATFORM_CONF_PATH}: {e}") from e
