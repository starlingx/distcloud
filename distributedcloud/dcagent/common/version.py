#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pbr.version

DCAGENT_VENDOR = "Wind River Systems"
DCAGENT_PRODUCT = "Distributed Cloud DC Agent"
DCAGENT_PACKAGE = None  # OS distro package version suffix

version_info = pbr.version.VersionInfo("distributedcloud")
version_string = version_info.version_string


def vendor_string():
    return DCAGENT_VENDOR


def product_string():
    return DCAGENT_PRODUCT


def package_string():
    return DCAGENT_PACKAGE


def version_string_with_package():
    if package_string() is None:
        return version_info.version_string()
    else:
        return "%s-%s" % (version_info.version_string(), package_string())
