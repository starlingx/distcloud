#    Copyright 2011 OpenStack Foundation
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import pbr.version

DC_ORCH_VENDOR = "Wind River Systems"
DC_ORCH_PRODUCT = "Distributed Cloud Orchestrator"
DC_ORCH_PACKAGE = None  # OS distro package version suffix

version_info = pbr.version.VersionInfo('distributedcloud')
version_string = version_info.version_string


def vendor_string():
    return DC_ORCH_VENDOR


def product_string():
    return DC_ORCH_PRODUCT


def package_string():
    return DC_ORCH_PACKAGE


def version_string_with_package():
    if package_string() is None:
        return version_info.version_string()
    else:
        return "%s-%s" % (version_info.version_string(), package_string())
