# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

SECONDS_IN_HOUR = 3600

KS_ENDPOINT_ADMIN = "admin"
KS_ENDPOINT_INTERNAL = "internal"
KS_ENDPOINT_DEFAULT = KS_ENDPOINT_INTERNAL

ENDPOINT_TYPE_IDENTITY_OS = "identity_openstack"

# openstack endpoint types
ENDPOINT_TYPES_LIST_OS = [ENDPOINT_TYPE_IDENTITY_OS]

# distributed Cloud constants
CLOUD_0 = "RegionOne"
VIRTUAL_MASTER_CLOUD = "SystemController"

SW_UPDATE_DEFAULT_TITLE = "all clouds default"

USER_HEADER_VALUE = "distcloud"
USER_HEADER = {'User-Header': USER_HEADER_VALUE}
