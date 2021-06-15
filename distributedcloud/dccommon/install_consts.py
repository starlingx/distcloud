# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

SUPPORTED_INSTALL_TYPES = 6

MANDATORY_INSTALL_VALUES = [
    'image',
    'software_version',
    'bootstrap_interface',
    'bootstrap_address',
    'bootstrap_address_prefix',
    'bmc_address',
    'bmc_username',
    'bmc_password',
    'install_type'
]

ANSIBLE_SUBCLOUD_INSTALL_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/install.yml'
