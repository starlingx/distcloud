# Copyright (c) 2015 Ericsson AB
# Copyright (c) 2020-2021, 2024 Wind River Systems, Inc.
# All Rights Reserved.
#
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

from oslo_context import context


def create_route_dict(data_list):
    return {
        "created-at": data_list[0],
        "updated-at": data_list[1],
        "deleted-at": data_list[2],
        "id": data_list[3],
        "uuid": data_list[4],
        "family": data_list[5],
        "network": data_list[6],
        "prefix": data_list[7],
        "gateway": data_list[8],
        "metric": data_list[9],
        "interface-id": data_list[10],
    }


def create_endpoint_dict(data_list):
    return {
        "id": data_list[0],
        "legacy_endpoint_id": data_list[1],
        "interface": data_list[2],
        "service_id": data_list[3],
        "url": data_list[4],
        "extra": data_list[5],
        "enabled": data_list[6],
        "region_id": data_list[7],
    }


def dummy_context(user="test_username", tenant="test_project_id", region_name=None):
    return context.RequestContext.from_dict(
        {
            "auth_token": "abcd1234",
            "user": user,
            "project": tenant,
            "is_admin": True,
            "region_name": region_name,
        }
    )
