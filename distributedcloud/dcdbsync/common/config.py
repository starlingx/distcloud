#    Copyright 2016 Ericsson AB
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
#
# Copyright (c) 2019, 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
File to store all the configurations
"""
from oslo_config import cfg
from oslo_utils import importutils

# Ensure keystonemiddleware options are imported
importutils.import_module("keystonemiddleware.auth_token")

# OpenStack credentials used for Endpoint Cache
# We need to register the below non-standard config
# options to dbsync engine
keystone_opts = [
    cfg.StrOpt("username", help="Username of account"),
    cfg.StrOpt("password", help="Password of account"),
    cfg.StrOpt("project_name", help="Tenant name of account"),
    cfg.StrOpt(
        "user_domain_name", default="Default", help="User domain name of account"
    ),
    cfg.StrOpt(
        "project_domain_name", default="Default", help="Project domain name of account"
    ),
]


# Pecan_opts
pecan_opts = [
    cfg.StrOpt(
        "root",
        default="dcdbsync.api.controllers.root.RootController",
        help="Pecan root controller",
    ),
    cfg.ListOpt(
        "modules",
        default=["dcdbsync.api"],
        help="A list of modules where pecan will search for applications.",
    ),
    cfg.BoolOpt(
        "debug",
        default=False,
        help=(
            "Enables the ability to display tracebacks in the browser and "
            "interactively debug during development.",
        ),
    ),
    cfg.BoolOpt(
        "auth_enable", default=True, help="Enables user authentication in pecan."
    ),
]


# OpenStack credentials used for Endpoint Cache
cache_opts = [
    cfg.StrOpt("auth_uri", help="Keystone authorization url"),
    cfg.StrOpt("identity_uri", help="Keystone service url"),
    cfg.StrOpt(
        "admin_username",
        help="Username of admin account, needed when auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_password",
        help="Password of admin account, needed when auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_tenant",
        help="Tenant of admin account, needed when auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_user_domain_name",
        default="Default",
        help="User domain of admin, needed when auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_project_domain_name",
        default="Default",
        help="Project domain of admin, needed when auto_refresh_endpoint set to True",
    ),
]

common_opts = [
    cfg.IntOpt("workers", default=1, help="number of workers"),
    cfg.StrOpt("host", default="localhost", help="hostname of the machine"),
]

keystone_opt_group = cfg.OptGroup(name="keystone_authtoken", title="Keystone options")
# The group stores the pecan configurations.
pecan_group = cfg.OptGroup(name="pecan", title="Pecan options")

cache_opt_group = cfg.OptGroup(name="cache", title="OpenStack Credentials")


def list_opts():
    yield cache_opt_group.name, cache_opts
    yield pecan_group.name, pecan_opts
    yield None, common_opts


def register_options():
    for group, opts in list_opts():
        cfg.CONF.register_opts(opts, group=group)
