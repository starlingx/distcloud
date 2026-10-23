#    Copyright 2016 Ericsson AB
#    Copyright (c) 2020-2024 Wind River Systems, Inc.
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

"""
File to store all the configurations
"""
from oslo_config import cfg

global_opts = [
    cfg.IntOpt(
        "report_interval",
        default=60,
        help="Seconds between running periodic reporting tasks.",
    ),
    cfg.IntOpt(
        "rlimit_nofile", default=4096, help="Maximum number of open files per process."
    ),
]

# Pecan_opts
pecan_opts = [
    cfg.StrOpt(
        "root",
        default="dcorch.api.controllers.root.RootController",
        help="Pecan root controller",
    ),
    cfg.ListOpt(
        "modules",
        default=["dcorch.api"],
        help="A list of modules where pecan will search for applications.",
    ),
    cfg.BoolOpt(
        "debug",
        default=False,
        help="Enables the ability to display tracebacks in the browser and"
        "interactively debug during development.",
    ),
    cfg.BoolOpt(
        "auth_enable", default=True, help="Enables user authentication in pecan."
    ),
]


# OpenStack admin user credentials used for Endpoint Cache
cache_opts = [
    cfg.StrOpt("auth_uri", help="Keystone authorization url"),
    cfg.StrOpt("identity_uri", help="Keystone service url"),
    cfg.StrOpt(
        "admin_username",
        help="Username of admin, needed when auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_password",
        secret=True,
        help="Password of admin, needed when auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_tenant",
        help="Tenant name of admin, needed when auto_refresh_endpoint set to True",
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

# OpenStack credentials used for Endpoint Cache
endpoint_cache_opts = [
    cfg.StrOpt("auth_uri", help="Keystone authorization url"),
    cfg.StrOpt("auth_plugin", help="Name of the plugin to load"),
    cfg.StrOpt("username", help="Username of account"),
    cfg.StrOpt("password", secret=True, help="Password of account"),
    cfg.StrOpt("project_name", help="Project name of account"),
    cfg.StrOpt(
        "user_domain_name", default="Default", help="User domain name of account"
    ),
    cfg.StrOpt(
        "project_domain_name", default="Default", help="Project domain name of account"
    ),
    cfg.IntOpt(
        "http_discovery_timeout",
        default=15,
        help="Discovery timeout value for communicating with Identity API server.",
    ),
    cfg.IntOpt(
        "http_connect_timeout",
        help="Request timeout value for communicating with Identity API server.",
    ),
    cfg.IntOpt(
        "token_cache_size",
        default=10000,
        help="Maximum number of entries in the in-memory token cache",
    ),
]

scheduler_opts = [
    cfg.BoolOpt(
        "periodic_enable",
        default=True,
        help="boolean value for enable/disenable periodic tasks",
    ),
    cfg.IntOpt(
        "periodic_interval",
        default=1200,
        help="periodic time interval for the resource sync audit",
    ),
]

common_opts = [
    cfg.IntOpt("workers", default=5, help="number of engine-worker workers"),
    cfg.StrOpt("host", default="localhost", help="hostname of the machine"),
    cfg.StrOpt(
        "disable_audit_endpoints",
        default="",
        help="endpoints for which audit is disabled",
    ),
]

fernet_opts = [
    cfg.IntOpt(
        "key_rotation_interval",
        default=168,
        help="Hours between running fernet key rotation tasks.",
    )
]


scheduler_opt_group = cfg.OptGroup(
    "scheduler", title="Scheduler options for periodic job"
)
# The group stores the pecan configurations.
pecan_group = cfg.OptGroup(name="pecan", title="Pecan options")

cache_opt_group = cfg.OptGroup(name="cache", title="OpenStack Admin Credentials")

endpoint_cache_opt_group = cfg.OptGroup(
    name="endpoint_cache", title="OpenStack Credentials"
)

openstack_cache_opt_group = cfg.OptGroup(
    name="openstack_cache", title="Containerized OpenStack Credentials"
)

fernet_opt_group = cfg.OptGroup(name="fernet", title="Fernet Options")


def list_opts():
    yield cache_opt_group.name, cache_opts
    yield endpoint_cache_opt_group.name, endpoint_cache_opts
    yield openstack_cache_opt_group.name, cache_opts
    yield scheduler_opt_group.name, scheduler_opts
    yield pecan_group.name, pecan_opts
    yield fernet_opt_group.name, fernet_opts
    yield None, global_opts
    yield None, common_opts


def register_options():
    for group, opts in list_opts():
        cfg.CONF.register_opts(opts, group=group)
