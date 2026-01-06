# Copyright 2016 Ericsson AB
# Copyright (c) 2017-2025 Wind River Systems, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#

"""
File to store all the configurations
"""
from oslo_config import cfg
from oslo_utils import importutils

# Ensure keystonemiddleware options are imported
importutils.import_module("keystonemiddleware.auth_token")

global_opts = [
    cfg.BoolOpt(
        "use_default_quota_class",
        default=True,
        help="Enables or disables use of default quota class with default quota.",
    ),
    cfg.IntOpt(
        "report_interval",
        default=60,
        help="Seconds between running periodic reporting tasks.",
    ),
]

# OpenStack credentials used for Endpoint Cache
# We need to register the below non-standard config
# options to dcmanager engine
keystone_opts = [
    cfg.StrOpt("username", help="Username of account"),
    cfg.StrOpt("password", secret=True, help="Password of account"),
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
        default="dcmanager.api.controllers.root.RootController",
        help="Pecan root controller",
    ),
    cfg.ListOpt(
        "modules",
        default=["dcmanager.api"],
        help="A list of modules where pecan will search for applications.",
    ),
    cfg.BoolOpt(
        "debug",
        default=False,
        help=(
            "Enables the ability to display tracebacks in the browser and "
            "interactively debug during development."
        ),
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
        help="Username of admin, when auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_password",
        secret=True,
        help="Password of admin, when auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_tenant",
        help="Tenant name of admin, when auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_user_domain_name",
        default="Default",
        help="User domain name of admin, when auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_project_domain_name",
        default="Default",
        help=("Project domain name of admin, when auto_refresh_endpoint set to True"),
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
        help="boolean value for enable/disable periodic tasks",
    ),
    cfg.IntOpt(
        "subcloud_audit_interval",
        default=30,
        help="periodic time interval for subcloud audit",
    ),
    cfg.IntOpt(
        "kube_rootca_update_audit_expiry_days",
        default=90,
        help="Num days remaining for a kube rootca to be out-of-sync",
    ),
    cfg.IntOpt(
        "audit_interval",
        default=900,
        help="default time interval for firmware and root-ca audits",
    ),
    cfg.IntOpt(
        "orchestration_interval",
        default=120,
        help="default time interval for retrieving pending steps during processing",
    ),
]

common_opts = [
    cfg.IntOpt("workers", default=1, help="number of workers"),
    cfg.IntOpt("orch_workers", default=1, help="number of orchestrator workers"),
    cfg.IntOpt(
        "orch_worker_workers", default=2, help="number of orchestrator-worker workers"
    ),
    cfg.IntOpt("state_workers", default=8, help="number of state workers"),
    cfg.IntOpt("audit_workers", default=1, help="number of audit workers"),
    cfg.IntOpt(
        "audit_worker_workers", default=8, help="number of audit-worker workers"
    ),
    cfg.StrOpt("host", default="localhost", help="hostname of the machine"),
    cfg.IntOpt(
        "playbook_timeout",
        default=3600,
        help="global ansible playbook timeout (seconds)",
    ),
    cfg.IntOpt(
        "ipmi_capture",
        default=1,
        help=(
            "global IPMI capture control. 0: globally disabled "
            "1:enabled via rvmc_debug_level, 2:globally enabled"
        ),
    ),
    cfg.IntOpt(
        "dcmanager_worker_rlimit_nofile",
        default=4096,
        help="Maximum number of open files per dcmanager_manager worker process.",
    ),
    cfg.IntOpt(
        "orchestrator_worker_rlimit_nofile",
        default=4096,
        help="Maximum number of open files per dcmanager_orchestrator worker process.",
    ),
    cfg.IntOpt(
        "audit_worker_rlimit_nofile",
        default=4096,
        help="Maximum number of open files per dcmanager_audit worker process.",
    ),
    cfg.IntOpt(
        "state_worker_rlimit_nofile",
        default=4096,
        help="Maximum number of open files per dcmanager_state worker process.",
    ),
]

scheduler_opt_group = cfg.OptGroup(
    name="scheduler", title="Scheduler options for periodic job"
)
keystone_opt_group = cfg.OptGroup(name="keystone_authtoken", title="Keystone options")
# The group stores the pecan configurations.
pecan_group = cfg.OptGroup(name="pecan", title="Pecan options")

cache_opt_group = cfg.OptGroup(name="cache", title="OpenStack Admin Credentials")

endpoint_cache_opt_group = cfg.OptGroup(
    name="endpoint_cache", title="OpenStack Credentials"
)


def list_opts():
    yield cache_opt_group.name, cache_opts
    yield endpoint_cache_opt_group.name, endpoint_cache_opts
    yield scheduler_opt_group.name, scheduler_opts
    yield pecan_group.name, pecan_opts
    yield None, global_opts
    yield None, common_opts


def register_options():
    for group, opts in list_opts():
        cfg.CONF.register_opts(opts, group=group)


# Only necessary for dcmanager engine, keystone_authtoken options for
# dcmanager-api will get picked up and registered automatically from the
# config file
def register_keystone_options():
    cfg.CONF.register_opts(keystone_opts, group=keystone_opt_group.name)
