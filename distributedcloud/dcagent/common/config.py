#
# Copyright (c) 2024 Wind River Systems, Inc.
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
# We need to register the below non-standard config options to dcagent engine
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
        default="dcagent.api.controllers.root.RootController",
        help="Pecan root controller",
    ),
    cfg.ListOpt(
        "modules",
        default=["dcagent.api"],
        help="A list of modules where pecan will search for applications.",
    ),
    cfg.BoolOpt(
        "debug",
        default=False,
        help="Enables the ability to display tracebacks in the browser and "
        "interactively debug during development.",
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
        help="Username of admin account, needed when "
        "auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_password",
        help="Password of admin account, needed when "
        "auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_tenant",
        help="Tenant name of admin account, needed when "
        "auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_user_domain_name",
        default="Default",
        help="User domain name of admin account, needed when "
        "auto_refresh_endpoint set to True",
    ),
    cfg.StrOpt(
        "admin_project_domain_name",
        default="Default",
        help="Project domain name of admin account, needed when "
        "auto_refresh_endpoint set to True",
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
]

scheduler_opts = [
    cfg.BoolOpt(
        "periodic_enable",
        default=True,
        help="Boolean value to enable or disable periodic tasks",
    ),
    cfg.IntOpt(
        "dcagent_audit_interval",
        default=30,
        help="Periodic time interval for subcloud audit",
    ),
]

common_opts = [
    cfg.IntOpt("workers", default=1, help="Number of workers"),
    cfg.StrOpt("host", default="localhost", help="Hostname of the machine"),
]

scheduler_opt_group = cfg.OptGroup(
    name="scheduler", title="Scheduler options for periodic job"
)

keystone_opt_group = cfg.OptGroup(name="keystone_authtoken", title="Keystone options")
# The group stores the pecan configurations.
pecan_group = cfg.OptGroup(name="pecan", title="Pecan options")

cache_opt_group = cfg.OptGroup(name="cache", title="OpenStack Credentials")

endpoint_cache_opt_group = cfg.OptGroup(
    name="endpoint_cache", title="OpenStack Credentials"
)


def list_opts():
    yield cache_opt_group.name, cache_opts
    yield endpoint_cache_opt_group.name, endpoint_cache_opts
    yield scheduler_opt_group.name, scheduler_opts
    yield pecan_group.name, pecan_opts
    yield None, common_opts


def register_options():
    for group, opts in list_opts():
        cfg.CONF.register_opts(opts, group=group)
