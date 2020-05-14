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
# Copyright (c) 2017-2020 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

"""
File to store all the configurations
"""
from oslo_config import cfg
from oslo_utils import importutils

# Ensure keystonemiddleware options are imported
importutils.import_module('keystonemiddleware.auth_token')

global_opts = [
    cfg.BoolOpt('use_default_quota_class',
                default=True,
                help='Enables or disables use of default quota class '
                     'with default quota.'),
    cfg.IntOpt('report_interval',
               default=60,
               help='Seconds between running periodic reporting tasks.'),
]

# OpenStack credentials used for Endpoint Cache
# We need to register the below non-standard config
# options to dcmanager engine
keystone_opts = [
    cfg.StrOpt('username',
               help='Username of account'),
    cfg.StrOpt('password',
               help='Password of account'),
    cfg.StrOpt('project_name',
               help='Tenant name of account'),
    cfg.StrOpt('user_domain_name',
               default='Default',
               help='User domain name of account'),
    cfg.StrOpt('project_domain_name',
               default='Default',
               help='Project domain name of account'),
]


# Pecan_opts
pecan_opts = [
    cfg.StrOpt(
        'root',
        default='dcmanager.api.controllers.root.RootController',
        help='Pecan root controller'
    ),
    cfg.ListOpt(
        'modules',
        default=["dcmanager.api"],
        help='A list of modules where pecan will search for applications.'
    ),
    cfg.BoolOpt(
        'debug',
        default=False,
        help='Enables the ability to display tracebacks in the browser and'
             'interactively debug during development.'
    ),
    cfg.BoolOpt(
        'auth_enable',
        default=True,
        help='Enables user authentication in pecan.'
    )
]


# OpenStack credentials used for Endpoint Cache
cache_opts = [
    cfg.StrOpt('auth_uri',
               help='Keystone authorization url'),
    cfg.StrOpt('identity_uri',
               help='Keystone service url'),
    cfg.StrOpt('admin_username',
               help='Username of admin account, needed when'
                    ' auto_refresh_endpoint set to True'),
    cfg.StrOpt('admin_password',
               help='Password of admin account, needed when'
                    ' auto_refresh_endpoint set to True'),
    cfg.StrOpt('admin_tenant',
               help='Tenant name of admin account, needed when'
                    ' auto_refresh_endpoint set to True'),
    cfg.StrOpt('admin_user_domain_name',
               default='Default',
               help='User domain name of admin account, needed when'
                    ' auto_refresh_endpoint set to True'),
    cfg.StrOpt('admin_project_domain_name',
               default='Default',
               help='Project domain name of admin account, needed when'
                    ' auto_refresh_endpoint set to True')
]

scheduler_opts = [
    cfg.BoolOpt('periodic_enable',
                default=True,
                help='boolean value for enable/disable periodic tasks'),
    cfg.IntOpt('subcloud_audit_interval',
               default=20,
               help='periodic time interval for subcloud audit'),
    cfg.IntOpt('patch_audit_interval',
               default=10,
               help='periodic time interval for patch audit')
]

common_opts = [
    cfg.IntOpt('workers', default=1,
               help='number of workers'),
    cfg.IntOpt('audit_workers', default=1,
               help='number of audit workers'),
    cfg.StrOpt('host',
               default='localhost',
               help='hostname of the machine')
]

scheduler_opt_group = cfg.OptGroup(name='scheduler',
                                   title='Scheduler options for periodic job')
keystone_opt_group = cfg.OptGroup(name='keystone_authtoken',
                                  title='Keystone options')
# The group stores the pecan configurations.
pecan_group = cfg.OptGroup(name='pecan',
                           title='Pecan options')

cache_opt_group = cfg.OptGroup(name='cache',
                               title='OpenStack Credentials')


def list_opts():
    yield cache_opt_group.name, cache_opts
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
