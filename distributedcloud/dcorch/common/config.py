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

"""
File to store all the configurations
"""
from oslo_config import cfg

global_opts = [
    cfg.BoolOpt('use_default_quota_class',
                default=True,
                help='Enables or disables use of default quota class '
                     'with default quota.'),
    cfg.IntOpt('report_interval',
               default=60,
               help='Seconds between running periodic reporting tasks.'),
]

# Pecan_opts
pecan_opts = [
    cfg.StrOpt(
        'root',
        default='dcorch.api.controllers.root.RootController',
        help='Pecan root controller'
    ),
    cfg.ListOpt(
        'modules',
        default=["dcorch.api"],
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


# Global nova quotas for all projects
nova_quotas = [
    cfg.IntOpt('quota_instances',
               default=10,
               help='Number of instances allowed per project'),
    cfg.IntOpt('quota_cores',
               default=20,
               help='Number of instance cores allowed per project'),
    cfg.IntOpt('quota_ram',
               default=50 * 1024,
               help='Megabytes of instance RAM allowed per project'),
    cfg.IntOpt('quota_floating_ips',
               default=10,
               help='Number of floating IPs allowed per project'),
    cfg.IntOpt('quota_fixed_ips',
               default=-1,
               help='Number of fixed IPs allowed per project (this should be '
                    'at least the number of instances allowed)'),
    cfg.IntOpt('quota_metadata_items',
               default=128,
               help='Number of metadata items allowed per instance'),
    cfg.IntOpt('quota_security_groups',
               default=10,
               help='Number of security groups per project'),
    cfg.IntOpt('quota_key_pairs',
               default=100,
               help='Number of key pairs per user'),
]

# Global neutron quotas for all projects
neutron_quotas = [
    cfg.IntOpt('quota_network',
               default=10,
               help='Number of networks allowed per project. '
                    'A negative value means unlimited.'),
    cfg.IntOpt('quota_subnet',
               default=10,
               help='Number of subnets allowed per project, '
                    'A negative value means unlimited.'),
    cfg.IntOpt('quota_port',
               default=50,
               help='Number of ports allowed per project. '
                    'A negative value means unlimited.'),
    cfg.IntOpt('quota_security_group',
               default=10,
               help='Number of security groups allowed per project. '
                    'A negative value means unlimited.'),
    cfg.IntOpt('quota_security_group_rule',
               default=100,
               help='Number of security rules allowed per project. '
                    'A negative value means unlimited.'),
    cfg.IntOpt('quota_router',
               default=10,
               help='Number of routers allowed per project. '
                    'A negative value means unlimited.'),
    cfg.IntOpt('quota_floatingip',
               default=50,
               help='Number of floating IPs allowed per project. '
                    'A negative value means unlimited.')
]

# Global cinder quotas for all projects
cinder_quotas = [
    cfg.IntOpt('quota_volumes',
               default=10,
               help='Number of volumes allowed per project.'),
    cfg.IntOpt('quota_snapshots',
               default=10,
               help='Number of volume snapshots allowed per project.'),
    cfg.IntOpt('quota_gigabytes',
               default=1000,
               help='Total amount of storage, in gigabytes, allowed '
                    'for volumes and snapshots per project.'),
    cfg.IntOpt('quota_backups', default=10,
               help='Number of volume backups allowed per project.'),
    cfg.IntOpt('quota_backup_gigabytes',
               default=1000,
               help='Total amount of storage, in gigabytes, allowed '
                    'for backups per project.')
]

# OpenStack admin user credentials used for Endpoint Cache
cache_opts = [
    cfg.StrOpt('auth_uri',
               help='Keystone authorization url'),
    cfg.StrOpt('identity_uri',
               help='Keystone service url'),
    cfg.StrOpt('admin_username',
               help='Username of admin account, needed when'
                    ' auto_refresh_endpoint set to True'),
    cfg.StrOpt('admin_password',
               secret=True,
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

# OpenStack credentials used for Endpoint Cache
endpoint_cache_opts = [
    cfg.StrOpt('auth_uri',
               help='Keystone authorization url'),
    cfg.StrOpt('auth_plugin',
               help='Name of the plugin to load'),
    cfg.StrOpt('username',
               help='Username of account'),
    cfg.StrOpt('password',
               secret=True,
               help='Password of account'),
    cfg.StrOpt('project_name',
               help='Project name of account'),
    cfg.StrOpt('user_domain_name',
               default='Default',
               help='User domain name of account'),
    cfg.StrOpt('project_domain_name',
               default='Default',
               help='Project domain name of account'),
    cfg.IntOpt('http_connect_timeout',
               help='Request timeout value for communicating with Identity'
                    ' API server.'),
]

scheduler_opts = [
    cfg.BoolOpt('periodic_enable',
                default=True,
                help='boolean value for enable/disenable periodic tasks'),
    cfg.IntOpt('periodic_interval',
               default=1200,
               help='periodic time interval for automatic quota sync job'
                    ' and resource sync audit')
]

common_opts = [
    cfg.IntOpt('workers', default=1,
               help='number of workers'),
    cfg.StrOpt('host',
               default='localhost',
               help='hostname of the machine'),
    cfg.StrOpt('disable_audit_endpoints',
               default='',
               help='endpoints for which audit is disabled')
]

fernet_opts = [
    cfg.IntOpt('key_rotation_interval',
               default=168,
               help='Hours between running fernet key rotation tasks.')
]

scheduler_opt_group = cfg.OptGroup('scheduler',
                                   title='Scheduler options for periodic job')
# The group stores DC Orchestrator global limit for all the projects.
default_quota_group = cfg.OptGroup(name='dc_orch_global_limit',
                                   title='Global quota limit for all projects')
# The group stores the pecan configurations.
pecan_group = cfg.OptGroup(name='pecan',
                           title='Pecan options')

cache_opt_group = cfg.OptGroup(name='cache',
                               title='OpenStack Admin Credentials')

endpoint_cache_opt_group = cfg.OptGroup(name='endpoint_cache',
                                        title='OpenStack Credentials')

openstack_cache_opt_group = cfg.OptGroup(name='openstack_cache',
                                         title='Containerized OpenStack'
                                               ' Credentials')

fernet_opt_group = cfg.OptGroup(name='fernet',
                                title='Fernet Options')


def list_opts():
    yield default_quota_group.name, nova_quotas
    yield default_quota_group.name, neutron_quotas
    yield default_quota_group.name, cinder_quotas
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
