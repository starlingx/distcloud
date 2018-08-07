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
from dcorch.common.i18n import _
from dcorch.common import version
from oslo_config import cfg
from oslo_log import log as logging
import sys


LOG = logging.getLogger(__name__)

snmp_server_opts = [
    cfg.StrOpt('snmp_ip', default='0.0.0.0',
               help='ip to listen on'),
    cfg.IntOpt('snmp_port',
               default=162,
               help='snmp trap port'),
    cfg.StrOpt('snmp_comm_str', default='dcorchAlarmAggregator',
               help='community string'),
    cfg.StrOpt('snmp_sec_area', default='fm-aggregator',
               help='security area'),
    cfg.StrOpt('auth_strategy', default='keystone',
               help=_("The type of authentication to use")),
    cfg.IntOpt('delay_time',
               default=30,
               help='min time (seconds) between update requests per server'),
    cfg.IntOpt('alarm_audit_interval_time',
               default=787,
               help='interval of periodic updates in seconds'),
    cfg.IntOpt('throttle_threshold',
               default=10,
               help='min number alarms over delay_time before throttling')
]

snmp_opt_group = cfg.OptGroup(name='snmp',
                              title='SNMP Options')


def init(args, **kwargs):
    # Register the configuration options
    # cfg.CONF.register_opts(common_opts)

    # ks_session.Session.register_conf_options(cfg.CONF)
    # auth.register_conf_options(cfg.CONF)
    logging.register_options(cfg.CONF)
    register_options()
    cfg.CONF(args=args, project='dc-orch',
             version='%%(prog)s %s' % version.version_info.release_string(),
             **kwargs)


def setup_logging():
    """Sets up the logging options for a log with supplied name."""
    product_name = "dc-orch"
    logging.setup(cfg.CONF, product_name)
    LOG.info("Logging enabled!")
    LOG.info("%(prog)s version %(version)s",
             {'prog': sys.argv[0],
              'version': version.version_info.release_string()})
    LOG.debug("command line: %s", " ".join(sys.argv))


def reset_service():
    # Reset worker in case SIGHUP is called.
    # Note that this is called only in case a service is running in
    # daemon mode.
    setup_logging()

    # TODO(joehuang) enforce policy later
    # policy.refresh()


def test_init():
    # Register the configuration options
    # cfg.CONF.register_opts(common_opts)
    logging.register_options(cfg.CONF)
    register_options()
    setup_logging()


def list_opts():
    yield snmp_opt_group.name, snmp_server_opts


def register_options():
    for group, opts in list_opts():
        cfg.CONF.register_opts(opts, group=group)
