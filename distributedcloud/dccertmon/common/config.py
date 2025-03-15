#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import configparser
import os

import keyring
from oslo_config import cfg

from dccommon import consts as dccommon_consts
from dcmanager.common import utils

CONF = cfg.CONF

logging_default_format_string = (
    "%(process)d %(levelname)s %(name)s [-] %(instance)s%(message)s"
)

config_values = {
    "keystone_authtoken": {
        "auth_url": "http://controller.internal:5000",
        "auth_uri": "http://controller.internal:5000",
        "auth_type": "password",
        "project_name": "services",
        "username": "sysinv",
        "password": "None",
        "user_domain_name": "Default",
        "project_domain_name": "Default",
        "interface": "internal",
        "region_name": "None",
    },
    "DEFAULT": {
        "syslog_log_facility": "local4",
        "use_syslog": "True",
        "debug": "False",
        "logging_default_format_string": logging_default_format_string,
        "logging_debug_format_suffix": "%(pathname)s:%(lineno)d",
        "auth_strategy": "keystone",
        "transport_url": "None",
    },
    "dccertmon": {
        "retry_interval": "600",
        "max_retry": "14",
        "audit_interval": "86400",
        "startup_audit_all": "False",
        "network_retry_interval": "180",
        "network_max_retry": "30",
        "audit_batch_size": "40",
        "audit_greenpool_size": "20",
        "certificate_timeout_secs": "5",
    },
    "endpoint_cache": {
        "auth_plugin": "password",
        "username": "dcmanager",
        "password": "None",
        "project_name": "services",
        "user_domain_name": "Default",
        "project_domain_name": "Default",
        "http_connect_timeout": "15",
        "auth_uri": "http://controller.internal:5000/v3",
    },
}

common_opts = [cfg.StrOpt("host", default="localhost", help="hostname of the machine")]

dc_cert_mon_opts = [
    cfg.IntOpt(
        "audit_interval",
        default=86400,  # 24 hours
        help="Interval to run certificate audit",
    ),
    cfg.IntOpt(
        "retry_interval",
        default=10 * 60,  # retry every 10 minutes
        help="Interval to reattempt accessing external system if failure occurred",
    ),
]


def register_config_opts():
    CONF.register_opts(common_opts)
    CONF.register_opts(dc_cert_mon_opts, "dccertmon")


def override_config_values():
    rabbit_auth_password = keyring.get_password("amqp", "rabbit")

    config_values["keystone_authtoken"]["region_name"] = utils.get_region_name(
        "http://controller.internal:6385"
    )
    config_values["endpoint_cache"]["password"] = keyring.get_password(
        "dcmanager", dccommon_consts.SERVICES_USER_NAME
    )
    config_values["keystone_authtoken"]["password"] = keyring.get_password(
        "sysinv", dccommon_consts.SERVICES_USER_NAME
    )
    config_values["DEFAULT"][
        "transport_url"
    ] = f"rabbit://guest:{rabbit_auth_password}@controller.internal:5672"


def create_conf_file():
    output_dir = "/etc/dccertmon"
    output_file = os.path.join(output_dir, "dccertmon.conf")

    os.makedirs(output_dir, exist_ok=True)

    config = configparser.RawConfigParser()

    # Populate the config parser with values
    for section, options in config_values.items():
        config[section] = options

    with open(output_file, "w") as f:
        config.write(f)

    os.chmod(output_file, 0o600)


def generate_config():
    # Set dynamic values (e.g., passwords, urls, etc)
    override_config_values()
    # Create service conf file
    create_conf_file()


def list_opts():
    yield "dccertmon", dc_cert_mon_opts
    yield None, common_opts
