from oslo_config import cfg

from dccertmon.common import config

# Ensure config options are registered before importing any module using CONF
config.register_config_opts()
cfg.CONF([], project="dccertmon", default_config_files=[])
