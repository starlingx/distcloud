===============================
cmd
===============================

Scripts to start the DC Orchestrators API and Engine services

api.py:
    start API service
    python api.py --config-file=/etc/dcorch.conf

engine.py:
    start Engine service
    python engine.py --config-file=/etc/dcorch.conf

manage.py:
    CLI interface for DC Orchestrators management
    dcorch-manage --config-file /etc/dcorch.conf db_sync
    dcorch-manage --config-file /etc/dcorch.conf db_version
