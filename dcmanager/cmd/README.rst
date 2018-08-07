===============================
cmd
===============================

Scripts to start the DC Manager API and Manager services

api.py:
    start API service
    python api.py --config-file=/etc/dcmanager.conf

manager.py:
    start Manager service
    python manager.py --config-file=/etc/dcmanager.conf

manage.py:
    CLI interface for dcmanager database management
    dcmanager-manage --config-file /etc/dcmanager.conf db_sync
    dcmanager-manage --config-file /etc/dcmanager.conf db_version
