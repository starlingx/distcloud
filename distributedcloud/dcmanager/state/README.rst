===============================
Service
===============================

DC Manager State Service has responsibility for:
    Subcloud state updates coming from dcmanager-manager service

service.py:
    run DC Manager State Service in multi-worker mode, and establish RPC server

subcloud_state_manager.py:
    Provide subcloud state updates
