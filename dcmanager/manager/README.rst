===============================
Service
===============================

DC Manager Service has responsibility for:
    Main subcloud state machine as well as all operations on subclouds
    including creation, deletion and update.

service.py:
    run DC Manager service in multi-worker mode, and establish RPC server

subcloud_manager.py:
    Manages all subcloud related activities such as creation, deletion, 
    availability status, management state

audit_manager.py:
    A Periodic audit to contact each subcloud and ensure that at least 
    one of each service group is up and active, which is a pre-requisite 
    for declaring a subcloud as online.

scheduler.py:
   Thread group manager, also responsible for periodic timer tasks - ie. audit.

