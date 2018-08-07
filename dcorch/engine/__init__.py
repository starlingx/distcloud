# the sync services needs to be imported for them to
# be seen as subclasses to SyncThread in subcloud.py
from dcorch.engine.sync_services.compute import ComputeSyncThread  # noqa
from dcorch.engine.sync_services.identity import IdentitySyncThread  # noqa
from dcorch.engine.sync_services.network import NetworkSyncThread  # noqa
from dcorch.engine.sync_services.sysinv import SysinvSyncThread  # noqa
from dcorch.engine.sync_services.volume import VolumeSyncThread  # noqa
