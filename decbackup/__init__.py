"""decbackup — Python clone of the Stormshield SNS backup decryption utility.

Reimplementation of ``/usr/Firewall/sbin/decbackup`` and the backup
container handling of ``libncrypto.so`` from Stormshield SNS v5.1.4,
derived by reverse engineering (see ``RECON.md``).
"""

__version__ = "0.2.0"

from .backup import BackupError, decrypt_backup  # noqa: F401
