import os
import tempfile
import unittest
from unittest import mock

from ghost import config
from ghost.db import migrate
from ghost.services import operations

ENV_VARS = ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "IPINFO_TOKEN", "GHOST_AI_BASE_URL", "GHOST_AI_MODEL",
            "GHOST_VAULT_PASSPHRASE", "GHOST_ALLOW_PRIVATE_TARGETS")


class GhostTestCase(unittest.TestCase):
    """Every test gets a private data dir and an environment with no providers, AI or vault configured."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.tmp = self._tmp.name
        patcher = mock.patch.dict(os.environ, {}, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        for v in ENV_VARS:
            os.environ.pop(v, None)
        self.reset()
        migrate()

    def tearDown(self):
        operations.shutdown_pool()
        self._tmp.cleanup()

    @property
    def data_dir(self):
        from pathlib import Path
        return Path(self.tmp) / "data"

    def reset(self, **overrides):
        return config.reset_settings(data_dir=self.data_dir, **overrides)

    def setenv(self, **kv):
        os.environ.update(kv)
        self.reset()
