"""Isolated disposable repositories; never use the developer's Git settings."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "secrets_check.py"
# Construct an inert fixture at runtime so the test source contains no complete
# credential-shaped token. No fixture is ever authenticated against a service.
SAMPLE_GITHUB = "ghp_" + "Ab9Cd8Ef7Gh6Ij5Kl4Mn3Op2Qr1St0Uv9Wx8"


def assignment(name, value, separator=" = ", quote='"'):
    """Assemble credential-like test input without embedding it in source."""
    return name + separator + quote + value + quote + "\n"


class RepositoryCase(unittest.TestCase):
    """Give each test its own repository, index, hooks, and Git configuration."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repository with spaces"
        self.repo.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(
            GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
            PYTHONDONTWRITEBYTECODE="1",
        )
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Scanner Test")
        self.git("config", "user.email", "scanner@example.invalid")
        self.git("config", "core.autocrlf", "false")

    def git(self, *args, input=None):
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], env=self.env,
            input=input, capture_output=True, check=True,
        ).stdout

    def stage(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())
        self.git("add", "--", name)
        return path

    def scan(self, *args, cwd=None):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT_PATH), *args], cwd=cwd or self.repo,
            env=self.env, capture_output=True, text=True,
        )

    def install_hook(self):
        import shlex

        location = self.git("rev-parse", "--git-path", "hooks/pre-commit").decode().strip()
        hook = self.repo / location
        hook.parent.mkdir(parents=True, exist_ok=True)
        command = shlex.quote(Path(sys.executable).as_posix()) + " -B " + shlex.quote(SCRIPT_PATH.as_posix())
        hook.write_text("#!/bin/sh\nexec " + command + "\n", encoding="utf-8")
        hook.chmod(0o755)

    def commit_result(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-qm", "Fixture commit", *args],
            env=self.env, capture_output=True, text=True,
        )
