from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import pexpect
import pytest

BIN = Path(sys.executable).parent


def isolated_env(root: Path) -> dict[str, str]:
    """Environment with its own HOME and btcli config; the real wallets are never touched."""
    home = root / "home"
    home.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BT_", "BTCLI_"))}
    env.update(
        HOME=str(home),
        BTCLI_CONFIG=str(home / "btcli.json"),
        NO_COLOR="1",
        TERM="dumb",
        COLUMNS="200",
    )
    return env


class Terminal:
    """Drives a CLI on a pseudo-terminal, as a person would, recording what it displays."""

    def __init__(self, program: str, args: list[str], env: dict[str, str]) -> None:
        self._display = io.StringIO()
        self.child = pexpect.spawn(
            str(BIN / program),
            args,
            env=env,
            encoding="utf-8",
            timeout=120,
            dimensions=(50, 200),
        )
        self.child.logfile_read = self._display

    def answer(self, prompt: str, reply: str) -> None:
        self.child.expect(prompt)
        self.child.sendline(reply)

    def expect(self, text: str) -> None:
        self.child.expect(text)

    def finish(self) -> int:
        self.child.expect(pexpect.EOF)
        self.child.close()
        return self.child.exitstatus

    @property
    def screen(self) -> str:
        return self._display.getvalue()


def run_detached(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run btsafe with no controlling terminal at all (like cron or a pipeline)."""
    return subprocess.run(
        [str(BIN / "btsafe"), *args],
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        start_new_session=True,
        timeout=120,
    )


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return isolated_env(tmp_path)
