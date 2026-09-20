from __future__ import annotations

import subprocess

import pytest
import typer
from bittensor.cli import main as btcli_main
from bittensor.cli.commands import wallet as btcli_wallet
from bittensor.wallet import Wallet

from btsafe import cli, commands

from .conftest import BIN

ORIGINALS = {btcli_wallet.new_coldkey, btcli_wallet.regen_coldkey, btcli_wallet.create}


def test_no_original_command_is_reachable_after_install():
    cli.install()
    cli.install()  # idempotent
    callbacks = [info.callback for info in cli._commands(btcli_main.app)]
    assert not ORIGINALS & set(callbacks)
    ours = {
        commands.new_coldkey,
        commands.regen_coldkey,
        commands.create_disabled,
        commands.show_mnemonic,
    }
    routed = [
        (info.name, info.callback)
        for info in btcli_wallet.app.registered_commands
        if info.callback in ours
    ]
    assert sorted(routed, key=lambda pair: pair[0]) == [
        ("create", commands.create_disabled),
        ("new-coldkey", commands.new_coldkey),
        ("new_coldkey", commands.new_coldkey),
        ("regen-coldkey", commands.regen_coldkey),
        ("regen_coldkey", commands.regen_coldkey),
        ("show-mnemonic", commands.show_mnemonic),
        ("show_mnemonic", commands.show_mnemonic),
    ]


def test_show_mnemonic_never_shadows_a_btcli_command():
    wallet_app = typer.Typer()
    wallet_app.command("show-mnemonic")(lambda: None)
    with pytest.raises(RuntimeError, match="will not shadow it"):
        cli._add(wallet_app, "show-mnemonic", commands.show_mnemonic, "panel")


def test_install_refuses_when_btcli_commands_moved():
    elsewhere = typer.Typer()
    elsewhere.command("new-coldkey")(lambda: None)
    with pytest.raises(RuntimeError, match="cannot guarantee mnemonics stay hidden"):
        cli.install(elsewhere)


def test_install_refuses_when_regenerate_coldkey_stops_naming_suppress(monkeypatch):
    """`suppress=True` is what keeps the mnemonic off the screen, and regenerate_coldkey
    ends in **_, so a renamed keyword would be swallowed instead of raising."""

    def renamed(self, mnemonic=None, quiet=False, **_):
        raise AssertionError("btsafe must refuse to start before calling this")

    monkeypatch.setattr(Wallet, "regenerate_coldkey", renamed)
    with pytest.raises(RuntimeError, match="no longer takes .*suppress"):
        cli.install()


def test_install_accepts_the_real_regenerate_coldkey():
    cli._check_regenerate_coldkey()


@pytest.mark.parametrize(
    "group, command",
    [
        ("wallet", "new-coldkey"),
        ("w", "new_coldkey"),
        ("wallets", "regen-coldkey"),
        ("w", "regen_coldkey"),
        ("wallet", "show-mnemonic"),
        ("w", "show_mnemonic"),
    ],
)
def test_every_alias_reaches_btsafe(env, group, command):
    result = subprocess.run(
        [str(BIN / "btsafe"), group, command, "--help"],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "--mnemonic-file" in result.stdout
    assert "--mnemonic " not in result.stdout
    assert "--no-password" not in result.stdout
