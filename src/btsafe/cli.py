"""Entry point: bittensor's own btcli app with its mnemonic-exposing commands replaced.

Everything not replaced here is stock btcli, so `btsafe stake add ...` or
`btsafe w list` behave exactly like `btcli`.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from typing import Any

import typer
from bittensor.cli import main as btcli_main
from bittensor.cli.commands import wallet as btcli_wallet
from typer.models import CommandInfo

from . import commands

HELP = (
    "btsafe - btcli with coldkey mnemonics kept off the screen. `wallet new-coldkey` "
    "seals the mnemonic in an encrypted file and `wallet regen-coldkey` restores from "
    "it; every other command is stock btcli."
)

# `wallet create` accepts btcli's flags so any invocation reaches the refusal
# message instead of a "no such option" error.
_ACCEPT_ANY_ARGS = {"allow_extra_args": True, "ignore_unknown_options": True}


def _replacements() -> dict[Callable[..., Any], tuple[Callable[..., Any], dict | None]]:
    return {
        btcli_wallet.new_coldkey: (commands.new_coldkey, None),
        btcli_wallet.regen_coldkey: (commands.regen_coldkey, None),
        btcli_wallet.create: (commands.create_disabled, _ACCEPT_ANY_ARGS),
    }


def install(root: typer.Typer = btcli_main.app) -> None:
    """Point every registration of the replaced commands at btsafe's versions.

    The wallet group is mounted as `wallet`, `w` and `wallets`, and each
    hyphenated command also has a hidden snake_case alias, so the whole tree
    is walked. Raises RuntimeError when an original cannot be found (btcli
    moved or renamed it): btsafe must never fall through to a command that
    prints a mnemonic.
    """
    replacements = _replacements()
    installed = {new: original for original, (new, _) in replacements.items()}
    covered = set()
    for info in _commands(root):
        if info.callback in replacements:
            original = info.callback
            # Unnamed commands take their name from the callback; keep btcli's.
            info.name = info.name or original.__name__.replace("_", "-")
            info.callback, settings = replacements[original]
            if settings is not None:
                info.context_settings = settings
            covered.add(original)
        elif info.callback in installed:
            covered.add(installed[info.callback])
    missing = [fn.__name__ for fn in replacements if fn not in covered]
    if missing:
        raise RuntimeError(
            f"btcli command(s) {', '.join(missing)} not found in this bittensor version; "
            "btsafe cannot guarantee mnemonics stay hidden"
        )
    root.info.help = HELP
    # Tracebacks must never render local variables (mnemonics, passwords).
    root.pretty_exceptions_show_locals = False


def _commands(app: typer.Typer, seen: set[int] | None = None) -> Iterator[CommandInfo]:
    seen = set() if seen is None else seen
    if id(app) in seen:
        return
    seen.add(id(app))
    yield from app.registered_commands
    for group in app.registered_groups:
        if group.typer_instance is not None:
            yield from _commands(group.typer_instance, seen)


def main() -> None:
    try:
        install()
    except RuntimeError as error:
        print(f"btsafe: refusing to start: {error}", file=sys.stderr)
        sys.exit(70)
    btcli_main.main()
