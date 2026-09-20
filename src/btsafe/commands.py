"""btsafe's versions of `btcli wallet new-coldkey`, `regen-coldkey` and `create`,
plus `show-mnemonic`, which btcli does not have.

They run inside btcli's own app (see cli.py), so wallet selection, config
defaults, --json/--quiet and output styling behave exactly as in btcli.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import typer
from bittensor import wallets
from bittensor.cli.context import AppContext, ctx_of
from bittensor.cli.globals import with_globals
from bittensor.cli.prompt import confirm_wallet
from bittensor.keyfiles import KeyfileError, Keypair
from bittensor.wallet import Wallet

from . import backup, passwords, screen

N_WORDS = (12, 15, 18, 21, 24)

_NEW_FILE_HELP = (
    "Where to write the encrypted mnemonic file, e.g. /media/usb/mywallet.btsafe. "
    "The directory must already exist; an existing file is never overwritten."
)
_EXISTING_FILE_HELP = "Encrypted mnemonic file written by `btsafe wallet new-coldkey`."
_N_WORDS_HELP = "Number of words in the generated mnemonic: 12, 15, 18, 21, or 24."
_CRYPTO_TYPE_HELP = "Key scheme: ed25519 (0) or sr25519 (1, default)."
_OVERWRITE_HELP = (
    "Replace the wallet's existing coldkey files. The old key is lost unless it has its own backup."
)
_KEEP_SAFE = (
    "The mnemonic was not displayed. It exists in two encrypted copies: the mnemonic_file "
    "above, under the mnemonic-file password, and the wallet's coldkey keyfile, under the "
    "coldkey password. Move the mnemonic file to offline storage and keep its password "
    "somewhere else: the coldkey cannot be restored from the file without it. Restore with "
    "`btsafe wallet regen-coldkey --mnemonic-file PATH`."
)
_FILE_KEPT = (
    "the mnemonic file {path} was written and verified, and has been kept: it is a working "
    "backup of a coldkey that is in no wallet. Install that coldkey with `btsafe wallet "
    "regen-coldkey --mnemonic-file {path}`, or delete the file"
)
_SHOW_WARNING = (
    "The mnemonic will be displayed on this terminal. Make sure nobody can see your "
    "screen and nothing is recording or sharing it."
)


class _Refusal(Exception):
    def __init__(self, message: str, help: str | None = None) -> None:
        super().__init__(message)
        self.help = help


class _KeptFile:
    """A mnemonic file that is already written and verified when a later step fails."""

    def __init__(self) -> None:
        self.path: Path | None = None

    def help(self) -> str | None:
        return None if self.path is None else _FILE_KEPT.format(path=self.path)


@with_globals
def new_coldkey(
    ctx: typer.Context,
    mnemonic_file: str = typer.Option(..., "--mnemonic-file", help=_NEW_FILE_HELP),
    n_words: int = typer.Option(12, "--n-words", help=_N_WORDS_HELP),
    overwrite: bool = typer.Option(False, "--overwrite", help=_OVERWRITE_HELP),
    crypto_type: str = typer.Option("sr25519", "--crypto-type", help=_CRYPTO_TYPE_HELP),
):
    """Create a new coldkey, sealing its mnemonic in an encrypted file instead of printing it.

    Asks for two different passwords: one encrypts the coldkey in the wallet,
    the other encrypts the mnemonic file written to --mnemonic-file. The file
    is read back and decrypted before the coldkey is written, so a coldkey is
    never created without a working backup. Restore it with
    `btsafe wallet regen-coldkey --mnemonic-file PATH`.
    """
    app_ctx: AppContext = ctx_of(ctx)
    confirm_wallet(app_ctx, help_text="Wallet to create the coldkey in.", must_exist=False)
    kept = _KeptFile()
    with _refusals(app_ctx, kept):
        crypto = wallets.parse_crypto_type(crypto_type)
        if n_words not in N_WORDS:
            raise _Refusal(f"--n-words must be one of {', '.join(map(str, N_WORDS))}")
        target = _fresh_file_path(mnemonic_file)
        wallet = Wallet(app_ctx.wallet_name, path=app_ctx.wallet_path)
        _check_replaceable(wallet, overwrite)

        coldkey_password = passwords.choose(
            label="coldkey",
            min_length=passwords.COLDKEY_MIN_LENGTH,
            report=_reporter(app_ctx),
        )
        file_password = passwords.choose(
            label="mnemonic file",
            min_length=passwords.FILE_MIN_LENGTH,
            report=_reporter(app_ctx),
            other=coldkey_password,
            other_label="coldkey",
        )

        mnemonic = Keypair.generate_mnemonic(n_words)
        record = backup.MnemonicRecord(
            mnemonic=mnemonic,
            ss58_address=Keypair.create_from_mnemonic(mnemonic, crypto).ss58_address,
            crypto_type=wallets.format_crypto_type(crypto),
            wallet_name=app_ctx.wallet_name,
            created_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        with app_ctx.output.activity("encrypting the mnemonic file"):
            backup.write_new(target, backup.encrypt(record, file_password))
            _verify_file(target, record, file_password)
        kept.path = target
        _write_coldkey(app_ctx, wallet, record, coldkey_password, overwrite)

    app_ctx.output.detail(
        "created coldkey",
        {
            "wallet": app_ctx.wallet_name,
            "crypto_type": record.crypto_type,
            "ss58": record.ss58_address,
            "mnemonic_file": str(target),
        },
    )
    app_ctx.output.message(_KEEP_SAFE)


@with_globals
def regen_coldkey(
    ctx: typer.Context,
    mnemonic_file: str = typer.Option(..., "--mnemonic-file", help=_EXISTING_FILE_HELP),
    overwrite: bool = typer.Option(False, "--overwrite", help=_OVERWRITE_HELP),
):
    """Regenerate a coldkey from an encrypted mnemonic file; the mnemonic is never shown.

    Asks for the mnemonic file's password to decrypt it, then for a new password
    to encrypt the regenerated coldkey (the two must differ). The key scheme
    comes from the file, and the regenerated address is checked against the one
    recorded when the file was created.
    """
    app_ctx: AppContext = ctx_of(ctx)
    with _refusals(app_ctx):
        source, data = _read_existing(mnemonic_file)
    confirm_wallet(app_ctx, help_text="Wallet to regenerate the coldkey in.", must_exist=False)
    with _refusals(app_ctx):
        wallet = Wallet(app_ctx.wallet_name, path=app_ctx.wallet_path)
        _check_replaceable(wallet, overwrite)

        record, file_password = _open_file(app_ctx, data)
        _check_derivation(record)
        coldkey_password = passwords.choose(
            label="coldkey",
            min_length=passwords.COLDKEY_MIN_LENGTH,
            report=_reporter(app_ctx),
            other=file_password,
            other_label="mnemonic file",
        )
        _write_coldkey(app_ctx, wallet, record, coldkey_password, overwrite)

    app_ctx.output.detail(
        "regenerated coldkey",
        {
            "wallet": app_ctx.wallet_name,
            "crypto_type": record.crypto_type,
            "ss58": record.ss58_address,
            "path": app_ctx.wallet_path,
            "mnemonic_file": str(source),
        },
    )


def show_mnemonic(
    ctx: typer.Context,
    mnemonic_file: str = typer.Option(..., "--mnemonic-file", help=_EXISTING_FILE_HELP),
):
    """Display the mnemonic sealed in an encrypted mnemonic file.

    Asks for the password the file was encrypted with. The words appear on the
    terminal's alternate screen, never on stdout (a pipe or redirect cannot
    capture them), and are wiped from the terminal when you press Enter.
    """
    app_ctx: AppContext = ctx_of(ctx)
    with _refusals(app_ctx):
        _, data = _read_existing(mnemonic_file)
        app_ctx.output.message(_SHOW_WARNING)
        record, _ = _open_file(app_ctx, data)
        # Never show a phrase that would not restore the recorded key.
        _check_derivation(record)
        screen.show_until_enter(_mnemonic_card(record))
    app_ctx.output.message("mnemonic hidden and screen cleared")


def create_disabled(ctx: typer.Context) -> None:
    """Disabled in btsafe: `btcli wallet create` prints the coldkey mnemonic.

    Run `btsafe wallet new-coldkey --mnemonic-file PATH`, then
    `btsafe wallet new-hotkey`.
    """
    ctx_of(ctx).output.error(
        "`wallet create` is disabled in btsafe because it prints the coldkey mnemonic",
        help="run `btsafe wallet new-coldkey --mnemonic-file PATH`, "
        "then `btsafe wallet new-hotkey`",
    )
    raise typer.Exit(1)


@contextmanager
def _refusals(app_ctx: AppContext, kept: _KeptFile | None = None) -> Iterator[None]:
    """Report expected failures as btcli-style errors instead of tracebacks.

    ``kept`` names a mnemonic file left on disk by an earlier step, so every
    failure after that point says what the file is and how to use it.
    """
    kept = kept or _KeptFile()
    try:
        yield
    except _Refusal as error:
        app_ctx.output.error(str(error), help=error.help or kept.help())
        raise typer.Exit(1) from None
    except (
        backup.BackupError,
        passwords.PasswordError,
        screen.ScreenError,
        KeyfileError,
        OSError,
        ValueError,
    ) as e:
        app_ctx.output.error(str(e) or type(e).__name__, help=kept.help())
        raise typer.Exit(1) from None
    except BaseException:
        # Ctrl-C or a bug: still say what was left behind, then let it through.
        if kept.path is not None:
            app_ctx.output.message(kept.help())
        raise


def _reporter(app_ctx: AppContext) -> Callable[[str], None]:
    return lambda text: app_ctx.output.error(text)


def _fresh_file_path(raw: str) -> Path:
    path = Path(os.path.abspath(Path(raw).expanduser()))
    if path.exists() or path.is_symlink():
        raise _Refusal(
            f"{path} already exists",
            help="btsafe never overwrites a mnemonic file; choose a new file path",
        )
    if not path.parent.is_dir():
        raise _Refusal(
            f"directory {path.parent} does not exist",
            help="create it (or mount the drive) first; btsafe does not create "
            "directories, so a mistyped mount point cannot put the file on the local disk",
        )
    if not os.access(path.parent, os.W_OK):
        raise _Refusal(f"directory {path.parent} is not writable")
    return path


def _read_existing(raw: str) -> tuple[Path, bytes]:
    path = Path(raw).expanduser()
    if not path.is_file():
        raise _Refusal(f"mnemonic file {path} does not exist")
    data = backup.read(path)
    backup.check(data)
    return path, data


def _check_derivation(record: backup.MnemonicRecord) -> None:
    crypto = wallets.parse_crypto_type(record.crypto_type)
    derived = Keypair.create_from_mnemonic(record.mnemonic, crypto).ss58_address
    if derived != record.ss58_address:
        raise _Refusal(
            f"the mnemonic in the file derives {derived}, "
            f"but the file records {record.ss58_address}"
        )


def _mnemonic_card(record: backup.MnemonicRecord) -> str:
    return (
        f"Mnemonic for {record.ss58_address}\n"
        f"wallet {record.wallet_name}, {record.crypto_type}, sealed {record.created_at}\n\n"
        f"{screen.numbered(record.mnemonic.split())}\n\n"
        f"   {record.mnemonic}"
    )


def _check_replaceable(wallet: Wallet, overwrite: bool) -> None:
    existing = [
        keyfile.path
        for keyfile in (wallet.coldkey_file, wallet.coldkeypub_file)
        if keyfile.exists_on_device()
    ]
    if existing and not overwrite:
        raise _Refusal(
            f"wallet {wallet.name!r} already has coldkey files: {', '.join(existing)}",
            help="pass --overwrite to replace them, or choose another --wallet",
        )


def _verify_file(path: Path, record: backup.MnemonicRecord, password: str) -> None:
    """Prove the bytes on disk decrypt to ``record`` before the key exists anywhere else."""
    try:
        matches = backup.decrypt(backup.read(path), password) == record
    except backup.BackupError:
        matches = False
    if not matches:
        path.unlink(missing_ok=True)
        raise _Refusal(f"{path} did not decrypt back to the new key; nothing was created")


def _open_file(app_ctx: AppContext, data: bytes) -> tuple[backup.MnemonicRecord, str]:
    for attempt in range(1, passwords.MAX_ATTEMPTS + 1):
        password = passwords.read_hidden("Enter the mnemonic file password: ")
        try:
            with app_ctx.output.activity("decrypting the mnemonic file"):
                return backup.decrypt(data, password), password
        except backup.WrongPasswordError as error:
            if attempt == passwords.MAX_ATTEMPTS:
                raise
            app_ctx.output.error(str(error))
    raise AssertionError("unreachable")


def _write_coldkey(
    app_ctx: AppContext,
    wallet: Wallet,
    record: backup.MnemonicRecord,
    password: str,
    overwrite: bool,
) -> None:
    crypto = wallets.parse_crypto_type(record.crypto_type)
    with app_ctx.output.activity("encrypting the coldkey"):
        # suppress=True matters: without it this prints the mnemonic.
        wallet.regenerate_coldkey(
            mnemonic=record.mnemonic,
            use_password=True,
            overwrite=overwrite,
            suppress=True,
            coldkey_password=password,
            crypto_type=crypto,
        )
        # Unlock what landed on disk, the way later btcli commands will.
        on_disk = Wallet(wallet.name, path=wallet.path)
        unlocked = on_disk.get_coldkey(password).ss58_address
        public = on_disk.coldkeypub.ss58_address
    if unlocked != record.ss58_address or public != record.ss58_address:
        raise _Refusal(
            f"the coldkey written to {wallet.coldkey_file.path} does not unlock to "
            f"{record.ss58_address}"
        )
