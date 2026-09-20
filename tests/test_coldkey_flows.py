"""End-to-end: the two operations btsafe exists for, driven on a real pseudo-terminal."""

from __future__ import annotations

import json
import re
import shlex
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest
from bittensor.keyfiles import Keypair
from bittensor.sp_core import CRYPTO_ED25519, CRYPTO_SR25519
from bittensor.wallet import Wallet

from btsafe import backup

from .conftest import BIN, Terminal, isolated_env, run_detached

COLDKEY_PASSWORD = "coldkey-pass-1"
FILE_PASSWORD = "file-password-2"
NEW_COLDKEY_PASSWORD = "coldkey-pass-3"
# Cheap parameters for files this test module writes itself; btsafe always uses DEFAULT_KDF.
FAST = backup.KdfParams(iterations=1, memory_kib=1024, lanes=1)
VALID_MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow"


@dataclass
class Created:
    env: dict[str, str]
    wallets: Path
    file: Path
    screen: str
    exit_code: int


def assert_never_displayed(screen: str, *secrets: str) -> None:
    for secret in secrets:
        assert secret not in screen
    # No two consecutive mnemonic words either (catches partial or wrapped echoes).
    mnemonic = secrets[0].split()
    for left, right in zip(mnemonic, mnemonic[1:], strict=False):
        assert f"{left} {right}" not in screen


@pytest.fixture(scope="module")
def created(tmp_path_factory: pytest.TempPathFactory) -> Created:
    """Operation 1: `btsafe wallet new-coldkey`, answering both password prompts."""
    root = tmp_path_factory.mktemp("created")
    env = isolated_env(root)
    wallets, backups = root / "wallets", root / "usb"
    backups.mkdir()
    file = backups / "alice.btsafe"
    term = Terminal(
        "btsafe",
        [
            "wallet",
            "new-coldkey",
            "--wallet",
            "alice",
            "--wallet-path",
            str(wallets),
            "--mnemonic-file",
            str(file),
        ],
        env,
    )
    term.answer("Enter a new coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Retype the coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Enter a new mnemonic file password: ", FILE_PASSWORD)
    term.answer("Retype the mnemonic file password: ", FILE_PASSWORD)
    exit_code = term.finish()
    return Created(env, wallets, file, term.screen, exit_code)


@pytest.fixture(scope="module")
def ed25519(tmp_path_factory: pytest.TempPathFactory) -> Created:
    """The other key scheme, with the longest mnemonic: both must survive the round trip."""
    root = tmp_path_factory.mktemp("ed25519")
    env = isolated_env(root)
    wallets, backups = root / "wallets", root / "usb"
    backups.mkdir()
    file = backups / "erin.btsafe"
    term = Terminal(
        "btsafe",
        [
            "wallet",
            "new-coldkey",
            "--wallet",
            "erin",
            "--wallet-path",
            str(wallets),
            "--mnemonic-file",
            str(file),
            "--crypto-type",
            "ed25519",
            "--n-words",
            "24",
        ],
        env,
    )
    term.answer("Enter a new coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Retype the coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Enter a new mnemonic file password: ", FILE_PASSWORD)
    term.answer("Retype the mnemonic file password: ", FILE_PASSWORD)
    exit_code = term.finish()
    return Created(env, wallets, file, term.screen, exit_code)


# --- operation 1: new-coldkey -------------------------------------------------------


def test_new_coldkey_writes_an_encrypted_mnemonic_file_instead_of_printing(created: Created):
    assert created.exit_code == 0, created.screen
    record = backup.decrypt(created.file.read_bytes(), FILE_PASSWORD)
    assert len(record.mnemonic.split()) == 12
    assert_never_displayed(created.screen, record.mnemonic, COLDKEY_PASSWORD, FILE_PASSWORD)
    assert "not displayed" in created.screen
    assert record.ss58_address in created.screen
    assert str(created.file) in created.screen
    assert stat.S_IMODE(created.file.stat().st_mode) == 0o600


def test_new_coldkey_file_and_wallet_hold_the_same_key(created: Created):
    record = backup.decrypt(created.file.read_bytes(), FILE_PASSWORD)
    wallet = Wallet("alice", path=str(created.wallets))
    assert wallet.coldkeypub.ss58_address == record.ss58_address
    assert wallet.get_coldkey(COLDKEY_PASSWORD).ss58_address == record.ss58_address
    derived = Keypair.create_from_mnemonic(record.mnemonic, CRYPTO_SR25519)
    assert derived.ss58_address == record.ss58_address


def test_new_coldkey_passwords_are_not_interchangeable(created: Created):
    with pytest.raises(backup.WrongPasswordError):
        backup.decrypt(created.file.read_bytes(), COLDKEY_PASSWORD)
    with pytest.raises(Exception, match="(?i)password|decrypt"):
        Wallet("alice", path=str(created.wallets)).get_coldkey(FILE_PASSWORD)


def test_file_mnemonic_is_standard_for_stock_btcli(created: Created, tmp_path: Path):
    """The sealed mnemonic regenerates the same address through stock btcli."""
    record = backup.decrypt(created.file.read_bytes(), FILE_PASSWORD)
    term = Terminal(
        "btcli",
        ["wallet", "regen-coldkey", "--wallet", "stock", "--wallet-path", str(tmp_path)],
        created.env,
    )
    term.answer("mnemonic, hex seed, or private key", record.mnemonic)
    term.answer("Enter password to encrypt key", COLDKEY_PASSWORD)
    term.answer("Retype password: ", COLDKEY_PASSWORD)
    assert term.finish() == 0, term.screen
    assert Wallet("stock", path=str(tmp_path)).coldkeypub.ss58_address == record.ss58_address


def test_stock_btcli_unlocks_the_coldkey(created: Created):
    """Plain btcli, not btsafe, decrypts the coldkey btsafe wrote and signs with it."""
    term = Terminal(
        "btcli",
        [
            "wallet",
            "sign",
            "--wallet",
            "alice",
            "--wallet-path",
            str(created.wallets),
            "--message",
            "hello",
            "--json",
        ],
        created.env,
    )
    term.answer("password", COLDKEY_PASSWORD)
    assert term.finish() == 0, term.screen
    signature = re.search(r"(?:0x)?([0-9a-f]{128})", term.screen)
    assert signature, term.screen
    address = Wallet("alice", path=str(created.wallets)).coldkeypub.ss58_address
    assert Keypair(ss58_address=address).verify(b"hello", bytes.fromhex(signature.group(1)))


# --- operation 2: regen-coldkey -----------------------------------------------------


def test_regen_coldkey_restores_from_the_encrypted_file(created: Created):
    term = Terminal(
        "btsafe",
        [
            "w",
            "regen-coldkey",
            "--wallet",
            "restored",
            "--wallet-path",
            str(created.wallets),
            "--mnemonic-file",
            str(created.file),
        ],
        created.env,
    )
    term.answer("Enter the mnemonic file password: ", FILE_PASSWORD)
    term.answer("Enter a new coldkey password: ", NEW_COLDKEY_PASSWORD)
    term.answer("Retype the coldkey password: ", NEW_COLDKEY_PASSWORD)
    assert term.finish() == 0, term.screen

    record = backup.decrypt(created.file.read_bytes(), FILE_PASSWORD)
    restored = Wallet("restored", path=str(created.wallets))
    assert restored.coldkeypub.ss58_address == record.ss58_address
    assert restored.get_coldkey(NEW_COLDKEY_PASSWORD).ss58_address == record.ss58_address
    assert_never_displayed(term.screen, record.mnemonic, FILE_PASSWORD, NEW_COLDKEY_PASSWORD)
    assert record.ss58_address in term.screen


def test_regen_coldkey_rejects_a_wrong_file_password(created: Created):
    term = Terminal(
        "btsafe",
        [
            "wallet",
            "regen-coldkey",
            "--wallet",
            "intruder",
            "--wallet-path",
            str(created.wallets),
            "--mnemonic-file",
            str(created.file),
        ],
        created.env,
    )
    for _ in range(3):
        term.answer("Enter the mnemonic file password: ", "not-the-password")
        term.expect("wrong password")
    assert term.finish() == 1
    assert not (created.wallets / "intruder").exists()


def test_regen_coldkey_refuses_the_file_password_as_coldkey_password(created: Created):
    term = Terminal(
        "btsafe",
        [
            "wallet",
            "regen_coldkey",
            "--wallet",
            "restored2",
            "--wallet-path",
            str(created.wallets),
            "--mnemonic-file",
            str(created.file),
        ],
        created.env,
    )
    term.answer("Enter the mnemonic file password: ", FILE_PASSWORD)
    term.answer("Enter a new coldkey password: ", FILE_PASSWORD)
    term.expect("must differ from the mnemonic file password")
    term.answer("Enter a new coldkey password: ", NEW_COLDKEY_PASSWORD)
    term.answer("Retype the coldkey password: ", NEW_COLDKEY_PASSWORD)
    assert term.finish() == 0, term.screen


def test_regen_coldkey_refuses_to_replace_a_coldkey_without_overwrite(created: Created):
    result = run_detached(
        [
            "wallet",
            "regen-coldkey",
            "--wallet",
            "alice",
            "--wallet-path",
            str(created.wallets),
            "--mnemonic-file",
            str(created.file),
        ],
        created.env,
    )
    assert result.returncode == 1
    assert "already has coldkey files" in result.stderr


def test_regen_coldkey_rejects_a_file_that_is_not_a_backup(env, tmp_path: Path):
    bogus = tmp_path / "notes.txt"
    bogus.write_text("just some words")
    result = run_detached(
        [
            "wallet",
            "regen-coldkey",
            "--wallet",
            "x",
            "--wallet-path",
            str(tmp_path / "w"),
            "--mnemonic-file",
            str(bogus),
        ],
        env,
    )
    assert result.returncode == 1
    assert "not a btsafe mnemonic file" in result.stderr


# --- new-coldkey guard rails --------------------------------------------------------


def test_new_coldkey_enforces_the_password_policy(env, tmp_path: Path):
    file = tmp_path / "bob.btsafe"
    term = Terminal(
        "btsafe",
        [
            "wallet",
            "new-coldkey",
            "--wallet",
            "bob",
            "--wallet-path",
            str(tmp_path / "w"),
            "--mnemonic-file",
            str(file),
        ],
        env,
    )
    term.answer("Enter a new coldkey password: ", "short")
    term.expect("at least 8 characters")
    term.answer("Enter a new coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Retype the coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Enter a new mnemonic file password: ", COLDKEY_PASSWORD)
    term.expect("must differ from the coldkey password")
    term.answer("Enter a new mnemonic file password: ", "eleven-char")
    term.expect("at least 12 characters")
    term.answer("Enter a new mnemonic file password: ", FILE_PASSWORD)
    term.answer("Retype the mnemonic file password: ", FILE_PASSWORD)
    assert term.finish() == 0, term.screen
    assert backup.decrypt(file.read_bytes(), FILE_PASSWORD).wallet_name == "bob"


def test_new_coldkey_never_overwrites_a_mnemonic_file(env, tmp_path: Path):
    file = tmp_path / "existing.btsafe"
    file.write_text("someone's only backup")
    result = run_detached(
        [
            "wallet",
            "new-coldkey",
            "--wallet",
            "carol",
            "--wallet-path",
            str(tmp_path / "w"),
            "--mnemonic-file",
            str(file),
        ],
        env,
    )
    assert result.returncode == 1
    assert "already exists" in result.stderr
    assert file.read_text() == "someone's only backup"
    assert not (tmp_path / "w").exists()


def test_new_coldkey_requires_the_directory_to_exist(env, tmp_path: Path):
    result = run_detached(
        [
            "wallet",
            "new-coldkey",
            "--wallet",
            "carol",
            "--wallet-path",
            str(tmp_path / "w"),
            "--mnemonic-file",
            str(tmp_path / "not-mounted" / "carol.btsafe"),
        ],
        env,
    )
    assert result.returncode == 1
    assert "does not exist" in result.stderr
    assert not (tmp_path / "not-mounted").exists()


def test_new_coldkey_refuses_to_replace_a_coldkey_without_overwrite(created: Created):
    file = created.file.with_name("second.btsafe")
    result = run_detached(
        [
            "wallet",
            "new-coldkey",
            "--wallet",
            "alice",
            "--wallet-path",
            str(created.wallets),
            "--mnemonic-file",
            str(file),
        ],
        created.env,
    )
    assert result.returncode == 1
    assert "already has coldkey files" in result.stderr
    assert not file.exists()


def test_without_a_terminal_nothing_is_created(env, tmp_path: Path):
    file = tmp_path / "dave.btsafe"
    result = run_detached(
        [
            "wallet",
            "new-coldkey",
            "--wallet",
            "dave",
            "--wallet-path",
            str(tmp_path / "w"),
            "--mnemonic-file",
            str(file),
        ],
        env,
    )
    assert result.returncode == 1
    assert "no terminal available" in result.stderr
    assert not file.exists()
    assert not (tmp_path / "w").exists()


# --- the rest of btcli --------------------------------------------------------------


@pytest.mark.parametrize("group", ["wallet", "w", "wallets"])
def test_wallet_create_is_disabled(env, tmp_path: Path, group: str):
    result = run_detached(
        [
            group,
            "create",
            "--wallet",
            "erin",
            "--wallet-path",
            str(tmp_path / "w"),
            "--n-words",
            "24",
            "--no-password",
        ],
        env,
    )
    assert result.returncode == 1
    assert "disabled in btsafe because it prints the coldkey mnemonic" in result.stderr
    assert not (tmp_path / "w").exists()


def test_other_commands_pass_through_to_btcli(created: Created):
    result = run_detached(
        ["wallet", "list", "--wallet-path", str(created.wallets), "--json"], created.env
    )
    assert result.returncode == 0, result.stderr
    listed = {ck["coldkey"]: ck["ss58"] for ck in json.loads(result.stdout)["coldkeys"]}
    record = backup.decrypt(created.file.read_bytes(), FILE_PASSWORD)
    assert listed["alice"] == record.ss58_address


# --- both key schemes ---------------------------------------------------------------


def test_new_coldkey_seals_the_scheme_it_created(ed25519: Created):
    assert ed25519.exit_code == 0, ed25519.screen
    record = backup.decrypt(ed25519.file.read_bytes(), FILE_PASSWORD)
    assert record.crypto_type == "ed25519"
    assert len(record.mnemonic.split()) == 24
    assert_never_displayed(ed25519.screen, record.mnemonic, COLDKEY_PASSWORD, FILE_PASSWORD)
    assert Wallet("erin", path=str(ed25519.wallets)).coldkeypub.crypto_type == CRYPTO_ED25519


def test_regen_coldkey_takes_the_scheme_from_the_file(ed25519: Created):
    """No --crypto-type is passed: the sr25519 default would restore a different key."""
    term = Terminal(
        "btsafe",
        [
            "wallet",
            "regen-coldkey",
            "--wallet",
            "erin-restored",
            "--wallet-path",
            str(ed25519.wallets),
            "--mnemonic-file",
            str(ed25519.file),
        ],
        ed25519.env,
    )
    term.answer("Enter the mnemonic file password: ", FILE_PASSWORD)
    term.answer("Enter a new coldkey password: ", NEW_COLDKEY_PASSWORD)
    term.answer("Retype the coldkey password: ", NEW_COLDKEY_PASSWORD)
    assert term.finish() == 0, term.screen

    record = backup.decrypt(ed25519.file.read_bytes(), FILE_PASSWORD)
    restored = Wallet("erin-restored", path=str(ed25519.wallets))
    assert restored.coldkeypub.ss58_address == record.ss58_address
    assert restored.get_coldkey(NEW_COLDKEY_PASSWORD).crypto_type == CRYPTO_ED25519


def test_new_coldkey_overwrite_rotates_the_key(ed25519: Created):
    """--overwrite replaces the wallet's coldkey; the old file still opens the old key."""
    old = backup.decrypt(ed25519.file.read_bytes(), FILE_PASSWORD)
    rotated = ed25519.file.with_name("erin-rotated.btsafe")
    term = Terminal(
        "btsafe",
        [
            "wallet",
            "new-coldkey",
            "--wallet",
            "erin",
            "--wallet-path",
            str(ed25519.wallets),
            "--mnemonic-file",
            str(rotated),
            "--overwrite",
        ],
        ed25519.env,
    )
    term.answer("Enter a new coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Retype the coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Enter a new mnemonic file password: ", FILE_PASSWORD)
    term.answer("Retype the mnemonic file password: ", FILE_PASSWORD)
    assert term.finish() == 0, term.screen

    new = backup.decrypt(rotated.read_bytes(), FILE_PASSWORD)
    assert new.ss58_address != old.ss58_address
    wallet = Wallet("erin", path=str(ed25519.wallets))
    assert wallet.coldkeypub.ss58_address == new.ss58_address
    assert wallet.get_coldkey(COLDKEY_PASSWORD).ss58_address == new.ss58_address
    assert backup.decrypt(ed25519.file.read_bytes(), FILE_PASSWORD) == old


# --- machine-readable output --------------------------------------------------------


def test_json_mode_prints_one_record_and_no_secret(env, tmp_path: Path):
    """stdout is redirected to a file, so only the prompts reach the terminal."""
    file, out = tmp_path / "grace.btsafe", tmp_path / "out.json"
    argv = [
        str(BIN / "btsafe"), "wallet", "new-coldkey",
        "--wallet", "grace",
        "--wallet-path", str(tmp_path / "w"),
        "--mnemonic-file", str(file),
        "--json",
    ]  # fmt: skip
    command = f"{shlex.join(argv)} > {shlex.quote(str(out))}"
    term = Terminal("/bin/sh", ["-c", command], env)
    term.answer("Enter a new coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Retype the coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Enter a new mnemonic file password: ", FILE_PASSWORD)
    term.answer("Retype the mnemonic file password: ", FILE_PASSWORD)
    assert term.finish() == 0, term.screen

    record = backup.decrypt(file.read_bytes(), FILE_PASSWORD)
    printed = json.loads(out.read_text())
    assert printed == {
        "wallet": "grace",
        "crypto_type": "sr25519",
        "ss58": record.ss58_address,
        "mnemonic_file": str(file),
    }
    assert_never_displayed(out.read_text(), record.mnemonic, COLDKEY_PASSWORD, FILE_PASSWORD)
    assert_never_displayed(term.screen, record.mnemonic, COLDKEY_PASSWORD, FILE_PASSWORD)


# --- more guard rails ---------------------------------------------------------------


def test_regen_coldkey_refuses_a_file_that_records_another_address(env, tmp_path: Path):
    """Authentic file, contradictory contents: only someone with the password could
    have written it, so the mnemonic is not trusted over the recorded address."""
    lying = backup.MnemonicRecord(
        mnemonic=VALID_MNEMONIC,
        ss58_address="5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
        crypto_type="sr25519",
        wallet_name="heidi",
        created_at="2026-09-18T00:00:00+00:00",
    )
    file = tmp_path / "heidi.btsafe"
    file.write_bytes(backup.encrypt(lying, FILE_PASSWORD, FAST))
    term = Terminal(
        "btsafe",
        [
            "wallet",
            "regen-coldkey",
            "--wallet",
            "heidi",
            "--wallet-path",
            str(tmp_path / "w"),
            "--mnemonic-file",
            str(file),
        ],
        env,
    )
    term.answer("Enter the mnemonic file password: ", FILE_PASSWORD)
    term.expect("but the file records")
    assert term.finish() == 1
    assert not (tmp_path / "w").exists()


def test_a_failed_coldkey_write_keeps_the_file_and_says_what_it_is(env, tmp_path: Path):
    """The wallet path is a regular file, so the coldkey cannot be written — after the
    mnemonic file has been written and verified."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("")
    file = tmp_path / "ivan.btsafe"
    term = Terminal(
        "btsafe",
        [
            "wallet",
            "new-coldkey",
            "--wallet",
            "ivan",
            "--wallet-path",
            str(blocker),
            "--mnemonic-file",
            str(file),
        ],
        env,
    )
    term.answer("Enter a new coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Retype the coldkey password: ", COLDKEY_PASSWORD)
    term.answer("Enter a new mnemonic file password: ", FILE_PASSWORD)
    term.answer("Retype the mnemonic file password: ", FILE_PASSWORD)
    assert term.finish() == 1

    screen = " ".join(term.screen.split())
    assert "has been kept" in screen
    assert "regen-coldkey --mnemonic-file" in screen
    record = backup.decrypt(file.read_bytes(), FILE_PASSWORD)
    assert record.wallet_name == "ivan"
    assert_never_displayed(term.screen, record.mnemonic, COLDKEY_PASSWORD, FILE_PASSWORD)
