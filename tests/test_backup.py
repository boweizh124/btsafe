from __future__ import annotations

import base64
import json
import os
import stat
import time
from pathlib import Path

import pytest

from btsafe import backup

# Cheap parameters so the format tests stay fast; the CLI always uses DEFAULT_KDF.
FAST = backup.KdfParams(iterations=1, memory_kib=1024, lanes=1)
MNEMONIC = "legal winner thank year wave sausage worth useful legal winner thank yellow"
RECORD = backup.MnemonicRecord(
    mnemonic=MNEMONIC,
    ss58_address="5FakeAddressForFormatTestsOnly",
    crypto_type="sr25519",
    wallet_name="alice",
    created_at="2026-09-18T00:00:00+00:00",
)


def sealed(password: str = "correct horse battery") -> bytes:
    return backup.encrypt(RECORD, password, FAST)


def edited(data: bytes, change) -> bytes:
    document = json.loads(data)
    change(document)
    return json.dumps(document).encode()


def test_round_trip():
    assert backup.decrypt(sealed(), "correct horse battery") == RECORD


def test_nothing_about_the_key_is_stored_in_the_clear():
    data = sealed()
    assert MNEMONIC.encode() not in data
    assert b"legal winner" not in data
    assert RECORD.ss58_address.encode() not in data
    assert b"alice" not in data


def test_record_repr_hides_the_mnemonic():
    assert "legal" not in repr(RECORD)
    assert "legal" not in str(RECORD)


def test_wrong_password_is_rejected():
    with pytest.raises(backup.WrongPasswordError):
        backup.decrypt(sealed(), "correct horse battery!")


def test_each_file_gets_a_fresh_salt_and_nonce():
    first, second = json.loads(sealed()), json.loads(sealed())
    assert first["kdf"]["salt"] != second["kdf"]["salt"]
    assert first["cipher"]["nonce"] != second["cipher"]["nonce"]


def flip_first_byte(value: str) -> str:
    raw = bytearray(base64.b64decode(value))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


@pytest.mark.parametrize(
    "tamper",
    [
        lambda d: d["kdf"].update(salt=flip_first_byte(d["kdf"]["salt"])),
        lambda d: d["kdf"].update(iterations=2),
        lambda d: d["cipher"].update(nonce=flip_first_byte(d["cipher"]["nonce"])),
        lambda d: d.update(ciphertext=flip_first_byte(d["ciphertext"])),
    ],
    ids=["salt", "kdf-cost", "nonce", "ciphertext"],
)
def test_modified_file_fails_authentication(tamper):
    with pytest.raises(backup.WrongPasswordError):
        backup.decrypt(edited(sealed(), tamper), "correct horse battery")


def test_reformatted_file_still_decrypts():
    # The associated data is canonical JSON, so re-indenting or reordering is harmless.
    document = json.loads(sealed())
    reformatted = json.dumps(dict(reversed(list(document.items()))), indent=8).encode()
    assert backup.decrypt(reformatted, "correct horse battery") == RECORD


@pytest.mark.parametrize(
    "tamper, message",
    [
        (lambda d: d.update(format="something-else"), "not a btsafe"),
        (lambda d: d.update(version=2), "unsupported mnemonic file version"),
        (lambda d: d.update(extra=1), "malformed"),
        (lambda d: d["kdf"].update(name="scrypt"), "unsupported algorithms"),
        (lambda d: d["kdf"].update(memory_kib=10**9), "kdf.memory_kib"),
        (lambda d: d["kdf"].update(iterations=10**6), "kdf.iterations"),
        (lambda d: d["kdf"].update(lanes=True), "kdf.lanes"),
        (lambda d: d["cipher"].update(nonce="!!"), "not valid base64"),
    ],
)
def test_malformed_files_are_rejected_before_any_key_derivation(tamper, message):
    started = time.monotonic()
    with pytest.raises(backup.BackupError, match=message):
        backup.check(edited(sealed(), tamper))
    assert time.monotonic() - started < 1


def test_non_json_is_rejected():
    with pytest.raises(backup.BackupError, match="not JSON"):
        backup.check(b"\x00\x01binary")


def test_default_kdf_cost_is_not_weakened():
    expected = backup.KdfParams(iterations=3, memory_kib=1024 * 1024, lanes=4)
    assert expected == backup.DEFAULT_KDF
    document = json.loads(backup.encrypt(RECORD, "correct horse battery"))
    assert document["kdf"]["memory_kib"] == 1024 * 1024
    assert document["kdf"]["iterations"] == 3


def test_write_new_is_owner_only(tmp_path: Path):
    old_umask = os.umask(0o022)
    try:
        backup.write_new(tmp_path / "a.btsafe", b"data")
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE((tmp_path / "a.btsafe").stat().st_mode) == 0o600


def test_write_new_never_replaces_a_file(tmp_path: Path):
    target = tmp_path / "a.btsafe"
    target.write_bytes(b"the only backup")
    with pytest.raises(FileExistsError):
        backup.write_new(target, b"new")
    assert target.read_bytes() == b"the only backup"
