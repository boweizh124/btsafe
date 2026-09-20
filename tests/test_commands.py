from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from btsafe import backup, commands

FAST = backup.KdfParams(iterations=1, memory_kib=1024, lanes=1)
RECORD = backup.MnemonicRecord(
    mnemonic="legal winner thank year wave sausage worth useful legal winner thank yellow",
    ss58_address="5FakeAddressForFormatTestsOnly",
    crypto_type="sr25519",
    wallet_name="alice",
    created_at="2026-09-18T00:00:00+00:00",
)


def test_verify_file_accepts_the_file_it_just_wrote(tmp_path: Path):
    path = tmp_path / "alice.btsafe"
    backup.write_new(path, backup.encrypt(RECORD, "file-password-2", FAST))
    commands._verify_file(path, RECORD, "file-password-2")
    assert path.exists()


def test_verify_file_removes_a_file_that_does_not_decrypt_back(tmp_path: Path):
    """The coldkey is only written after this passes, so a bad file must stop everything."""
    path = tmp_path / "alice.btsafe"
    backup.write_new(path, backup.encrypt(RECORD, "file-password-2", FAST))
    with pytest.raises(commands._Refusal, match="did not decrypt back"):
        commands._verify_file(path, RECORD, "a-different-password")
    assert not path.exists()


def test_verify_file_rejects_a_file_holding_another_key(tmp_path: Path):
    other = replace(RECORD, ss58_address="5SomeoneElse")
    path = tmp_path / "alice.btsafe"
    backup.write_new(path, backup.encrypt(other, "file-password-2", FAST))
    with pytest.raises(commands._Refusal, match="did not decrypt back"):
        commands._verify_file(path, RECORD, "file-password-2")
    assert not path.exists()


def test_a_kept_file_explains_itself_only_once_written(tmp_path: Path):
    kept = commands._KeptFile()
    assert kept.help() is None
    kept.path = tmp_path / "alice.btsafe"
    assert "regen-coldkey --mnemonic-file" in kept.help()
    assert str(kept.path) in kept.help()
