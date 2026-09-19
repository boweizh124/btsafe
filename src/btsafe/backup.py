"""The encrypted mnemonic file: Argon2id key derivation, ChaCha20-Poly1305 sealing.

A file is UTF-8 JSON:

    {
      "format": "btsafe-mnemonic",
      "version": 1,
      "kdf": {"name": "argon2id", "iterations": 3, "memory_kib": 1048576,
              "lanes": 4, "salt": "<base64, 16 random bytes>"},
      "cipher": {"name": "chacha20-poly1305", "nonce": "<base64, 12 random bytes>"},
      "ciphertext": "<base64>"
    }

The 32-byte key is Argon2id(password as UTF-8, salt) with the recorded cost.
Every field except ``ciphertext``, serialized as JSON with sorted keys and no
whitespace, is the AEAD associated data, so editing any header field makes
decryption fail the same way a wrong password does. The plaintext is a JSON
object with ``mnemonic``, ``ss58_address``, ``crypto_type``, ``wallet_name``
and ``created_at``. Nothing identifying the key is stored outside the
ciphertext.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

FORMAT = "btsafe-mnemonic"
VERSION = 1
KDF_NAME = "argon2id"
CIPHER_NAME = "chacha20-poly1305"
SUFFIX = ".btsafe"

SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
TAG_BYTES = 16
MAX_FILE_BYTES = 64 * 1024
# Ceilings on header-supplied KDF cost, so a crafted file cannot make
# decryption allocate unbounded memory or run for hours.
MAX_MEMORY_KIB = 4 * 1024 * 1024
MAX_ITERATIONS = 64
MAX_LANES = 64


class BackupError(Exception):
    """The file is not a usable btsafe mnemonic file."""


class WrongPasswordError(BackupError):
    """Authentication failed: the password is wrong or the file was modified."""


@dataclass(frozen=True)
class KdfParams:
    iterations: int = 3
    # 1 GiB: the memory bittensor already spends encrypting a coldkey, and
    # well above RFC 9106's 64 MiB recommendation for this setting.
    memory_kib: int = 1024 * 1024
    lanes: int = 4


DEFAULT_KDF = KdfParams()


@dataclass(frozen=True, repr=False)
class MnemonicRecord:
    mnemonic: str
    ss58_address: str
    crypto_type: str
    wallet_name: str
    created_at: str

    def __repr__(self) -> str:
        # Keep the phrase out of logs, tracebacks and debugger output.
        return (
            f"MnemonicRecord(ss58_address={self.ss58_address!r}, "
            f"crypto_type={self.crypto_type!r}, wallet_name={self.wallet_name!r})"
        )


def encrypt(record: MnemonicRecord, password: str, kdf: KdfParams = DEFAULT_KDF) -> bytes:
    """Seal ``record`` under ``password``; returns the file contents."""
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    header = {
        "format": FORMAT,
        "version": VERSION,
        "kdf": {
            "name": KDF_NAME,
            "iterations": kdf.iterations,
            "memory_kib": kdf.memory_kib,
            "lanes": kdf.lanes,
            "salt": _b64(salt),
        },
        "cipher": {"name": CIPHER_NAME, "nonce": _b64(nonce)},
    }
    plaintext = json.dumps(asdict(record)).encode()
    ciphertext = ChaCha20Poly1305(_derive_key(password, salt, kdf)).encrypt(
        nonce, plaintext, _associated_data(header)
    )
    return (json.dumps({**header, "ciphertext": _b64(ciphertext)}, indent=2) + "\n").encode()


def check(data: bytes) -> None:
    """Raise BackupError unless ``data`` is structurally a btsafe mnemonic file."""
    _parse(data)


def decrypt(data: bytes, password: str) -> MnemonicRecord:
    """Open a file produced by :func:`encrypt`."""
    header, kdf, salt, nonce, ciphertext = _parse(data)
    try:
        plaintext = ChaCha20Poly1305(_derive_key(password, salt, kdf)).decrypt(
            nonce, ciphertext, _associated_data(header)
        )
    except InvalidTag:
        raise WrongPasswordError("wrong password, or the file has been modified") from None
    try:
        payload = json.loads(plaintext)
        values = {field.name: payload[field.name] for field in fields(MnemonicRecord)}
    except (ValueError, TypeError, KeyError):
        raise BackupError("decrypted contents are not a mnemonic record") from None
    if not all(isinstance(value, str) for value in values.values()):
        raise BackupError("decrypted contents are not a mnemonic record")
    return MnemonicRecord(**values)


def read(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise BackupError(f"{path} is {size} bytes; a mnemonic file is under 1 KiB")
    return path.read_bytes()


def write_new(path: Path, data: bytes) -> None:
    """Create ``path`` owner-only and durable; never replaces an existing file.

    O_EXCL (rather than write-then-rename) keeps this working on FAT/exFAT
    removable media, where a mnemonic file is likely to be kept.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        try:
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        # O_EXCL guarantees this partial file is ours.
        path.unlink(missing_ok=True)
        raise
    _fsync_directory(path.parent)


def _derive_key(password: str, salt: bytes, kdf: KdfParams) -> bytes:
    return Argon2id(
        salt=salt,
        length=KEY_BYTES,
        iterations=kdf.iterations,
        lanes=kdf.lanes,
        memory_cost=kdf.memory_kib,
    ).derive(password.encode())


def _associated_data(header: dict[str, Any]) -> bytes:
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


def _parse(data: bytes) -> tuple[dict[str, Any], KdfParams, bytes, bytes, bytes]:
    if len(data) > MAX_FILE_BYTES:
        raise BackupError("file is too large to be a mnemonic file")
    try:
        document = json.loads(data)
    except ValueError:
        raise BackupError("not a btsafe mnemonic file (not JSON)") from None
    if not isinstance(document, dict) or document.get("format") != FORMAT:
        raise BackupError("not a btsafe mnemonic file")
    if document.get("version") != VERSION:
        raise BackupError(
            f"unsupported mnemonic file version {document.get('version')!r}; "
            f"this btsafe reads version {VERSION}"
        )
    _expect_keys(document, {"format", "version", "kdf", "cipher", "ciphertext"}, "file")
    kdf_doc, cipher_doc = document["kdf"], document["cipher"]
    _expect_keys(kdf_doc, {"name", "iterations", "memory_kib", "lanes", "salt"}, "kdf")
    _expect_keys(cipher_doc, {"name", "nonce"}, "cipher")
    if kdf_doc["name"] != KDF_NAME or cipher_doc["name"] != CIPHER_NAME:
        raise BackupError(f"unsupported algorithms {kdf_doc['name']!r}/{cipher_doc['name']!r}")
    lanes = _bounded_int(kdf_doc, "lanes", 1, MAX_LANES)
    kdf = KdfParams(
        iterations=_bounded_int(kdf_doc, "iterations", 1, MAX_ITERATIONS),
        memory_kib=_bounded_int(kdf_doc, "memory_kib", 8 * lanes, MAX_MEMORY_KIB),
        lanes=lanes,
    )
    salt = _unb64(kdf_doc["salt"], "kdf.salt")
    nonce = _unb64(cipher_doc["nonce"], "cipher.nonce")
    ciphertext = _unb64(document["ciphertext"], "ciphertext")
    if len(salt) < SALT_BYTES or len(nonce) != NONCE_BYTES or len(ciphertext) <= TAG_BYTES:
        raise BackupError("salt, nonce or ciphertext has the wrong length")
    header = {key: value for key, value in document.items() if key != "ciphertext"}
    return header, kdf, salt, nonce, ciphertext


def _expect_keys(value: Any, keys: set[str], where: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise BackupError(f"malformed mnemonic file ({where} fields)")


def _bounded_int(doc: dict[str, Any], key: str, low: int, high: int) -> int:
    value = doc[key]
    # bool is an int subclass; a header saying `true` is malformed, not 1.
    if type(value) is not int or not low <= value <= high:
        raise BackupError(f"kdf.{key} must be an integer in [{low}, {high}], got {value!r}")
    return value


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(value: Any, where: str) -> bytes:
    if not isinstance(value, str):
        raise BackupError(f"{where} is not base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except binascii.Error:
        raise BackupError(f"{where} is not valid base64") from None


def _fsync_directory(directory: Path) -> None:
    # Makes the new directory entry durable; not every filesystem allows it.
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)
