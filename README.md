# btsafe

`btcli` with the coldkey mnemonic kept off the screen.

`btcli wallet new-coldkey` prints the new mnemonic to the terminal, where it stays in
scrollback, terminal logs, screen recordings and over-the-shoulder view.
`btcli wallet regen-coldkey` has you type or paste it back. btsafe wraps btcli and
replaces those two commands:

- **`btsafe wallet new-coldkey`** never shows the mnemonic. It writes the mnemonic to an
  encrypted file and asks for **two different passwords**: one encrypts the coldkey in
  the wallet (as btcli does), and the other encrypts the mnemonic file.
- **`btsafe wallet regen-coldkey`** reads that file. It asks for the file's password to
  decrypt it, then for a password to encrypt the regenerated coldkey.

Every other command is stock btcli (`btsafe stake add …`, `btsafe w list`, …). btsafe
runs btcli's own app from the official `bittensor` package (11.1.0, which ships btcli)
and swaps those commands into it. Global flags, `btcli config` defaults, `--json` and
the `w`/`wallets`/snake_case aliases therefore work unchanged.

## Quick start

```bash
uv sync                  # or: pip install -e .
uv run btsafe --help
```

### Create a coldkey

```bash
btsafe wallet new-coldkey --wallet mywallet --mnemonic-file /media/usb/mywallet.btsafe
```

```
Enter a new coldkey password:
Retype the coldkey password:
Enter a new mnemonic file password:
Retype the mnemonic file password:
created coldkey
         wallet  mywallet
    crypto_type  sr25519
           ss58  5HYwmq4gE7dwNvTwY9na5Y7p3YzCTnG8WizT16VzSSNViM6C
  mnemonic_file  /media/usb/mywallet.btsafe
The mnemonic was not displayed. It exists only in the mnemonic_file above, …
```

The order of operations guarantees you never end up with a coldkey that has no working
backup:

1. btsafe asks for both passwords before generating anything.
2. It writes the mnemonic file.
3. It reads the file back and decrypts it.
4. Only after that succeeds does it write the coldkey.
5. It then unlocks the written coldkey with its password to confirm it.

Options: `--n-words 12|15|18|21|24`, `--crypto-type sr25519|ed25519`, and
`--overwrite` to replace an existing coldkey in the wallet.

### Restore a coldkey

```bash
btsafe wallet regen-coldkey --wallet mywallet --mnemonic-file /media/usb/mywallet.btsafe
```

```
Enter the mnemonic file password:
Enter a new coldkey password:
Retype the coldkey password:
regenerated coldkey
         wallet  mywallet
    crypto_type  sr25519
           ss58  5HYwmq4gE7dwNvTwY9na5Y7p3YzCTnG8WizT16VzSSNViM6C
```

The key scheme comes from the file, so you do not need to remember `--crypto-type`. The
regenerated address is checked against the one recorded when the file was created. Use
`--overwrite` to replace a coldkey that is already in the wallet.

If you leave out `--wallet` or `--mnemonic-file`, btsafe prompts for them on a terminal,
as btcli does.

## What btsafe enforces

- **The passwords are separate.** The mnemonic-file password must differ from the
  coldkey password, in both commands.
- **Minimum lengths.** The coldkey password needs at least 8 characters. The
  mnemonic-file password needs at least 12, because the file is meant to be stored
  off-machine, where whoever finds it can guess offline without limit. Each prompt allows
  3 attempts.
- **Passwords come only from the terminal.** They are read with echo off. btsafe has no
  password flags or environment variables. Without a terminal it refuses to run (it
  does not fall back to reading visible input) and writes nothing.
- **Mnemonic files are never overwritten.** The file is created with `O_EXCL`, mode
  `0600`, and fsynced. The directory must already exist; btsafe does not create
  directories, so a mistyped mount point such as `/media/usbb/…` cannot quietly put the
  file on the local disk.
- **Existing coldkeys are protected.** An existing coldkey or coldkeypub is only
  replaced with `--overwrite`. This is checked before any password prompt.
- **`wallet create` is disabled.** It prints the coldkey mnemonic too. Run
  `btsafe wallet new-coldkey` and then `btsafe wallet new-hotkey` instead.
- **It fails closed.** At startup btsafe checks that every registration of the btcli
  commands it replaces has been swapped out. If a bittensor release moves them, btsafe
  refuses to start rather than fall through to a command that prints a mnemonic.

## The mnemonic file

The file is UTF-8 JSON. It is documented here so it can be decrypted without btsafe if
you ever need to:

```json
{
  "format": "btsafe-mnemonic",
  "version": 1,
  "kdf": {"name": "argon2id", "iterations": 3, "memory_kib": 1048576, "lanes": 4,
          "salt": "<base64, 16 random bytes>"},
  "cipher": {"name": "chacha20-poly1305", "nonce": "<base64, 12 random bytes>"},
  "ciphertext": "<base64>"
}
```

- **Key:** `Argon2id(password as UTF-8, salt)` with the parameters recorded in the file,
  32 bytes long. Each file gets a fresh random salt and nonce.
- **Associated data:** every field except `ciphertext`, serialized as JSON with sorted
  keys and no whitespace. Editing any header field therefore fails decryption, the same
  way a wrong password does.
- **Plaintext:** JSON holding `mnemonic`, `ss58_address`, `crypto_type`, `wallet_name`
  and `created_at`. Nothing that identifies the key is stored outside the ciphertext.
- **Cost:** 1 GiB of memory and about 1 second per password attempt on a modern CPU.
  This is the same memory bittensor already uses to encrypt a coldkey.

btsafe does not reuse bittensor's keyfile encryption for this file, because that
encryption derives every key with one hard-coded Argon2i salt. The mnemonic file uses
Argon2id with a per-file salt, via PyCA `cryptography`.

## Limits

- **Coldkey keyfile.** The coldkey is still written by bittensor's own keyfile code.
  Like any btcli coldkey, the encrypted keyfile contains the mnemonic, protected by the
  coldkey password.
- **Memory.** The mnemonic and passwords are ordinary Python strings while the command
  runs. Python cannot reliably wipe them from memory.
- **Failure after the file is written.** If writing the coldkey fails after the mnemonic
  file was written and verified, the file is kept, because it is a valid backup. The
  error is reported.
- **Pinned versions.** btsafe replaces commands inside btcli, so it is held to
  `bittensor>=11.1.0,<11.2`. It also pins `typer<0.27.2`, because typer 0.27.2 makes
  every btcli 11.1.0 command exit 1 with a traceback. After upgrading either one, run
  `just check`.

## Development

```bash
just check        # ruff + pytest
```

The end-to-end tests run `btsafe` (and stock `btcli`, for comparison) on a
pseudo-terminal, typing passwords at the real prompts. They use a throwaway `HOME` and
wallet path, so real wallets are never touched. They check that:

- The mnemonic and passwords never appear on screen.
- The file and the wallet hold the same key, and stock btcli regenerates the same
  address from the sealed mnemonic.
- `regen-coldkey` restores the key from the file.
- Each refusal above leaves nothing behind.
