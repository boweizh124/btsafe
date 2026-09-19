"""Showing a secret on the terminal without it reaching stdout or scrollback."""

from __future__ import annotations

import io
import math
import os

# xterm private modes, understood by essentially every modern terminal, tmux
# and screen: the alternate screen has no scrollback, and leaving it restores
# the normal screen exactly as it was.
ENTER_ALTERNATE_SCREEN = "\x1b[?1049h"
LEAVE_ALTERNATE_SCREEN = "\x1b[?1049l"
CLEAR = "\x1b[2J\x1b[3J\x1b[H"


class ScreenError(Exception):
    """No terminal to show the secret on."""


def show_until_enter(text: str) -> None:
    """Show ``text`` on the controlling terminal's alternate screen until Enter.

    Written to /dev/tty rather than stdout, so redirecting or piping btsafe
    cannot capture it. The screen is wiped on the way out, including on
    Ctrl-C.
    """
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        raise ScreenError("no terminal available to display the mnemonic on") from None
    # Opened as getpass does: buffered "r+" needs a seekable file, a tty is not one.
    tty = io.TextIOWrapper(io.FileIO(fd, "w+"), encoding="utf-8", line_buffering=True)
    with tty:
        try:
            tty.write(ENTER_ALTERNATE_SCREEN + CLEAR + text)
            tty.write("\n\nPress Enter to hide the mnemonic and clear the screen.")
            tty.flush()
            tty.readline()
        finally:
            tty.write(CLEAR + LEAVE_ALTERNATE_SCREEN)
            tty.flush()


def numbered(words: list[str], columns: int = 4) -> str:
    """Words as a numbered grid, read left to right, for copying onto paper."""
    width = max(len(word) for word in words)
    rows = math.ceil(len(words) / columns)
    lines = []
    for row in range(rows):
        cells = [
            f"{index + 1:>2}. {words[index]:<{width}}"
            for index in range(row * columns, min((row + 1) * columns, len(words)))
        ]
        lines.append("   " + "   ".join(cells).rstrip())
    return "\n".join(lines)
