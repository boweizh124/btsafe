"""Hidden password entry and the policy for the coldkey and mnemonic-file passwords."""

from __future__ import annotations

import getpass
import warnings
from collections.abc import Callable

COLDKEY_MIN_LENGTH = 8
# The mnemonic file is meant to live off-machine, where anyone who finds it
# can guess offline for as long as they like, so it gets the longer minimum.
FILE_MIN_LENGTH = 12
# Length alone accepts "aaaaaaaaaaaa". This is a floor under the worst
# passwords, not a strength meter: a long string of common words still passes,
# so pick something with real entropy.
MIN_DISTINCT_CHARACTERS = 5
MAX_ATTEMPTS = 3


class PasswordError(Exception):
    """No acceptable password was entered."""


def read_hidden(prompt: str) -> str:
    """getpass that refuses, rather than falling back to echoing, without a terminal."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except getpass.GetPassWarning:
            raise PasswordError(
                "no terminal available for hidden password entry; run btsafe interactively"
            ) from None
        except EOFError:
            raise PasswordError("password entry aborted") from None


def problem(
    password: str,
    *,
    label: str,
    min_length: int,
    other: str | None = None,
    other_label: str = "",
) -> str | None:
    """Why ``password`` is unacceptable, or None."""
    if len(password) < min_length:
        return f"the {label} password must be at least {min_length} characters"
    if len(set(password)) < MIN_DISTINCT_CHARACTERS:
        return (
            f"the {label} password must use at least {MIN_DISTINCT_CHARACTERS} different characters"
        )
    if other is not None and password == other:
        return f"the {label} password must differ from the {other_label} password"
    return None


def choose(
    *,
    label: str,
    min_length: int,
    report: Callable[[str], None],
    other: str | None = None,
    other_label: str = "",
) -> str:
    """Ask for a new password twice, re-asking up to MAX_ATTEMPTS on policy failures."""
    for _ in range(MAX_ATTEMPTS):
        password = read_hidden(f"Enter a new {label} password: ")
        issue = problem(
            password, label=label, min_length=min_length, other=other, other_label=other_label
        )
        if issue is None:
            if read_hidden(f"Retype the {label} password: ") == password:
                return password
            issue = "passwords do not match"
        report(issue)
    raise PasswordError(f"no acceptable {label} password after {MAX_ATTEMPTS} attempts")
