from __future__ import annotations

import pytest

from btsafe import passwords


def problem(password: str, **kwargs) -> str | None:
    return passwords.problem(password, label="mnemonic file", min_length=12, **kwargs)


def test_a_good_password_has_no_problem():
    assert problem("file-password-2") is None


def test_too_short_is_rejected():
    assert "at least 12 characters" in problem("eleven-char")


def test_a_repeated_character_is_rejected_however_long():
    # Long enough to pass the length rule, and worthless.
    assert "different characters" in problem("a" * 40)
    assert "different characters" in problem("abab" * 10)


def test_the_two_passwords_must_differ():
    message = problem("file-password-2", other="file-password-2", other_label="coldkey")
    assert message == "the mnemonic file password must differ from the coldkey password"


def test_length_is_reported_before_the_other_rules():
    # A short password that is also degenerate names the length first, so the
    # retry prompt asks for one thing at a time.
    assert "at least 12 characters" in problem("aaa")


@pytest.mark.parametrize("label, min_length", [("coldkey", 8), ("mnemonic file", 12)])
def test_both_prompts_carry_their_own_minimum(label, min_length):
    message = passwords.problem("short", label=label, min_length=min_length)
    assert message == f"the {label} password must be at least {min_length} characters"
