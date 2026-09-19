from __future__ import annotations

import re

from btsafe import screen


def test_numbered_grid_reads_left_to_right():
    words = [f"w{index}" for index in range(1, 13)]
    grid = screen.numbered(words).splitlines()
    assert len(grid) == 3
    assert re.findall(r"(\d+)\. (w\d+)", grid[0]) == [
        ("1", "w1"),
        ("2", "w2"),
        ("3", "w3"),
        ("4", "w4"),
    ]
    numbers = [int(n) for n, word in re.findall(r"(\d+)\. (w\d+)", "\n".join(grid))]
    assert numbers == list(range(1, 13))


def test_numbered_grid_handles_counts_that_do_not_fill_the_last_row():
    words = [f"w{index}" for index in range(1, 16)]
    grid = screen.numbered(words).splitlines()
    assert len(grid) == 4
    assert grid[-1].split() == ["13.", "w13", "14.", "w14", "15.", "w15"]
