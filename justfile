default: check

# Install dependencies into .venv
install:
    uv sync

# Lint and test (the end-to-end tests drive btsafe and btcli on a pseudo-terminal)
check:
    uv run ruff check src tests
    uv run ruff format --check src tests
    uv run pytest -q

fmt:
    uv run ruff format src tests
    uv run ruff check --fix src tests

# Create a coldkey:  just new-coldkey mywallet /media/usb/mywallet.btsafe
new-coldkey wallet file:
    uv run btsafe wallet new-coldkey --wallet {{wallet}} --mnemonic-file {{file}}

# Restore a coldkey:  just regen-coldkey mywallet /media/usb/mywallet.btsafe
regen-coldkey wallet file:
    uv run btsafe wallet regen-coldkey --wallet {{wallet}} --mnemonic-file {{file}}
