#!/bin/sh
# Run from a reviewed checkout/download. No sudo, pipe-to-shell or VPN changes.
set -eu
INSTALLER_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "${ATLAS_PYTHON:-python3}" "$INSTALLER_DIR/install.py" "$@"
