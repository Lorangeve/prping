#!/bin/sh
BIN="$1"; shift
sudo -n setcap cap_net_raw+ep "$BIN" 2>/dev/null
exec "$BIN" "$@"
