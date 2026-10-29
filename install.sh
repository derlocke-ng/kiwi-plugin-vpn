#!/usr/bin/env bash
# install.sh — kiwi-plugin-vpn, a kiwi-proxy provider module.
#
# Installs the module payload (module/) into kiwi-proxy's modules directory, where
# kiwi-proxy discovers it. User scope only: rootless, nothing outside $HOME.
#
#   KIWI_SCOPE   user      (anything else is a no-op)
#   KIWI_ACTION  install | update | uninstall
#   KIWI_PURGE   1 only when the user asked for --purge
set -euo pipefail

MODULE="vpn"
KIWI_SCOPE="${KIWI_SCOPE:-user}"
KIWI_ACTION="${KIWI_ACTION:-${1:-install}}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/kiwi-proxy"
# Where kiwi-fox kept modules before the proxy engine moved to kiwi-proxy.
LEGACY="${XDG_DATA_HOME:-$HOME/.local/share}/kiwi-fox"
DEST="$DATA/modules/$MODULE"
STATE="$DATA/modules-state/$MODULE"

if [[ "$KIWI_SCOPE" != user ]]; then
    echo "install.sh: $MODULE is user-scope only; nothing to do for scope '$KIWI_SCOPE'"
    exit 0
fi

do_install() {
    # A copy kiwi-fox loaded before the split imports kiwi_fox, which no longer
    # carries the contract: drop it. Its state (VPN config, identities) is not
    # per-version, so it comes along unless this module already has its own.
    rm -rf "$LEGACY/modules/$MODULE"
    if [[ -d "$LEGACY/modules-state/$MODULE" && ! -e "$STATE" ]]; then
        mkdir -p "$(dirname "$STATE")"
        cp -a "$LEGACY/modules-state/$MODULE" "$STATE"
        echo "took the state kiwi-fox kept for '$MODULE' ($LEGACY/modules-state/$MODULE)"
    fi
    rm -rf "$DEST"
    mkdir -p "$DEST"
    cp -r "$SRC/module/." "$DEST/"
    echo "installed provider module '$MODULE' to $DEST"
    echo "build its image with: kiwi-proxy module setup $MODULE   (or: kiwi-proxy setup)"
}

do_uninstall() {
    rm -rf "$DEST"
    if [[ "${KIWI_PURGE:-0}" == 1 ]]; then
        rm -rf "$STATE"
        echo "purged provider module '$MODULE' and its state"
    else
        echo "removed provider module '$MODULE' (state kept; --purge to remove)"
    fi
}

case "$KIWI_ACTION" in
    install|update) do_install ;;
    uninstall)      do_uninstall ;;
    *) echo "install.sh: unknown action '$KIWI_ACTION'" >&2; exit 2 ;;
esac
