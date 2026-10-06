#!/usr/bin/env bash
# install.sh — kiwi-plugin-vpn, a kiwi-fox provider module.
#
# Installs the module payload (module/) into kiwi-fox's modules directory, where
# kiwi-fox discovers it. User scope only: rootless, nothing outside $HOME.
#
#   KIWI_SCOPE   user      (anything else is a no-op)
#   KIWI_ACTION  install | update | uninstall
#   KIWI_PURGE   1 only when the user asked for --purge
set -euo pipefail

MODULE="vpn"
KIWI_SCOPE="${KIWI_SCOPE:-user}"
KIWI_ACTION="${KIWI_ACTION:-${1:-install}}"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA="${XDG_DATA_HOME:-$HOME/.local/share}/kiwi-fox"
DEST="$DATA/modules/$MODULE"
STATE="$DATA/modules-state/$MODULE"

if [[ "$KIWI_SCOPE" != user ]]; then
    echo "install.sh: $MODULE is user-scope only; nothing to do for scope '$KIWI_SCOPE'"
    exit 0
fi

do_install() {
    rm -rf "$DEST"
    mkdir -p "$DEST"
    cp -r "$SRC/module/." "$DEST/"
    echo "installed provider module '$MODULE' to $DEST"
    echo "build its image with: kiwi-fox module setup $MODULE   (or: kiwi-fox setup)"
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
