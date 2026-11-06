#!/usr/bin/env bash
# Build the module's image the way `kiwi-proxy module setup vpn` does and run it
# once. 0.2.1's adapter image did not build (`apk add microsocks`: Alpine does not
# carry it) and nothing noticed until a desktop built it — the unit tests never
# touch a Containerfile — and a build can succeed and leave an image with nothing
# in it, so the binary is run and the entrypoint is started on a port.
#
# gluetun, the tunnel, is pulled (GLUETUN_IMAGE in module/provider.py), not built.
#
#   tests/smoke/images.sh [podman build flags]      images.yml passes --no-cache
#
# A distinct tag: kiwi-proxy/vpn-adapter:latest, the one kiwi-proxy runs, is left alone.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

ADAPTER=kiwi-proxy/vpn-adapter:smoke
NAME=kf-smoke-vpn-adapter
PORT=1080
fail() { printf 'smoke: FAIL: %s\n' "$*" >&2; podman logs "$NAME" >&2 2>&1 || true; exit 1; }
cleanup() { podman rm -f -t 0 "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

echo "== build $ADAPTER"
podman build "$@" -t "$ADAPTER" -f module/containers/adapter/Containerfile module/containers/adapter

echo "== microsocks is in the image and runs"
podman run --rm --entrypoint sh "$ADAPTER" -c 'microsocks -h 2>&1 | grep "^usage: microsocks"' \
    || fail "microsocks does not run in the image"

echo "== the entrypoint listens on the port kiwi-proxy passes"
podman run --detach --name "$NAME" "$ADAPTER" "$PORT" >/dev/null
hex="$(printf '%04X' "$PORT")"
for _ in $(seq 1 20); do
    # A listener (state 0A) on any address at that port, read from procfs: the
    # image has no tools beyond busybox and needs none.
    if podman exec "$NAME" grep -q ":$hex 00000000:0000 0A" /proc/net/tcp; then
        echo "ok: microsocks listens on 0.0.0.0:$PORT"
        exit 0
    fi
    [ "$(podman inspect -f '{{.State.Running}}' "$NAME")" = true ] || fail "the adapter exited during startup"
    sleep 0.5
done
fail "nothing listens on :$PORT within 10 s"
