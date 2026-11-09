#!/usr/bin/env bash
# Starts the AppImage under Xvfb with llvmpipe in a clean Ubuntu container for 8 s, then checks that
# it did not crash or exit early, and that it fails gracefully with no display.
# Usage: [UBUNTU=24.04] [SMOKE_FUSE=0] packaging/smoke.sh path/to/Zombos-Razor-x.y.z-x86_64.AppImage
# SMOKE_FUSE=0 skips the FUSE mount (use extract-and-run) for hosts where /dev/fuse is not allowed.
set -euo pipefail

if [ "${ZOMBO_SMOKE_INSIDE:-}" != 1 ]; then
    APPIMAGE="$(readlink -f "${1:?usage: $0 path/to/Zombos-Razor.AppImage}")"
    UBUNTU="${UBUNTU:-24.04}"
    CONTAINER="${CONTAINER:-$(command -v docker || command -v podman)}"
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    "$CONTAINER" build -q -t "zombo-razor-smoke-$UBUNTU" --build-arg "UBUNTU=$UBUNTU" -f "$ROOT/Dockerfile.smoke" "$ROOT" >/dev/null
    fuse=(--device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor=unconfined)
    [ "${SMOKE_FUSE:-1}" = 0 ] && fuse=(-e APPIMAGE_EXTRACT_AND_RUN=1)
    exec "$CONTAINER" run --rm "${fuse[@]}" -e ZOMBO_SMOKE_INSIDE=1 \
        -v "$APPIMAGE:/app.AppImage:ro" -v "$ROOT/smoke.sh:/smoke.sh:ro" \
        "zombo-razor-smoke-$UBUNTU" bash /smoke.sh
fi

. /etc/os-release
echo "smoke on $PRETTY_NAME, fuse: $([ "${APPIMAGE_EXTRACT_AND_RUN:-}" = 1 ] && echo extract-and-run || echo mount)"
log="$(mktemp)"
fail() {
    echo "FAIL: $1" >&2
    sed 's/^/  | /' "$log" >&2
    exit 1
}

export XDG_RUNTIME_DIR="$(mktemp -d)" XDG_CONFIG_HOME="$(mktemp -d)" XDG_STATE_HOME="$(mktemp -d)" XDG_DATA_HOME="$(mktemp -d)"
Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
XVFB=$!
trap 'kill $XVFB 2>/dev/null || true' EXIT
for _ in $(seq 50); do xdpyinfo -display :99 >/dev/null 2>&1 && break; sleep 0.1; done

unset WAYLAND_DISPLAY
DISPLAY=:99 LIBGL_ALWAYS_SOFTWARE=1 /app.AppImage >"$log" 2>&1 &
APP=$!
sleep 8
kill -0 $APP 2>/dev/null || { wait $APP && rc=0 || rc=$?; fail "the app exited early with status $rc"; }
kill $APP
wait $APP 2>/dev/null || true
grep -q "window system could not start\|panicked" "$log" && fail "the app reported a startup failure"
echo "ran 8 s without crashing. $(grep -m1 'first render' "$log" || echo 'no first-render line printed')"

: >"$log"
rc=0
# A dead DISPLAY first, then no display variable at all.
env -u WAYLAND_DISPLAY DISPLAY=:77 timeout 20 /app.AppImage >"$log" 2>&1 || rc=$?
[ "$rc" != 0 ] && [ "$rc" != 124 ] || fail "with no display the app should exit with an error, got status $rc"
grep -q "the window system could not start" "$log" || fail "with no display the app did not print the graceful-failure message"
echo "dead display: exit $rc with the graceful-failure message"
rc=0
env -u WAYLAND_DISPLAY -u DISPLAY timeout 20 /app.AppImage >"$log" 2>&1 || rc=$?
[ "$rc" != 0 ] && [ "$rc" != 124 ] || fail "with no display variable the app should exit with an error, got status $rc"
grep -q "no display found" "$log" || fail "with no display variable the app did not say so"
echo "no display variable: exit $rc with the message"

/app.AppImage --help | grep -q -- "--appimage-extract-and-run" || fail "--help lacks the extract-and-run fallback text"
echo "OK"
