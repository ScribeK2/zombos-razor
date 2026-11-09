#!/usr/bin/env bash
# Builds Zombos-Razor-<version>-x86_64.AppImage, zombo-<version>-x86_64-linux.tar.gz and SHA256SUMS
# in build/dist, inside an Ubuntu 24.04 container (glibc 2.39, so the result runs on 24.04 and newer).
# Usage: [VERSION=1.2.3] [SOURCE_DATE_EPOCH=n] [CONTAINER=docker|podman] packaging/build-appimage.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Pinned: type2-runtime 20251108 (static libfuse3, runs with the fuse3 package only) and appimagetool 1.9.1.
RUNTIME_URL=https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64
RUNTIME_SHA256=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d
TOOL_URL=https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage
TOOL_SHA256=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0

inside() {
    cd /src
    DIST=/src/build/dist
    APPDIR=/src/build/AppDir
    ID=io.github.scribek2.zombos-razor
    export CARGO_TARGET_DIR=/src/build/target
    export RUSTFLAGS="--remap-path-prefix=/src=. --remap-path-prefix=/opt/cargo=/cargo"
    ZOMBO_VERSION="$VERSION" cargo build --release --locked -p zombo-ui -p zombo

    rm -rf "$APPDIR" "$DIST"
    mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib" "$APPDIR/usr/share/licenses/zombo-razor" \
        "$APPDIR/usr/share/applications" "$APPDIR/usr/share/metainfo" \
        "$APPDIR/usr/share/icons/hicolor/256x256/apps" "$APPDIR/usr/share/icons/hicolor/scalable/apps" "$DIST"
    install -m755 "$CARGO_TARGET_DIR/release/zombo-razor" "$APPDIR/usr/bin/"

    # Only libxkbcommon travels with the app; the Vulkan loader, Mesa and drivers stay on the host.
    for lib in libxkbcommon.so.0 libxkbcommon-x11.so.0; do
        install -m644 "$(readlink -f "$(ldconfig -p | awk -v l="$lib" '$1 == l && /x86-64/ {print $NF; exit}')")" "$APPDIR/usr/lib/$lib"
    done

    local p=packaging DATE
    DATE="$(date -u -d "@$SOURCE_DATE_EPOCH" +%F)"
    sed "s/@VERSION@/$VERSION/" $p/AppRun >"$APPDIR/AppRun"
    chmod 755 "$APPDIR/AppRun"
    sed -e "s/@VERSION@/$VERSION/" -e "s/@DATE@/$DATE/" $p/$ID.metainfo.xml >"$APPDIR/usr/share/metainfo/$ID.metainfo.xml"
    cp $p/$ID.desktop "$APPDIR/usr/share/applications/"
    cp $p/$ID.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/"
    cp $p/$ID.svg "$APPDIR/usr/share/icons/hicolor/scalable/apps/"
    cp LICENSE "$APPDIR/usr/share/licenses/zombo-razor/LICENSE"
    cp crates/zombo-ui/assets/OFL.txt "$APPDIR/usr/share/licenses/zombo-razor/OFL-Geist.txt"
    cp $p/$ID.desktop $p/$ID.png "$APPDIR/"
    cp $p/$ID.png "$APPDIR/.DirIcon"

    desktop-file-validate "$APPDIR/$ID.desktop"
    appstreamcli validate --no-net "$APPDIR/usr/share/metainfo/$ID.metainfo.xml"
    find "$APPDIR" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

    local out="$DIST/Zombos-Razor-$VERSION-x86_64.AppImage"
    ARCH=x86_64 /tools/appimagetool --appimage-extract-and-run --runtime-file /tools/runtime "$APPDIR" "$out"

    local cli="zombo-$VERSION-x86_64-linux"
    mkdir -p "build/$cli"
    install -m755 "$CARGO_TARGET_DIR/release/zombo" "build/$cli/"
    cp LICENSE "build/$cli/"
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -C build -cf - "$cli" \
        | gzip -9n >"$DIST/$cli.tar.gz"
    rm -rf "build/$cli"

    (cd "$DIST" && sha256sum "$(basename "$out")" "$cli.tar.gz" >SHA256SUMS)
    chown -R "$HOST_UID:$HOST_GID" /src/build
}

if [ "${ZOMBO_IN_CONTAINER:-}" = 1 ]; then
    inside
    exit 0
fi

CONTAINER="${CONTAINER:-$(command -v docker || command -v podman)}"
cd "$ROOT"
VERSION="${VERSION:-$(git describe --tags --always --dirty | sed 's/^v//')}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"

export VERSION SOURCE_DATE_EPOCH
mkdir -p build/tools
fetch() {
    echo "$3  build/tools/$1" | sha256sum -c --status 2>/dev/null || curl -fsSL -o "build/tools/$1" "$2"
    echo "$3  build/tools/$1" | sha256sum -c --quiet
    chmod +x "build/tools/$1"
}
fetch appimagetool "$TOOL_URL" "$TOOL_SHA256"
fetch runtime "$RUNTIME_URL" "$RUNTIME_SHA256"

"$CONTAINER" build -q -t zombo-razor-build -f packaging/Dockerfile.build packaging >/dev/null
START=$SECONDS
"$CONTAINER" run --rm \
    -v "$ROOT:/src" -v "$ROOT/build/tools:/tools:ro" -v zombo-razor-cargo:/opt/cargo/registry \
    -e ZOMBO_IN_CONTAINER=1 -e VERSION -e SOURCE_DATE_EPOCH -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    zombo-razor-build bash packaging/build-appimage.sh
echo "Built in $((SECONDS - START)) s:"
ls -l build/dist
cat build/dist/SHA256SUMS
