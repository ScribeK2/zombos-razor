# Releasing Zombo's Razor

A release is an AppImage, a CLI tarball and a `SHA256SUMS` file. CI builds them when a `v*` tag is pushed. Run the same build locally with one command.

## Build

```
packaging/build-appimage.sh
```

The script needs `docker` or `podman`, `curl` and `git`. It writes `build/dist/`:

- `Zombos-Razor-<version>-x86_64.AppImage` holds `zombo-razor` and `libxkbcommon`.
- `zombo-<version>-x86_64-linux.tar.gz` holds the `zombo` CLI.
- `SHA256SUMS` lists both files.

The build runs in `ubuntu:24.04` (pinned by digest, glibc 2.39). A binary built on a newer glibc fails on Ubuntu 24.04. `VERSION` defaults to `git describe`. `SOURCE_DATE_EPOCH` defaults to the commit time. The script verifies the SHA-256 of `appimagetool` 1.9.1 and `type2-runtime` 20251108 before it uses them. Update the pins in `packaging/build-appimage.sh` to change a tool.

## What is bundled

Only `libxkbcommon.so.0` and `libxkbcommon-x11.so.0`. The Vulkan loader, Mesa and the GPU drivers stay on the host (ADR-0006). The Geist fonts are compiled into the binary. Their licence (OFL 1.1) is in `usr/share/licenses/zombo-razor/` and in the AppStream metadata.

## The runtime needs `fuse3` only

`type2-runtime` 20251108 links libfuse3 statically and calls `fusermount3`. The `fuse3` package is enough, and `libfuse2` is not needed. Without FUSE, run `./Zombos-Razor-<version>-x86_64.AppImage --appimage-extract-and-run`. The text appears in `--help`.

## Smoke test

```
packaging/smoke.sh build/dist/Zombos-Razor-<version>-x86_64.AppImage
UBUNTU=26.04 packaging/smoke.sh build/dist/Zombos-Razor-<version>-x86_64.AppImage
```

The test runs the AppImage in a clean Ubuntu container under Xvfb with llvmpipe. It mounts the AppImage through FUSE (`/dev/fuse`, `SYS_ADMIN`). Set `SMOKE_FUSE=0` to use extract-and-run instead. It checks four things:

1. The app is still running after 8 s.
2. The log has no startup failure.
3. With no display, the app exits with the graceful-failure message.
4. `--help` shows the `--appimage-extract-and-run` fallback.

It prints the time to first render. That time stops at the first render call, not at the first presented frame.

## Release flow

1. Tag the commit: `git tag v1.2.3 && git push origin v1.2.3`.
2. `.github/workflows/release.yml` builds, checks the 40 MB size budget, runs the smoke test on Ubuntu 24.04 and 26.04, signs `SHA256SUMS`, and creates a draft GitHub release.
3. Open the draft, read the notes, and publish it.

The signing step is a placeholder. It fails the job when the `MINISIGN_SECRET_KEY` secret is missing, so an unsigned release is never drafted. The minisign worker replaces the `TODO` in that step.

## Compatibility

The AppImage targets Ubuntu 24.04 and newer. Arch needs `fuse3` for the mount, or the extract-and-run flag. The host supplies Vulkan and Mesa on every distribution.


## Before the first real release: the signing key

The app embeds a TEST update key (`crates/zombo-core/update_key.pub`). A release build that still holds it never contacts GitHub, shows no update prompt, and the settings pane says "Updates are not available in this build". To enable updates:

1. Install minisign and run `minisign -G -p update_key.pub -s zombo-update.key`. Set a password. Never commit the secret key.
2. Replace the whole contents of `crates/zombo-core/update_key.pub` with the new two-line public key and commit it.
3. Delete the two tests that pin the test key: `the_embedded_key_is_the_one_the_tests_sign_with_until_the_real_key_replaces_it` in `crates/zombo-core/tests/update.rs` and `updates_are_unavailable_in_a_release_build_that_embeds_the_test_key`.
4. Add the repository secrets `MINISIGN_SECRET_KEY` (the key file contents) and its password.
5. In `.github/workflows/release.yml`, replace the signing `TODO` line: run `sha256sum <name>.AppImage > SHA256SUMS`, then `minisign -S -s <key file> -t "zombo-razor <version>" -m SHA256SUMS` (the trusted comment is exactly `zombo-razor 1.4.0`, no leading `v`), and upload `SHA256SUMS`, `SHA256SUMS.minisig` and the AppImage. Every AppImage name must end in `.AppImage` and appear in `SHA256SUMS`.
6. `RELEASE_REPO` in `crates/zombo-core/src/update.rs` is `ScribeK2/zombos-razor`, the real repository (renamed 2026-11-09).
7. Test once against a real draft release with a debug build and `ZOMBO_UPDATE_BASE` only if you need to; release builds have no such hook.
