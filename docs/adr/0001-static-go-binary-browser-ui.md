# Static Go binary serving a browser UI, not a native-window shell

Stackwell ships as a single static Go binary (no cgo) inside an AppImage. It serves its UI on localhost and opens it in Chromium `--app=` mode when available, falling back to the default browser. Arch (rolling) and Ubuntu 22.04+ x86_64 are the targets.

## Considered Options

- **Tauri / Wails (system WebKitGTK)**: bundled WebKit and Mesa break against rolling-distro GPU stacks (blank windows, EGL_BAD_PARAMETER on Arch). Rejected.
- **Electron**: reliable bundled Chromium and AppImage auto-update, but about 100 MB, and Ubuntu 24.04+ AppArmor needs a `--no-sandbox` workaround. Rejected; revisit only if owning a native window becomes a requirement.
- **Keep Ruby/Rails (ToolHarness)**: relocating a Ruby runtime into an AppImage was the main source of build and launch bugs. Rejected.

## Consequences

The app still has to handle port selection, single-instance and opening the browser, but in Go code rather than AppRun shell.

## Status

Superseded by [ADR-0006](0006-rust-gpui-rewrite-gated-on-spike.md).
