# Rewrite in Rust with GPUI, gated on a spike

Status: **accepted** (2026-11-09). The spike passed on a real Ubuntu 24.04.5 work laptop (GNOME Wayland, Intel Alder Lake-P graphics), with Orca, and in Ubuntu 24.04 and 26.04 containers. This supersedes ADR-0001 and ADR-0005. See `docs/spike-results.md`. Not yet covered: NVIDIA GPUs. Re-run `spike/team-test.sh` on such hardware when it is available.

Zombo's Razor becomes a native Linux app: a Rust workspace with `zombo-core` (all Checks, no UI, also a CLI) and `zombo-ui` (GPUI). It ships as an AppImage. The Go engine and its tests stay in the repo as the behaviour oracle until each Check passes its Go fixtures in Rust, then the Go code is deleted.

## The spike

One day, before any rewrite. Build a GPUI hello-window as an AppImage and launch it on:

1. A real team laptop (not only a VM), on Ubuntu stable.
2. Ubuntu 24.04, 26.04 and 26.10, and Arch.
3. Wayland and X11 sessions.
4. One VM with no GPU (llvmpipe fallback).

Also check that Orca reads the window through AT-SPI, and test the component library's text input, tables and theming (ADR-0007).

## If the spike fails

Keep the Go engine and the Svelte UI (ADR-0001 stays in force). The project shrinks to three jobs: drop casework, add multi-resolver propagation, and rename. Scope, catalog, UI shape, security and design decisions do not change.

## Considered Options

- **Keep Go and the browser UI**: works today, but the team wants a native, faster, more polished app.
- **Go engine as a sidecar behind GPUI**: adds IPC and a second runtime to secure. Rejected.
- **cgo into GPUI**: breaks the static binary. Rejected.
- **Tauri / Wails / Electron**: rejected in ADR-0001; the reasons still hold.

## Consequences

GPUI needs a working Vulkan or GL driver on the host; the Vulkan loader, drivers and Mesa stay on the host and are not bundled. GPUI is pre-1.0 and breaks its API often. Rebuilding the DNS, RDAP, TLS and email parsers in Rust is the main cost. With no localhost server, the attack surface that ADR-0005 defended disappears.
