# Pin one GPUI snapshot through gpui-kit (proposed)

Status: **proposed**, gated on the spike in ADR-0006.

We depend on `gpui-kit` (formerly `gpui-component`) at one exact version, with its `gpui-pre` snapshot crates pinned exactly (`=0.3.12` at 0.9.1) and `Cargo.lock` committed. `gpui-kit` takes GPUI from these crates.io snapshots, not from a Zed git commit, so no git dependency or vendored Zed checkout is needed. We upgrade on purpose, about once a quarter, move `gpui-kit` and the snapshot crates together, and fix the breakage each time. The old `gpui` crate on crates.io (0.2.2) is not used: it predates the wgpu renderer.

The first spike run confirmed that `gpui-kit` 0.9.1 builds and opens a window on Wayland and X11. Whether it is good enough (text input, tables, theming) is still decided in the spike. If not, we hand-build widgets on `gpui-pre`.

## Considered Options

- **Track Zed's main branch**: newest fixes, but breaks often.
- **Use crates.io `gpui` 0.2.2**: stable, but the old renderer.

## Consequences

Upgrades are a planned task, not a surprise. Vendoring adds repository size. The pinned commit and the chosen widget library are recorded in this file once the spike ends.
