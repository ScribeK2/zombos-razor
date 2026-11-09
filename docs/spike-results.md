# GPUI spike: results so far

Spike code: `spike/gpui-hello` (a hello window and a widget demo, built on `gpui-kit` 0.9.1). Container recipes: `spike/Dockerfile.build` (Ubuntu 24.04 build) and `spike/Dockerfile.run` (runtime images). The AppImage is `spike/dist/zombo-spike-x86_64.AppImage`. A teammate runs it with `spike/team-test.sh`.

Verdict: **passed.** Everything tested passes, including a real Ubuntu work laptop with Orca (tester report, 2026-11-09: opened the AppImage, tabbed through the widgets, typed in the input, scrolled the table fast, closed the window, and passed every Orca step). The laptop's Ubuntu version and GPU were not recorded. Intel and NVIDIA are still unconfirmed.

## Passed

| Test | Result |
|---|---|
| Arch, Hyprland (Wayland), AMD RX 9070 XT, Mesa 26.2.5 | Opens, renders, click reaches the handler. |
| Same machine, X11 through Xwayland | Opens at the same size. |
| Build in an Ubuntu 24.04 container (glibc 2.39) | Passes in 2 min 19 s. |
| Ubuntu 24.04 and 26.04 userland, host Wayland socket and GPU | Both open a native Wayland window. |
| Ubuntu 24.04 and 26.04, no GPU (llvmpipe), Xvfb | Both run 8 s with no crash. The 24.04 screenshot shows correct rendering. |
| AppImage runs with `fuse3` installed and no `libfuse2` | Mounts and starts the app on 24.04 and 26.04. |
| Widget demo: input, 100,000-row table, Geist Sans and Geist Mono | Renders correctly. The table has no visible cost at this size. |
| First render, 3 runs each | Hello 113 to 125 ms. Widgets 115 to 121 ms. One cold run took 1.65 s. |

## Packaging: no extra dependencies on stock Ubuntu

1. **Every runtime library is in a stock Ubuntu desktop.** I checked `ubuntu-desktop-minimal` on 24.04 and 26.04. It pulls in `libxkbcommon0`, `libxkbcommon-x11-0`, `libxcb1`, `libwayland-client0`, `libfontconfig1`, `libfreetype6`, `libvulkan1`, `mesa-vulkan-drivers`, `libgl1`, `libegl1` and `libx11-6`.
2. **The AppImage runtime needs `fuse3`, not `libfuse2`.** `ubuntu-desktop-minimal` pulls in `fuse3` on both releases. `libfuse2` is not installed and not needed.
3. **The AppImage bundles only `libxkbcommon`.** The Vulkan loader, Mesa and the GPU drivers must stay on the host, so the AppImage is small. It is 29 MB with both demo binaries and the fonts, under the 40 MB budget.
4. **Build on Ubuntu 24.04.** The Arch-built binary needs glibc 2.44 and fails on both Ubuntu releases. The 24.04 build runs on 26.04 too.
5. **Fallback if FUSE is missing:** `./app.AppImage --appimage-extract-and-run` needs no FUSE.

## Findings that change the plan

1. **GPUI comes from crates.io.** `gpui-kit` pins GPUI through exact `gpui-pre` snapshot crates, not a Zed git commit. ADR-0007 is updated. `gpui-component` is the old name of `gpui-kit`.
2. **The raw binary is large.** It is 53 MB, or 39 MB stripped. The AppImage compresses it, so the 40 MB budget applies to the AppImage and holds.
3. **No input seat means a panic.** On a Wayland compositor with no `wl_seat`, GPUI panics. Real desktops have a seat. The app should catch this and print a clear error.
4. **The window has no title and no app ID.** We must set both.
5. **Default table columns truncate text.** Column widths need theming work.
6. **The table can describe cells to a screen reader.** `TableDelegate::cell_label` exists, and plain text is otherwise invisible to assistive technology. Every Check result view must provide labels.
7. **The first-render timing stops at the first render call.** It is not the first presented frame.

## Not tested, so the spike cannot pass yet

- **Intel and NVIDIA GPUs.** Unconfirmed; the work laptop GPU was not recorded.
- **Wayland with no GPU.** Headless Weston has no input seat, so that run proved nothing.
- **Scroll frame rate.** Not measured.
- **The AppImage on a machine with Ubuntu's AppArmor settings.** Not tested.
