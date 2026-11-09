# Zombo's Razor: design

Decided in a grilling session on 2026-11-09. Terms are in `CONTEXT.md`. Where a number is marked "initial", tune it in the first UI build and update this file.

## Principles

1. **The verdict first.** A rep opens the app to learn what is wrong, so every screen leads with a conclusion and puts the data under it.
2. **Fast means instant.** The window is usable within 300 ms. Results stream in as each Check answers. Nothing waits for the slowest resolver.
3. **Keyboard first, mouse welcome.** Every action has a key and a palette entry.
4. **Quiet.** Structure is felt, not seen: few separators, soft borders, one restrained accent. Color marks status, never decoration.
5. **Honest.** A Check that was never run says "not run". A failed Check says why. Nothing looks like a pass by default.
6. **Nothing stored.** No accounts, no telemetry, no results on disk (ADR-0004).

## Structure

- **Window.** A custom slim title bar that holds the omnibox. Standard minimize, maximize and close buttons, in the system's usual place. Content is always dark. If a compositor mishandles the custom bar, fall back to the system title bar with the omnibox below it.
- **Tabs.** One tab per target, like a browser. Each tab keeps its Diagnosis in memory. Closing a tab drops its results.
- **Main layout.** Omnibox on top. A narrow left rail lists the sections with a status mark. The right pane shows the selected section. A status bar at the bottom shows active Watches.
- **Rail sections.** Summary, DNS, Delegation, DNSSEC, Email, Web, TLS, Registration. Evidence tabs have their own sections (message path, authentication, findings).
- **Section pane.** Verdict line, then findings, then the raw data. Short data stays open. Long data (DNSSEC key list, SPF tree, full header list) is collapsed.
- **Summary.** The Agreement verdict, then counts of critical, warning and ok findings across sections.

## Checks per target kind

| Target | Automatic | On demand (palette) |
|---|---|---|
| Domain | DNS and propagation, delegation, DNSSEC, registration, email authentication, web, TLS | port scan, SMTP banner and STARTTLS, blacklist |
| Hostname | DNS and propagation, web, TLS (registration uses the registrable domain) | port scan, SMTP banner and STARTTLS |
| IP address | reverse DNS, blacklist | port scan, TLS on a port |
| Email address | the domain Checks for its domain part | as for a domain |

On-demand Checks show as "not run" in the rail until asked. They connect to the target's servers, or send many queries, so they never start on their own.

## Check states

Each rail item has one of five states, always with a text label and never color alone: **running**, **done** (with a count of problems), **failed** (with a short reason), **timed out**, **not run**. Results stream into the section as they arrive. A failed or timed-out Check shows its reason and a Retry button, and never blocks another section. Findings appear with the section's first result.

## Evidence

A palette command opens a paste pane: "Analyse pasted headers" or "Analyse pasted mail log". The tab becomes an Evidence tab. The app sniffs the pasted text and suggests which kind it is. Pasted text stays in memory and is never written to disk.

## Copy

Three levels: a single value (click any record or address), a section, the whole Diagnosis. Default format is Markdown, which stays readable as plain text. The section menu also offers JSON. Values are monospace.

## History and change

Disk holds only the target name and the time, for the recent list. Inside a session, re-running a Check shows what changed since the previous run in that tab (records added or removed). Results are never kept across restarts.

## Watch

A Watch button on any result. Active Watches show in the status bar (target, Check, last run). A Watch stops itself when the answer changes and tells the rep with a desktop notification and an in-app toast. Notifications are optional: the app works without them where the desktop has no notification service.

## Empty state

The omnibox, focused, with the placeholder "domain, host, IP or email". Below it: the last 8 recent targets (name and relative time), selectable with the arrow keys, and four lines of key hints. No tutorial and no splash. It is interactive inside the 300 ms start budget.

## Keyboard

| Keys | Action |
|---|---|
| `Ctrl+L` | Focus the omnibox |
| `Enter` | Run the Diagnosis |
| `Ctrl+K` | Command palette |
| `Ctrl+R` | Re-run the current section's Check |
| `Ctrl+1` to `9` | Jump to a rail section |
| `Alt+Up`, `Alt+Down` | Previous or next section |
| `J`, `K` or arrows | Move through findings and rows |
| `Ctrl+C` | Copy the focused value |
| `Ctrl+Shift+C` | Copy the section as Markdown |
| `Ctrl+Alt+C` | Copy the whole Diagnosis |
| `Ctrl+T`, `Ctrl+W`, `Ctrl+Tab` | New tab, close tab, next tab |
| `W` | Watch the focused result |
| `?` | Shortcut cheat sheet |

Every action also appears in the palette with its shortcut shown.

## Settings

A small TOML file, and a settings pane that edits only these: extra resolvers for propagation, extra DKIM selectors, per-Check timeout, HTTP proxy (default: honour the environment), and whether Watch sends desktop notifications. No accounts, no sync, no themes, no telemetry switch.

## Accessibility

1. Every status has a text label.
2. Text contrast at least 4.5:1; large text and icons at least 3:1.
3. A visible focus ring on every focusable element.
4. Every table cell and finding has a screen-reader label (`TableDelegate::cell_label`).
5. All motion is off when the system's animation setting is off.
6. Everything works with the keyboard alone.

Later: automated checks in CI for rules 2 and 4.

## Motion

Carried over from the Go app's polish pass. The palette opens instantly. Hover and press feedback take 80 ms. A toast rises and fades in 150 ms and leaves in 120 ms. Results fade in over 100 ms. Nothing animates longer than 200 ms. Motion never delays an action: the result is usable at once.

## Visual foundation

- **Fonts.** Geist Sans for text, Geist Mono for every DNS record, IP address, header and other copyable data. Both bundled under the SIL OFL 1.1 with the license text; never modified.
- **Color.** Dark. Geist-style semantic scales of 10 steps: 100 to 300 backgrounds (default, hover, active), 400 to 600 borders, 700 and 800 high-contrast fills, 900 and 1000 text. The theme is derived in the LCH color space from three inputs: base, accent, contrast. The accent is restrained (one blue, used for focus and selection only).
- **Status colors.** Ok green, info blue, warning amber, critical red. Always with a text label and an icon shape that differs by status.
- **Radii.** 6 px for small surfaces, 12 px for larger surfaces, menus and dialogs.
- **Borders.** 1 px, low contrast. Prefer spacing and background steps over separators.
- **Spacing.** A 4 px grid: 4, 8, 12, 16, 24, 32. Pane padding 16. Gap between findings 8.
- **Density.** Table and list rows 28 px. Rail items 32 px. Omnibox 36 px. Title bar 40 px. Hit targets at least 28 px.
- **Type scale** (initial). Caption 12/16, label 13/18, body 14/20, subtitle 16/24, title 20/28, verdict 28/36. Weights 400, 500, 600. Monospace data 13/18.

### Initial dark palette (tune in the first build)

| Token | Value | Use |
|---|---|---|
| `bg-100` | `#0B0B0C` | window and pane background |
| `bg-200` | `#111113` | rail and status bar |
| `gray-100` | `#17171A` | raised surface |
| `gray-200` | `#1D1D21` | hover |
| `gray-300` | `#25252A` | active |
| `gray-400` | `#2E2E34` | border |
| `gray-500` | `#3A3A41` | hover border |
| `gray-600` | `#6B6B74` | input and control boundaries (3.4:1 or more on any surface) |
| `gray-900` | `#A1A1AA` | secondary text |
| `gray-1000` | `#EDEDEF` | primary text |
| `accent` | `#5B8DEF` | focus ring and selection |
| `ok` | `#3FB27F` | status |
| `info` | `#5B8DEF` | status |
| `warning` | `#E5A93D` | status |
| `critical` | `#F06A6E` | status (text on every background step reaches 5:1 or more) |

## Not in the app

Cases, ticket references, a Write-up, accounts, sync, telemetry, screenshots of pages, light theme (later, from the same inputs), a settings sprawl.

## Open

- A sketch of the main screen (Pencil) before the first UI code, if wanted.
- Contrast of the initial palette is checked: text and status colors reach 4.5:1 or more on every background step (`critical` was raised from `#E5484D`, which failed on the hover and active steps), and `gray-600` gives control boundaries 3:1 or more. Re-run the check whenever a token changes.
- How the rail behaves on a narrow window (collapse to icons at under 720 px, initial).
