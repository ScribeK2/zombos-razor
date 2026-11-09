# Progress

The single list of what is done, what is running, and what is left. Update it in the same commit as the work. `docs/plan.md` explains the why; this file tracks the state.

Last updated: 2026-11-09. Branch: `rewrite`.

## Active now

Three workers running (started 2026-11-09), each in its own worktree:

- [x] **SMTP and TLS extras** merged: SMTP banner and STARTTLS (`smtp/`, `zombo smtp`), CAA (`zombo caa`), OCSP stapling flag. Live from the dev machine: Gmail 587, 465 and 25 all passed. Not seen: a silent firewall on port 25, CAA from a clean network (rerun from the VPS). No MX resolution: a domain target is dialled by name
- [x] **Web follow-ups** merged: `web_redirect_downgrade` warning, `--insecure-origin` (`CertCheck` enum), `website_origin_cert_rejected` and `web_origin_cert_not_verified` findings. Cert-read path covered by the local test only, not live
- [x] **`zombo-ui` slice 1** merged (screenshot reviewed 2026-11-09). Follow-ups: see "UI follow-ups"

**Merge order when workers finish:** review each diff, merge one at a time (A, B, C), resolve the mechanical conflicts in `Cargo.toml`, `lib.rs`, `main.rs`, `tests/common/mod.rs`, run the whole suite plus clippy, `cargo deny check`, then update this file. Live-check each Check from the VPS (clean network).

## Done

- [x] Workers A to G (all six Check batches) reviewed and merged into `rewrite`. 419 tests pass; clippy, `cargo deny` and `cargo audit` clean. Registration, email auth, DNSSEC, evidence, blacklist and rDNS, web inspection are in. 236 tests pass; clippy, `cargo deny` and `cargo audit` clean. Email auth (`email_auth/`, `zombo email`): SPF walker with the 10-lookup count, DKIM, DMARC, TLS-RPT, BIMI, MTA-STS record. MX comes from the lookup inside `email_auth`

- [x] Planning session, ADR-0006 and ADR-0007, `CONTEXT.md` rewritten
- [x] GPUI spike passed (Ubuntu 24.04.5 laptop with Orca, 24.04 and 26.04 containers, AMD, Intel)
- [x] Rust workspace (`zombo-core`, `zombo`), release profile tuned
- [x] Target parser (`target.rs`)
- [x] DNS client: UDP then TCP, EDNS 1232 (`dns.rs`)
- [x] DNS lookup, 8 record types, TTLs, Go-exact record text (`lookup.rs`)
- [x] DNS propagation across 10 public resolvers, streaming, scopes (`propagation.rs`)
- [x] Authoritative Vantage: nameserver discovery, AA-flag trust, stale-cache finding
- [x] SOA serial comparison (behind vs serial not bumped)
- [x] Agreement verdict
- [x] Delegation and glue checks (`delegation.rs`, `zombo delegation`)
- [x] HTTP client chosen: `ureq` 3 with rustls (ring, bundled webpki-roots). Add `CDLA-Permissive-2.0` to `deny.toml`. Reused for the later web and MTA-STS checks
- [x] DNS-interception Finding (`dns_network_intercepts`) and `Agreement::Intercepted`, for propagation and delegation. Passive: at least two nameservers at different addresses all answering without AA but with RA
- [x] Shared zone fixtures in `testdata/zones` for Go and Rust tests
- [x] Verified live from a clean network (VPS) for propagation, stale cache, delegation

## To do: DNS and domain registration

- [ ] Interception canary probe for resolver-only runs (`--no-authoritative`): needs a short extra probe to an address that must never answer, so it is opt-in to keep clean runs fast
- [x] WHOIS/RDAP (`registration.rs`, `zombo registration`): RDAP first with WHOIS fallback, DENIC form, bounded `ureq`+rustls client (merged from worker A). 98 tests pass
- [x] DNSSEC (`dnssec.rs`, `zombo dnssec`, merged from worker C): resolver verdict (CD=0 vs CD=1) plus local DS/DNSKEY/RRSIG analysis. Key tag and DS digest proven on real cloudflare.com and iana.org data. 133 tests pass. Resolver verdicts NOT yet seen live from a clean network (do it from the VPS). Full chain-to-root validation is deliberately out of scope: validating resolvers do that, and the CD trick plus DS/DNSKEY/RRSIG analysis explains failures
- [ ] More record types in lookup (SRV, PTR, DNSKEY, DS) if needed by the UI

## To do: email

Go sources to port: `email_auth.go`, `blacklist.go`, `headers.go`, `maillog.go`.

- [x] MX
- [x] SPF with the 10-lookup count
- [x] DKIM by selector
- [x] DMARC
- [x] MTA-STS, TLS-RPT, BIMI: DNS records only. The MTA-STS policy file over HTTPS is not fetched yet (the HTTP client from `registration` can do it)
- [ ] SMTP banner and STARTTLS test
- [x] Blacklist lookup (`blacklist.rs`, `zombo blacklist`): Go zones, system resolver (not public ones), 127.255.255.x refusal handling, bounded
- [x] Reverse DNS and forward-confirmed reverse DNS (`rdns.rs`, `zombo rdns`)
- [ ] SMTP banner and STARTTLS test (new; unblocked now that `tls::inspect_stream` exists)
- [x] Header analysis (Evidence) (`evidence/headers.rs`, `zombo evidence headers`)
- [x] Mail-log analysis (Evidence) (`evidence/maillog.rs`, `zombo evidence maillog`)

## To do: hosting and web

Go sources to port: `website.go`, `origin.go`, `ssl.go`, `hosting.go`.

- [x] HTTP redirect chain, headers, status (`web/`, `zombo web`)
- [x] Origin versus CDN comparison (`--origin IP`; new, the Go `origin.go` was a UI guard)
- [x] Certificate and chain (`tls.rs`, `zombo tls`): trust states, expiry, SAN match, incomplete chain, weak key, SHA-1, not-yet-valid; rustls + ring, a permissive verifier with its own trust judgement. Reusable `inspect_stream` seam for STARTTLS
- [ ] TLS extras not in the Go code and not yet built: CAA check, OCSP stapling, HSTS preload view (HSTS header is already reported by `web`). TLS 1.0/1.1-only servers cannot be detected (rustls speaks 1.2 and 1.3 only): report 'handshake refused' with a hint
- [x] CDN and ASN detection (headers, CNAME chain, Team Cymru DNS)
- [x] TCP port connect test (`ports.rs`, `zombo ports`): Go service table, quick and full sweeps, banners, bounded

## To do: the app

- [ ] `zombo-ui` crate on `gpui-kit` (pinned snapshot, ADR-0007)
- [ ] One box (Diagnosis): all relevant Checks in parallel, results streaming
- [ ] Command palette for single Checks
- [ ] Watch (re-run until the answer changes)
- [x] `DESIGN.md` written (layout, Checks per target kind, states, Evidence, copy, history, Watch, keyboard, settings, accessibility, motion, type scale, spacing, initial dark palette with contrast checked)
- [ ] Design foundation in code: tokens, LCH theme derivation, fonts, 6/12 px radii
- [ ] Table cell labels for screen readers on every result view
- [ ] Tabs, rail with five Check states, status bar with Watches, empty state with recent targets
- [ ] Copy at three levels (value, section, Diagnosis) in Markdown, plus JSON per section
- [x] Evidence paste tabs (merged 2026-11-09, 612 tests); [x] settings pane (merged 2026-11-09: file, validation, recents, Watch notification; 588 tests)
- [x] Main screen sketch: `docs/sketches/main-screen.html` (+ PNG). Built as HTML, not Pencil: the Pencil tool needs the Cursor IDE running with its extension. Shows the stale-cache case on the test domain
- [ ] Window title and app ID set; clear error when the compositor has no `wl_seat`
- [ ] Recent-lookups list (no Cases)

## To do: security, quality, release

- [x] CI workflow `.github/workflows/rust.yml` (test, clippy `-D warnings`, `cargo deny`, `cargo audit`) and `deny.toml`; `cargo deny check` and `cargo audit` pass locally. Not yet run on GitHub (no remote yet)
- [ ] After the workers merge: `#![forbid(unsafe_code)]` via `[workspace.lints]`, then `cargo fmt` and a rustfmt CI check
- [ ] Fuzz tests for every parser of untrusted input (DNS messages, RDAP/WHOIS, headers, mail logs, certificates)
- [ ] Performance gates in CI: parser speed, AppImage size under 40 MB, llvmpipe render in a headless compositor
- [ ] Measure cold start, scroll frame rate, idle memory on a real laptop and record them
- [ ] AppImage build for `zombo` and the CLI from an Ubuntu 24.04 container; launch test on clean Ubuntu and Arch
- [ ] Signed releases (minisign) and updater (keep today's flow, verify signature first)
- [ ] Replace `packaging/smoke.sh` with a headless-compositor launch test

## To do: transition

- [ ] Parity: every Go Check passes its Go fixtures in Rust
- [ ] Last Go release with export-to-Markdown for old Cases
- [ ] Delete the Go code and the web UI
- [ ] Name-clash check for "Zombo's Razor", then rename the repo and app strings
- [ ] Open the PR for `spike/gpui` and `rewrite`

## Later, not scheduled

- [ ] Opt-in outside check for "down for everyone" (verify RIPE Atlas and probe-API limits first)
- [ ] Full TLS configuration scan (level 2, needs a custom TLS probe)
- [ ] Unprivileged traceroute
- [ ] Light theme, aarch64

## Decisions waiting

- [x] Fixed after a live run from the VPS: probing only mail ports with no answer no longer says CRITICAL "Host unreachable" (outbound SMTP is blocked by many networks); it is now an info finding `hosting_reachability_mail_filtered`

- [x] **Proxy policy (decided 2026-11-09, lead's call): keep both, and say so.** Registration (a lookup of public registry data) honours `HTTP_PROXY`/`HTTPS_PROXY`, so it works on corporate networks. The web Check ignores them, because it must show what the site does from this machine, not what a proxy relays. The settings pane and the web section state the rule. The proxy setting in DESIGN.md applies to registration only
- [x] **Web User-Agent (decided): keep `zombo/<version>`.** A 403 from a WAF is itself a finding about the site
- [ ] **Web cookies:** no cookie jar (Go kept cookies across hops), so a cookie-dependent redirect reads as a loop. Not decided: the answer "Yes" was read as applying to the downgrade finding. Ask again if a real site shows the loop
- [ ] **Web follows https to http downgrades** on redirect. Done: kept following, flagged as a warning
- [ ] **`--insecure-origin`** done
- [ ] **`rdns` for a host** lists addresses only, without PTR confirmation per address; add it if the Diagnosis wants it

- [ ] Refactor: DNSSEC has its own zone discovery (`find_zone`, asks with DO and CD set) because `find_apex` asks with CD=0 and a validating bootstrap resolver SERVFAILs on exactly the broken zones. Give `find_apex` the CD flag and delete the duplicate
- [ ] DNSSEC expiry warning is `min(3 days, lifetime / 4)`, not a flat 3 days (Cloudflare signs for about 2 days). Accepted as a deliberate deviation; unsigned-yet (not-before) signatures have no finding
- [ ] Email: the SPF walk is breadth-first with a 30-lookup cap, so which subtree is cut when the cap bites can differ from Go
- [x] `Finding.title` and `Finding.recommendation` are `Cow<'static, str>`: Go's " (Registrar)" suffix is back in three registration recommendations, and "DMARC applies to N% of mail" has its Go title again
- [ ] ureq honours `HTTP_PROXY`/`HTTPS_PROXY`; keep (corporate networks) or turn off

## Live-verified from a clean network (VPS, 2026-11-09)

- [x] `dnssec`: cloudflare.com SECURE on all 4 validating resolvers, DS matches; dnssec-failed.org BOGUS on all 4 with `dnssec_ds_mismatch` (DS tag 42069 vs served key 50719)
- [x] `registration`: registered and not-registered domains over RDAP
- [x] `email`: google.com, github.com, etsy.com (11 lookups), the test domain
- [x] Earlier: propagation, stale cache, delegation
- [x] `blacklist` (127.0.0.2 test entries, clean domain, public-resolver run), `rdns` (incl. generated PTR name detection), `tls` (valid, expired, self-signed), `ports`, `web` (HSTS, headers, ASN) from the VPS
- [ ] Not seen live: a Spamhaus 'refused' answer (Spamhaus answered normally through 8.8.8.8 today); web `--origin` against a real origin that differs from its CDN
- [ ] UI note: the `dnssec` nameserver list repeats identical lines per address; collapse identical rows in the UI

## Network egress (what the app contacts), to document in `docs/network-egress.md`

- [x] Written: `docs/network-egress.md` (the target's own servers; the resolvers (public list, system resolver, nameservers found by discovery); RDAP bootstrap bases and registry WHOIS servers (port 43); Team Cymru DNS (`*.asn.cymru.com`); the DNSBL zones in the blacklist table; the release endpoint for updates. Nothing else, no telemetry)

## Next batch (not started)

- [ ] SMTP banner and STARTTLS (worker): connect to MX hosts on port 25 (and 587), read the banner, EHLO, STARTTLS, then `tls::inspect_stream`. Many networks block outbound 25: report 'filtered' honestly. Needs the VPS to verify
- [ ] TLS extras: CAA, OCSP stapling (worker, small)
- [x] `docs/network-egress.md` written
- [x] Merged worker worktrees and branches removed (12 GB freed); stray test key directory deleted

## Still unverified

- [ ] NVIDIA GPUs
- [ ] The AppImage without `libfuse2` on real hardware (the work laptop has `libfuse2t64` installed)
- [ ] Broken-delegation paths against a real broken domain (fakes only so far)
- [ ] Web: origin comparison against a real CDN whose origin differs; the HTTPS success path is covered only live, not offline (no TLS fake server yet)
- [ ] Blacklist: a real Spamhaus refusal when queried through a public resolver (this network cannot show it); rerun from the VPS with and without `--resolver 8.8.8.8`
- [ ] Registration: a real https redirect chain and the proxy path are untested; `.ru`/`.it` referral seen live only via IANA
- [ ] Scroll frame rate

## UI follow-ups (from slice 1)

- [ ] Verdict chips clip at 1280 px ("ok" chip cut off); recheck after the `min_w_0` fix
- [ ] Geist weights 500 and 600 do not render (variable font axis ignored by GPUI): bundle static weight files
- [ ] Answer column shows every record type in one line; sketch shows one type per column
- [ ] Not built: On-demand rail group, Watch button and status line, collapsed data rows, "changed since previous run", window shadow and resize handle, motion
- [ ] `Ctrl+9` mapped but the rail has 8 sections
- [x] (done) `cargo deny`: allow `0BSD` (enum-iterator); ignore advisories for unmaintained `instant`, `paste`, `rustybuzz`, `ttf-parser`, `zbus_names`, `zvariant`, `zvariant_derive`, `rustls-pemfile` (each with a reason)
- [x] (done, untested on GitHub) CI: apt `-dev` packages for GPUI builds (take the list from `spike/Dockerfile.build`)
- [ ] Unverified: X11, GNOME, Retry, timeout and failed paths live, screen reader output, full tab order

## Location

The project moved to `/mnt/steamssd/Projects/zombos-razor` (ext4, NVMe) on 2026-11-09 because the old NTFS hard disk made builds take hours. The full workspace test now takes under 2 minutes. 501 tests pass; clippy, `cargo deny` and `cargo audit` clean.

## UI slice 2 (merged 2026-11-09)

- [x] Record-type switcher (`[` and `]`), verdict row wraps, static Geist weights, all Checks wired with five states and Retry, On demand rail group (not runnable from the app yet), Watch (`W`, 60 s interval, 8 s toast, no desktop notification until settings exist), "Changed since the previous run", Summary dedupes shared findings. 538 tests pass
- [x] Summary repeat: was 2 copies after slice 2 (dedupe compared exact text); fixed by code for network-wide findings. Not yet re-seen live
- [x] On demand Checks runnable from the app (port scan, SMTP, blacklist; merged). Never watched. 550 tests pass. Seen live: port scan, SMTP via palette, blacklist. Not seen: Enter on a focused pane, a real silent port 25
- [ ] Not built: rail count lines ("done, 1 note"), per-finding action buttons, nameserver answers and All records collapsed rows, window shadow and resize handle, CAA in the TLS section, SOA and CAA record types in the switcher (core never asks them across resolvers)
- [ ] Docs to update: Ctrl+9 goes to On demand; keys `W`, `[`, `]`; rail width 248 px
- [ ] Unverified: X11, GNOME, screen reader, Retry after a real failure, a real record change stopping a Watch

## Open from the on-demand slice

- [ ] SMTP on a domain dials the name on port 25 with no MX lookup; `Resolver::mx_hosts` is in a private module. Expose it and resolve MX first. Add a port field
- [ ] Collapse the description card above the results once a result exists
- [ ] The blacklist facts key column (200 px) wraps long names
- [ ] TLS on a port for an IP target (DESIGN.md says later)

- [ ] Settings unverified: a real Watch-stop desktop notification, a real proxied registration, keyboard-only checkbox toggle. Deviation to confirm: Save over a broken config copies it to `config.toml.bak` instead of refusing

## Open from Evidence tabs

- [ ] **Misleading rail mark:** Message path and Authentication always show a green check with "done", even when the Authentication verdict is Failed (the spoofed fixture shows it). Only Findings carries the problem count. Carry the verdict to the rail mark
- [ ] Core parses no ARC headers, so Authentication shows Authentication-Results, Received-SPF, DKIM-Signature and alignment only
- [ ] Copy exists only on Evidence tabs; Diagnosis copy (value, section, whole) is unbuilt
- [ ] No way back to edit pasted text after a successful analysis (open a new tab)
- [ ] Tab times are UTC (local time is not safe to read in a threaded process)
- [ ] Unverified: a pasted `message/rfc822` clipboard from a real mail client, a real hostile paste live, X11, GNOME, screen reader

## UI polish (merged 2026-11-09, 686 tests pass)

- [x] Honest rail marks (Evidence and Diagnosis, notes use the info glyph), rail count lines, per-finding section buttons, collapsed Nameserver answers and All records rows, Diagnosis copy (value, section, whole, section JSON on Ctrl+Shift+J), SMTP resolves MX first with a port field, on-demand pane card collapse and Enter focus, key column sizing, CAA in TLS, window frame with shadow and resize strips (only where the compositor does not draw one), motion with the system animation switch
- [ ] Rail captions ("done · 3 problems", "no received headers") truncate a little in the 132 px caption
- [ ] Remaining differences from the sketch: no Watch button on Summary, no live "Watching" status line unless a Watch exists, tab height and strip border, propagation table has a type switcher and header summary "TXT · 2 of 10 differ" is missing, DNSSEC rail label ("not signed") is a count line here
- [ ] Unverified: client-decorated frame on GNOME or KDE, resize drags, motion visually and with animations off, failed-MX fallback, 465 implicit TLS, the lowest MX silent and a later one answering, keyboard-only tab order

## Release work (2026-11-09)

- [x] AppImage packaging merged: `packaging/build-appimage.sh` (Ubuntu 24.04 container, pinned appimagetool and runtime, reproducible), `packaging/smoke.sh`, `.github/workflows/release.yml` (draft release on a `v*` tag; signing step is a placeholder that fails until the minisign step lands), `docs/release.md`. AppImage 17.3 MB, CLI tarball 3.7 MB, smoke test passes on Ubuntu 24.04.5 and 26.04.1 with `fuse3` only. First render 219 ms and 233 ms
- [x] Fixed: no display variable at all made the app run forever with no window; it now exits 1 with a message (`session.rs`)
- [ ] Not verified: the AppImage on a stock Arch install without `fuse3` (fallback is `--appimage-extract-and-run`), the FUSE mount path in CI (CI smoke uses extract-and-run), the release workflow itself, a from-scratch build on a second machine
- [ ] Local builds take their version from `git describe`, which finds the old Go tag `v1.0.0`; tag the Rust release or set VERSION
- [ ] Metainfo homepage URL still says ScribeK2/Stackwell; change with the rename
- [x] Signed self-update merged (727 tests): minisign-verify, trusted comment bound to the version (no downgrade replay), SHA256SUMS then AppImage hash, bounded https, atomic replace, prompt card, `update.toml`. Fails closed on the test key in release builds, with four guards (background_check, check_in, install_in, UpdateCard::install). Live-checked in a debug build only
- [ ] Owner: create the real key and secret, fill the release.yml signing line, set RELEASE_REPO (steps in docs/release.md). Delete the two tests that pin the test key
- [ ] Not verified: a real GitHub endpoint, a real `minisign` binary reading our signatures, the update card's refusal in a release binary seen live
- [x] Hardening merged (746 tests): `unsafe_code = "forbid"` and deny of `unwrap`, `expect`, indexing and `panic` in production code of both crates (the update code was brought under the lints in the merge), 12 fuzz targets in `fuzz/` (about 280 s each, no crash or hang found), `tests/hostile.rs` and `tests/fuzz_regressions.rs` always run, weekly `fuzz.yml`. Found and fixed: control characters from WHOIS and RDAP reaching findings, a debug-only key tag overflow
- [x] Test that all 10 propagation and 4 DNSSEC resolver addresses parse (the tables now drop a bad literal instead of panicking)
- [ ] In progress: one shared `zombo_core::text` cleaner that also strips bidirectional and zero-width characters (U+202E and similar passed `is_control`), replacing about a dozen local helpers, plus a structure test that bans new `.is_control()` calls
- [ ] Fuzz gaps: CAA rdata, propagation text parse and blacklist beyond the DNS path, OCSP content (not checked by design); ASAN runs failed to build `gpui-pre` so runs were coverage only; `fuzz/rust-toolchain.toml` untested without rustup
- [ ] The fuzz and release workflows have never run on GitHub (no remote yet)
- [x] Text policy merged (766 tests): `zombo_core::text` strips controls, bidirectional and zero-width characters (ZWJ kept); five local helpers deleted; `text_policy` tests ban new `.is_control()`. Weak: the redirect `Location` test passed under mutation, no web page title test
- [x] First test AppImage built from `rewrite` (`VERSION=0.1.0-test`, 17.3 MB, SHA256SUMS verified), smoke passes on Ubuntu 24.04.5 and 26.04.1 with FUSE mount: first render 231 ms and 240 ms under llvmpipe, graceful message with a dead display and with no display variable
- [x] Work laptop (Ubuntu, 2026-11-09): the test AppImage `0.1.0-test` runs and everything worked without issue (user report). No numbers recorded for cold start, scroll or memory; NVIDIA still untested

## Go code removed (2026-11-09, user decision)

- [x] No last Go release. `cmd/`, `internal/`, `web/`, `go.mod`, `go.sum` and the Go CI workflow deleted from `rewrite`; the Go source stays in git history at `main` (tip `b8fc3d5`) and the tag `v1.0.0`. 766 tests still pass. `testdata/` stays (the Rust tests read it)
- [ ] Parity audit running (`docs/parity.md`); its scripts read Go from `main`
