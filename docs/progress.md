# Progress

The single list of what is done, what is running, and what is left. Update it in the same commit as the work. `docs/plan.md` explains the why; this file tracks the state.

Last updated: 2026-11-09. Branch: `rewrite`.

## Active now

| Work | Owner | Branch | Notes |
|---|---|---|---|
| DNS-interception Finding | lead | `rewrite` | Small. `propagation.rs` only. |
| WHOIS/RDAP (`zombo-core::registration`, `zombo registration`) | worker | worktree branch off `rewrite` | Port of `internal/app/registration.go`. Does not touch `main.rs` wiring beyond its subcommand, or any docs. |

## Done

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
- [x] Shared zone fixtures in `testdata/zones` for Go and Rust tests
- [x] Verified live from a clean network (VPS) for propagation, stale cache, delegation

## To do: DNS and domain registration

- [ ] DNS-interception Finding and downgraded Agreement (in progress)
- [ ] WHOIS/RDAP: registrar, status, expiry, nameservers, holds, deletion states (in progress)
- [ ] DNSSEC validation (DS at parent vs DNSKEY, RRSIG expiry, chain)
- [ ] More record types in lookup (SRV, PTR, DNSKEY, DS) if needed by the UI

## To do: email

Go sources to port: `email_auth.go`, `blacklist.go`, `headers.go`, `maillog.go`.

- [ ] MX
- [ ] SPF with the 10-lookup count
- [ ] DKIM by selector
- [ ] DMARC
- [ ] MTA-STS, TLS-RPT, BIMI
- [ ] SMTP banner and STARTTLS test
- [ ] Blacklist lookup
- [ ] Reverse DNS and forward-confirmed reverse DNS
- [ ] Header analysis (Evidence)
- [ ] Mail-log analysis (Evidence)

## To do: hosting and web

Go sources to port: `website.go`, `origin.go`, `ssl.go`, `hosting.go`.

- [ ] HTTP redirect chain, headers, status
- [ ] Origin versus CDN comparison
- [ ] Certificate and chain, level 1 (trust, expiry, SAN match, OCSP stapling, HSTS, CAA)
- [ ] CDN and ASN detection
- [ ] TCP port connect test

## To do: the app

- [ ] `zombo-ui` crate on `gpui-kit` (pinned snapshot, ADR-0007)
- [ ] One box (Diagnosis): all relevant Checks in parallel, results streaming
- [ ] Command palette for single Checks
- [ ] Watch (re-run until the answer changes)
- [ ] Design foundation in code: Geist scales, LCH theme, fonts, 6/12 px radii; write `DESIGN.md` with sizes, spacing, motion, keyboard rules
- [ ] Table cell labels for screen readers on every result view
- [ ] Window title and app ID set; clear error when the compositor has no `wl_seat`
- [ ] Recent-lookups list (no Cases)

## To do: security, quality, release

- [ ] CI: `cargo test`, `clippy`, `cargo-deny`, `cargo-audit`
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

## Still unverified

- [ ] NVIDIA GPUs
- [ ] The AppImage without `libfuse2` on real hardware (the work laptop has `libfuse2t64` installed)
- [ ] Broken-delegation paths against a real broken domain (fakes only so far)
- [ ] Scroll frame rate
