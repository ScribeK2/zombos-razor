# Progress

The single list of what is done, what is running, and what is left. Update it in the same commit as the work. `docs/plan.md` explains the why; this file tracks the state.

Last updated: 2026-11-09. Branch: `rewrite`.

## Active now

Nothing running. Next batch below under "Next batch".

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
- [ ] Evidence paste tabs; settings pane (resolvers, DKIM selectors, timeout, proxy, notifications)
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

- [ ] **Proxy policy is inconsistent.** `registration` honours `HTTP_PROXY`/`HTTPS_PROXY`; `web` turns the environment proxy off on purpose ("a diagnostic must show what the site does"). Decide one rule, or keep both and say so in the UI
- [ ] **Web User-Agent** is `zombo/<version>` (Go sent a browser-like string to avoid WAF blocks): expect more 403s. Keep honest, or send a browser-like string
- [ ] **Web cookies:** no cookie jar (Go kept cookies across hops), so a cookie-dependent redirect reads as a loop. Add a per-Check jar if it matters
- [ ] **Web follows https to http downgrades** on redirect (same as Go). Decide whether to flag it as a finding or refuse
- [ ] **`--origin` with a self-signed or Cloudflare Origin CA certificate** reads as "did not answer directly". Add `--insecure-origin`?
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
