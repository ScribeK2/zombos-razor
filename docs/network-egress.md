# Network egress

What Zombo's Razor contacts. The app has no telemetry, no accounts and no analytics. Every connection below is made on the rep's machine, for a Check the rep asked for. Keep this file in step with the code: a new destination needs a line here in the same commit.

## Always the target

Every Check talks to the target the rep typed, or to infrastructure that serves it: its web servers (HTTP, HTTPS), its mail servers (SMTP, when asked), its authoritative nameservers (UDP and TCP 53), and the servers it lists in DNS (MX, NS, CNAME chains). The port test, the SMTP test and the TLS on a port test connect to the target's servers only when the rep starts them.

## DNS resolvers

| Who | When |
|---|---|
| The ten public resolvers in `propagation::default_resolvers` (Google, Cloudflare, Quad9, OpenDNS, Level3, DNS.SB, AdGuard, Yandex, 114DNS, CleanBrowsing) | propagation, delegation, email authentication, DNSSEC discovery |
| Google, Cloudflare, Quad9, OpenDNS | the DNSSEC verdict (validating resolvers only) |
| The machine's own resolver (`/etc/resolv.conf`, at most 3 servers) | blocklist lookups (public resolvers are refused by some lists), reverse DNS (also the automatic Reverse DNS section for an IP target), the web Check's DNS, the TLS on a port Check's name lookup, and the "This machine" row of DNS propagation (first server only; the same questions as the public resolvers, the target's name and nothing else) |
| The authoritative nameservers and the parent zone's servers, found by discovery | authoritative Vantage, delegation, DNSSEC |
| Resolvers the rep adds in settings (propagation and discovery only) or with `--resolver` | as configured |

The queries contain the target's name, nothing else.

## Registration

| Destination | Purpose |
|---|---|
| The RDAP service for the TLD, from the IANA bootstrap bundled in the app (`crates/zombo-core/data/rdap_bootstrap.json`), HTTPS only | domain registration |
| The registry's WHOIS server, port 43 (a bundled table; `whois.iana.org` for a referral on other TLDs) | fallback when RDAP is unavailable |

## Reference services

| Destination | Purpose |
|---|---|
| Team Cymru DNS (`*.origin.asn.cymru.com`, `*.asn.cymru.com`) | the AS number and name of an address, in the web Check |
| The DNS blocklists in the bundled table in `blacklist.rs` (Spamhaus ZEN and DBL, SpamCop, Barracuda, PSBL, Mailspike, UCEPROTECT, Manitu, GBUdb, SURBL, and others) | blacklist lookup, asked through the machine's resolver. The queried address or domain goes to the list operator, as with any DNSBL |

## Updates

Once a day, when the app runs as an AppImage and "Check for updates once a day" is on (default on), it requests the release list of the repository named in `RELEASE_REPO` (`crates/zombo-core/src/update.rs`) from `https://api.github.com`. The request carries the User-Agent `zombo/<version>` and nothing about the rep or any lookup, and no cookies. A newer version is downloaded only after the rep clicks Update, from the release assets (`SHA256SUMS`, `SHA256SUMS.minisig`, the AppImage) over https with at most 5 redirects, 256 KiB for metadata and a 120 MiB cap on the AppImage. The minisign signature on `SHA256SUMS` is verified against the embedded public key, its trusted comment must name the release version, and the AppImage's SHA-256 must match the signed sums. Only then is the file renamed over the old AppImage. A build that still carries the test key refuses to check or install. The last check time and one skipped version are kept in `update.toml` in the state directory.

## Nothing else

No telemetry, crash reports, usage statistics, fonts or assets from a CDN, advertising or analytics endpoints. The fonts and the bootstrap data are bundled. Results are kept in memory and never sent anywhere.

## HTTP clients

The HTTP clients (registration, web) use `ureq` with rustls and send the User-Agent `zombo/<release version>`: no OpenSSL, bounded responses (1 MiB for registration, 64 KiB of body for the web Check), a redirect limit and one overall deadline. The registration client uses the proxy from settings first, then `HTTP_PROXY` and `HTTPS_PROXY`; the web Check ignores them on purpose (see `docs/progress.md`, decisions waiting).
