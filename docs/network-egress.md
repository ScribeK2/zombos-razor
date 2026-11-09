# Network egress

What Zombo's Razor contacts. The app has no telemetry, no accounts and no analytics. Every connection below is made on the rep's machine, for a Check the rep asked for. Keep this file in step with the code: a new destination needs a line here in the same commit.

## Always the target

Every Check talks to the target the rep typed, or to infrastructure that serves it: its web servers (HTTP, HTTPS), its mail servers (SMTP, when asked), its authoritative nameservers (UDP and TCP 53), and the servers it lists in DNS (MX, NS, CNAME chains). The port test and the SMTP test connect to the target's servers only when the rep starts them.

## DNS resolvers

| Who | When |
|---|---|
| The ten public resolvers in `propagation::default_resolvers` (Google, Cloudflare, Quad9, OpenDNS, Level3, DNS.SB, AdGuard, Yandex, 114DNS, CleanBrowsing) | propagation, delegation, email authentication, DNSSEC discovery |
| Google, Cloudflare, Quad9, OpenDNS | the DNSSEC verdict (validating resolvers only) |
| The machine's own resolver (`/etc/resolv.conf`, at most 3 servers) | blocklist lookups (public resolvers are refused by some lists), reverse DNS, the web Check's DNS |
| The authoritative nameservers and the parent zone's servers, found by discovery | authoritative Vantage, delegation, DNSSEC |
| Resolvers the rep adds in settings or with `--resolver` | as configured |

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

The release endpoint (a GitHub release page) once a day, to check for a newer version. The download is verified (SHA256SUMS, and a signature from the signing work still to do) before it is applied, and never applied without a prompt.

## Nothing else

No telemetry, crash reports, usage statistics, fonts or assets from a CDN, advertising or analytics endpoints. The fonts and the bootstrap data are bundled. Results are kept in memory and never sent anywhere.

## HTTP clients

The HTTP clients (registration, web) use `ureq` with rustls: no OpenSSL, bounded responses (1 MiB for registration, 64 KiB of body for the web Check), a redirect limit and one overall deadline. The registration client honours `HTTP_PROXY` and `HTTPS_PROXY`; the web Check ignores them on purpose (see `docs/progress.md`, decisions waiting).
