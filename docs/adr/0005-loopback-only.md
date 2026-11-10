# The server listens on 127.0.0.1 only

Stackwell has no login: whoever can reach the port is the rep. It therefore never listens on any interface other than loopback, not even behind a flag. Remote or headless use goes through `--no-browser` plus an SSH tunnel (`ssh -L`).

Listening on loopback is not enough on its own: any web page the rep has open can make the browser send requests to 127.0.0.1. So every request must name a loopback host (which defeats DNS rebinding, where a hostile domain is re-pointed at 127.0.0.1 to read the API), and any request that changes something is refused if it carries a foreign `Origin` (browsers always send one on cross-site POST, PUT and DELETE). Local tools that send no `Origin`, such as curl, keep working.

## Status

Moot: ADR-0006 is accepted, and the Rust GPUI app has no localhost server.
