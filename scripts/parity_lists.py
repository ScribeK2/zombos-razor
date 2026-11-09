#!/usr/bin/env python3
"""Check that the Go reference tables exist in Rust: public resolvers, DNSBLs, ZEN return
codes, service ports, mail providers. Go is read from git (see parity_findings.GO_COMMIT).
Prints one line per table and exits 1 when an entry is missing."""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
GO_COMMIT = "b8fc3d5"


def go(path):
    return subprocess.run(["git", "-C", str(ROOT), "show", f"{GO_COMMIT}:{path}"], check=True,
                          capture_output=True, text=True).stdout


def rs(path):
    return (ROOT / path).read_text()


def ws(pattern):
    return re.compile(r"\s*".join(pattern))


def main():
    missing = 0

    def report(name, entries, present):
        nonlocal missing
        gone = [e for e in entries if not present(e)]
        missing += len(gone)
        print(f"{name}: {len(entries) - len(gone)} of {len(entries)} Go entries present in Rust"
              + (f"; MISSING {gone}" if gone else ""))

    prop_go, prop_rs = go("internal/app/propagation.go"), rs("crates/zombo-core/src/propagation.rs")
    resolvers = re.findall(r'\{"([^"]+)", "([^"]+)", "([\d.]+):53"\}', prop_go)
    report("public resolvers (name, location, address)", resolvers,
           lambda e: f'("{e[0]}", "{e[1]}", "{e[2]}")' in prop_rs)

    bl_go, bl_rs = go("internal/app/blacklist.go"), rs("crates/zombo-core/src/blacklist.rs")
    dnsbls = re.findall(r'\{"([^"]+)", "([\w.-]+)", kind(IP|Domain), "(critical|warning|info)"', bl_go)
    report("DNSBLs (name, zone, kind, severity)", dnsbls,
           lambda e: ws([re.escape(f'"{e[0]}",'), re.escape(f'"{e[1]}",'),
                         "(Ip|Domain)," if False else ("Ip," if e[2] == "IP" else "Domain,"),
                         e[3].capitalize() + ","]).search(bl_rs) is not None)
    zen = re.findall(r'"(127\.0\.0\.\d+)": "([A-Z ]+)"', bl_go)
    report("Spamhaus ZEN return codes", zen, lambda e: f'"{e[0]}"' in bl_rs and f'"{e[1]}"' in bl_rs)

    host_go, ports_rs = go("internal/app/hosting.go"), rs("crates/zombo-core/src/ports.rs")
    for depth, const in (("quick", "QUICK"), ("full", "FULL")):
        block = re.search(r'"quick": \{(.*?)\},\n', host_go) if depth == "quick" else \
            re.search(r'"full": \{(.*?)\n\t\},', host_go, re.S)
        entries = re.findall(r'\{(\d+), "([^"]+)"\}', block.group(1))
        rblock = re.search(rf"pub const {const}: &\[ServicePort\] = &\[(.*?)\];", ports_rs, re.S).group(1)
        report(f"{depth} port sweep (port, service)", entries,
               lambda e: f'sp({e[0]}, "{e[1]}")' in rblock)

    scopes = re.findall(r'"(all|mail|web)":\s*\{([^}]*)\}', prop_go)
    types = lambda e: ", ".join(re.findall(r'"(\w+)"', e[1]))
    report("propagation scopes", scopes,
           lambda e: f'Scope::{e[0].capitalize()} => vec![{types(e)}]' in prop_rs)

    em_go, em_rs = go("internal/app/email_auth.go"), rs("crates/zombo-core/src/email_auth/findings.rs")
    providers = re.findall(r'\{"([^"]+)", \[\]string\{([^}]*)\}, "([^"]+)"\}', em_go)
    report("mail providers (name, MX suffixes, include)", providers,
           lambda e: f'"{e[0]}"' in em_rs and f'"{e[2]}"' in em_rs
           and all(f'"{s}"' in em_rs for s in re.findall(r'"([^"]+)"', e[1])))
    return 1 if missing else 0


sys.exit(main())
