#!/usr/bin/env python3
"""Fill fuzz/corpus/<target>/ with seeds: the repo's testdata plus a few hand-built binary inputs."""
import base64
import pathlib
import re
import struct

root = pathlib.Path(__file__).resolve().parent.parent
corpus = root / "fuzz" / "corpus"
data = root / "testdata"


def put(target, name, blob):
    d = corpus / target
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(blob if isinstance(blob, bytes) else blob.encode())


def copy(target, pattern):
    for p in sorted(data.glob(pattern)):
        put(target, p.name, p.read_bytes())


copy("email_records", "zones/email_*.zone")
copy("email_headers", "evidence/*.txt")
copy("mail_log", "evidence/*.log")
copy("rdap_json", "registration/rdap_*.json")
copy("whois_text", "registration/*.txt")
copy("ui_text", "evidence/*")
copy("ui_text", "registration/denic_plain.txt")
put("ui_text", "settings.toml", 'resolver = "9.9.9.9"\ntimeout_seconds = 12\n')

for p in sorted(data.glob("web/wordpress_*.html")):
    put("web_response", p.name, b"Server: nginx\nLocation: /next\nStrict-Transport-Security: max-age=1\n\0" + p.read_bytes())

put("smtp_reply", "ehlo", "220 mail.example.com ESMTP ready\r\n250-mail.example.com\r\n250-STARTTLS\r\n250-SIZE 35882577\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
put("smtp_reply", "multiline", "220-hello\r\n220-more\r\n220 done\r\n")
put("target", "urls", "https://user@Example.COM:8443/path?x=1\n")
put("target", "email", "someone@bücher.example\n")
put("target", "ip", "2001:db8::1\n")

pem = (data / "tls" / "weak-rsa1024-sha1.pem").read_text()
der = base64.b64decode("".join(re.findall(r"^[A-Za-z0-9+/=]+$", pem, re.M)))
put("tls_certificate", "weak", struct.pack(">H", len(der)) + der)


def name(*labels):
    return b"".join(bytes([len(l)]) + l for l in labels) + b"\0"


def message(ident, answers, flags=0x8180):
    head = struct.pack(">HHHHHH", ident, flags, 1, len(answers), 0, 0)
    q = name(b"example", b"com") + struct.pack(">HH", 1, 1)
    out = head + q
    for rtype, rdata in answers:
        out += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
    return out


put("dns_message", "a", message(1, [(1, bytes([192, 0, 2, 1]))]))
put("dns_message", "txt", message(2, [(16, bytes([11]) + b"v=spf1 -all")]))
put("dns_message", "mx", message(3, [(15, struct.pack(">H", 10) + name(b"mail") + b"")]))
put("dns_message", "loop", message(4, [(5, b"\xc0\x0c")]))

key = bytes([1, 1, 3, 13]) + bytes(range(64))
put("dnssec_rdata", "dnskey", key)
put("dnssec_rdata", "ds", struct.pack(">HBB", 2371, 13, 2) + bytes(32))
sig = struct.pack(">HBBIIIH", 48, 13, 2, 3600, 2000000000, 1000000000, 2371) + name(b"example", b"com") + bytes(64)
put("dnssec_rdata", "rrsig", sig)
