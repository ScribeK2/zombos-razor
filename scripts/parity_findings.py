#!/usr/bin/env python3
"""Parity tooling for the Go to Rust rewrite.

  parity_findings.py --json        every Finding site in Go and Rust, raw expression text
  parity_findings.py --tables      markdown tables: Go codes against Rust, wording diff, test coverage
  parity_findings.py --check DOC   verify every `crate/path.rs::test_name` cited in DOC exists
  parity_findings.py --write DOC   regenerate the block between the GENERATED markers in DOC
  parity_findings.py --stale DOC   exit 1 when that block is out of date

Go is read from git (GO_COMMIT), not the working tree: the Go code is deleted from `rewrite`.
Rust Findings are found by `code: "x"` literals and by calls such as `finding("x", Severity, ..)`
whose argument list has a snake_case literal followed by a severity. A `.recommend(text)` right after
the call's closing parenthesis supplies the recommendation. The same literal is also
looked up in every test body, so a code with no test naming it is visible.
"""
import contextlib
import io
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
GO_COMMIT = "b8fc3d5"  # last Go commit, tip of `main`
RUNE = re.compile(r"'(\\.|[^'\\])'")
RAW = re.compile(r'r(#*)"')


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True, text=True).stdout


def skip_literal(s, i):
    """Index after the string or char literal at s[i], or i when there is none."""
    c = s[i]
    if c == "r" and (m := RAW.match(s, i)) and (i == 0 or not (s[i - 1].isalnum() or s[i - 1] == "_")):
        return s.index('"' + m.group(1), m.end()) + 1 + len(m.group(1))
    if c == "`":
        return s.index("`", i + 1) + 1
    if c == '"':
        j = i + 1
        while s[j] != '"':
            j += 2 if s[j] == "\\" else 1
        return j + 1
    if c == "'":
        m = RUNE.match(s, i)
        return m.end() if m else i
    return i


def group_end(s, start):
    """Index of the bracket closing the one that opens at s[start]."""
    depth, i = 0, start
    while i < len(s):
        j = skip_literal(s, i)
        if j != i:
            i = j
            continue
        if s[i:i + 2] == "//":
            i = s.index("\n", i)
            continue
        if s[i] in "([{":
            depth += 1
        elif s[i] in ")]}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(s) - 1


def split_top(s, start):
    """Parts of the bracket group opening at s[start], split at depth-1 commas."""
    end = group_end(s, start)
    parts, cur, depth, i = [], start + 1, 0, start
    while i < end:
        j = skip_literal(s, i)
        if j != i:
            i = j
            continue
        if s[i:i + 2] == "//":
            i = s.index("\n", i)
            continue
        c = s[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 1:
            parts.append(s[cur:i])
            cur = i + 1
        i += 1
    parts.append(s[cur:end])
    return parts


def clean(x):
    """Collapse whitespace and drop `//` comments, leaving string literals alone."""
    out, i = [], 0
    while i < len(x):
        j = skip_literal(x, i)
        if j != i:
            out.append(x[i:j])
            i = j
        elif x[i:i + 2] == "//":
            i = x.find("\n", i) if "\n" in x[i:] else len(x)
        else:
            out.append(x[i])
            i += 1
    return re.sub(r"\s+", " ", "".join(out)).strip()


def kv(parts, keys):
    out = {}
    for p in parts:
        m = re.match(r"\s*(\w+)\s*:(?!:)(.*)", p, re.S) or re.match(r"\s*((\w+))\s*$", p)
        if m and m.group(1) in keys:
            out[m.group(1)] = clean(m.group(2))
    return out


def enclosing_open(s, pos):
    depth = 0
    for i in range(pos, -1, -1):
        if s[i] in "}])":
            depth += 1
        elif s[i] in "{[(":
            if depth == 0:
                return i
            depth -= 1
    return -1


def line_of(s, pos):
    return s.count("\n", 0, pos) + 1


def go_sources():
    names = git("ls-tree", "--name-only", GO_COMMIT, "internal/app/").split()
    for name in sorted(n for n in names if n.endswith(".go") and not n.endswith("_test.go")):
        yield name, git("show", f"{GO_COMMIT}:{name}")


def go_findings():
    rows = []
    for name, s in go_sources():
        for m in re.finditer(r'\bCode:\s*"([a-z0-9_]+)"', s):
            f = kv(split_top(s, enclosing_open(s, m.start())), {"Severity", "Title", "Message", "Recommendation"})
            if "Severity" in f:
                rows.append(dict(code=m.group(1), file=f"{pathlib.Path(name).name}:{line_of(s, m.start())}",
                                 severity=f["Severity"], title=f.get("Title", ""),
                                 message=f.get("Message", ""), recommendation=f.get("Recommendation", "")))
    return rows


SEV = re.compile(r"^(Severity::\w+|Ok|Info|Warning|Critical|sev\w*|severity|s|if .*\b(Ok|Info|Warning|Critical)\b.*)$")
RECOMMEND = re.compile(r"\s*\.recommend\(")  # `Finding::new(..).recommend(text)`: the fifth argument
LITERAL = re.compile(r'"([a-z][a-z0-9]*(?:_[a-z0-9]+)+)"')
WEB_TUPLE = (("website_cdn_detected", 'format!("Served through {}", d.provider)'),
             ("website_host_detected", 'format!("Hosted on {}", d.provider)'))


def rust_files():
    for p in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        yield p, p.read_text()
    for p in sorted((ROOT / "crates").glob("*/tests/**/*.rs")):
        yield p, p.read_text()


def rust_findings():
    rows = []
    for p in sorted((ROOT / "crates").glob("*/src/**/*.rs")):
        s = p.read_text()
        cut = s.find("#[cfg(test)]")
        prod = s[:cut] if cut >= 0 else s
        rel = p.relative_to(ROOT)

        def add(code, pos, severity, title, message, rec):
            rows.append(dict(code=code, file=f"{rel}:{line_of(s, pos)}", severity=severity,
                             title=title, message=message, recommendation=rec))

        for m in re.finditer(r'\bcode:\s*"([a-z0-9_]+)"', prod):
            f = kv(split_top(s, enclosing_open(s, m.start())), {"severity", "title", "message", "recommendation"})
            if "severity" in f:
                add(m.group(1), m.start(), f["severity"], f.get("title", ""), f.get("message", ""),
                    f.get("recommendation", "None"))
        for m in LITERAL.finditer(prod):
            o = enclosing_open(s, m.start())
            if o < 0 or s[o] != "(":
                continue
            args = [clean(a) for a in split_top(s, o)]
            if args[-1] == "":  # trailing comma
                args.pop()
            lit = f'"{m.group(1)}"'
            if lit not in args:
                continue
            i = args.index(lit)
            if len(args) >= i + 3 and SEV.match(args[i + 1]):
                rec = args[i + 4] if len(args) > i + 4 else "None"
                if len(args) <= i + 4 and (t := RECOMMEND.match(s, group_end(s, o) + 1)):
                    rec = clean(split_top(s, t.end() - 1)[0])
                add(m.group(1), m.start(), args[i + 1], args[i + 2], args[i + 3] if len(args) > i + 3 else "", rec)
        if str(rel) == "crates/zombo-core/src/web/findings.rs":
            for code, title in WEB_TUPLE:
                add(code, prod.index(code), "Severity::Info", title,
                    'format!("{} points to {} ({}).", h.host, d.provider, d.evidence.join("; "))', "None")
    return rows


def rust_tests():
    """{ 'zombo-core/tests/x.rs::name': body } for every #[test] and #[tokio::test] function."""
    out = {}
    for p, s in rust_files():
        rel = p.relative_to(ROOT / "crates")
        for m in re.finditer(r"#\[(?:tokio::)?test[^\]]*\]\s*(?:#\[[^\]]*\]\s*)*(?:pub )?(?:async )?fn (\w+)", s):
            b = s.index("{", m.end())
            out[f"{rel}::{m.group(1)}"] = s[b:group_end(s, b)]
    return out


def shape(expr, go):
    """The sorted words of an expression's string literals: wording equality that ignores
    the order and spelling of interpolated values, punctuation and case."""
    parts, i = [], 0
    while i < len(expr):
        j = skip_literal(expr, i)
        if j != i and expr[i] != "'":
            lit = expr[i + 1:j - 1]
            lit = re.sub(r"%[a-z]", "§", lit) if go else re.sub(r"\{[^}]*\}", "§", lit)
            parts.append(lit)
            i = j
        else:
            if not expr[i].isspace() and expr[i] not in "+(),":
                parts.append("§")
                while i < len(expr) and expr[i] not in "\"`+,":
                    i += 1
                continue
            i += 1
    words = re.findall(r"[a-z0-9]+", " ".join(parts).replace("§", " ").lower())
    return " ".join(sorted(words))


def sev_word(x):
    m = re.findall(r"\b(critical|warning|info|ok)\b", x.lower())
    return "/".join(sorted(set(m))) if m else "dynamic"


def compare(go, rs):
    out = {}
    for code in sorted({r["code"] for r in go}):
        g = [r for r in go if r["code"] == code]
        r = [x for x in rs if x["code"] == code]
        if not r:
            out[code] = None
            continue
        row = {}
        for field, norm in (("severity", lambda x, lang: sev_word(x)),
                            ("title", lambda x, lang: shape(x, lang == "go")),
                            ("message", lambda x, lang: shape(x, lang == "go")),
                            ("recommendation", lambda x, lang: shape(x, lang == "go") if x not in ("", "None") else "")):
            gs = {norm(x[field], "go") for x in g}
            rss = {norm(x[field], "rust") for x in r}
            row[field] = "same" if gs & rss else "DIFF"
        out[code] = row
    return out


def named_tests(code, tests, limit=2):
    named = [k for k, b in tests.items() if f'"{code}"' in b]
    return ", ".join(f"`{k}`" for k in named[:limit]) + (f" (+{len(named) - limit})" if len(named) > limit else "") or "NONE"


def tables():
    go, rs, tests = go_findings(), rust_findings(), rust_tests()
    gc, rc = {r["code"] for r in go}, {r["code"] for r in rs}
    cmp = compare(go, rs)
    print(f"Go: {len(go)} Finding sites, {len(gc)} codes. Rust: {len(rs)} sites, {len(rc)} codes. "
          f"In both: {len(gc & rc)}. Go only: {len(gc - rc)}. Rust only: {len(rc - gc)}.\n")
    print("#### Go codes absent from Rust\n")
    for c in sorted(gc - rc):
        print(f"- `{c}` ({', '.join(r['file'] for r in go if r['code'] == c)})")
    print("\n#### Every Go code against Rust\n")
    print("Sev is the severity word at the Go site and at the Rust site. The three wording columns say `same` when "
          "a Go site and a Rust site have the same literal words (order, values, punctuation and case ignored) and "
          "`DIFF` otherwise. Tests are the first two test functions whose body names the code.\n")
    print("| Go code | Sev Go | Sev Rust | Title | Message | Rec | Tests naming the code |\n|---|---|---|---|---|---|---|")
    for c in sorted(gc):
        g = sev_word(next(r["severity"] for r in go if r["code"] == c))
        rsev = "/".join(sorted({sev_word(r["severity"]) for r in rs if r["code"] == c})) or "absent"
        row = cmp[c] or {"title": "-", "message": "-", "recommendation": "-"}
        print(f"| `{c}` | {g} | {rsev} | {row['title']} | {row['message']} | {row['recommendation']} | "
              f"{named_tests(c, tests) if c in rc else '-'} |")
    diffs = [c for c, r in cmp.items() if r and "DIFF" in r.values()]
    print(f"\n{len(diffs)} shared codes have at least one DIFF: {', '.join(f'`{c}`' for c in diffs)}.\n")
    print("#### Rust-only codes\n")
    print("| Code | Source | Severity | Tests naming the code |\n|---|---|---|---|")
    for c in sorted(rc - gc):
        site = next(r for r in rs if r["code"] == c)
        print(f"| `{c}` | {site['file']} | {sev_word(site['severity'])} | {named_tests(c, tests)} |")
    nameless = [c for c in sorted(rc) if not any(f'"{c}"' in b for b in tests.values())]
    print(f"\n#### Rust codes that no test body names ({len(nameless)})\n")
    for c in nameless:
        print(f"- `{c}`{' (also in Go)' if c in gc else ''}")


def check(doc):
    text = pathlib.Path(doc).read_text()
    tests = rust_tests()
    cited = sorted(set(re.findall(r"`((?:zombo|zombo-core|zombo-ui)/[\w/.]+\.rs::\w+)`", text)))
    missing = [c for c in cited if c not in tests]
    print(f"{len(cited)} cited tests, {len(missing)} missing")
    for c in missing:
        print("MISSING", c)
    return 1 if missing else 0


BEGIN, END = "<!-- BEGIN GENERATED findings -->", "<!-- END GENERATED findings -->"


STATUSES = ("ported", "ported with deviation", "replaced", "dropped on purpose", "MISSING")


def status_counts(text):
    rows = re.findall(r"^\| [A-Z]+\d+ \| .*$", text, re.M)
    counts = dict.fromkeys(STATUSES, 0)
    for r in rows:
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", r)]
        if len(cells) == 7:  # the inventory has five columns; the MISSING list below it has three
            counts[cells[3]] += 1  # KeyError on a status word that is not in STATUSES
    return counts


def regenerate(doc):
    text = pathlib.Path(doc).read_text()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        tables()
    head, rest = text.split(BEGIN, 1)
    text = head + BEGIN + "\n" + buf.getvalue() + END + rest.split(END, 1)[1]
    table = "| Status | Rows |\n|---|---|\n" + "".join(f"| {k} | {v} |\n" for k, v in status_counts(text).items())
    a, b = text.index("<!-- COUNTS -->\n") + len("<!-- COUNTS -->\n"), text.index("<!-- /COUNTS -->")
    return text[:a] + table + text[b:]


if __name__ == "__main__":
    if "--json" in sys.argv:
        json.dump({"go": go_findings(), "rust": rust_findings()}, sys.stdout, indent=1)
    elif "--tables" in sys.argv:
        tables()
    elif "--write" in sys.argv:
        doc = sys.argv[sys.argv.index("--write") + 1]
        pathlib.Path(doc).write_text(regenerate(doc))
    elif "--stale" in sys.argv:
        doc = sys.argv[sys.argv.index("--stale") + 1]
        sys.exit(0 if regenerate(doc) == pathlib.Path(doc).read_text() else 1)
    elif "--check" in sys.argv:
        sys.exit(check(sys.argv[sys.argv.index("--check") + 1]))
    else:
        sys.exit(__doc__)
