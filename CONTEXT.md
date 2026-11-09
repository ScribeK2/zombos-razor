# Zombo's Razor

A local desktop tool a support rep uses to answer "what is wrong with this domain, and is it real or just caching?" It replaces the third-party DNS, domain-registration, email and hosting lookup sites the team opens every day. (Renamed from Stackwell; casework was dropped.)

## Language

**Rep**:
The person running Zombo's Razor. Each rep runs their own copy; there is no shared server.
_Avoid_: User, agent, operator

**Target**:
A thing a Check examines: a domain, hostname, IP, URL or email address.
_Avoid_: Input, subject

**Check**:
One kind of diagnostic, such as DNS records, propagation, WHOIS/RDAP, SPF, SMTP banner, blacklist or TLS certificate.
_Avoid_: Tool, probe, test

**Vantage**:
The place a Check observes from: the local machine, an authoritative nameserver, or one named public resolver. A Check can run from several Vantages at once.
_Avoid_: Location, source, node

**Lookup**:
One execution of a Check on a Target from one or more Vantages, with its result. A Lookup is live: it is never served from a cache, and re-running it makes a new Lookup.
_Avoid_: Run, step, query

**Diagnosis**:
The set of Lookups a Target gets when the rep types it into the one box: every relevant Check, run in parallel, results streaming in as each finishes.
_Avoid_: Scan, report, investigation

**Agreement**:
The verdict on whether the Vantages of a Lookup return the same answer. Disagreement is the usual sign of caching or propagation in progress.
_Avoid_: Consistency, sync status, match

**Finding**:
A conclusion with a severity, derived from one Lookup. Every severity is shown with a text label, never by color alone.
_Avoid_: Issue, result, alert

**Evidence**:
Material the rep pastes in (email headers, mail logs, bounce messages) rather than something fetched. Evidence analysis is itself a Check.
_Avoid_: Paste, input, attachment

**Watch**:
Re-running one Check on one Target at an interval until its result changes, then telling the rep. Re-runs that give the same answer record nothing.
_Avoid_: Monitor, poll, schedule
