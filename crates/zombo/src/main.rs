//! `zombo`: the command-line front end to zombo-core.

use std::{net::SocketAddr, process::ExitCode, time::Duration};

use zombo_core::{
    Finding, Severity,
    delegation::{Ports, ServerState, check_delegation, delegation_findings},
    propagation::{Scope, Vantage, VantageAnswer, VantageKind, default_resolvers, discover_nameservers, propagation_findings, propagation_with},
    target::{Kind, parse_target},
};

const USAGE: &str = "usage: zombo delegation <domain|host> [--resolver ip[:port]]... [--timeout-ms N] [--json]\n       zombo propagation <domain|host> [--scope all|mail|web] [--resolver ip[:port]]... [--nameserver ip[:port]]... [--no-authoritative] [--timeout-ms N] [--json]";

fn addr(v: &str) -> Result<SocketAddr, String> {
    v.parse()
        .or_else(|_| format!("{v}:53").parse())
        .or_else(|_| format!("[{v}]:53").parse())
        .map_err(|_| format!("{v:?} is not an IP address"))
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("zombo: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Vec<String>) -> Result<(), String> {
    let mut it = args.into_iter();
    match it.next().as_deref() {
        Some("propagation") => propagation(it).await,
        Some("delegation") => delegation(it).await,
        _ => Err(USAGE.into()),
    }
}

fn print_findings(findings: &[Finding]) {
    for f in findings {
        let tag = match f.severity {
            Severity::Ok => "ok",
            Severity::Info => "info",
            Severity::Warning => "WARNING",
            Severity::Critical => "CRITICAL",
        };
        println!("[{tag}] {}: {}", f.title, f.message);
        if let Some(r) = f.recommendation {
            println!("        {r}");
        }
    }
}

async fn delegation(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut json, mut timeout) = (None, false, Duration::from_secs(4));
    let mut bootstrap: Vec<SocketAddr> = vec![];
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--timeout-ms" => {
                timeout = Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--resolver" => bootstrap.push(addr(&value("--resolver")?)?),
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(USAGE.into()),
        }
    }
    let t = parse_target(&target.ok_or(USAGE)?)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname) {
        return Err(format!("delegation needs a domain or host name, not {:?}", t.kind));
    }
    if bootstrap.is_empty() {
        bootstrap = default_resolvers().iter().map(|r| r.address).collect();
    }
    let r = check_delegation(&bootstrap, &t.value, Ports::default(), timeout).await.map_err(|e| e.to_string())?;
    let findings = delegation_findings(&r);
    if json {
        let out = serde_json::json!({ "result": r, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!("{} is delegated from {}", r.apex, r.parent);
    for s in &r.servers {
        let glue = r.glue.get(&s.name).map(|g| match g.len() {
            1..=2 => g.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
            n => format!("{n} addresses"),
        });
        let state = match &s.state {
            ServerState::Ok { serial } => format!("authoritative, serial {serial}"),
            ServerState::Unreachable => "no answer".to_string(),
            ServerState::Lame { why } => format!("LAME: {why}"),
        };
        println!("  {:<32} glue: {:<24} {state}", s.name, glue.unwrap_or_else(|| "-".into()));
    }
    println!();
    print_findings(&findings);
    Ok(())
}

async fn propagation(mut it: std::vec::IntoIter<String>) -> Result<(), String> {
    let (mut target, mut scope, mut json, mut timeout) = (None, Scope::All, false, Duration::from_secs(4));
    let (mut resolvers, mut nameservers, mut no_auth) = (vec![], vec![], false);
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--scope" => scope = value("--scope")?.parse()?,
            "--timeout-ms" => {
                timeout = Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--no-authoritative" => no_auth = true,
            "--resolver" => {
                let v = value("--resolver")?;
                resolvers.push(Vantage::resolver(&v, "custom", addr(&v)?));
            }
            "--nameserver" => {
                let v = value("--nameserver")?;
                nameservers.push(Vantage::nameserver(&v, addr(&v)?));
            }
            f if f.starts_with("--") => return Err(format!("unknown option {f}\n{USAGE}")),
            _ if target.is_none() => target = Some(a),
            _ => return Err(USAGE.into()),
        }
    }
    let t = parse_target(&target.ok_or(USAGE)?)?;
    if !matches!(t.kind, Kind::Domain | Kind::Hostname) {
        return Err(format!("propagation needs a domain or host name, not {:?}", t.kind));
    }
    if resolvers.is_empty() {
        resolvers = default_resolvers();
    }

    if !no_auth && nameservers.is_empty() {
        let bootstrap: Vec<SocketAddr> = resolvers.iter().map(|r| r.address).collect();
        match discover_nameservers(&bootstrap, &t.value, 53, timeout).await {
            Ok(found) => nameservers = found,
            Err(e) => eprintln!("zombo: skipping the authoritative nameservers: {e}"),
        }
    }

    let show = |a: &VantageAnswer| {
        if json {
            return;
        }
        let r = &a.vantage;
        match (&a.error, a.rcode) {
            (Some(e), _) => println!("  {:<14} {:<16} {e}", r.name, r.location),
            (None, rcode) => println!(
                "  {:<14} {:<16} {:?}  {} record types answered{}",
                r.name,
                r.location,
                rcode.unwrap(),
                a.answers.len(),
                if a.authoritative == Some(false) && r.kind == VantageKind::Authoritative { "  (NOT authoritative)" } else { "" }
            ),
        }
    };
    if !json {
        println!("{} ({:?}): {} resolvers, {} authoritative nameservers", t.value, t.kind, resolvers.len(), nameservers.len());
    }
    let res = propagation_with(&resolvers, &nameservers, &t.value, scope, timeout, show).await.map_err(|e| e.to_string())?;
    let findings = propagation_findings(&t.value, &res);
    if json {
        let out = serde_json::json!({ "result": res, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!();
    for ty in &res.types {
        let mut variants: Vec<(Vec<String>, Vec<&str>)> = vec![];
        for a in res.nameservers.iter().chain(&res.resolvers).filter(|a| a.error.is_none() && !a.failed.contains(ty)) {
            let vals = a.answers.get(ty).cloned().unwrap_or_default();
            match variants.iter_mut().find(|(v, _)| *v == vals) {
                Some((_, who)) => who.push(&a.vantage.name),
                None => variants.push((vals, vec![&a.vantage.name])),
            }
        }
        let mark = if res.disagree.contains(ty) { "DIFFERS" } else { "agree" };
        println!("{ty:<6} {mark}");
        for (vals, who) in variants {
            let v = if vals.is_empty() { "(none)".to_string() } else { vals.join(" | ") };
            println!("       {v}  <- {}", who.join(", "));
        }
    }
    println!();
    println!("Agreement: {} - {}", res.agreement.label(), res.agreement.reason());
    println!();
    print_findings(&findings);
    Ok(())
}
