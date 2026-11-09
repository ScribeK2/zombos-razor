//! `zombo`: the command-line front end to zombo-core.

use std::{net::SocketAddr, process::ExitCode, time::Duration};

use zombo_core::{
    Severity,
    propagation::{PublicResolver, ResolverAnswer, Scope, default_resolvers, propagation_findings, propagation_with},
    target::{Kind, parse_target},
};

const USAGE: &str = "usage: zombo propagation <domain|host> [--scope all|mail|web] [--resolver ip[:port]]... [--timeout-ms N] [--json]";

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
    if it.next().as_deref() != Some("propagation") {
        return Err(USAGE.into());
    }
    let (mut target, mut scope, mut json, mut timeout) = (None, Scope::All, false, Duration::from_secs(4));
    let mut resolvers: Vec<PublicResolver> = vec![];
    while let Some(a) = it.next() {
        let mut value = |flag: &str| it.next().ok_or(format!("{flag} needs a value"));
        match a.as_str() {
            "--json" => json = true,
            "--scope" => scope = value("--scope")?.parse()?,
            "--timeout-ms" => {
                timeout = Duration::from_millis(value("--timeout-ms")?.parse().map_err(|_| "--timeout-ms needs a number")?)
            }
            "--resolver" => {
                let v = value("--resolver")?;
                let address: SocketAddr = v
                    .parse()
                    .or_else(|_| format!("{v}:53").parse())
                    .or_else(|_| format!("[{v}]:53").parse())
                    .map_err(|_| format!("{v:?} is not an IP address"))?;
                resolvers.push(PublicResolver { name: v, location: "custom".into(), address });
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

    let show = |a: &ResolverAnswer| {
        if json {
            return;
        }
        let r = &a.resolver;
        match (&a.error, a.rcode) {
            (Some(e), _) => println!("  {:<14} {:<16} {e}", r.name, r.location),
            (None, rcode) => println!(
                "  {:<14} {:<16} {:?}  {} record types answered",
                r.name,
                r.location,
                rcode.unwrap(),
                a.answers.len()
            ),
        }
    };
    if !json {
        println!("{} ({:?}), {} resolvers", t.value, t.kind, resolvers.len());
    }
    let res = propagation_with(&resolvers, &t.value, scope, timeout, show).await.map_err(|e| e.to_string())?;
    let findings = propagation_findings(&t.value, &res);
    if json {
        let out = serde_json::json!({ "result": res, "findings": findings });
        println!("{}", serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?);
        return Ok(());
    }
    println!();
    for ty in &res.types {
        let mut variants: Vec<(Vec<String>, Vec<&str>)> = vec![];
        for a in res.resolvers.iter().filter(|a| a.error.is_none() && !a.failed.contains(ty)) {
            let vals = a.answers.get(ty).cloned().unwrap_or_default();
            match variants.iter_mut().find(|(v, _)| *v == vals) {
                Some((_, who)) => who.push(&a.resolver.name),
                None => variants.push((vals, vec![&a.resolver.name])),
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
    for f in &findings {
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
    Ok(())
}
