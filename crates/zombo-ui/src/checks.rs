use std::{net::SocketAddr, time::Duration};

use tokio::sync::mpsc::UnboundedSender;
use zombo_core::{
    check::{Check, Request},
    propagation::{Scope, ask_vantage, default_resolvers, discover_nameservers, propagation_with},
    resolver::system_resolvers,
    target::{Kind, Target},
};

use crate::{
    diagnosis::PropEvent,
    outcome::{CheckEvent, Outcome},
    section::Section,
    settings_model::{Settings, budget},
};

/// The Checks that run on their own when a target is submitted (DESIGN.md, "Checks per target kind").
pub fn automatic(kind: Kind) -> Vec<Section> {
    use Section::*;
    let listed: &[Section] = match kind {
        Kind::Domain | Kind::Email | Kind::Hostname => &[Dns],
        Kind::Ip => &[],
    };
    Section::ALL
        .into_iter()
        .filter(|s| match s.check() {
            Some(check) => check.automatic_for.contains(&kind),
            None => listed.contains(s),
        })
        .collect()
}

/// Whether this build has a Check behind the rail section.
pub fn wired(section: Section) -> bool {
    section != Section::Summary
}

/// A Watch re-runs its Check on a timer, so it is offered only where that is harmless.
/// An on-demand Check connects to the target's servers, so it is never watched.
pub fn watchable(section: Section) -> bool {
    wired(section) && !section.is_on_demand()
}

pub fn check_name(target: &Target) -> Option<String> {
    match target.kind {
        Kind::Domain | Kind::Hostname => Some(target.value.clone()),
        Kind::Email => target.value.split_once('@').map(|(_, d)| d.to_string()),
        Kind::Ip => None,
    }
}

/// The name an on-demand Check connects to or asks about. An IP address is a valid subject
/// here, unlike for the automatic Checks.
pub fn name_for(section: Section, target: &Target) -> Option<String> {
    let takes_ip = section.is_on_demand() || section.check().is_some_and(|c| c.automatic_for.contains(&Kind::Ip));
    if takes_ip && target.kind == Kind::Ip { Some(target.value.clone()) } else { check_name(target) }
}

/// The ten public resolvers, then the rep's own that are not already among them.
fn propagation_resolvers(extra: &[SocketAddr]) -> Vec<zombo_core::propagation::Vantage> {
    let mut resolvers = default_resolvers();
    for &address in extra {
        if !resolvers.iter().any(|r| r.address == address) {
            resolvers.push(zombo_core::propagation::Vantage::resolver(
                &address.to_string(),
                "Added in settings",
                address,
            ));
        }
    }
    resolvers
}

pub async fn run_propagation(target: String, settings: Settings, tx: UnboundedSender<PropEvent>) {
    let _ = tx.send(PropEvent::Started);
    let limits = budget(Section::Dns, settings.timeout);
    let work = async {
        let resolvers = propagation_resolvers(&settings.resolvers);
        let bootstrap: Vec<SocketAddr> = resolvers.iter().map(|r| r.address).collect();
        let nameservers = discover_nameservers(&bootstrap, &target, 53, limits.query).await.unwrap_or_default();
        let ask_local = async {
            let answer = match crate::this_machine::vantage(&system_resolvers()) {
                Some(v) => ask_vantage(v, &target, Scope::All, limits.query).await,
                None => crate::this_machine::unavailable(),
            };
            let _ = tx.send(PropEvent::Local(Box::new(answer)));
        };
        let (result, ()) = tokio::join!(
            propagation_with(&resolvers, &nameservers, &target, Scope::All, limits.query, |a| {
                let _ = tx.send(PropEvent::Answer(Box::new(a.clone())));
            }),
            ask_local
        );
        result.map_err(|e| e.to_string())
    };
    let event = match tokio::time::timeout(limits.whole, work).await {
        Ok(result) => PropEvent::Finished(Box::new(result)),
        Err(_) => PropEvent::TimedOut,
    };
    let _ = tx.send(event);
}

pub async fn run_section(
    section: Section,
    name: String,
    kind: Kind,
    settings: Settings,
    port: u16,
    tx: UnboundedSender<CheckEvent>,
) {
    let _ = tx.send(CheckEvent::Started);
    let event = match tokio::time::timeout(
        budget(section, settings.timeout).whole,
        produce(section, &name, kind, &settings, port),
    )
    .await
    {
        Ok(result) => CheckEvent::Finished(Box::new(result)),
        Err(_) => CheckEvent::TimedOut,
    };
    let _ = tx.send(event);
}

/// `port` is what the tab holds for this section's own picker. A Check that does not take the
/// chosen port keeps the system port, so the automatic TLS row is the service on 443 whatever
/// port the picker holds. The target kind, the rep's proxy and DKIM selectors go to every Check;
/// each takes them or ignores them.
fn request_for<'a>(
    check: &Check,
    name: &'a str,
    kind: Kind,
    query: Duration,
    bootstrap: &'a [SocketAddr],
    port: u16,
    settings: &'a Settings,
) -> Request<'a> {
    let request = Request {
        kind,
        proxy: settings.proxy.as_deref(),
        selectors: &settings.selectors,
        ..Request::system(name, query, bootstrap)
    };
    if check.takes_chosen_port { Request { port, ..request } } else { request }
}

async fn produce(section: Section, name: &str, kind: Kind, settings: &Settings, port: u16) -> Result<Outcome, String> {
    let query = budget(section, settings.timeout).query;
    let bootstrap: Vec<SocketAddr> = default_resolvers().iter().map(|r| r.address).collect();
    match section.check() {
        Some(check) => check.run(&request_for(check, name, kind, query, &bootstrap, port, settings)).await,
        None => Err(format!("{} has no Check behind it", section.label())),
    }
}

#[cfg(test)]
mod tests {
    use zombo_core::{dnssec, smtp, tls};

    use super::*;

    fn t(value: &str, kind: Kind) -> Target {
        Target { value: value.into(), kind }
    }

    #[test]
    fn propagation_asks_about_the_name_behind_the_target() {
        assert_eq!(check_name(&t("example.com", Kind::Domain)).as_deref(), Some("example.com"));
        assert_eq!(check_name(&t("www.example.com", Kind::Hostname)).as_deref(), Some("www.example.com"));
        assert_eq!(check_name(&t("a@example.com", Kind::Email)).as_deref(), Some("example.com"));
        assert_eq!(check_name(&t("192.0.2.1", Kind::Ip)), None);
    }

    #[test]
    fn a_domain_runs_every_check_and_a_host_name_the_short_list() {
        assert_eq!(automatic(Kind::Domain).len(), 7);
        assert_eq!(automatic(Kind::Email), automatic(Kind::Domain));
        assert_eq!(automatic(Kind::Hostname), [Section::Dns, Section::Web, Section::Tls, Section::Registration]);
        assert_eq!(automatic(Kind::Ip), [Section::Rdns]);
        assert!(automatic(Kind::Domain).iter().all(|s| wired(*s) && !s.is_on_demand()));
    }

    /// A label over 63 bytes is not a DNS name, so the Check fails before it sends a query.
    #[tokio::test]
    async fn a_section_with_a_descriptor_runs_the_descriptor() {
        let name = format!("{}.example.com", "a".repeat(64));
        let err = produce(Section::Dnssec, &name, Kind::Hostname, &Settings::default(), 443).await.unwrap_err();
        assert_eq!(err, format!("no nameservers found for {name}"));
        let err = produce(Section::Summary, &name, Kind::Hostname, &Settings::default(), 443).await.unwrap_err();
        assert_eq!(err, "Summary has no Check behind it");
    }

    fn request_with<'a>(check: &Check, port: u16, settings: &'a Settings) -> Request<'a> {
        request_for(check, "example.com", Kind::Domain, Duration::from_secs(1), &[], port, settings)
    }

    #[test]
    fn only_the_checks_that_take_the_picked_port_get_it() {
        let settings = Settings::default();
        let port = |c| request_with(c, 993, &settings).port;
        let (tls, on_port, dnssec, smtp) =
            (port(&tls::CHECK), port(&tls::ON_PORT), port(&dnssec::CHECK), port(&smtp::CHECK));
        assert_eq!((tls, on_port, dnssec, smtp), (443, 993, 443, 993));
        for section in Section::ALL {
            if let Some(check) = section.check() {
                assert_eq!(port(check) == 993, check.takes_chosen_port, "{section:?}");
            }
        }
    }

    #[test]
    fn every_check_is_handed_the_kind_of_the_target() {
        let settings = Settings::default();
        for kind in [Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip] {
            for section in Section::ALL {
                if let Some(check) = section.check() {
                    let request = request_for(check, "example.com", kind, Duration::from_secs(1), &[], 25, &settings);
                    assert_eq!(request.kind, kind, "{section:?}");
                }
            }
        }
    }

    #[test]
    fn every_check_is_handed_the_rep_proxy() {
        let settings = Settings { proxy: Some("http://proxy.example:3128".into()), ..Settings::default() };
        let proxy = |c| request_with(c, 443, &settings).proxy;
        for section in Section::ALL {
            if let Some(check) = section.check() {
                assert_eq!(proxy(check), Some("http://proxy.example:3128"), "{section:?}");
            }
        }
        let none = Settings::default();
        assert_eq!(request_with(&dnssec::CHECK, 443, &none).proxy, None);
    }

    #[test]
    fn every_check_is_handed_the_rep_dkim_selectors() {
        let settings = Settings { selectors: vec!["acme2024".into(), "mail.k1".into()], ..Settings::default() };
        let request = |c| request_with(c, 443, &settings);
        for section in Section::ALL {
            if let Some(check) = section.check() {
                assert_eq!(request(check).selectors, ["acme2024", "mail.k1"], "{section:?}");
            }
        }
        let none = Settings::default();
        assert!(request_with(&dnssec::CHECK, 443, &none).selectors.is_empty());
    }

    #[test]
    fn an_ip_target_runs_reverse_dns_on_its_own_and_no_other_target_does() {
        assert_eq!(automatic(Kind::Ip), [Section::Rdns]);
        for kind in [Kind::Domain, Kind::Hostname, Kind::Email] {
            assert!(!automatic(kind).contains(&Section::Rdns), "{kind:?}");
        }
        let ip = t("192.0.2.1", Kind::Ip);
        assert_eq!(name_for(Section::Rdns, &ip).as_deref(), Some("192.0.2.1"));
        assert_eq!(name_for(Section::Dns, &ip), None, "the DNS Check still needs a name");
    }

    #[test]
    fn an_on_demand_check_is_never_watched() {
        assert!(Section::ALL.iter().filter(|s| s.is_on_demand()).all(|s| !watchable(*s)));
        assert!(watchable(Section::Dns) && watchable(Section::Web));
        assert!(!watchable(Section::Summary));
    }

    #[test]
    fn no_on_demand_check_is_ever_automatic() {
        for kind in [Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip] {
            assert!(automatic(kind).iter().all(|s| !s.is_on_demand()));
        }
    }

    #[test]
    fn an_on_demand_check_can_be_asked_about_an_ip_but_an_automatic_one_cannot() {
        let ip = t("192.0.2.1", Kind::Ip);
        assert_eq!(name_for(Section::Ports, &ip).as_deref(), Some("192.0.2.1"));
        assert_eq!(name_for(Section::Blacklist, &ip).as_deref(), Some("192.0.2.1"));
        assert_eq!(name_for(Section::Dnssec, &ip), None);
        assert_eq!(name_for(Section::Smtp, &t("a@example.com", Kind::Email)).as_deref(), Some("example.com"));
    }

    #[test]
    fn nothing_on_demand_starts_with_a_target_whatever_its_kind() {
        for kind in [Kind::Domain, Kind::Hostname, Kind::Email, Kind::Ip] {
            for s in crate::ondemand::on_demand(kind) {
                assert!(s.is_on_demand() && wired(*s), "{s:?}");
                assert!(!automatic(kind).contains(s), "{s:?} would start by itself for {kind:?}");
            }
        }
    }

    #[test]
    fn the_rep_s_resolvers_join_the_ten_public_ones_without_repeating_any() {
        let own: SocketAddr = "192.0.2.53:53".parse().unwrap();
        let already: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let all = propagation_resolvers(&[own, already, own]);
        assert_eq!(all.len(), default_resolvers().len() + 1);
        assert_eq!(all.last().map(|v| v.address), Some(own));
        assert_eq!(all.iter().filter(|v| v.address == already).count(), 1);
        assert_eq!(propagation_resolvers(&[]).len(), default_resolvers().len());
    }
}
