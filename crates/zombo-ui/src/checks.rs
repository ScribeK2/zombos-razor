use std::{net::SocketAddr, time::Duration};

use tokio::sync::mpsc::UnboundedSender;
use zombo_core::{
    propagation::{Scope, default_resolvers, discover_nameservers, propagation_with},
    target::{Kind, Target},
};

use crate::diagnosis::PropEvent;

const PER_VANTAGE: Duration = Duration::from_secs(4);
const WHOLE_CHECK: Duration = Duration::from_secs(20);

pub fn propagation_name(target: &Target) -> Option<String> {
    match target.kind {
        Kind::Domain | Kind::Hostname => Some(target.value.clone()),
        Kind::Email => target.value.split_once('@').map(|(_, d)| d.to_string()),
        Kind::Ip => None,
    }
}

pub async fn run_propagation(target: String, tx: UnboundedSender<PropEvent>) {
    let _ = tx.send(PropEvent::Started);
    let work = async {
        let resolvers = default_resolvers();
        let bootstrap: Vec<SocketAddr> = resolvers.iter().map(|r| r.address).collect();
        let nameservers = discover_nameservers(&bootstrap, &target, 53, PER_VANTAGE).await.unwrap_or_default();
        propagation_with(&resolvers, &nameservers, &target, Scope::All, PER_VANTAGE, |a| {
            let _ = tx.send(PropEvent::Answer(Box::new(a.clone())));
        })
        .await
        .map_err(|e| e.to_string())
    };
    let event = match tokio::time::timeout(WHOLE_CHECK, work).await {
        Ok(result) => PropEvent::Finished(Box::new(result)),
        Err(_) => PropEvent::TimedOut,
    };
    let _ = tx.send(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(value: &str, kind: Kind) -> Target {
        Target { value: value.into(), kind }
    }

    #[test]
    fn propagation_asks_about_the_name_behind_the_target() {
        assert_eq!(propagation_name(&t("example.com", Kind::Domain)).as_deref(), Some("example.com"));
        assert_eq!(propagation_name(&t("www.example.com", Kind::Hostname)).as_deref(), Some("www.example.com"));
        assert_eq!(propagation_name(&t("a@example.com", Kind::Email)).as_deref(), Some("example.com"));
        assert_eq!(propagation_name(&t("192.0.2.1", Kind::Ip)), None);
    }
}
