#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
//! Not run by default: asks the real GitHub release API as a running 0.1.0-rc1 would.
//! `cargo test -p zombo-core --test update_live -- --ignored --nocapture`
use zombo_core::update::{self, Endpoints, Version};

#[test]
#[ignore]
fn the_real_release_list_offers_the_next_release_candidate() {
    let current = Version::parse("0.1.0-rc1").unwrap();
    let ep = Endpoints::real(&current);
    let r = update::check_in(&ep, &current, false);
    println!("{r:#?}");
    assert!(matches!(r, Ok(Some(_))), "{r:?}");
}
