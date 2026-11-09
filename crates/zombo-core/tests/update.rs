//! The signed self-update against a fake release server over https. Every rejection leaves the
//! installed AppImage byte for byte as it was, with nothing else beside it.

#[path = "common/update.rs"]
mod fake;
#[path = "common/tls.rs"]
mod pki;

use std::{os::unix::fs::PermissionsExt, time::Duration};

use fake::{Fixture, Install, OLD, Reply, TestKey, serve};
use zombo_core::update::{self, Available, Endpoints, UpdateError, Version};

const NEW: &[u8] = b"#!/bin/sh\necho new version\n";

fn running() -> Version {
    Version::parse("1.2.3").unwrap()
}

async fn check(ep: Endpoints) -> Result<Option<Available>, UpdateError> {
    tokio::task::spawn_blocking(move || update::check(&ep, &running())).await.unwrap()
}

async fn install(ep: Endpoints, rel: Available, target: std::path::PathBuf) -> Result<(), UpdateError> {
    tokio::task::spawn_blocking(move || update::install(&ep, &rel, &target)).await.unwrap()
}

/// Check, then install into a fresh directory. The error of whichever step failed.
async fn run(
    key: &TestKey,
    signed_with: &TestKey,
    tweak: impl Fn(Fixture) -> Fixture + Send + Sync + 'static,
    route: impl Fn(&Fixture, &str, u16) -> Option<Reply> + Send + Sync + 'static,
) -> (Result<(), UpdateError>, Install) {
    let fx = tweak(Fixture::signed("1.4.0", NEW, signed_with));
    let server = serve(move |p, port| route(&fx, p, port).unwrap_or_else(|| fx.reply(p, port))).await;
    let ep = server.endpoints(key);
    let inst = Install::new("run");
    let result = match check(ep.clone()).await {
        Ok(Some(rel)) => install(ep, rel, inst.path.clone()).await,
        Ok(None) => panic!("no update offered"),
        Err(e) => Err(e),
    };
    (result, inst)
}

fn plain(_: &Fixture, _: &str, _: u16) -> Option<Reply> {
    None
}

#[tokio::test]
async fn a_signed_newer_release_replaces_the_file_atomically_and_keeps_its_mode() {
    let key = TestKey::random();
    let (result, inst) = run(&key, &key, |f| f, plain).await;
    result.unwrap();
    assert_eq!(std::fs::read(&inst.path).unwrap(), NEW);
    assert_eq!(std::fs::metadata(&inst.path).unwrap().permissions().mode() & 0o7777, 0o750);
    let left: Vec<_> = std::fs::read_dir(&inst.dir).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(left.len(), 1, "nothing else is kept: {left:?}");
}

#[tokio::test]
async fn the_check_names_the_version_notes_and_release_page_and_sends_an_honest_request() {
    let key = TestKey::random();
    let mut fx = Fixture::signed("1.4.0", NEW, &key);
    fx.notes = format!("Big news\u{1b}[31m {}", "y".repeat(900));
    let f2 = fx.clone();
    let server = serve(move |p, port| f2.reply(p, port)).await;
    let rel = check(server.endpoints(&key)).await.unwrap().unwrap();
    assert_eq!(rel.version.to_string(), "1.4.0");
    assert!(rel.notes.starts_with("Big news[31m yyy") && rel.notes.ends_with("..."), "{}", rel.notes);
    assert!(!rel.notes.chars().any(char::is_control));
    assert!(rel.page_url.ends_with("/releases/tag/v1.4.0"), "{}", rel.page_url);
    let seen = server.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let header = |n: &str| seen[0].iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(header("user-agent").as_deref(), Some("zombo/0.0.1"));
    assert!(header("cookie").is_none());
}

#[tokio::test]
async fn an_older_or_equal_release_is_no_update() {
    let key = TestKey::random();
    for v in ["1.2.3", "1.0.0"] {
        let fx = Fixture::signed(v, NEW, &key);
        let server = serve(move |p, port| fx.reply(p, port)).await;
        assert_eq!(check(server.endpoints(&key)).await.unwrap(), None, "{v}");
    }
}

#[tokio::test]
async fn an_old_signed_release_replayed_as_a_new_one_is_a_downgrade_and_is_refused() {
    let key = TestKey::embedded();
    let (result, inst) = run(
        &key,
        &key,
        |_| {
            let mut old = Fixture::signed("1.0.0", NEW, &TestKey::embedded());
            old.tag = "v1.4.0".into();
            old
        },
        plain,
    )
    .await;
    assert!(matches!(result, Err(UpdateError::WrongVersion { .. })), "{result:?}");
    assert!(inst.untouched());
}

#[tokio::test]
async fn a_signature_by_another_key_is_refused() {
    let (trusted, attacker) = (TestKey::random(), TestKey::random());
    let (result, inst) = run(&trusted, &attacker, |f| f, plain).await;
    assert!(matches!(result, Err(UpdateError::BadSignature(_))), "{result:?}");
    assert!(inst.untouched());
}

#[tokio::test]
async fn sums_changed_after_signing_are_refused() {
    let key = TestKey::random();
    let (result, inst) = run(
        &key,
        &key,
        |mut f| {
            let at = f.sums.iter().position(|b| b.is_ascii_hexdigit()).unwrap();
            f.sums[at] = if f.sums[at] == b'0' { b'1' } else { b'0' };
            f
        },
        plain,
    )
    .await;
    assert!(matches!(result, Err(UpdateError::BadSignature(_))), "{result:?}");
    assert!(inst.untouched());
}

#[tokio::test]
async fn a_signature_made_over_different_sums_is_refused() {
    let key = TestKey::embedded();
    let (result, inst) = run(
        &key,
        &key,
        |mut f| {
            f.sig = TestKey::embedded().sign(b"some other SHA256SUMS\n", "zombo-razor 1.4.0");
            f
        },
        plain,
    )
    .await;
    assert!(matches!(result, Err(UpdateError::BadSignature(_))), "{result:?}");
    assert!(inst.untouched());
}

#[tokio::test]
async fn a_tampered_binary_fails_the_signed_checksum() {
    let key = TestKey::random();
    let (result, inst) = run(
        &key,
        &key,
        |mut f| {
            f.appimage.extend_from_slice(b"# evil\n");
            f
        },
        plain,
    )
    .await;
    assert!(matches!(result, Err(UpdateError::ChecksumMismatch)), "{result:?}");
    assert!(inst.untouched(), "the temp file is gone and the old file is intact");
}

#[tokio::test]
async fn a_truncated_download_is_refused() {
    let key = TestKey::random();
    let (result, inst) = run(
        &key,
        &key,
        |f| f,
        |fx, p, _| {
            (p == format!("/dl/{}", fx.name)).then(|| Reply {
                declared_len: Some(fx.appimage.len()),
                body: fx.appimage[..8].to_vec(),
                ..Reply::ok(vec![])
            })
        },
    )
    .await;
    assert!(matches!(result, Err(UpdateError::Truncated)), "{result:?}");
    assert!(inst.untouched());
}

#[tokio::test]
async fn a_download_that_ends_cleanly_but_short_is_refused() {
    let key = TestKey::random();
    let (result, inst) = run(
        &key,
        &key,
        |f| f,
        |fx, p, _| {
            (p == format!("/dl/{}", fx.name)).then(|| Reply { chunked: true, ..Reply::ok(fx.appimage[..8].to_vec()) })
        },
    )
    .await;
    assert!(matches!(result, Err(UpdateError::Truncated)), "{result:?}");
    assert!(inst.untouched());
}

#[tokio::test]
async fn an_oversize_appimage_is_refused_by_its_declared_and_by_its_actual_size() {
    let key = TestKey::random();
    let big = vec![b'x'; 2 * 1024 * 1024];
    let big2 = big.clone();
    // Declared by Content-Length.
    let (result, inst) =
        run(&key, &key, |f| f, move |fx, p, _| (p == format!("/dl/{}", fx.name)).then(|| Reply::ok(big.clone()))).await;
    assert!(matches!(result, Err(UpdateError::TooLarge { .. })), "{result:?}");
    assert!(inst.untouched());
    // Chunked, so only the bytes themselves say how big it is.
    let (result, inst) = run(
        &key,
        &key,
        |f| f,
        move |fx, p, _| (p == format!("/dl/{}", fx.name)).then(|| Reply { chunked: true, ..Reply::ok(big2.clone()) }),
    )
    .await;
    assert!(matches!(result, Err(UpdateError::TooLarge { .. })), "{result:?}");
    assert!(inst.untouched());
}

#[tokio::test]
async fn an_oversize_release_list_is_refused() {
    let key = TestKey::random();
    let fx = Fixture::signed("1.4.0", NEW, &key);
    let server = serve(
        move |p, port| {
            if p.contains("/releases") { Reply::ok(vec![b' '; 300 * 1024]) } else { fx.reply(p, port) }
        },
    )
    .await;
    let r = check(server.endpoints(&key)).await;
    assert!(matches!(r, Err(UpdateError::TooLarge { .. })), "{r:?}");
}

#[tokio::test]
async fn a_redirect_to_http_is_refused() {
    let key = TestKey::random();
    let (result, inst) = run(
        &key,
        &key,
        |f| f,
        |fx, p, _| (p == format!("/dl/{}", fx.name)).then(|| Reply::redirect("http://127.0.0.1:9/evil")),
    )
    .await;
    assert!(matches!(result, Err(UpdateError::Insecure(_))), "{result:?}");
    assert!(inst.untouched());
}

#[tokio::test]
async fn a_redirect_loop_stops() {
    let key = TestKey::random();
    let fx = Fixture::signed("1.4.0", NEW, &key);
    let server = serve(move |p, port| {
        if p.contains("/releases") {
            Reply::redirect(&format!("https://127.0.0.1:{port}/repos/owner/repo/releases?again"))
        } else {
            fx.reply(p, port)
        }
    })
    .await;
    let r = check(server.endpoints(&key)).await;
    assert!(matches!(r, Err(UpdateError::TooManyRedirects)), "{r:?}");
}

#[tokio::test]
async fn a_malformed_api_reply_is_refused() {
    let key = TestKey::random();
    for body in [
        "not json",
        "{}",
        r#"[{"tag_name":"v9.0.0"}]"#,
        r#"[{"tag_name":7,"draft":false,"prerelease":false,"html_url":"x","assets":[]}]"#,
    ] {
        let server = serve(move |_, _| Reply::ok(body.as_bytes().to_vec())).await;
        let r = check(server.endpoints(&key)).await;
        assert!(matches!(r, Err(UpdateError::BadRelease(_))), "{body}: {r:?}");
    }
}

#[tokio::test]
async fn an_http_status_is_an_error_not_an_update() {
    let key = TestKey::random();
    let server = serve(move |_, _| Reply { status: 500, ..Reply::ok(vec![]) }).await;
    let r = check(server.endpoints(&key)).await;
    assert!(matches!(r, Err(UpdateError::Status(500))), "{r:?}");
}

#[tokio::test]
async fn a_server_that_stalls_hits_the_deadline() {
    let key = TestKey::random();
    let server = serve(move |_, _| Reply { delay: Duration::from_secs(5), ..Reply::ok(vec![]) }).await;
    let mut ep = server.endpoints(&key);
    ep.metadata_deadline = Duration::from_millis(400);
    let r = check(ep).await;
    assert!(matches!(r, Err(UpdateError::TimedOut)), "{r:?}");
}

#[tokio::test]
async fn a_certificate_from_an_untrusted_authority_is_refused() {
    let key = TestKey::random();
    let fx = Fixture::signed("1.4.0", NEW, &key);
    let server = serve(move |p, port| fx.reply(p, port)).await;
    let mut ep = server.endpoints(&key);
    ep.roots = Some(vec![pki::Ca::root("Somebody Else").der().to_vec()]);
    let r = check(ep).await;
    assert!(matches!(r, Err(UpdateError::Network(_))), "{r:?}");
}

#[tokio::test]
async fn an_unwritable_directory_fails_cleanly_and_leaves_the_old_file() {
    let key = TestKey::random();
    let fx = Fixture::signed("1.4.0", NEW, &key);
    let server = serve(move |p, port| fx.reply(p, port)).await;
    let ep = server.endpoints(&key);
    let rel = check(ep.clone()).await.unwrap().unwrap();
    let inst = Install::new("ro");
    std::fs::set_permissions(&inst.dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    if std::fs::File::create(inst.dir.join("probe")).is_ok() {
        return; // running as root: the directory is writable anyway
    }
    let r = install(ep, rel, inst.path.clone()).await;
    assert!(matches!(r, Err(UpdateError::Write(_))), "{r:?}");
    assert_eq!(std::fs::read(&inst.path).unwrap(), OLD);
}

#[cfg(not(feature = "release-key-required"))]
#[test]
fn the_embedded_key_is_the_one_the_tests_sign_with_until_the_real_key_replaces_it() {
    let want = TestKey::embedded().public_file();
    assert_eq!(
        update::PUBLIC_KEY.lines().nth(1),
        want.lines().nth(1),
        "update_key.pub must hold the TEST key; second line should be {:?}",
        want.lines().nth(1)
    );
}
