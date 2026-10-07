use std::path::Path;

use c2pa_check_core::report::TrustSelector;
use c2pa_check_core::{Options, TrustBundle, Verifier};

fn verifier() -> Verifier {
    Verifier::new(&TrustBundle::default(), TrustSelector::None).expect("a verifier with no anchors")
}

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);

    std::fs::read(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

#[test]
fn an_asset_without_a_manifest_is_still_absent_without_a_remote_store() {
    let report = verifier()
        .verify(
            &fixture("jpeg/no-manifest.jpg"),
            "image/jpeg",
            &Options::default(),
        )
        .expect("a report");

    assert_eq!(report.credential.status.as_str(), "absent");
}

#[test]
fn a_remote_store_larger_than_the_manifest_limit_is_refused_before_parsing() {
    let options = Options {
        max_manifest_bytes: 16,
        ..Options::default()
    };

    let err = verifier()
        .verify_with_manifest(
            &fixture("jpeg/no-manifest.jpg"),
            "image/jpeg",
            &[0u8; 17],
            &options,
        )
        .expect_err("an oversized remote store");

    assert_eq!(err.code(), "limit_exceeded");
}

#[test]
fn a_remote_store_that_is_not_jumbf_is_a_parse_failure_not_an_absent_credential() {
    let err = verifier()
        .verify_with_manifest(
            &fixture("jpeg/no-manifest.jpg"),
            "image/jpeg",
            b"not a c2pa manifest store",
            &Options::default(),
        )
        .expect_err("garbage is not a manifest store");

    assert_eq!(err.code(), "parse_failed");
}
