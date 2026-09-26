use std::path::{Path, PathBuf};

use c2pa_check_core::report::TrustSelector;
use c2pa_check_core::{media, Options, Report, TrustBundle, Verifier};
use serde_json::Value;

const MEDIA_EXTENSIONS: &[&str] = &["jpg", "jpeg", "png", "webp", "avif", "tif", "tiff", "mp4"];

struct Fixture {
    path: PathBuf,
    expected: Value,
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn collect(dir: &Path, into: &mut Vec<Fixture>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|err| panic!("{}: {err}", dir.display()));

    for entry in entries {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            collect(&path, into);

            continue;
        }

        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !MEDIA_EXTENSIONS.contains(&extension.as_str()) {
            continue;
        }

        let expected_path = path.parent().expect("a parent directory").join(format!(
            "{}.expected.json",
            path.file_stem()
                .and_then(|value| value.to_str())
                .expect("a file stem")
        ));
        assert!(
            expected_path.exists(),
            "{} has no expected document at {}",
            path.display(),
            expected_path.display()
        );

        let raw = std::fs::read_to_string(&expected_path)
            .unwrap_or_else(|err| panic!("{}: {err}", expected_path.display()));
        into.push(Fixture {
            path,
            expected: serde_json::from_str(&raw)
                .unwrap_or_else(|err| panic!("{}: {err}", expected_path.display())),
        });
    }
}

fn fixtures() -> Vec<Fixture> {
    let mut out = Vec::new();
    collect(&corpus_root(), &mut out);
    out.sort_by(|a, b| a.path.cmp(&b.path));

    assert!(!out.is_empty(), "the corpus is empty");

    out
}

fn verifier() -> Verifier {
    let bundle = TrustBundle::bundled();

    Verifier::new(&bundle, TrustSelector::Official)
        .or_else(|_| Verifier::new(&TrustBundle::default(), TrustSelector::None))
        .expect("a verifier with no anchors always builds")
}

fn run(verifier: &Verifier, fixture: &Fixture) -> Result<Report, c2pa_check_core::Error> {
    let bytes = std::fs::read(&fixture.path)
        .unwrap_or_else(|err| panic!("{}: {err}", fixture.path.display()));
    let mime = media::mime_from_extension(fixture.path.to_str().expect("a utf-8 fixture path"));

    verifier.verify(&bytes, mime, &Options::default())
}

#[test]
fn every_fixture_produces_the_document_recorded_beside_it() {
    let verifier = verifier();

    for fixture in fixtures() {
        let name = fixture.path.display().to_string();
        let outcome = run(&verifier, &fixture);

        match (
            fixture.expected.get("credential").and_then(Value::as_str),
            fixture.expected.get("error").and_then(Value::as_str),
        ) {
            (Some(status), None) => {
                let report = outcome
                    .unwrap_or_else(|err| panic!("{name}: expected {status}, got error {err}"));

                assert_eq!(report.credential.status.as_str(), status, "{name}");
            }
            (None, Some(code)) => {
                let err = outcome
                    .err()
                    .unwrap_or_else(|| panic!("{name}: expected error {code}, got a report"));

                assert_eq!(err.code(), code, "{name}");
            }
            _ => panic!("{name}: the expected document needs exactly one of credential or error"),
        }
    }
}

#[test]
fn a_trusted_expectation_is_never_silently_skipped() {
    let anchored = Verifier::new(&TrustBundle::bundled(), TrustSelector::Official).is_ok();

    for fixture in fixtures() {
        let expects_trust = fixture
            .expected
            .get("credential")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "valid_trusted");

        assert!(
            !expects_trust || anchored,
            "{} expects valid_trusted but the bundled trust list does not load; \
             run cli/scripts/fetch-trust-list.sh",
            fixture.path.display()
        );
    }
}

#[test]
fn every_fixture_is_small_enough_to_stay_in_the_repository() {
    const MAX_FIXTURE_BYTES: u64 = 2 * 1024 * 1024;

    for fixture in fixtures() {
        let size = std::fs::metadata(&fixture.path)
            .expect("a readable fixture")
            .len();

        assert!(
            size <= MAX_FIXTURE_BYTES,
            "{} is {size} bytes",
            fixture.path.display()
        );
    }
}

#[test]
fn the_corpus_covers_every_container_the_reader_accepts() {
    let covered: Vec<String> = fixtures()
        .iter()
        .filter_map(|fixture| {
            fixture
                .path
                .extension()
                .and_then(|value| value.to_str())
                .map(str::to_ascii_lowercase)
        })
        .collect();

    for extension in ["jpg", "png", "webp"] {
        assert!(
            covered.iter().any(|found| found == extension),
            "no {extension} fixture"
        );
    }
}
