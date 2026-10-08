use std::io::Cursor;

use c2pa::Signer as _;
use c2pa_check_core::carry::{
    self, generate_identity, local_signer, new_placeholder, pem_chain_to_der, CarryError,
    CarryInput, CarryOptions, DeferredSigner, LocalIdentity,
};
use c2pa_check_core::report::{CredentialStatus, TrustSelector};
use c2pa_check_core::{Options, TrustBundle, Verifier};
use image::codecs::jpeg::JpegEncoder;
use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use serde_json::{json, Value};

const AI_SOURCE: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia";

fn verifier() -> Verifier {
    Verifier::new(&TrustBundle::default(), TrustSelector::None).expect("a verifier")
}

fn scene(width: u32, height: u32, shift: f32) -> DynamicImage {
    let waves: Vec<(f32, f32, f32, f32)> = (0..24u32)
        .map(|k| {
            let a = (k as f32 * 2.399).sin().abs() * 9.0 + 1.0;
            let b = (k as f32 * 1.618).cos().abs() * 9.0 + 1.0;
            let phase = k as f32 * 0.7 + shift;
            let weight = 1.0 / (1.0 + k as f32 * 0.15);
            (a, b, phase, weight)
        })
        .collect();
    DynamicImage::ImageRgb8(RgbImage::from_fn(width, height, |x, y| {
        let fx = x as f32 / width as f32;
        let fy = y as f32 / height as f32;
        let v: f32 = waves
            .iter()
            .map(|(a, b, phase, weight)| {
                weight
                    * (a * fx * std::f32::consts::TAU + phase).sin()
                    * (b * fy * std::f32::consts::TAU - phase).cos()
            })
            .sum();
        let l = (v * 40.0 + 128.0).clamp(0.0, 255.0);
        Rgb([
            l as u8,
            (l * 0.8 + fx * 50.0) as u8,
            (255.0 - l * 0.6) as u8,
        ])
    }))
}

fn unrelated(width: u32, height: u32) -> DynamicImage {
    let image = scene(height, width, 0.37).rotate90();
    image.resize_exact(width, height, image::imageops::FilterType::Triangle)
}

fn encode(image: &DynamicImage, format: ImageFormat) -> Vec<u8> {
    let mut out = Cursor::new(Vec::new());
    image.write_to(&mut out, format).expect("encodes");
    out.into_inner()
}

fn jpeg(image: &DynamicImage) -> Vec<u8> {
    let mut out = Vec::new();
    image
        .write_with_encoder(JpegEncoder::new_with_quality(&mut out, 85))
        .expect("jpeg encodes");
    out
}

fn sign_generated(png: Vec<u8>, identity: &LocalIdentity) -> Vec<u8> {
    let signer = local_signer(&identity.chain_pem, &identity.key_pem, None).expect("signer");
    let context = c2pa::Context::new()
        .with_settings(json!({"builder": {"thumbnail": {"enabled": false}}}))
        .expect("context");
    let mut builder = c2pa::Builder::from_context(context)
        .with_definition(json!({
            "claim_generator_info": [{"name": "test-generator", "version": "1"}],
            "title": "generated.png",
            "format": "image/png",
            "assertions": [{"label": "c2pa.actions", "data": {"actions": [
                {"action": "c2pa.created", "digitalSourceType": AI_SOURCE}
            ]}}]
        }))
        .expect("definition");
    let mut out = Cursor::new(Vec::new());
    builder
        .sign(
            signer.as_ref(),
            "image/png",
            &mut Cursor::new(png),
            &mut out,
        )
        .expect("generator signs");
    out.into_inner()
}

fn generated() -> (Vec<u8>, DynamicImage) {
    let image = scene(800, 600, 0.0);
    let identity = generate_identity("Test Generator").expect("generator identity");
    (
        sign_generated(encode(&image, ImageFormat::Png), &identity),
        image,
    )
}

fn options() -> CarryOptions {
    CarryOptions {
        force: false,
        title: Some("hero.jpg".into()),
        max_pixels: 100_000_000,
    }
}

fn actions(report: &c2pa_check_core::Report) -> Vec<String> {
    report.actions.iter().map(|a| a.action.clone()).collect()
}

#[test]
fn a_png_carried_to_jpeg_keeps_its_parent_and_says_what_changed() {
    let (source, image) = generated();
    let derived = jpeg(&image.resize_exact(400, 300, image::imageops::FilterType::Triangle));
    let identity = generate_identity("Carry Test").expect("identity");
    let signer = local_signer(&identity.chain_pem, &identity.key_pem, None).expect("signer");

    let outcome = carry::carry(
        &source,
        "image/png",
        &derived,
        "image/jpeg",
        signer.as_ref(),
        &options(),
    )
    .expect("carried");

    assert_eq!(
        outcome.actions,
        ["c2pa.opened", "c2pa.transcoded", "c2pa.resized"]
    );
    assert!(outcome.distance.is_some_and(|d| d <= 31));

    let report = verifier()
        .verify(&outcome.bytes, "image/jpeg", &Options::default())
        .expect("a report");
    assert_eq!(report.credential.status, CredentialStatus::ValidUntrusted);
    assert_eq!(report.ingredients.len(), 1);
    assert_eq!(
        report.ingredients[0].relationship.as_deref(),
        Some("parentOf")
    );
    assert_eq!(
        report.ingredients[0].credential_status,
        Some(CredentialStatus::ValidUntrusted)
    );
    for action in ["c2pa.opened", "c2pa.transcoded", "c2pa.resized"] {
        assert!(actions(&report).contains(&action.to_string()), "{action}");
    }
}

#[test]
fn a_carried_file_is_recognised_so_a_rerun_skips_it() {
    let (source, image) = generated();
    let derived = jpeg(&image);
    let identity = generate_identity("Carry Test").expect("identity");
    let signer = local_signer(&identity.chain_pem, &identity.key_pem, None).expect("signer");

    let outcome = carry::carry(
        &source,
        "image/png",
        &derived,
        "image/jpeg",
        signer.as_ref(),
        &options(),
    )
    .expect("carried");

    assert!(carry::already_carried(
        &source,
        "image/png",
        &outcome.bytes,
        "image/jpeg"
    ));
    assert!(!carry::already_carried(
        &source,
        "image/png",
        &derived,
        "image/jpeg"
    ));
}

#[test]
fn a_png_carried_to_webp_at_the_same_size_is_not_called_resized() {
    let (source, image) = generated();
    let derived = encode(&image, ImageFormat::WebP);
    let identity = generate_identity("Carry Test").expect("identity");
    let signer = local_signer(&identity.chain_pem, &identity.key_pem, None).expect("signer");

    let outcome = carry::carry(
        &source,
        "image/png",
        &derived,
        "image/webp",
        signer.as_ref(),
        &options(),
    )
    .expect("carried");

    assert_eq!(outcome.actions, ["c2pa.opened", "c2pa.transcoded"]);
    let report = verifier()
        .verify(&outcome.bytes, "image/webp", &Options::default())
        .expect("a report");
    assert_eq!(report.credential.status, CredentialStatus::ValidUntrusted);
}

#[test]
fn an_unsigned_source_has_nothing_to_carry() {
    let image = scene(800, 600, 0.0);
    let identity = generate_identity("Carry Test").expect("identity");
    let signer = local_signer(&identity.chain_pem, &identity.key_pem, None).expect("signer");

    let err = carry::carry(
        &encode(&image, ImageFormat::Png),
        "image/png",
        &jpeg(&image),
        "image/jpeg",
        signer.as_ref(),
        &options(),
    )
    .unwrap_err();

    assert!(matches!(err, CarryError::NoSourceCredential));
    assert!(err.refused());
}

#[test]
fn a_different_picture_is_refused() {
    let (source, image) = generated();
    let identity = generate_identity("Carry Test").expect("identity");
    let signer = local_signer(&identity.chain_pem, &identity.key_pem, None).expect("signer");

    let err = carry::carry(
        &source,
        "image/png",
        &jpeg(&unrelated(image.width(), image.height())),
        "image/jpeg",
        signer.as_ref(),
        &options(),
    )
    .unwrap_err();

    assert!(matches!(err, CarryError::DifferentPicture(d) if d > 31));
}

#[test]
fn the_local_identity_passes_the_c2pa_certificate_profile() {
    let identity = generate_identity("Profile Test").expect("identity");
    let source = sign_generated(encode(&scene(800, 600, 0.0), ImageFormat::Png), &identity);

    let report = verifier()
        .verify(&source, "image/png", &Options::default())
        .expect("a report");

    assert_eq!(report.credential.status, CredentialStatus::ValidUntrusted);
    assert!(report
        .validation
        .errors
        .iter()
        .all(|e| !e.code.starts_with("signingCredential.invalid")));
}

struct Hosted {
    identity: LocalIdentity,
    placeholder: [u8; 64],
    pending: Vec<u8>,
    tbs: Vec<u8>,
}

impl Hosted {
    fn signature(&self) -> Vec<u8> {
        let signer = local_signer(&self.identity.chain_pem, &self.identity.key_pem, None)
            .expect("org signer");
        signer.sign(&self.tbs).expect("signature")
    }
}

fn hosted(source: &[u8], derived: &[u8], derived_mime: &str) -> Hosted {
    let identity = generate_identity("acme.example via c2pa.design").expect("identity");
    let placeholder = new_placeholder().expect("placeholder");
    let signer = DeferredSigner::new(
        pem_chain_to_der(&identity.chain_pem).expect("chain"),
        placeholder,
    );

    let outcome = carry::carry(
        source,
        "image/png",
        derived,
        derived_mime,
        &signer,
        &options(),
    )
    .expect("pending carry");

    Hosted {
        identity,
        placeholder,
        tbs: signer.take_tbs().expect("tbs captured"),
        pending: outcome.bytes,
    }
}

fn forged(
    source: &[u8],
    derived: &[u8],
    definition: Value,
    extra_ingredient: Option<&[u8]>,
) -> Hosted {
    let identity = generate_identity("acme.example via c2pa.design").expect("identity");
    let placeholder = new_placeholder().expect("placeholder");
    let signer = DeferredSigner::new(
        pem_chain_to_der(&identity.chain_pem).expect("chain"),
        placeholder,
    );
    let context = c2pa::Context::new()
        .with_settings(json!({"builder": {"thumbnail": {"enabled": false}}}))
        .expect("context");
    let mut builder = c2pa::Builder::from_context(context)
        .with_definition(definition)
        .expect("definition");
    builder
        .add_ingredient_from_stream(
            json!({"title": "source", "relationship": "parentOf", "label": "parent"}).to_string(),
            "image/png",
            &mut Cursor::new(source),
        )
        .expect("parent");
    if let Some(extra) = extra_ingredient {
        builder
            .add_ingredient_from_stream(
                json!({"title": "extra", "relationship": "componentOf", "label": "extra"})
                    .to_string(),
                "image/png",
                &mut Cursor::new(extra),
            )
            .expect("extra");
    }
    let mut out = Cursor::new(Vec::new());
    builder
        .sign(&signer, "image/jpeg", &mut Cursor::new(derived), &mut out)
        .expect("forged pending");

    Hosted {
        identity,
        placeholder,
        tbs: signer.take_tbs().expect("tbs"),
        pending: out.into_inner(),
    }
}

fn definition(actions: Value, extra_assertions: Value) -> Value {
    let mut assertions = vec![json!({"label": "c2pa.actions", "data": {"actions": actions}})];
    if let Value::Array(extra) = extra_assertions {
        assertions.extend(extra);
    }
    json!({
        "claim_generator_info": [{"name": "c2pa-check carry", "version": "0"}],
        "title": "hero.jpg",
        "format": "image/jpeg",
        "assertions": assertions
    })
}

fn opened() -> Value {
    json!({"action": "c2pa.opened", "parameters": {"ingredientIds": ["parent"]}})
}

fn check(source: &[u8], hosted: &Hosted, signature: &[u8]) -> c2pa_check_core::carry::CarryCheck {
    check_as(source, "image/png", hosted, signature)
}

fn check_as(
    source: &[u8],
    source_mime: &str,
    hosted: &Hosted,
    signature: &[u8],
) -> c2pa_check_core::carry::CarryCheck {
    verifier().carry_check(
        &CarryInput {
            source,
            source_mime,
            derived: &hosted.pending,
            derived_mime: "image/jpeg",
            placeholder: &hosted.placeholder,
            signature,
        },
        &Options::default(),
    )
}

#[test]
fn an_honest_hosted_carry_is_accepted_and_reports_both_sides() {
    let (source, image) = generated();
    let job = hosted(&source, &jpeg(&image), "image/jpeg");

    let result = check(&source, &job, &job.signature());

    assert!(result.accepted, "{} {}", result.rule, result.detail);
    assert_eq!(result.source.status, Some(CredentialStatus::ValidUntrusted));
    assert_eq!(
        result.source.signer.as_deref(),
        Some("c2pa-check local identity")
    );
    assert_eq!(
        result.derived.status,
        Some(CredentialStatus::ValidUntrusted)
    );
    assert!(result.derived.certificate_serial.is_some());
    let derived_report = result.derived.report.as_ref().expect("derived report");
    assert!(derived_report.raw_manifest_store.is_none());
    assert_eq!(derived_report.asset.sha256, result.derived.sha256);
    let source_report = result.source.report.as_ref().expect("source report");
    assert!(source_report.raw_manifest_store.is_none());
    assert_eq!(source_report.asset.sha256, result.source.sha256);
    assert!(result.distance.is_some_and(|d| d <= 31));
    assert_ne!(
        result.derived.sha256,
        c2pa_check_core::digest::hex_sha256(&job.pending)
    );

    let carried = carry::patch_placeholder(&job.pending, &job.placeholder, &job.signature())
        .expect("patched");
    let report = verifier()
        .verify(&carried, "image/jpeg", &Options::default())
        .expect("report");
    assert_eq!(report.credential.status, CredentialStatus::ValidUntrusted);
}

#[test]
fn a_wrong_placeholder_is_placeholder_missing() {
    let (source, image) = generated();
    let mut job = hosted(&source, &jpeg(&image), "image/jpeg");
    let signature = job.signature();
    job.placeholder = new_placeholder().expect("placeholder");

    assert_eq!(check(&source, &job, &signature).rule, "placeholder_missing");
}

#[test]
fn a_signature_over_something_else_is_signature_invalid() {
    let (source, image) = generated();
    let job = hosted(&source, &jpeg(&image), "image/jpeg");

    assert_eq!(check(&source, &job, &[9u8; 64]).rule, "signature_invalid");
}

#[test]
fn an_unsigned_source_is_source_unsigned() {
    let (source, image) = generated();
    let job = hosted(&source, &jpeg(&image), "image/jpeg");
    let unsigned = encode(&image, ImageFormat::Png);

    assert_eq!(
        check(&unsigned, &job, &job.signature()).rule,
        "source_unsigned"
    );
}

#[test]
fn a_different_source_is_an_ingredient_mismatch() {
    let (source, image) = generated();
    let (other_source, _) = generated();
    let job = hosted(&source, &jpeg(&image), "image/jpeg");

    assert_eq!(
        check(&other_source, &job, &job.signature()).rule,
        "ingredient_mismatch"
    );
}

#[test]
fn a_swapped_picture_is_different_picture() {
    let (source, image) = generated();
    let job = forged(
        &source,
        &jpeg(&unrelated(image.width(), image.height())),
        definition(json!([opened()]), json!([])),
        None,
    );

    assert_eq!(
        check(&source, &job, &job.signature()).rule,
        "different_picture"
    );
}

#[test]
fn a_new_generator_is_generator_changed() {
    let (source, image) = generated();
    let job = forged(
        &source,
        &jpeg(&image),
        definition(
            json!([opened(), {"action": "c2pa.transcoded", "digitalSourceType": AI_SOURCE, "parameters": {"ingredientIds": ["parent"]}}]),
            json!([]),
        ),
        None,
    );

    assert_eq!(
        check(&source, &job, &job.signature()).rule,
        "generator_changed"
    );
}

#[test]
fn an_edit_action_is_action_not_allowed() {
    let (source, image) = generated();
    let job = forged(
        &source,
        &jpeg(&image),
        definition(
            json!([opened(), {"action": "c2pa.color_adjustments"}]),
            json!([]),
        ),
        None,
    );

    assert_eq!(
        check(&source, &job, &job.signature()).rule,
        "action_not_allowed"
    );
}

#[test]
fn a_model_claim_is_assertion_not_allowed() {
    let (source, image) = generated();
    let job = forged(
        &source,
        &jpeg(&image),
        definition(
            json!([opened()]),
            json!([{"label": "org.example.model", "data": {"model": "other"}}]),
        ),
        None,
    );

    assert_eq!(
        check(&source, &job, &job.signature()).rule,
        "assertion_not_allowed"
    );
}

#[test]
fn a_second_ingredient_is_an_ingredient_mismatch() {
    let (source, image) = generated();
    let (extra, _) = generated();
    let job = forged(
        &source,
        &jpeg(&image),
        definition(
            json!([opened(), {"action": "c2pa.placed", "parameters": {"ingredientIds": ["extra"]}}]),
            json!([]),
        ),
        Some(&extra),
    );

    let rule = check(&source, &job, &job.signature()).rule;
    assert!(
        rule == "ingredient_mismatch" || rule == "action_not_allowed",
        "{rule}"
    );
}

#[test]
fn a_flat_picture_is_low_quality() {
    let flat = DynamicImage::ImageRgb8(RgbImage::from_pixel(64, 64, Rgb([90, 90, 90])));
    let identity = generate_identity("Test Generator").expect("generator identity");
    let source = sign_generated(encode(&flat, ImageFormat::Png), &identity);
    let job = forged(
        &source,
        &jpeg(&flat),
        definition(json!([opened()]), json!([])),
        None,
    );

    assert_eq!(check(&source, &job, &job.signature()).rule, "low_quality");
}

#[test]
fn the_private_key_is_never_part_of_the_chain() {
    let identity = generate_identity("Leak Test").expect("identity");

    assert!(!identity.chain_pem.contains("PRIVATE KEY"));
    assert!(identity.key_pem.contains("PRIVATE KEY"));
}

#[test]
fn a_signature_of_the_wrong_size_is_placeholder_missing() {
    let (source, image) = generated();
    let job = hosted(&source, &jpeg(&image), "image/jpeg");
    let signature = job.signature();

    let result = check(&source, &job, &signature[..63]);

    assert!(!result.accepted);
    assert_eq!(result.rule, "placeholder_missing");
}

#[test]
fn a_source_of_an_unsupported_type_is_source_invalid() {
    let (source, image) = generated();
    let job = hosted(&source, &jpeg(&image), "image/jpeg");

    let result = check_as(&source, "application/zip", &job, &job.signature());

    assert_eq!(result.rule, "source_invalid");
    assert!(result.source.report.is_none());
}

#[test]
fn a_carry_into_an_unsupported_type_is_refused_before_signing() {
    let (source, image) = generated();
    let identity = generate_identity("Carry Test").expect("identity");
    let signer = local_signer(&identity.chain_pem, &identity.key_pem, None).expect("signer");

    let err = carry::carry(
        &source,
        "image/png",
        &jpeg(&image),
        "image/bmp",
        signer.as_ref(),
        &options(),
    )
    .unwrap_err();

    assert!(matches!(err, CarryError::UnsupportedMediaType(mime) if mime == "image/bmp"));
}

#[test]
fn a_gif_carried_from_a_png_keeps_its_parent() {
    let (source, image) = generated();
    let derived = encode(
        &image.resize_exact(200, 150, image::imageops::FilterType::Triangle),
        ImageFormat::Gif,
    );
    let identity = generate_identity("Carry Test").expect("identity");
    let signer = local_signer(&identity.chain_pem, &identity.key_pem, None).expect("signer");

    let outcome = carry::carry(
        &source,
        "image/png",
        &derived,
        "image/gif",
        signer.as_ref(),
        &options(),
    )
    .expect("carried");

    assert_eq!(
        outcome.actions,
        ["c2pa.opened", "c2pa.transcoded", "c2pa.resized"]
    );
    let report = verifier()
        .verify(&outcome.bytes, "image/gif", &Options::default())
        .expect("a report");
    assert_eq!(report.credential.status, CredentialStatus::ValidUntrusted);
    assert_eq!(report.ingredients.len(), 1);
}

#[test]
fn a_derived_file_of_an_unsupported_type_is_derived_unreadable() {
    let (source, image) = generated();
    let job = hosted(&source, &jpeg(&image), "image/jpeg");

    let result = verifier().carry_check(
        &CarryInput {
            source: &source,
            source_mime: "image/png",
            derived: &job.pending,
            derived_mime: "image/bmp",
            placeholder: &job.placeholder,
            signature: &job.signature(),
        },
        &Options::default(),
    );

    assert_eq!(result.rule, "derived_unreadable");
    assert!(result.source.report.is_none());
}
