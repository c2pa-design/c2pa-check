use std::io::Cursor;

use c2pa_check_core::carry::{self, generate_identity, local_signer, CarryOptions, LocalIdentity};
use c2pa_check_core::report::{CredentialStatus, OriginStatus, TrustSelector};
use c2pa_check_core::{Options, Report, TrustBundle, Verifier};
use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use serde_json::json;

const ORGANIZATION: &str = "c2pa-check local identity";

fn scene(shift: f32) -> DynamicImage {
    DynamicImage::ImageRgb8(RgbImage::from_fn(640, 480, |x, y| {
        let fx = x as f32 / 640.0;
        let fy = y as f32 / 480.0;
        let v: f32 = (0..16u32)
            .map(|k| {
                let k = k as f32;
                ((k * 2.399).sin().abs() * 9.0 * fx * std::f32::consts::TAU + k * 0.7 + shift).sin()
                    * ((k * 1.618).cos().abs() * 9.0 * fy * std::f32::consts::TAU - k).cos()
                    / (1.0 + k * 0.15)
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

fn encode(image: &DynamicImage, format: ImageFormat) -> Vec<u8> {
    let mut out = Cursor::new(Vec::new());
    image.write_to(&mut out, format).expect("encodes");
    out.into_inner()
}

fn sign(png: Vec<u8>, identity: &LocalIdentity) -> Vec<u8> {
    let signer = local_signer(&identity.chain_pem, &identity.key_pem, None).expect("signer");
    let context = c2pa::Context::new()
        .with_settings(json!({"builder": {"thumbnail": {"enabled": false}}}))
        .expect("context");
    let mut builder = c2pa::Builder::from_context(context)
        .with_definition(json!({
            "claim_generator_info": [{"name": "test-generator", "version": "1"}],
            "title": "generated.png",
            "format": "image/png",
            "assertions": [{"label": "c2pa.actions", "data": {"actions": [{
                "action": "c2pa.created",
                "digitalSourceType": "http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"
            }]}}]
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
        .expect("signs");
    out.into_inner()
}

fn carried(source: &[u8], source_mime: &str, image: &DynamicImage, format: ImageFormat) -> Vec<u8> {
    let identity = generate_identity("Carry Test").expect("identity");
    let signer = local_signer(&identity.chain_pem, &identity.key_pem, None).expect("signer");
    let options = CarryOptions {
        force: false,
        title: Some("carried".into()),
        max_pixels: 100_000_000,
    };

    carry::carry(
        source,
        source_mime,
        &encode(image, format),
        format.to_mime_type(),
        signer.as_ref(),
        &options,
    )
    .expect("carried")
    .bytes
}

fn trusting(identity: &LocalIdentity) -> Verifier {
    let root = identity
        .chain_pem
        .rsplit_once("-----BEGIN CERTIFICATE-----")
        .map(|(_, root)| format!("-----BEGIN CERTIFICATE-----{root}"))
        .expect("a root certificate");
    let bundle = TrustBundle::from_pem(root, String::new(), "2026-10-12").expect("a bundle");

    Verifier::new(&bundle, TrustSelector::Official).expect("a verifier")
}

fn report(verifier: &Verifier, bytes: &[u8], mime: &str) -> Report {
    verifier
        .verify(bytes, mime, &Options::default())
        .expect("a report")
}

#[test]
fn a_file_signed_by_a_listed_signer_is_traced_at_depth_zero() {
    let generator = generate_identity("Listed Generator").expect("identity");
    let signed = sign(encode(&scene(0.0), ImageFormat::Png), &generator);

    let report = report(&trusting(&generator), &signed, "image/png");

    assert_eq!(report.credential.status, CredentialStatus::ValidTrusted);
    assert_eq!(report.origin.status, OriginStatus::Traced);
    assert_eq!(report.origin.depth, Some(0));
    assert_eq!(report.origin.signer_name.as_deref(), Some(ORGANIZATION));
    assert_eq!(report.origin.relationship, None);
}

#[test]
fn a_file_carried_from_a_listed_signer_is_traced_and_stays_untrusted() {
    let generator = generate_identity("Listed Generator").expect("identity");
    let image = scene(0.0);
    let signed = sign(encode(&image, ImageFormat::Png), &generator);
    let webp = carried(&signed, "image/png", &image, ImageFormat::WebP);

    let report = report(&trusting(&generator), &webp, "image/webp");

    assert_eq!(report.credential.status, CredentialStatus::ValidUntrusted);
    assert_eq!(report.origin.status, OriginStatus::Traced);
    assert_eq!(report.origin.depth, Some(1));
    assert_eq!(report.origin.relationship.as_deref(), Some("parentOf"));
    assert_eq!(report.origin.signer_name.as_deref(), Some(ORGANIZATION));
    assert_eq!(report.ingredients.len(), 1);
    assert_eq!(
        report.ingredients[0].credential_status,
        Some(CredentialStatus::ValidTrusted)
    );
    assert_eq!(
        report.ingredients[0].signer_name.as_deref(),
        Some(ORGANIZATION)
    );
}

#[test]
fn a_file_carried_from_an_unlisted_signer_is_untraced() {
    let listed = generate_identity("Listed Generator").expect("identity");
    let unlisted = generate_identity("Unlisted Generator").expect("identity");
    let image = scene(0.0);
    let signed = sign(encode(&image, ImageFormat::Png), &unlisted);
    let webp = carried(&signed, "image/png", &image, ImageFormat::WebP);

    let anchored = report(&trusting(&listed), &webp, "image/webp");
    let unanchored = report(
        &Verifier::new(&TrustBundle::default(), TrustSelector::None).expect("a verifier"),
        &webp,
        "image/webp",
    );

    for report in [anchored, unanchored] {
        assert_eq!(report.credential.status, CredentialStatus::ValidUntrusted);
        assert_eq!(report.origin.status, OriginStatus::Untraced);
        assert_eq!(report.origin.depth, None);
        assert_eq!(report.origin.signer_name, None);
        assert_eq!(
            report.ingredients[0].credential_status,
            Some(CredentialStatus::ValidUntrusted)
        );
        assert_eq!(
            report.ingredients[0].signer_name.as_deref(),
            Some(ORGANIZATION)
        );
    }
}

#[test]
fn a_file_carried_twice_is_traced_two_hops_away() {
    let generator = generate_identity("Listed Generator").expect("identity");
    let image = scene(0.0);
    let signed = sign(encode(&image, ImageFormat::Png), &generator);
    let webp = carried(&signed, "image/png", &image, ImageFormat::WebP);
    let jpeg = carried(&webp, "image/webp", &image, ImageFormat::Jpeg);

    let report = report(&trusting(&generator), &jpeg, "image/jpeg");

    assert_eq!(report.credential.status, CredentialStatus::ValidUntrusted);
    assert_eq!(report.origin.status, OriginStatus::Traced);
    assert_eq!(report.origin.depth, Some(2));
    assert_eq!(report.origin.relationship.as_deref(), Some("parentOf"));
    assert_eq!(
        report.ingredients[0].credential_status,
        Some(CredentialStatus::ValidUntrusted)
    );
}

#[test]
fn a_composite_of_a_listed_and_an_unsigned_component_is_traced() {
    let generator = generate_identity("Listed Generator").expect("identity");
    let composer = generate_identity("Composer").expect("identity");
    let signer = local_signer(&composer.chain_pem, &composer.key_pem, None).expect("signer");
    let signed = sign(encode(&scene(0.0), ImageFormat::Png), &generator);
    let plain = encode(&scene(0.4), ImageFormat::Png);
    let components = [
        carry::Component {
            bytes: &signed,
            mime: "image/png",
            title: "signed.png",
        },
        carry::Component {
            bytes: &plain,
            mime: "image/png",
            title: "plain.png",
        },
    ];

    let composed = carry::compose(
        &components,
        &encode(&scene(0.9), ImageFormat::Png),
        "image/png",
        false,
        Some("atlas.png"),
        signer.as_ref(),
    )
    .expect("composed");
    let report = report(&trusting(&generator), &composed.bytes, "image/png");

    assert_eq!(report.credential.status, CredentialStatus::ValidUntrusted);
    assert_eq!(report.origin.status, OriginStatus::Traced);
    assert_eq!(report.origin.depth, Some(1));
    assert_eq!(report.origin.relationship.as_deref(), Some("componentOf"));
    assert_eq!(
        report
            .ingredients
            .iter()
            .map(|item| item.credential_status)
            .collect::<Vec<_>>(),
        [
            Some(CredentialStatus::ValidTrusted),
            Some(CredentialStatus::Absent)
        ]
    );
}

#[test]
fn a_file_without_a_credential_has_no_origin() {
    let generator = generate_identity("Listed Generator").expect("identity");

    let report = report(
        &trusting(&generator),
        &encode(&scene(0.0), ImageFormat::Png),
        "image/png",
    );

    assert_eq!(report.credential.status, CredentialStatus::Absent);
    assert_eq!(report.origin.status, OriginStatus::None);
}
