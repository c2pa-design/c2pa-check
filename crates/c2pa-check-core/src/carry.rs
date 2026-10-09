use std::io::Cursor;
use std::sync::Mutex;

use serde::Serialize;
use serde_json::{json, Value};

use crate::pdq::{self, hamming, Fingerprint, MATCH_DISTANCE, MIN_QUALITY};
use crate::report::{Asset, CredentialStatus, Report};
use crate::{media, Options, Verifier, ENGINE_VERSION};

pub const PLACEHOLDER_LEN: usize = 64;
const GENERATOR: &str = "c2pa-check carry";
const GENERATOR_COMPOSE: &str = "c2pa-check compose";
const COMPOSITE_SOURCE_TYPE: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/composite";
const SIGNATURE_PREFIX: [u8; 2] = [0x58, 0x40];
const PARENT_LABEL: &str = "parent";
const RESERVE_MARGIN: usize = 16 * 1024;
const RASTERS: [&str; 7] = ["jpeg", "png", "webp", "gif", "avif", "heic", "heif"];
const ALLOWED_ACTIONS: [&str; 5] = [
    "c2pa.opened",
    "c2pa.transcoded",
    "c2pa.resized",
    "c2pa.converted",
    "c2pa.compressed",
];
const ALLOWED_ASSERTIONS: [&str; 4] = [
    "c2pa.actions",
    "c2pa.ingredient",
    "c2pa.hash.",
    "c2pa.thumbnail.",
];

#[derive(Debug, thiserror::Error)]
pub enum CarryError {
    #[error("the source has no Content Credential to carry")]
    NoSourceCredential,
    #[error("the two files are not the same picture (PDQ distance {0})")]
    DifferentPicture(u32),
    #[error("the pictures are too flat to compare (PDQ quality below 50)")]
    LowQuality,
    #[error("the files cannot be compared as pictures; pass --force to carry anyway")]
    NotComparable,
    #[error("the signature placeholder was not found in the signed file")]
    PlaceholderMissing,
    #[error("the signature placeholder appears more than once in the signed file")]
    PlaceholderAmbiguous,
    #[error("the placeholder and the signature must be {PLACEHOLDER_LEN} bytes each")]
    SignatureSize,
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("the source could not be read: {0}")]
    Source(String),
}

impl CarryError {
    pub fn rule(&self) -> Option<&'static str> {
        match self {
            Self::NoSourceCredential => Some("source_unsigned"),
            Self::DifferentPicture(_) => Some("different_picture"),
            Self::LowQuality => Some("low_quality"),
            Self::NotComparable => Some("not_comparable"),
            _ => None,
        }
    }

    pub fn refused(&self) -> bool {
        matches!(
            self,
            Self::NoSourceCredential
                | Self::DifferentPicture(_)
                | Self::LowQuality
                | Self::NotComparable
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct CarryOptions {
    pub force: bool,
    pub title: Option<String>,
    pub max_pixels: u64,
}

#[derive(Debug, Clone)]
pub struct CarryOutcome {
    pub bytes: Vec<u8>,
    pub actions: Vec<String>,
    pub distance: Option<u32>,
    pub source_valid: bool,
}

fn is_raster(format: &str) -> bool {
    RASTERS.contains(&format)
}

pub fn carry(
    source: &[u8],
    source_mime: &str,
    derived: &[u8],
    derived_mime: &str,
    signer: &dyn c2pa::Signer,
    options: &CarryOptions,
) -> Result<CarryOutcome, CarryError> {
    let source_format = media::format_for(source_mime)
        .ok_or_else(|| CarryError::UnsupportedMediaType(source_mime.to_string()))?;
    let derived_format = media::format_for(derived_mime)
        .ok_or_else(|| CarryError::UnsupportedMediaType(derived_mime.to_string()))?;

    let source_valid = source_state(source, source_format)?;
    let max_pixels = if options.max_pixels == 0 {
        Options::default().max_pixels
    } else {
        options.max_pixels
    };
    let distance = guard(
        (source, source_format),
        (derived, derived_format),
        max_pixels,
        options.force,
    )?;

    let mut actions = vec!["c2pa.opened".to_string()];
    if base_mime(source_mime) != base_mime(derived_mime) {
        actions.push("c2pa.transcoded".to_string());
    }
    if resized(source, derived, max_pixels) {
        actions.push("c2pa.resized".to_string());
    }

    let parent_actions = actions
        .iter()
        .map(|action| json!({"action": action, "parameters": {"ingredientIds": [PARENT_LABEL]}}))
        .collect();
    let mut builder = builder(
        GENERATOR,
        derived_mime,
        options.title.as_deref().unwrap_or("carried"),
        parent_actions,
    )?;
    let parent = json!({
        "title": "source",
        "relationship": "parentOf",
        "label": PARENT_LABEL,
    });
    builder
        .add_ingredient_from_stream(parent.to_string(), source_format, &mut Cursor::new(source))
        .map_err(|e| CarryError::Source(e.to_string()))?;

    let mut output = Cursor::new(Vec::new());
    builder
        .sign(
            signer,
            derived_format,
            &mut Cursor::new(derived),
            &mut output,
        )
        .map_err(|e| CarryError::Sign(e.to_string()))?;

    Ok(CarryOutcome {
        bytes: output.into_inner(),
        actions,
        distance,
        source_valid,
    })
}

pub struct Component<'a> {
    pub bytes: &'a [u8],
    pub mime: &'a str,
    pub title: &'a str,
}

#[derive(Debug, Clone)]
pub struct ComposeOutcome {
    pub bytes: Vec<u8>,
    pub actions: Vec<String>,
    pub components_with_credentials: usize,
}

pub fn compose(
    components: &[Component<'_>],
    output: &[u8],
    output_mime: &str,
    edited: bool,
    title: Option<&str>,
    signer: &dyn c2pa::Signer,
) -> Result<ComposeOutcome, CarryError> {
    let output_format = media::format_for(output_mime)
        .ok_or_else(|| CarryError::UnsupportedMediaType(output_mime.to_string()))?;
    if components.is_empty() {
        return Err(CarryError::Source("no component files".into()));
    }

    let labels: Vec<String> = (0..components.len())
        .map(|i| format!("component{i}"))
        .collect();
    let placed_from = usize::from(edited);
    let (mut actions, mut names) = if edited {
        (
            vec![
                json!({"action": "c2pa.opened", "parameters": {"ingredientIds": [labels[0]]}}),
                json!({"action": "c2pa.edited"}),
            ],
            vec!["c2pa.opened", "c2pa.edited"],
        )
    } else {
        (
            vec![json!({"action": "c2pa.created", "digitalSourceType": COMPOSITE_SOURCE_TYPE})],
            vec!["c2pa.created"],
        )
    };
    actions.extend(
        labels[placed_from..].iter().map(
            |label| json!({"action": "c2pa.placed", "parameters": {"ingredientIds": [label]}}),
        ),
    );
    if labels.len() > placed_from {
        names.push("c2pa.placed");
    }

    let mut builder = builder(
        GENERATOR_COMPOSE,
        output_mime,
        title.unwrap_or("composite"),
        actions,
    )?;
    let mut with_credentials = 0;
    for (index, (component, label)) in components.iter().zip(&labels).enumerate() {
        let format = media::format_for(component.mime)
            .ok_or_else(|| CarryError::UnsupportedMediaType(component.mime.to_string()))?;
        if store(component.bytes, component.mime)
            .as_ref()
            .and_then(active_label)
            .is_some()
        {
            with_credentials += 1;
        }
        let relationship = if index < placed_from {
            "parentOf"
        } else {
            "componentOf"
        };
        let ingredient = json!({
            "title": component.title,
            "relationship": relationship,
            "label": label,
        });
        builder
            .add_ingredient_from_stream(
                ingredient.to_string(),
                format,
                &mut Cursor::new(component.bytes),
            )
            .map_err(|e| CarryError::Source(e.to_string()))?;
    }

    let mut signed = Cursor::new(Vec::new());
    builder
        .sign(signer, output_format, &mut Cursor::new(output), &mut signed)
        .map_err(|e| CarryError::Sign(e.to_string()))?;

    Ok(ComposeOutcome {
        bytes: signed.into_inner(),
        actions: names.into_iter().map(str::to_string).collect(),
        components_with_credentials: with_credentials,
    })
}

fn builder(
    generator: &str,
    mime: &str,
    title: &str,
    actions: Vec<Value>,
) -> Result<c2pa::Builder, CarryError> {
    let context = c2pa::Context::new()
        .with_settings(json!({
            "verify": {"remote_manifest_fetch": false, "ocsp_fetch": false},
            "builder": {"thumbnail": {"enabled": false}}
        }))
        .map_err(|e| CarryError::Sign(e.to_string()))?;

    c2pa::Builder::from_context(context)
        .with_definition(json!({
            "claim_generator_info": [{"name": generator, "version": ENGINE_VERSION}],
            "title": title,
            "format": base_mime(mime),
            "assertions": [{"label": "c2pa.actions", "data": {"actions": actions}}]
        }))
        .map_err(|e| CarryError::Sign(e.to_string()))
}

fn read_context() -> Result<c2pa::Context, c2pa::Error> {
    c2pa::Context::new().with_settings(json!({
        "verify": {"remote_manifest_fetch": false, "ocsp_fetch": false, "verify_trust": false}
    }))
}

fn store(bytes: &[u8], mime: &str) -> Option<Value> {
    let format = media::format_for(mime)?;
    let reader = c2pa::Reader::from_context(read_context().ok()?)
        .with_stream(format, Cursor::new(bytes))
        .ok()?;
    serde_json::from_str(&reader.json()).ok()
}

fn active_label(store: &Value) -> Option<&str> {
    store
        .get("active_manifest")
        .and_then(Value::as_str)
        .filter(|label| !label.is_empty())
}

pub fn already_carried(
    source: &[u8],
    source_mime: &str,
    derived: &[u8],
    derived_mime: &str,
) -> bool {
    let (Some(from), Some(to)) = (store(source, source_mime), store(derived, derived_mime)) else {
        return false;
    };
    let (Some(parent), Some(active)) = (active_label(&from), active_label(&to)) else {
        return false;
    };
    to.get("manifests")
        .and_then(|m| m.get(active))
        .and_then(|m| m.get("ingredients"))
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.get("relationship").and_then(Value::as_str) == Some("parentOf")
                    && item.get("active_manifest").and_then(Value::as_str) == Some(parent)
            })
        })
}

fn source_state(source: &[u8], format: &str) -> Result<bool, CarryError> {
    let context = read_context().map_err(|e| CarryError::Source(e.to_string()))?;
    match c2pa::Reader::from_context(context).with_stream(format, Cursor::new(source)) {
        Ok(reader) => Ok(!matches!(
            reader.validation_state(),
            c2pa::ValidationState::Invalid
        )),
        Err(c2pa::Error::JumbfNotFound) => Err(CarryError::NoSourceCredential),
        Err(err) => Err(CarryError::Source(err.to_string())),
    }
}

fn guard(
    (source, source_format): (&[u8], &str),
    (derived, derived_format): (&[u8], &str),
    max_pixels: u64,
    force: bool,
) -> Result<Option<u32>, CarryError> {
    let comparison = if is_raster(source_format) && is_raster(derived_format) {
        compare(
            &pdq::fingerprint(source, source_format, max_pixels),
            &pdq::fingerprint(derived, derived_format, max_pixels),
        )
    } else {
        Comparison::Unavailable
    };

    match comparison {
        Comparison::Unavailable if force => Ok(None),
        Comparison::Unavailable => Err(CarryError::NotComparable),
        Comparison::LowQuality => Err(CarryError::LowQuality),
        Comparison::Distance(d) if d > MATCH_DISTANCE => Err(CarryError::DifferentPicture(d)),
        Comparison::Distance(d) => Ok(Some(d)),
    }
}

enum Comparison {
    Unavailable,
    LowQuality,
    Distance(u32),
}

fn compare(from: &Fingerprint, to: &Fingerprint) -> Comparison {
    let (Some(a), Some(b)) = (&from.pdq, &to.pdq) else {
        return Comparison::Unavailable;
    };
    if a.quality < MIN_QUALITY || b.quality < MIN_QUALITY {
        return Comparison::LowQuality;
    }

    let sources = [Some(a.hash.as_str()), from.black.as_deref()];
    let targets = [Some(b.hash.as_str()), to.black.as_deref()];
    sources
        .iter()
        .flatten()
        .flat_map(|s| targets.iter().flatten().filter_map(move |t| hamming(s, t)))
        .min()
        .map_or(Comparison::Unavailable, Comparison::Distance)
}

fn resized(source: &[u8], derived: &[u8], max_pixels: u64) -> bool {
    match (
        media::dimensions(source, max_pixels),
        media::dimensions(derived, max_pixels),
    ) {
        (Ok(Some(a)), Ok(Some(b))) => a != b,
        _ => false,
    }
}

fn base_mime(mime: &str) -> String {
    media::base_type(mime).to_ascii_lowercase()
}

pub fn patch_placeholder(
    bytes: &[u8],
    placeholder: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, CarryError> {
    if placeholder.len() != PLACEHOLDER_LEN || signature.len() != PLACEHOLDER_LEN {
        return Err(CarryError::SignatureSize);
    }
    let mut needle = [0u8; PLACEHOLDER_LEN + 2];
    needle[..2].copy_from_slice(&SIGNATURE_PREFIX);
    needle[2..].copy_from_slice(placeholder);

    let mut found = bytes
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(at, _)| at + SIGNATURE_PREFIX.len());
    let at = found.next().ok_or(CarryError::PlaceholderMissing)?;
    if found.next().is_some() {
        return Err(CarryError::PlaceholderAmbiguous);
    }

    let mut out = bytes.to_vec();
    out[at..at + PLACEHOLDER_LEN].copy_from_slice(signature);
    Ok(out)
}

pub fn new_placeholder() -> Result<[u8; PLACEHOLDER_LEN], CarryError> {
    let mut out = [0u8; PLACEHOLDER_LEN];
    getrandom::fill(&mut out).map_err(|e| CarryError::Sign(e.to_string()))?;
    out[0] |= 0x80;
    Ok(out)
}

pub struct DeferredSigner {
    chain: Vec<Vec<u8>>,
    placeholder: [u8; PLACEHOLDER_LEN],
    tbs: Mutex<Option<Vec<u8>>>,
}

impl DeferredSigner {
    pub fn new(chain: Vec<Vec<u8>>, placeholder: [u8; PLACEHOLDER_LEN]) -> Self {
        Self {
            chain,
            placeholder,
            tbs: Mutex::new(None),
        }
    }

    pub fn placeholder(&self) -> &[u8; PLACEHOLDER_LEN] {
        &self.placeholder
    }

    pub fn take_tbs(&self) -> Option<Vec<u8>> {
        self.tbs.lock().ok().and_then(|mut tbs| tbs.take())
    }
}

impl c2pa::Signer for DeferredSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        let mut tbs = self
            .tbs
            .lock()
            .map_err(|_| c2pa::Error::OtherError("the signer state is poisoned".into()))?;
        *tbs = Some(data.to_vec());
        Ok(self.placeholder.to_vec())
    }

    fn alg(&self) -> c2pa::SigningAlg {
        c2pa::SigningAlg::Es256
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        Ok(self.chain.clone())
    }

    fn reserve_size(&self) -> usize {
        self.chain
            .iter()
            .fold(PLACEHOLDER_LEN + RESERVE_MARGIN, |sum, der| {
                sum.saturating_add(der.len())
            })
    }
}

pub fn pem_chain_to_der(text: &str) -> Result<Vec<Vec<u8>>, CarryError> {
    let blocks = pem::parse_many(text).map_err(|e| CarryError::Sign(e.to_string()))?;
    let chain: Vec<Vec<u8>> = blocks
        .into_iter()
        .filter(|block| block.tag() == "CERTIFICATE")
        .map(pem::Pem::into_contents)
        .collect();
    if chain.is_empty() {
        return Err(CarryError::Sign("the chain holds no certificate".into()));
    }
    Ok(chain)
}

pub struct LocalIdentity {
    pub chain_pem: String,
    pub key_pem: String,
}

pub fn generate_identity(common_name: &str) -> Result<LocalIdentity, CarryError> {
    use rcgen::{
        date_time_ymd, BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    };

    let fail = |e: rcgen::Error| CarryError::Sign(e.to_string());

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(fail)?;
    let mut ca = CertificateParams::new(Vec::<String>::new()).map_err(fail)?;
    ca.distinguished_name
        .push(DnType::OrganizationName, "c2pa-check local identity");
    ca.distinguished_name
        .push(DnType::CommonName, format!("{common_name} local CA"));
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca.use_authority_key_identifier_extension = true;
    ca.not_before = date_time_ymd(2025, 1, 1);
    ca.not_after = date_time_ymd(2045, 1, 1);
    let ca_cert = ca.self_signed(&ca_key).map_err(fail)?;

    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(fail)?;
    let mut leaf = CertificateParams::new(Vec::<String>::new()).map_err(fail)?;
    leaf.distinguished_name
        .push(DnType::OrganizationName, "c2pa-check local identity");
    leaf.distinguished_name
        .push(DnType::CommonName, common_name.to_string());
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::Other(vec![
        1, 3, 6, 1, 5, 5, 7, 3, 36,
    ])];
    leaf.use_authority_key_identifier_extension = true;
    leaf.not_before = date_time_ymd(2025, 1, 1);
    leaf.not_after = date_time_ymd(2044, 12, 31);
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key).map_err(fail)?;

    Ok(LocalIdentity {
        chain_pem: format!("{}{}", leaf_cert.pem(), ca_cert.pem()),
        key_pem: leaf_key.serialize_pem(),
    })
}

pub fn local_signer(
    chain_pem: &str,
    key_pem: &str,
    tsa_url: Option<String>,
) -> Result<Box<dyn c2pa::Signer + Send + Sync>, CarryError> {
    c2pa::create_signer::from_keys(
        chain_pem.as_bytes(),
        key_pem.as_bytes(),
        c2pa::SigningAlg::Es256,
        tsa_url,
    )
    .map_err(|e| CarryError::Sign(e.to_string()))
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CarrySide {
    pub sha256: String,
    pub mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<CredentialStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdq: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdq_quality: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<Report>,
}

impl CarrySide {
    fn new(bytes: &[u8], mime: &str) -> Self {
        Self {
            sha256: crate::digest::hex_sha256(bytes),
            mime_type: base_mime(mime),
            ..Self::default()
        }
    }

    fn record(&mut self, report: Report) {
        self.status = Some(report.credential.status);
        self.pdq.clone_from(&report.asset.pdq);
        self.pdq_quality = report.asset.pdq_quality;
        self.report = Some(report);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CarryCheck {
    pub accepted: bool,
    pub rule: String,
    pub detail: String,
    pub source: CarrySide,
    pub derived: CarrySide,
    pub distance: Option<u32>,
}

impl CarryCheck {
    fn reject(mut self, rule: &str, detail: impl Into<String>) -> Self {
        self.accepted = false;
        self.rule = rule.to_string();
        self.detail = detail.into();
        self
    }
}

pub struct CarryInput<'a> {
    pub source: &'a [u8],
    pub source_mime: &'a str,
    pub derived: &'a [u8],
    pub derived_mime: &'a str,
    pub placeholder: &'a [u8],
    pub signature: &'a [u8],
}

impl Verifier {
    pub fn carry_check(&self, input: &CarryInput<'_>, options: &Options) -> CarryCheck {
        let options = Options {
            include_raw: true,
            ..options.clone()
        };
        let mut check = CarryCheck {
            accepted: true,
            rule: String::new(),
            detail: String::new(),
            source: CarrySide::new(input.source, input.source_mime),
            derived: CarrySide::new(input.derived, input.derived_mime),
            distance: None,
        };

        if media::format_for(input.source_mime).is_none() {
            return check.reject(
                "source_invalid",
                format!("unsupported media type {:?}", input.source_mime),
            );
        }
        let Some(derived_format) = media::format_for(input.derived_mime) else {
            return check.reject(
                "derived_unreadable",
                format!("unsupported media type {:?}", input.derived_mime),
            );
        };

        let patched = match patch_placeholder(input.derived, input.placeholder, input.signature) {
            Ok(bytes) => bytes,
            Err(CarryError::PlaceholderAmbiguous) => {
                return check.reject(
                    "placeholder_ambiguous",
                    "the placeholder appears more than once",
                )
            }
            Err(err) => return check.reject("placeholder_missing", err.to_string()),
        };
        check.derived.sha256 = crate::digest::hex_sha256(&patched);

        let mut source = match self.verify(input.source, input.source_mime, &options) {
            Ok(report) => report,
            Err(err) => return check.reject("source_invalid", err.to_string()),
        };
        let source_store = source.raw_manifest_store.take();
        let source_print = fingerprint_of(&source.asset);
        check.source.signer = source
            .signer
            .as_ref()
            .and_then(|s| s.organization.clone().or_else(|| s.common_name.clone()));
        let source_status = source.credential.status;
        let source_codes = codes(&source);
        check.source.record(source);
        match source_status {
            CredentialStatus::ValidTrusted | CredentialStatus::ValidUntrusted => {}
            CredentialStatus::Absent => {
                return check.reject("source_unsigned", "the source has no Content Credential")
            }
            _ => return check.reject("source_invalid", source_codes),
        }
        let Some(source_label) = source_store.as_ref().and_then(active_label) else {
            return check.reject("source_invalid", "the source has no active manifest");
        };

        let mut derived = match self.verify(&patched, input.derived_mime, &options) {
            Ok(report) => report,
            Err(err) => return check.reject("derived_unreadable", err.to_string()),
        };
        drop(patched);
        let derived_store = derived.raw_manifest_store.take();
        let derived_print = fingerprint_of(&derived.asset);
        check.derived.certificate_serial =
            derived.signer.as_ref().and_then(|s| s.cert_serial.clone());
        let derived_status = derived.credential.status;
        let derived_codes = codes(&derived);
        let ingredient_valid = derived
            .ingredients
            .first()
            .and_then(|i| i.credential_status)
            .is_some_and(is_valid);
        check.derived.record(derived);
        match derived_status {
            CredentialStatus::ValidTrusted | CredentialStatus::ValidUntrusted => {}
            CredentialStatus::Absent => {
                return check.reject("derived_unreadable", "the derived file has no manifest")
            }
            _ => return check.reject("signature_invalid", derived_codes),
        }

        if let Err((rule, detail)) = policy(derived_store.as_ref(), source_label, ingredient_valid)
        {
            return check.reject(rule, detail);
        }

        let source_format = media::format_for(input.source_mime).unwrap_or_default();
        if is_raster(source_format) && is_raster(derived_format) {
            match compare(&source_print, &derived_print) {
                Comparison::Distance(d) => {
                    check.distance = Some(d);
                    if d > MATCH_DISTANCE {
                        return check.reject("different_picture", format!("PDQ distance {d}"));
                    }
                }
                Comparison::LowQuality | Comparison::Unavailable => {
                    return check.reject("low_quality", "the pictures cannot be compared")
                }
            }
        }

        check
    }
}

fn is_valid(status: CredentialStatus) -> bool {
    matches!(
        status,
        CredentialStatus::ValidTrusted | CredentialStatus::ValidUntrusted
    )
}

fn fingerprint_of(asset: &Asset) -> Fingerprint {
    Fingerprint {
        pdq: asset
            .pdq
            .clone()
            .zip(asset.pdq_quality)
            .map(|(hash, quality)| pdq::Pdq { hash, quality }),
        black: asset.pdq_black.clone(),
        ..Fingerprint::default()
    }
}

fn codes(report: &Report) -> String {
    report
        .validation
        .errors
        .iter()
        .map(|e| e.code.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

type Refusal = (&'static str, String);

fn policy(
    store: Option<&Value>,
    source_label: &str,
    ingredient_valid: bool,
) -> Result<(), Refusal> {
    let store = store.ok_or(("derived_unreadable", "no manifest store".to_string()))?;
    let label =
        active_label(store).ok_or(("derived_unreadable", "no active manifest".to_string()))?;
    if label == source_label {
        return Err((
            "ingredient_mismatch",
            "the derived file carries the source manifest unchanged".into(),
        ));
    }
    let manifest = store.get("manifests").and_then(|m| m.get(label)).ok_or((
        "derived_unreadable",
        "the active manifest is missing".to_string(),
    ))?;

    for assertion in manifest
        .get("assertions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = assertion
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !ALLOWED_ASSERTIONS
            .iter()
            .any(|allowed| name.starts_with(allowed))
        {
            return Err(("assertion_not_allowed", name.to_string()));
        }
        if name.starts_with("c2pa.actions") {
            actions_allowed(assertion.get("data"))?;
        }
    }

    let ingredients = manifest
        .get("ingredients")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let [ingredient] = ingredients else {
        return Err((
            "ingredient_mismatch",
            format!("{} ingredients", ingredients.len()),
        ));
    };
    if ingredient.get("relationship").and_then(Value::as_str) != Some("parentOf") {
        return Err((
            "ingredient_mismatch",
            "the ingredient is not parentOf".into(),
        ));
    }
    if ingredient.get("active_manifest").and_then(Value::as_str) != Some(source_label) {
        return Err((
            "ingredient_mismatch",
            "the ingredient is not the source's active manifest".into(),
        ));
    }
    if !ingredient_valid {
        return Err((
            "ingredient_mismatch",
            "the ingredient manifest does not validate".into(),
        ));
    }

    Ok(())
}

fn actions_allowed(data: Option<&Value>) -> Result<(), Refusal> {
    for action in data
        .and_then(|d| d.get("actions"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = action
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !ALLOWED_ACTIONS.contains(&name) {
            return Err(("action_not_allowed", name.to_string()));
        }
        if action.get("digitalSourceType").is_some() {
            return Err((
                "generator_changed",
                format!("{name} declares a digital source type"),
            ));
        }
        let agent = match action.get("softwareAgent") {
            None | Some(Value::Null) => continue,
            Some(Value::String(agent)) => agent.as_str(),
            Some(other) => other
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        };
        if !agent.starts_with("c2pa-check") {
            return Err((
                "generator_changed",
                format!("{name} names software agent {agent}"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placeholder() -> [u8; PLACEHOLDER_LEN] {
        new_placeholder().expect("random bytes")
    }

    fn pdq(hash: &str, quality: u8) -> Option<pdq::Pdq> {
        Some(pdq::Pdq {
            hash: hash.to_string(),
            quality,
        })
    }

    #[test]
    fn a_placeholder_is_patched_exactly_once() {
        let placeholder = placeholder();
        let signature = [7u8; PLACEHOLDER_LEN];
        let mut bytes = b"head".to_vec();
        bytes.extend_from_slice(&SIGNATURE_PREFIX);
        bytes.extend_from_slice(&placeholder);
        bytes.extend_from_slice(b"tail");

        let patched = patch_placeholder(&bytes, &placeholder, &signature).expect("patched");

        assert_eq!(patched.len(), bytes.len());
        assert_eq!(&patched[6..6 + PLACEHOLDER_LEN], &signature);
        assert!(patched.starts_with(b"head\x58\x40"));
        assert!(patched.ends_with(b"tail"));
    }

    #[test]
    fn a_placeholder_without_its_cbor_prefix_is_missing() {
        let placeholder = placeholder();
        let mut bytes = vec![0x58, 0x41];
        bytes.extend_from_slice(&placeholder);

        let err = patch_placeholder(&bytes, &placeholder, &[1u8; PLACEHOLDER_LEN]).unwrap_err();

        assert!(matches!(err, CarryError::PlaceholderMissing));
    }

    #[test]
    fn a_missing_placeholder_is_refused() {
        let err = patch_placeholder(b"nothing here", &placeholder(), &[1u8; PLACEHOLDER_LEN])
            .unwrap_err();

        assert!(matches!(err, CarryError::PlaceholderMissing));
    }

    #[test]
    fn a_placeholder_seen_twice_is_refused() {
        let placeholder = placeholder();
        let mut bytes = Vec::new();
        for _ in 0..2 {
            bytes.extend_from_slice(&SIGNATURE_PREFIX);
            bytes.extend_from_slice(&placeholder);
        }

        let err = patch_placeholder(&bytes, &placeholder, &[1u8; PLACEHOLDER_LEN]).unwrap_err();

        assert!(matches!(err, CarryError::PlaceholderAmbiguous));
    }

    #[test]
    fn a_placeholder_or_signature_of_the_wrong_size_is_refused() {
        let placeholder = placeholder();
        let mut bytes = SIGNATURE_PREFIX.to_vec();
        bytes.extend_from_slice(&placeholder);

        for (placeholder, signature) in [
            (&placeholder[..63], &[1u8; 64][..]),
            (&placeholder[..], &[1u8; 63][..]),
            (&placeholder[..], &[1u8; 65][..]),
            (&[][..], &[][..]),
        ] {
            assert!(matches!(
                patch_placeholder(&bytes, placeholder, signature),
                Err(CarryError::SignatureSize)
            ));
        }
    }

    #[test]
    fn placeholders_are_random_and_never_look_like_a_der_signature() {
        let first = placeholder();
        let second = placeholder();

        assert_ne!(first, second);
        for bytes in [first, second] {
            assert_ne!(bytes[0], 0x30);
            assert!(bytes[0] & 0x80 != 0);
        }
    }

    #[test]
    fn the_deferred_signer_keeps_the_tbs_once_and_returns_the_placeholder() {
        use c2pa::Signer as _;

        let placeholder = placeholder();
        let signer = DeferredSigner::new(vec![vec![0; 500], vec![0; 700]], placeholder);

        assert_eq!(signer.sign(b"to be signed").unwrap(), placeholder);
        assert_eq!(signer.take_tbs().as_deref(), Some(&b"to be signed"[..]));
        assert_eq!(signer.take_tbs(), None);
        assert_eq!(signer.alg(), c2pa::SigningAlg::Es256);
        assert_eq!(
            signer.reserve_size(),
            1200 + PLACEHOLDER_LEN + RESERVE_MARGIN
        );
    }

    #[test]
    fn a_pem_chain_yields_one_der_per_certificate() {
        let identity = generate_identity("test").expect("identity");

        assert_eq!(pem_chain_to_der(&identity.chain_pem).unwrap().len(), 2);
        assert!(identity.key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn a_pem_without_certificates_is_refused() {
        let identity = generate_identity("test").expect("identity");

        assert!(pem_chain_to_der("").is_err());
        assert!(pem_chain_to_der("not pem at all").is_err());
        assert!(pem_chain_to_der(&identity.key_pem).is_err());
        assert!(
            pem_chain_to_der("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n")
                .is_err()
        );
    }

    #[test]
    fn only_listed_actions_without_a_source_type_pass() {
        assert!(actions_allowed(Some(
            &json!({"actions": [{"action": "c2pa.opened"}, {"action": "c2pa.transcoded"}]})
        ))
        .is_ok());
        assert!(actions_allowed(None).is_ok());
        assert_eq!(
            actions_allowed(Some(&json!({"actions": [{"action": "c2pa.created"}]})))
                .unwrap_err()
                .0,
            "action_not_allowed"
        );
        assert_eq!(
            actions_allowed(Some(&json!({"actions": [{}]})))
                .unwrap_err()
                .0,
            "action_not_allowed"
        );
        assert_eq!(
            actions_allowed(Some(
                &json!({"actions": [{"action": "c2pa.opened", "digitalSourceType": "x"}]})
            ))
            .unwrap_err()
            .0,
            "generator_changed"
        );
        for agent in [
            json!({"name": "Other Model"}),
            json!("Other Model"),
            json!(7),
        ] {
            assert_eq!(
                actions_allowed(Some(
                    &json!({"actions": [{"action": "c2pa.resized", "softwareAgent": agent}]})
                ))
                .unwrap_err()
                .0,
                "generator_changed"
            );
        }
        for agent in [
            json!({"name": "c2pa-check carry"}),
            json!("c2pa-check 0.1"),
            Value::Null,
        ] {
            assert!(actions_allowed(Some(
                &json!({"actions": [{"action": "c2pa.resized", "softwareAgent": agent}]})
            ))
            .is_ok());
        }
    }

    fn store_with(manifest: Value) -> Value {
        json!({"active_manifest": "urn:derived", "manifests": {"urn:derived": manifest}})
    }

    fn honest_manifest() -> Value {
        json!({
            "assertions": [
                {"label": "c2pa.actions.v2", "data": {"actions": [{"action": "c2pa.opened"}]}},
                {"label": "c2pa.hash.data"}
            ],
            "ingredients": [{"relationship": "parentOf", "active_manifest": "urn:source"}]
        })
    }

    #[test]
    fn the_policy_accepts_one_valid_parent_and_listed_assertions() {
        assert!(policy(Some(&store_with(honest_manifest())), "urn:source", true).is_ok());
    }

    #[test]
    fn the_policy_names_the_rule_each_violation_breaks() {
        let rule =
            |store: Option<&Value>, valid: bool| policy(store, "urn:source", valid).unwrap_err().0;
        let mut extra_assertion = honest_manifest();
        extra_assertion["assertions"]
            .as_array_mut()
            .unwrap()
            .push(json!({"label": "c2pa.training-mining"}));
        let mut two_ingredients = honest_manifest();
        two_ingredients["ingredients"]
            .as_array_mut()
            .unwrap()
            .push(json!({"relationship": "componentOf"}));
        let mut component = honest_manifest();
        component["ingredients"][0]["relationship"] = json!("componentOf");
        let mut other_parent = honest_manifest();
        other_parent["ingredients"][0]["active_manifest"] = json!("urn:other");
        let mut no_ingredients = honest_manifest();
        no_ingredients
            .as_object_mut()
            .unwrap()
            .remove("ingredients");

        assert_eq!(rule(None, true), "derived_unreadable");
        assert_eq!(
            rule(Some(&json!({"manifests": {}})), true),
            "derived_unreadable"
        );
        assert_eq!(
            rule(Some(&json!({"active_manifest": "urn:gone"})), true),
            "derived_unreadable"
        );
        assert_eq!(
            rule(
                Some(&json!({"active_manifest": "urn:source", "manifests": {}})),
                true
            ),
            "ingredient_mismatch"
        );
        assert_eq!(
            rule(Some(&store_with(extra_assertion)), true),
            "assertion_not_allowed"
        );
        assert_eq!(
            rule(Some(&store_with(two_ingredients)), true),
            "ingredient_mismatch"
        );
        assert_eq!(
            rule(Some(&store_with(no_ingredients)), true),
            "ingredient_mismatch"
        );
        assert_eq!(
            rule(Some(&store_with(component)), true),
            "ingredient_mismatch"
        );
        assert_eq!(
            rule(Some(&store_with(other_parent)), true),
            "ingredient_mismatch"
        );
        assert_eq!(
            rule(Some(&store_with(honest_manifest())), false),
            "ingredient_mismatch"
        );
    }

    #[test]
    fn an_empty_active_label_is_no_label() {
        assert_eq!(active_label(&json!({"active_manifest": ""})), None);
        assert_eq!(active_label(&json!({"active_manifest": 5})), None);
        assert_eq!(
            active_label(&json!({"active_manifest": "urn:a"})),
            Some("urn:a")
        );
    }

    #[test]
    fn the_comparison_takes_the_closest_background_and_refuses_flat_pictures() {
        let zeros = "0".repeat(64);
        let ones = "f".repeat(64);
        let print = |hash: &str, quality: u8, black: Option<&str>| Fingerprint {
            pdq: pdq(hash, quality),
            black: black.map(str::to_string),
            ..Fingerprint::default()
        };

        assert!(matches!(
            compare(&print(&zeros, 90, None), &print(&ones, 90, Some(&zeros))),
            Comparison::Distance(0)
        ));
        assert!(matches!(
            compare(&print(&zeros, 90, None), &print(&ones, 90, None)),
            Comparison::Distance(256)
        ));
        assert!(matches!(
            compare(&print(&zeros, 49, None), &print(&zeros, 90, None)),
            Comparison::LowQuality
        ));
        assert!(matches!(
            compare(&Fingerprint::default(), &print(&zeros, 90, None)),
            Comparison::Unavailable
        ));
        assert!(matches!(
            compare(&print("bad", 90, None), &print(&zeros, 90, None)),
            Comparison::Unavailable
        ));
    }

    #[test]
    fn media_that_is_not_a_picture_is_carried_only_when_forced() {
        assert!(matches!(
            guard((b"a", "mp4"), (b"b", "mp4"), 1000, false),
            Err(CarryError::NotComparable)
        ));
        assert!(matches!(
            guard((b"a", "mp4"), (b"b", "mp4"), 1000, true),
            Ok(None)
        ));
        assert!(matches!(
            guard((b"a", "png"), (b"b", "png"), 1000, false),
            Err(CarryError::NotComparable)
        ));
    }

    #[test]
    fn only_refusals_the_user_can_act_on_are_refused() {
        assert!(CarryError::DifferentPicture(40).refused());
        assert!(CarryError::NoSourceCredential.refused());
        assert!(!CarryError::Sign("x".into()).refused());
        assert!(!CarryError::SignatureSize.refused());
    }

    #[test]
    fn the_base_media_type_drops_parameters_and_case() {
        assert_eq!(base_mime(" Image/PNG ; charset=x"), "image/png");
    }
}
