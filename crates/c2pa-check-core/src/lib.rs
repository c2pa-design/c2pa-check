#[cfg(feature = "avif")]
mod av1;
pub mod calendar;
pub mod carry;
pub mod classify;
pub mod digest;
pub mod error;
pub mod explain;
pub mod media;
pub mod metadata;
pub mod pdq;
pub mod report;
pub mod trust;

mod extract;

use std::io::Cursor;
use std::sync::Arc;

pub use c2pa;
pub use error::Error;
pub use report::{
    Asset, Credential, CredentialStatus, EngineInfo, Metadata, Report, SourceCategory,
    TrustSelector,
};
pub use trust::TrustBundle;

pub const ENGINE_NAME: &str = "c2pa-check-core";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const C2PA_VERSION: &str = "0.90.20";

#[derive(Debug, Clone)]
pub struct Options {
    pub include_raw: bool,
    pub max_bytes: u64,
    pub max_pixels: u64,
    pub max_manifest_bytes: usize,
    pub max_ingredients: usize,
    pub filename: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            include_raw: false,
            max_bytes: 64 * 1024 * 1024,
            max_pixels: 100_000_000,
            max_manifest_bytes: 16 * 1024 * 1024,
            max_ingredients: 256,
            filename: None,
        }
    }
}

pub struct Verifier {
    context: Arc<c2pa::Context>,
    selector: TrustSelector,
    trust_list_version: String,
}

impl Verifier {
    pub fn new(bundle: &TrustBundle, selector: TrustSelector) -> Result<Self, Error> {
        let anchors = bundle.anchors(selector);
        let verify_trust = !matches!(selector, TrustSelector::None) && !anchors.is_empty();

        let mut trust = serde_json::Map::new();
        if verify_trust {
            trust.insert(
                "trust_anchors".to_string(),
                serde_json::Value::String(anchors.into_owned()),
            );
        }

        let settings = serde_json::json!({
            "trust": trust,
            "verify": {
                "verify_trust": verify_trust,
                "verify_timestamp_trust": verify_trust,
                "ocsp_fetch": false,
                "remote_manifest_fetch": false
            }
        });

        let context = c2pa::Context::new()
            .with_settings(settings)
            .map_err(|e| Error::TrustList(e.to_string()))?;

        Ok(Self {
            context: context.into_shared(),
            selector,
            trust_list_version: bundle.version.clone(),
        })
    }

    pub fn selector(&self) -> TrustSelector {
        self.selector
    }

    pub fn verify(
        &self,
        bytes: &[u8],
        mime_type: &str,
        options: &Options,
    ) -> Result<Report, Error> {
        self.verify_against(bytes, mime_type, None, options)
    }

    pub fn verify_with_manifest(
        &self,
        bytes: &[u8],
        mime_type: &str,
        manifest: &[u8],
        options: &Options,
    ) -> Result<Report, Error> {
        self.verify_against(bytes, mime_type, Some(manifest), options)
    }

    fn verify_against(
        &self,
        bytes: &[u8],
        mime_type: &str,
        manifest: Option<&[u8]>,
        options: &Options,
    ) -> Result<Report, Error> {
        if bytes.len() as u64 > options.max_bytes {
            return Err(Error::LimitExceeded(format!(
                "{} bytes exceeds the {} byte limit",
                bytes.len(),
                options.max_bytes
            )));
        }

        let format = media::require_format(mime_type)?;
        let dimensions = media::dimensions(bytes, options.max_pixels)?;

        let base_mime = media::base_type(mime_type).to_string();
        let print = pdq::fingerprint(bytes, format, options.max_pixels);
        let metadata =
            metadata::applies_to(&base_mime).then(|| metadata::extract(bytes, &base_mime));

        let asset = Asset {
            sha256: digest::hex_sha256(bytes),
            mime_type: base_mime,
            size_bytes: bytes.len() as u64,
            width: dimensions.map(|(w, _)| w),
            height: dimensions.map(|(_, h)| h),
            pdq: print.pdq.as_ref().map(|p| p.hash.clone()),
            pdq_quality: print.pdq.as_ref().map(|p| p.quality),
            pdq_black: print.black,
            pdq_mirrors: print.mirrors,
            pdq_frames: print.frames,
        };

        let engine = EngineInfo {
            name: ENGINE_NAME.to_string(),
            version: ENGINE_VERSION.to_string(),
            trust_list_version: self.trust_list_version.clone(),
        };

        let mut report =
            match self.read_manifest_store(format, bytes, manifest, options.max_manifest_bytes)? {
                Some(store) => extract::build(store, engine, asset, options, self.selector),
                None => Report::absent(engine, asset),
            };
        report.metadata = metadata;

        Ok(report)
    }

    fn read_manifest_store(
        &self,
        format: &str,
        bytes: &[u8],
        manifest: Option<&[u8]>,
        max_manifest_bytes: usize,
    ) -> Result<Option<serde_json::Value>, Error> {
        let reader = c2pa::Reader::from_shared_context(&self.context);
        let read = match manifest {
            Some(data) if data.len() > max_manifest_bytes => {
                return Err(Error::LimitExceeded(format!(
                    "remote manifest of {} bytes exceeds the {max_manifest_bytes} byte limit",
                    data.len()
                )));
            }
            Some(data) => reader.with_manifest_data_and_stream(data, format, Cursor::new(bytes)),
            None => reader.with_stream(format, Cursor::new(bytes)),
        };
        let reader = match read {
            Ok(reader) => reader,
            Err(c2pa::Error::JumbfNotFound) if manifest.is_none() => return Ok(None),
            Err(c2pa::Error::RemoteManifestUrl(url)) => return Err(Error::RemoteManifest(url)),
            Err(err) => return Err(Error::ParseFailed(err.to_string())),
        };

        let json = reader.json();
        if json.len() > max_manifest_bytes {
            return Err(Error::LimitExceeded(format!(
                "manifest store of {} bytes exceeds the {max_manifest_bytes} byte limit",
                json.len()
            )));
        }

        let mut store: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| Error::ParseFailed(e.to_string()))?;

        if let serde_json::Value::Object(map) = &mut store {
            map.insert(
                "validation_state".into(),
                serde_json::Value::String(format!("{:?}", reader.validation_state())),
            );
        }

        Ok(Some(store))
    }
}

pub fn verify(
    bytes: &[u8],
    mime_type: &str,
    bundle: &TrustBundle,
    selector: TrustSelector,
    options: &Options,
) -> Result<Report, Error> {
    Verifier::new(bundle, selector)?.verify(bytes, mime_type, options)
}
