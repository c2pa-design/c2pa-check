use serde::{Deserialize, Serialize};

pub use crate::metadata::Metadata;

pub const SCHEMA_VERSION: &str = "1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    Absent,
    PresentInvalid,
    ValidUntrusted,
    ValidTrusted,
    Error,
}

impl CredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::PresentInvalid => "present_invalid",
            Self::ValidUntrusted => "valid_untrusted",
            Self::ValidTrusted => "valid_trusted",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceCategory {
    AiGenerated,
    AiComposite,
    AiEnhanced,
    Algorithmic,
    Software,
    Camera,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustSelector {
    Official,
    Interim,
    Both,
    None,
}

impl TrustSelector {
    pub const ALL: [Self; 4] = [Self::Official, Self::Interim, Self::Both, Self::None];

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "official" => Some(Self::Official),
            "interim" => Some(Self::Interim),
            "both" => Some(Self::Both),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Official => "official",
            Self::Interim => "interim",
            Self::Both => "both",
            Self::None => "none",
        }
    }

    pub fn index(self) -> usize {
        match self {
            Self::Official => 0,
            Self::Interim => 1,
            Self::Both => 2,
            Self::None => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: String,
    pub engine: EngineInfo,
    pub credential: Credential,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<Signer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim: Option<Claim>,
    pub source: Source,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Action>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ingredients: Vec<Ingredient>,
    pub validation: Validation,
    pub asset: Asset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_manifest_store: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineInfo {
    pub name: String,
    pub version: String,
    pub trust_list_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub present: bool,
    pub valid: bool,
    pub trusted: bool,
    pub status: CredentialStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Signer {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub common_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_trust_list: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conformant_product: Option<ConformantProduct>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformantProduct {
    pub name: String,
    pub assurance_level: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Claim {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Source {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digital_source_type: Option<String>,
    pub category: SourceCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ingredient {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relationship: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<CredentialStatus>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Validation {
    pub errors: Vec<ValidationEntry>,
    pub warnings: Vec<ValidationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationEntry {
    pub code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Asset {
    pub sha256: String,
    pub mime_type: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdq: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdq_quality: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pdq_black: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pdq_mirrors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pdq_frames: Vec<String>,
}

impl Report {
    pub fn absent(engine: EngineInfo, asset: Asset) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            engine,
            credential: Credential {
                present: false,
                valid: false,
                trusted: false,
                status: CredentialStatus::Absent,
            },
            signer: None,
            claim: None,
            source: Source {
                digital_source_type: None,
                category: SourceCategory::Unknown,
            },
            actions: Vec::new(),
            ingredients: Vec::new(),
            validation: Validation::default(),
            asset,
            metadata: None,
            raw_manifest_store: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_selector_parses_from_the_name_it_serializes_as() {
        for selector in TrustSelector::ALL {
            assert_eq!(TrustSelector::parse(selector.as_str()), Some(selector));
        }
    }

    #[test]
    fn an_unknown_selector_is_refused_rather_than_guessed() {
        for value in ["", "OFFICIAL", "all", "official "] {
            assert_eq!(TrustSelector::parse(value), None, "value {value:?}");
        }
    }

    #[test]
    fn every_selector_has_its_own_slot() {
        let mut seen = [false; TrustSelector::ALL.len()];

        for selector in TrustSelector::ALL {
            let index = selector.index();

            assert!(!seen[index], "{selector:?} shares a slot");
            seen[index] = true;
        }
    }

    #[test]
    fn every_credential_status_serializes_as_the_published_name() {
        let cases = [
            (CredentialStatus::Absent, "absent"),
            (CredentialStatus::PresentInvalid, "present_invalid"),
            (CredentialStatus::ValidUntrusted, "valid_untrusted"),
            (CredentialStatus::ValidTrusted, "valid_trusted"),
            (CredentialStatus::Error, "error"),
        ];

        for (status, name) in cases {
            assert_eq!(status.as_str(), name);
            assert_eq!(serde_json::to_value(status).unwrap(), name);
        }
    }

    #[test]
    fn a_report_serializes_without_its_empty_fields() {
        let report = Report::absent(
            EngineInfo {
                name: "t".into(),
                version: "0".into(),
                trust_list_version: "v".into(),
            },
            Asset {
                sha256: "ab".into(),
                mime_type: "image/png".into(),
                size_bytes: 1,
                width: None,
                height: None,
                pdq: None,
                pdq_quality: None,
                ..Asset::default()
            },
        );

        let value = serde_json::to_value(&report).expect("a serializable report");

        assert!(value.get("signer").is_none());
        assert!(value.get("claim").is_none());
        assert!(value.get("actions").is_none());
        assert!(value.get("raw_manifest_store").is_none());
        assert!(value.get("metadata").is_none());
        assert!(value["asset"].get("pdq").is_none());
        assert!(value["asset"].get("pdq_quality").is_none());
        assert!(value["asset"].get("pdq_black").is_none());
        assert!(value["asset"].get("pdq_mirrors").is_none());
        assert!(value["asset"].get("pdq_frames").is_none());
        assert_eq!(value["credential"]["status"], "absent");
        assert_eq!(value["schema_version"], SCHEMA_VERSION);
    }

    #[test]
    fn a_report_round_trips_through_json() {
        let report = Report::absent(
            EngineInfo {
                name: "t".into(),
                version: "0".into(),
                trust_list_version: "v".into(),
            },
            Asset {
                sha256: "ab".into(),
                mime_type: "image/png".into(),
                size_bytes: 1,
                width: Some(8),
                height: Some(8),
                pdq: Some("0".repeat(64)),
                pdq_quality: Some(42),
                ..Asset::default()
            },
        );

        let text = serde_json::to_string(&report).expect("a serializable report");
        let back: Report = serde_json::from_str(&text).expect("a readable report");

        assert_eq!(back.asset.width, Some(8));
        assert_eq!(back.asset.pdq_quality, Some(42));
        assert_eq!(back.asset.pdq.as_deref().map(str::len), Some(64));
        assert_eq!(back.credential.status, CredentialStatus::Absent);
    }

    #[test]
    fn metadata_serializes_with_explicit_nulls() {
        let metadata = Metadata {
            four_cs_score: 25,
            fields: vec!["Creator".into()],
            digital_source_type: None,
            ai_system_used: None,
        };

        let value = serde_json::to_value(&metadata).expect("serializable metadata");

        assert_eq!(value["four_cs_score"], 25);
        assert_eq!(value["fields"][0], "Creator");
        assert!(value["digital_source_type"].is_null());
        assert!(value.as_object().unwrap().contains_key("ai_system_used"));
    }
}
