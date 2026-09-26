use std::borrow::Cow;
use std::path::Path;

use crate::error::Error;

#[cfg(feature = "bundled-trust-list")]
const BUNDLED_OFFICIAL: &[u8] = include_bytes!("../trust/C2PA-TRUST-LIST.pem");
#[cfg(feature = "bundled-trust-list")]
const BUNDLED_TSA: &[u8] = include_bytes!("../trust/C2PA-TSA-TRUST-LIST.pem");
#[cfg(feature = "bundled-trust-list")]
const BUNDLED_DATE: &str = include_str!("../trust/VERSION");

const CERT_MARKER: &str = "-----BEGIN CERTIFICATE-----";

#[derive(Debug, Clone, Default)]
pub struct TrustBundle {
    pub official_pem: String,
    pub tsa_pem: String,
    pub interim_pem: Option<String>,
    pub version: String,
    pub sha256: String,
}

impl TrustBundle {
    #[cfg(feature = "bundled-trust-list")]
    pub fn bundled() -> Self {
        let official = String::from_utf8_lossy(BUNDLED_OFFICIAL).to_string();
        let sha = crate::digest::hex_sha256(official.as_bytes());

        Self {
            version: format!("{}-{}", BUNDLED_DATE.trim(), &sha[..12]),
            sha256: sha,
            official_pem: official,
            tsa_pem: String::from_utf8_lossy(BUNDLED_TSA).to_string(),
            interim_pem: None,
        }
    }

    pub fn from_pem(official: String, tsa: String, date: &str) -> Result<Self, Error> {
        if official.matches(CERT_MARKER).count() == 0 {
            return Err(Error::TrustList(
                "the official bundle contains no certificate".into(),
            ));
        }
        let sha = crate::digest::hex_sha256(official.as_bytes());

        Ok(Self {
            version: format!("{}-{}", date, &sha[..12]),
            sha256: sha,
            official_pem: official,
            tsa_pem: tsa,
            interim_pem: None,
        })
    }

    pub fn from_files(official: &Path, tsa: Option<&Path>, date: &str) -> Result<Self, Error> {
        let official_pem = std::fs::read_to_string(official)
            .map_err(|e| Error::TrustList(format!("{}: {e}", official.display())))?;
        let tsa_pem = match tsa {
            Some(path) => std::fs::read_to_string(path)
                .map_err(|e| Error::TrustList(format!("{}: {e}", path.display())))?,
            None => String::new(),
        };

        Self::from_pem(official_pem, tsa_pem, date)
    }

    pub fn with_interim(mut self, interim: String) -> Self {
        self.interim_pem = Some(interim);
        self
    }

    pub fn official_count(&self) -> usize {
        self.official_pem.matches(CERT_MARKER).count()
    }

    pub fn tsa_count(&self) -> usize {
        self.tsa_pem.matches(CERT_MARKER).count()
    }

    pub fn anchors(&self, selector: crate::report::TrustSelector) -> Cow<'_, str> {
        use crate::report::TrustSelector as S;

        match selector {
            S::None => Cow::Borrowed(""),
            S::Official => Cow::Borrowed(&self.official_pem),
            S::Interim => match &self.interim_pem {
                Some(interim) => Cow::Borrowed(interim),
                None => Cow::Borrowed(""),
            },
            S::Both => match &self.interim_pem {
                Some(interim) => Cow::Owned(format!("{}\n{interim}", self.official_pem)),
                None => Cow::Borrowed(&self.official_pem),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::TrustSelector;

    fn pem(name: &str) -> String {
        format!("{CERT_MARKER}\n{name}\n-----END CERTIFICATE-----\n")
    }

    #[test]
    fn a_bundle_without_certificates_is_refused() {
        assert!(TrustBundle::from_pem("not a pem".into(), String::new(), "2026-09-09").is_err());
    }

    #[test]
    fn the_version_names_the_content_not_the_download() {
        let a = TrustBundle::from_pem(pem("a"), String::new(), "2026-09-09").unwrap();
        let b = TrustBundle::from_pem(pem("a"), String::new(), "2026-09-09").unwrap();
        let c = TrustBundle::from_pem(pem("b"), String::new(), "2026-09-09").unwrap();

        assert_eq!(a.version, b.version);
        assert_ne!(a.version, c.version);
    }

    #[test]
    fn selectors_pick_the_right_anchors() {
        let bundle = TrustBundle::from_pem(pem("official"), String::new(), "2026-09-09")
            .unwrap()
            .with_interim(pem("interim"));

        assert!(bundle.anchors(TrustSelector::Official).contains("official"));
        assert!(bundle.anchors(TrustSelector::Interim).contains("interim"));
        assert!(bundle.anchors(TrustSelector::Both).contains("official"));
        assert!(bundle.anchors(TrustSelector::Both).contains("interim"));
        assert!(bundle.anchors(TrustSelector::None).is_empty());
        assert_eq!(bundle.official_count(), 1);
    }
}
