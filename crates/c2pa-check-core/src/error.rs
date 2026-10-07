use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),
    #[error("asset exceeds the configured limit: {0}")]
    LimitExceeded(String),
    #[error("the asset could not be parsed: {0}")]
    ParseFailed(String),
    #[error("the manifest store is remote, at {0}")]
    RemoteManifest(String),
    #[error("trust list: {0}")]
    TrustList(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedMediaType(_) => "unsupported_media_type",
            Self::LimitExceeded(_) => "limit_exceeded",
            Self::ParseFailed(_) => "parse_failed",
            Self::RemoteManifest(_) => "remote_manifest",
            Self::TrustList(_) => "trust_list",
            Self::Io(_) => "io",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_variant() -> Vec<Error> {
        vec![
            Error::UnsupportedMediaType("application/zip".into()),
            Error::LimitExceeded("too big".into()),
            Error::ParseFailed("truncated".into()),
            Error::RemoteManifest("https://example.com/m.c2pa".into()),
            Error::TrustList("no anchors".into()),
            Error::Io(std::io::Error::other("disk")),
        ]
    }

    #[test]
    fn every_code_is_the_stable_name_a_caller_switches_on() {
        let cases = [
            (
                Error::UnsupportedMediaType(String::new()),
                "unsupported_media_type",
            ),
            (Error::LimitExceeded(String::new()), "limit_exceeded"),
            (Error::ParseFailed(String::new()), "parse_failed"),
            (Error::RemoteManifest(String::new()), "remote_manifest"),
            (Error::TrustList(String::new()), "trust_list"),
            (Error::Io(std::io::Error::other("x")), "io"),
        ];

        for (error, code) in cases {
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn no_two_variants_share_a_code() {
        let mut seen = Vec::new();

        for error in every_variant() {
            let code = error.code();

            assert!(!seen.contains(&code), "{code} is reused");
            seen.push(code);
        }
    }

    #[test]
    fn every_message_names_the_cause_it_was_given() {
        let detail = "truncated jumbf";

        assert!(Error::ParseFailed(detail.into())
            .to_string()
            .contains(detail));
        assert!(Error::TrustList(detail.into()).to_string().contains(detail));
        assert!(Error::LimitExceeded(detail.into())
            .to_string()
            .contains(detail));
    }

    #[test]
    fn an_io_failure_keeps_its_source() {
        let error = Error::from(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "missing.jpg",
        ));

        assert_eq!(error.code(), "io");
        assert!(error.to_string().contains("missing.jpg"));
    }
}
