pub fn explanation_key(code: &str) -> String {
    let normalized = code.replace('.', "_");

    format!("validation.{normalized}")
}

const INFORMATIONAL: &[&str] = &[
    "claimSignature.validated",
    "signingCredential.trusted",
    "timeStamp.trusted",
    "timeStamp.validated",
    "assertion.hashedURI.match",
    "assertion.dataHash.match",
    "assertion.bmffHash.match",
    "assertion.boxesHash.match",
    "assertion.accessible",
    "ingredient.claimSignature.validated",
];

pub fn is_informational(code: &str) -> bool {
    INFORMATIONAL.contains(&code)
}

const WARNINGS: &[&str] = &[
    "signingCredential.untrusted",
    "timeStamp.untrusted",
    "timeStamp.mismatch",
    "signingCredential.expired",
    "assertion.dataHash.unknown",
];

pub fn is_warning(code: &str) -> bool {
    WARNINGS.contains(&code)
}

pub fn documentation_url(code: &str) -> String {
    format!(
        "https://c2pa.design/en/docs/errors#{}",
        code.replace('.', "-")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_stable_and_translatable() {
        assert_eq!(
            explanation_key("signingCredential.untrusted"),
            "validation.signingCredential_untrusted"
        );
    }

    #[test]
    fn untrusted_is_a_warning_not_an_error() {
        assert!(is_warning("signingCredential.untrusted"));
        assert!(!is_informational("signingCredential.untrusted"));
        assert!(is_informational("claimSignature.validated"));
    }
}
