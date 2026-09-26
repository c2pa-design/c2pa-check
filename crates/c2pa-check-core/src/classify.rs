use crate::report::{CredentialStatus, SourceCategory};

const IPTC_PREFIX: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/";

const SOURCE_TYPES: &[(&str, SourceCategory)] = &[
    ("trainedAlgorithmicMedia", SourceCategory::AiGenerated),
    (
        "compositeWithTrainedAlgorithmicMedia",
        SourceCategory::AiComposite,
    ),
    ("algorithmicallyEnhanced", SourceCategory::AiEnhanced),
    ("algorithmicMedia", SourceCategory::Algorithmic),
    ("digitalCapture", SourceCategory::Camera),
    ("negativeFilm", SourceCategory::Camera),
    ("positiveFilm", SourceCategory::Camera),
    ("print", SourceCategory::Camera),
    ("softwareImage", SourceCategory::Software),
    ("composite", SourceCategory::Software),
    ("compositeCapture", SourceCategory::Software),
    ("minorHumanEdits", SourceCategory::Software),
    ("humanEdits", SourceCategory::Software),
];

const AI_GENERATORS: &[&str] = &[
    "openai",
    "dall-e",
    "dalle",
    "sora",
    "chatgpt",
    "firefly",
    "midjourney",
    "imagen",
    "gemini",
    "nano banana",
    "stable diffusion",
    "stability",
    "flux",
    "ideogram",
    "leonardo",
    "runway",
    "grok",
    "xai",
    "luma",
    "kling",
    "veo",
];

fn rank(category: SourceCategory) -> u8 {
    match category {
        SourceCategory::AiGenerated => 6,
        SourceCategory::AiComposite => 5,
        SourceCategory::AiEnhanced => 4,
        SourceCategory::Algorithmic => 3,
        SourceCategory::Software => 2,
        SourceCategory::Camera => 1,
        SourceCategory::Unknown => 0,
    }
}

pub fn category_of(uri: &str) -> Option<SourceCategory> {
    let slug = uri
        .strip_prefix(IPTC_PREFIX)
        .unwrap_or_else(|| uri.rsplit('/').next().unwrap_or(uri));

    SOURCE_TYPES
        .iter()
        .find(|(name, _)| *name == slug)
        .map(|(_, category)| *category)
}

pub fn strongest(current: SourceCategory, candidate: SourceCategory) -> SourceCategory {
    if rank(candidate) > rank(current) {
        candidate
    } else {
        current
    }
}

pub fn from_generator(generator: &str) -> Option<SourceCategory> {
    let lower = generator.to_lowercase();
    AI_GENERATORS
        .iter()
        .any(|name| lower.contains(name))
        .then_some(SourceCategory::AiGenerated)
}

pub fn status(present: bool, valid: bool, trusted: bool) -> CredentialStatus {
    match (present, valid, trusted) {
        (false, _, _) => CredentialStatus::Absent,
        (true, false, _) => CredentialStatus::PresentInvalid,
        (true, true, false) => CredentialStatus::ValidUntrusted,
        (true, true, true) => CredentialStatus::ValidTrusted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_the_iptc_vocabulary() {
        assert_eq!(
            category_of("http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"),
            Some(SourceCategory::AiGenerated)
        );
        assert_eq!(category_of("digitalCapture"), Some(SourceCategory::Camera));
        assert_eq!(category_of("http://example.com/unknown"), None);
    }

    #[test]
    fn an_ai_declaration_outranks_a_capture_declaration() {
        let merged = strongest(SourceCategory::Camera, SourceCategory::AiGenerated);
        assert_eq!(merged, SourceCategory::AiGenerated);

        let kept = strongest(SourceCategory::AiGenerated, SourceCategory::Camera);
        assert_eq!(kept, SourceCategory::AiGenerated);
    }

    #[test]
    fn statuses_cover_every_combination() {
        assert_eq!(status(false, false, false), CredentialStatus::Absent);
        assert_eq!(status(true, false, false), CredentialStatus::PresentInvalid);
        assert_eq!(status(true, true, false), CredentialStatus::ValidUntrusted);
        assert_eq!(status(true, true, true), CredentialStatus::ValidTrusted);
    }

    #[test]
    fn generators_are_only_a_fallback() {
        assert_eq!(
            from_generator("OpenAI DALL-E"),
            Some(SourceCategory::AiGenerated)
        );
        assert_eq!(from_generator("Leica M11"), None);
    }
}
