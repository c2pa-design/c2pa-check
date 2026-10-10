use std::collections::BTreeMap;
use std::path::Path;

use c2pa_check_core::{CredentialStatus, Report};

pub type Baseline = BTreeMap<String, CredentialStatus>;

fn rank(status: CredentialStatus) -> u8 {
    match status {
        CredentialStatus::ValidTrusted => 2,
        CredentialStatus::ValidUntrusted => 1,
        _ => 0,
    }
}

fn key(target: &str) -> String {
    target.trim_start_matches("./").replace('\\', "/")
}

pub fn snapshot(results: &[(String, Option<Report>)]) -> Baseline {
    results
        .iter()
        .map(|(target, report)| {
            let status = report
                .as_ref()
                .map_or(CredentialStatus::Error, |r| r.credential.status);
            (key(target), status)
        })
        .collect()
}

pub fn regressions(baseline: &Baseline, results: &[(String, Option<Report>)]) -> Vec<String> {
    snapshot(results)
        .into_iter()
        .filter_map(|(target, now)| {
            let before = *baseline.get(&target)?;
            (rank(now) < rank(before))
                .then(|| format!("{target}: was {}, now {}", before.as_str(), now.as_str()))
        })
        .collect()
}

pub fn load(path: &Path) -> anyhow::Result<Baseline> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        anyhow::anyhow!(
            "reading baseline {}: {err} (create it with --update-baseline)",
            path.display()
        )
    })?;

    serde_json::from_str(&text).map_err(|err| anyhow::anyhow!("{}: {err}", path.display()))
}

pub fn write(path: &Path, baseline: &Baseline) -> anyhow::Result<()> {
    let mut text = serde_json::to_string_pretty(baseline)?;
    text.push('\n');

    std::fs::write(path, text).map_err(|err| anyhow::anyhow!("writing {}: {err}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_file_that_lost_ground_is_a_regression() {
        let baseline: Baseline = [
            ("kept.png", CredentialStatus::ValidTrusted),
            ("lost.png", CredentialStatus::ValidTrusted),
            ("downgraded.png", CredentialStatus::ValidTrusted),
            ("never.png", CredentialStatus::Absent),
            ("deleted.png", CredentialStatus::ValidTrusted),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect();
        let results = crate::tests::results_named(&[
            ("./kept.png", CredentialStatus::ValidTrusted),
            ("lost.png", CredentialStatus::Absent),
            ("downgraded.png", CredentialStatus::ValidUntrusted),
            ("never.png", CredentialStatus::Absent),
            ("new.png", CredentialStatus::Absent),
        ]);

        let got = regressions(&baseline, &results);

        assert_eq!(
            got,
            [
                "downgraded.png: was valid_trusted, now valid_untrusted",
                "lost.png: was valid_trusted, now absent"
            ]
        );
        assert_eq!(
            snapshot(&results)["kept.png"],
            CredentialStatus::ValidTrusted
        );
    }
}
