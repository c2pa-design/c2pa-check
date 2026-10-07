mod fetch;
mod mcp;
mod output;
mod trust_cmd;

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use c2pa_check_core::{report::TrustSelector, Options, Report, TrustBundle, Verifier};
use clap::{Parser, Subcommand, ValueEnum};

const EXIT_EXPECTATION: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_PARSE: u8 = 3;
const EXIT_NETWORK: u8 = 4;

#[derive(Parser)]
#[command(
    name = "c2pa-check",
    version,
    about = "Verify Content Credentials in files and URLs.",
    long_about = "Verify Content Credentials in files and URLs, and fail a build when \
provenance disappears. Monitor production provenance at https://c2pa.design."
)]
struct Cli {
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,

    #[arg(long, value_enum, default_value_t = TrustArg::Official)]
    trust: TrustArg,

    #[arg(long, value_name = "PATH")]
    trust_anchors: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,

    #[arg(long, value_enum)]
    expect: Option<Expect>,

    #[arg(long, value_name = "PCT")]
    coverage: Option<f64>,

    #[arg(long)]
    raw: bool,

    #[arg(long)]
    offline: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Inspect {
        target: String,
        #[arg(long)]
        json: bool,
    },
    Trust {
        #[command(subcommand)]
        action: trust_cmd::Action,
    },
    Completions {
        shell: clap_complete::Shell,
    },
    Mcp,
}

#[derive(Copy, Clone, ValueEnum)]
enum TrustArg {
    Official,
    Interim,
    Both,
    None,
}

impl From<TrustArg> for TrustSelector {
    fn from(value: TrustArg) -> Self {
        match value {
            TrustArg::Official => Self::Official,
            TrustArg::Interim => Self::Interim,
            TrustArg::Both => Self::Both,
            TrustArg::None => Self::None,
        }
    }
}

#[derive(Copy, Clone, ValueEnum)]
enum Format {
    Text,
    Json,
    Ndjson,
    Junit,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum)]
enum Expect {
    Present,
    Trusted,
    Absent,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("c2pa-check: {err}");

            ExitCode::from(EXIT_USAGE)
        }
    }
}

fn run(mut cli: Cli) -> anyhow::Result<u8> {
    match cli.command.take() {
        Some(Command::Completions { shell }) => {
            output::completions(shell);

            return Ok(0);
        }
        Some(Command::Trust { action }) => return trust_cmd::run(action, cli.offline),
        Some(Command::Mcp) => return mcp::serve(load_bundle(&cli)?),
        Some(Command::Inspect { target, json }) => return inspect(&cli, &target, json),
        None => {}
    }

    if cli.targets.is_empty() {
        eprintln!("c2pa-check: give at least one file, glob or URL (--help for usage)");

        return Ok(EXIT_USAGE);
    }

    let bundle = load_bundle(&cli)?;
    let verifier = verifier_for(&bundle, cli.trust.into())?;
    let options = Options {
        include_raw: cli.raw,
        ..Options::default()
    };

    let targets = expand(&cli.targets)?;
    let mut results = Vec::with_capacity(targets.len());
    let mut network_failure = false;
    let mut parse_failure = false;

    for target in &targets {
        match load(target, cli.offline) {
            Ok((bytes, mime)) => match verifier.verify(&bytes, &mime, &options) {
                Ok(report) => results.push((target.clone(), Some(report))),
                Err(err) => {
                    eprintln!("{target}: {err}");
                    parse_failure = true;
                    results.push((target.clone(), None));
                }
            },
            Err(err) => {
                eprintln!("{target}: {err}");
                network_failure = true;
                results.push((target.clone(), None));
            }
        }
    }

    output::render(cli.format, &results, std::io::stdout().is_terminal())?;

    if network_failure {
        return Ok(EXIT_NETWORK);
    }
    if parse_failure {
        return Ok(EXIT_PARSE);
    }
    if !meets_expectations(&results, cli.expect, cli.coverage) {
        return Ok(EXIT_EXPECTATION);
    }

    Ok(0)
}

fn inspect(cli: &Cli, target: &str, json: bool) -> anyhow::Result<u8> {
    let bundle = load_bundle(cli)?;
    let (bytes, mime) = load(target, cli.offline)?;
    let options = Options {
        include_raw: true,
        ..Options::default()
    };

    let report = verifier_for(&bundle, cli.trust.into())?.verify(&bytes, &mime, &options)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        output::tree(target, &report);
    }

    Ok(0)
}

fn verifier_for(bundle: &TrustBundle, trust: TrustSelector) -> anyhow::Result<Verifier> {
    Verifier::new(bundle, trust).map_err(|err| {
        anyhow::anyhow!(
            "the trust list {} could not be loaded ({err}); run `c2pa-check trust update`",
            bundle.version
        )
    })
}

fn load_bundle(cli: &Cli) -> anyhow::Result<TrustBundle> {
    if let Some(path) = &cli.trust_anchors {
        return Ok(TrustBundle::from_files(path, None, "custom")?);
    }
    if cli.offline {
        return Ok(TrustBundle::bundled());
    }

    trust_cmd::active()
}

fn is_url(target: &str) -> bool {
    target.starts_with("http://") || target.starts_with("https://")
}

fn load(target: &str, offline: bool) -> anyhow::Result<(Vec<u8>, String)> {
    if is_url(target) {
        if offline {
            anyhow::bail!("--offline refuses to fetch {target}");
        }

        return fetch::get(target);
    }

    let bytes = std::fs::read(target)?;
    let mime = c2pa_check_core::media::mime_from_extension(target).to_string();

    Ok((bytes, mime))
}

fn expand(targets: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();

    for target in targets {
        if is_url(target) || !target.contains(['*', '?', '[']) {
            out.push(target.clone());

            continue;
        }

        let before = out.len();
        for entry in glob::glob(target)? {
            out.push(entry?.to_string_lossy().to_string());
        }
        if out.len() == before {
            anyhow::bail!("{target} matched no files");
        }
    }

    Ok(out)
}

fn meets_expectations(
    results: &[(String, Option<Report>)],
    expect: Option<Expect>,
    coverage: Option<f64>,
) -> bool {
    use c2pa_check_core::CredentialStatus as S;

    if let Some(expect) = expect {
        let ok = results.iter().all(|(_, report)| {
            report.as_ref().is_some_and(|r| match expect {
                Expect::Present => {
                    matches!(r.credential.status, S::ValidTrusted | S::ValidUntrusted)
                }
                Expect::Trusted => r.credential.status == S::ValidTrusted,
                Expect::Absent => r.credential.status == S::Absent,
            })
        });
        if !ok {
            return false;
        }
    }

    if let Some(threshold) = coverage {
        let total = results.len();
        if total == 0 {
            return true;
        }
        let trusted = results
            .iter()
            .filter(|(_, report)| {
                report
                    .as_ref()
                    .is_some_and(|r| r.credential.status == S::ValidTrusted)
            })
            .count();
        let pct = trusted as f64 / total as f64 * 100.0;
        if pct + f64::EPSILON < threshold {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use c2pa_check_core::report::{Asset, Credential, CredentialStatus, EngineInfo};

    fn report(status: CredentialStatus) -> Report {
        let mut r = Report::absent(
            EngineInfo {
                name: "t".into(),
                version: "0".into(),
                trust_list_version: "v".into(),
            },
            Asset {
                sha256: "ab".into(),
                mime_type: "image/jpeg".into(),
                size_bytes: 1,
                width: None,
                height: None,
                pdq: None,
                pdq_quality: None,
            },
        );
        r.credential = Credential {
            present: status != CredentialStatus::Absent,
            valid: matches!(
                status,
                CredentialStatus::ValidTrusted | CredentialStatus::ValidUntrusted
            ),
            trusted: status == CredentialStatus::ValidTrusted,
            status,
        };
        r
    }

    fn results(statuses: &[CredentialStatus]) -> Vec<(String, Option<Report>)> {
        statuses
            .iter()
            .enumerate()
            .map(|(i, s)| (format!("f{i}.jpg"), Some(report(*s))))
            .collect()
    }

    #[test]
    fn expect_trusted_fails_on_an_untrusted_signer() {
        let set = results(&[
            CredentialStatus::ValidTrusted,
            CredentialStatus::ValidUntrusted,
        ]);

        assert!(!meets_expectations(&set, Some(Expect::Trusted), None));
        assert!(meets_expectations(&set, Some(Expect::Present), None));
    }

    #[test]
    fn coverage_is_the_share_of_trusted_assets() {
        let set = results(&[
            CredentialStatus::ValidTrusted,
            CredentialStatus::ValidTrusted,
            CredentialStatus::Absent,
        ]);

        assert!(meets_expectations(&set, None, Some(66.0)));
        assert!(!meets_expectations(&set, None, Some(100.0)));
    }

    #[test]
    fn a_url_is_never_treated_as_a_glob() {
        assert!(is_url("https://example.com/a.jpg"));
        assert!(is_url("http://example.com/a.jpg"));
        assert!(!is_url("http_report.jpg"));
        assert!(!is_url("./https/a.jpg"));
    }

    #[test]
    fn a_glob_that_matches_nothing_is_an_error_not_a_silent_pass() {
        let miss = expand(&["/nonexistent-directory-for-tests/*.jpg".to_string()]);

        assert!(miss.is_err());
    }

    #[test]
    fn a_plain_target_is_passed_through_untouched() {
        let out = expand(&[
            "photo.jpg".to_string(),
            "https://example.com/a.jpg".to_string(),
        ])
        .expect("no globs to expand");

        assert_eq!(out, vec!["photo.jpg", "https://example.com/a.jpg"]);
    }

    #[test]
    fn an_empty_result_set_never_satisfies_an_expectation_by_accident() {
        let empty: Vec<(String, Option<Report>)> = Vec::new();

        assert!(meets_expectations(&empty, Some(Expect::Trusted), None));
        assert!(meets_expectations(&empty, None, Some(100.0)));
    }

    #[test]
    fn a_target_that_could_not_be_read_never_counts_as_a_pass() {
        let set = vec![("broken.jpg".to_string(), None)];

        assert!(!meets_expectations(&set, Some(Expect::Absent), None));
    }
}
