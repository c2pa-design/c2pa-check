mod carry_cmd;
mod doctor;
mod env;
mod fetch;
mod mcp;
mod output;
#[cfg(test)]
mod test_server;
mod trust_cmd;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
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

    #[arg(
        long,
        value_name = "PATH",
        help = "write the report to PATH instead of stdout (e.g. --format junit --output c2pa-check.xml)"
    )]
    output: Option<PathBuf>,

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
    #[command(
        about = "Check the API key, quota, network, webhook secret and Node version",
        long_about = "Check the setup c2pa-check and the c2pa.design API rely on: C2PA_API_KEY \
(deprecated fallback C2PA_DESIGN_API_KEY) format, key type, plan and remaining quota from GET /whoami, \
reachability of C2PA_API_BASE (fallback C2PA_DESIGN_API_URL, default https://api.c2pa.design/v1), the C2PA_WEBHOOK_SECRET \
format, and the Node.js version when run through npx.\n\nExit codes: 0 every check passed \
(warnings allowed), 1 a check failed."
    )]
    Doctor(doctor::DoctorArgs),
    #[command(
        about = "Carry a Content Credential from a signed original into a converted copy",
        long_about = "Carry a Content Credential from a signed original into a converted copy \
(resized, re-encoded, compressed). The copy gets a new manifest with the original as its \
parentOf ingredient and c2pa.transcoded / c2pa.resized actions, so the chain back to the \
generator survives the conversion.\n\nSigner, in order: C2PA_SIGN_CERT + C2PA_SIGN_KEY (your \
certificate, or *_FILE paths); C2PA_API_KEY (or the deprecated C2PA_DESIGN_API_KEY; signs as your organization via \
c2pa.design, falls back to a local key if unavailable); otherwise a local key kept in \
~/.config/c2pa-check/identity.\n\nComposites: --compose A B ... --to OUTPUT signs OUTPUT as a \
new work (c2pa.created, or c2pa.edited with --edited) with every source attached as a \
componentOf ingredient. Hosted signing does not accept composites yet, so they are signed \
with your own certificate or the local key.\n\nExit codes: 0 carried and verified, 1 \
--strict and a file has no or an ambiguous original, 2 usage or I/O error, 5 refused (rule in \
--json: different_picture, source_unsigned, low_quality, not_comparable, or the rule \
c2pa.design returned with carry_rejected)."
    )]
    Carry(carry_cmd::CarryArgs),
    #[command(
        about = "Write a certificate chain and private key for C2PA_SIGN_CERT / C2PA_SIGN_KEY"
    )]
    Keygen(carry_cmd::KeygenArgs),
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
        Some(Command::Keygen(args)) => return carry_cmd::keygen(args),
        Some(Command::Doctor(args)) => return doctor::run(&args),
        Some(Command::Carry(args)) => {
            let bundle = load_bundle(&cli)?;
            let verifier = verifier_for(&bundle, cli.trust.into())?;

            return carry_cmd::run(args, &verifier);
        }
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
                eprintln!("{target}: {err:#}");
                if failure_exit(target) == EXIT_NETWORK {
                    network_failure = true;
                } else {
                    parse_failure = true;
                }
                results.push((target.clone(), None));
            }
        }
    }

    write_report(cli.format, &results, cli.output.as_deref())?;

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

fn write_report(
    format: Format,
    results: &[(String, Option<Report>)],
    path: Option<&Path>,
) -> anyhow::Result<()> {
    let Some(path) = path else {
        return output::render(
            format,
            results,
            std::io::stdout().is_terminal(),
            &mut std::io::stdout().lock(),
        );
    };
    let file = std::fs::File::create(path)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    let mut writer = std::io::BufWriter::new(file);
    output::render(format, results, false, &mut writer)?;
    std::io::Write::flush(&mut writer)
        .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))
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

fn failure_exit(target: &str) -> u8 {
    if is_url(target) {
        EXIT_NETWORK
    } else {
        EXIT_PARSE
    }
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

    let bytes = carry_cmd::read_media(Path::new(target))?;
    let mime = c2pa_check_core::media::mime_from_extension(target).to_string();

    Ok((bytes, mime))
}

fn expand(targets: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();

    for target in targets {
        if is_url(target) || !target.contains(['*', '?', '[', '{']) {
            out.push(target.clone());

            continue;
        }

        let before = out.len();
        for pattern in braces(target) {
            for entry in glob::glob(&pattern)? {
                let path = entry?;
                if path.is_file() {
                    out.push(path.to_string_lossy().to_string());
                }
            }
        }
        if out.len() == before {
            anyhow::bail!("{target} matched no files");
        }
    }

    Ok(out)
}

fn braces(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('{') else {
        return vec![pattern.to_string()];
    };
    let Some(len) = pattern[open..].find('}') else {
        return vec![pattern.to_string()];
    };
    let close = open + len;

    pattern[open + 1..close]
        .split(',')
        .flat_map(|alt| {
            braces(&format!(
                "{}{alt}{}",
                &pattern[..open],
                &pattern[close + 1..]
            ))
        })
        .collect()
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
                ..Asset::default()
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
    fn braces_expand_every_alternative() {
        assert_eq!(
            braces("dist/**/*.{jpg,png}"),
            ["dist/**/*.jpg", "dist/**/*.png"]
        );
        assert_eq!(
            braces("{a,b}/x.{c,d}"),
            ["a/x.c", "a/x.d", "b/x.c", "b/x.d"]
        );
        assert_eq!(braces("plain/*.jpg"), ["plain/*.jpg"]);
        assert_eq!(braces("open{a,b"), ["open{a,b"]);
    }

    #[test]
    fn expand_matches_brace_globs_and_skips_directories() {
        let dir = std::env::temp_dir().join(format!("c2pa-check-expand-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("nested.jpg")).unwrap();
        for name in ["a.jpg", "b.png", "c.txt"] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        let root = dir.to_string_lossy();

        let mut got = expand(&[format!("{root}/*.{{jpg,png}}")]).unwrap();
        got.sort();
        let all = expand(&[format!("{root}/*")]).unwrap();
        let none = expand(&[format!("{root}/*.{{gif,avif}}")]);
        std::fs::remove_dir_all(&dir).unwrap();

        assert_eq!(got, [format!("{root}/a.jpg"), format!("{root}/b.png")]);
        assert_eq!(all.len(), 3);
        assert!(none.is_err());
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

    #[test]
    fn output_writes_the_report_to_the_file() {
        let dir = std::env::temp_dir().join(format!("c2pa-check-output-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let json = dir.join("report.json");
        let junit = dir.join("report.xml");

        write_report(
            Format::Json,
            &results(&[CredentialStatus::Absent]),
            Some(&json),
        )
        .unwrap();
        write_report(
            Format::Junit,
            &results(&[CredentialStatus::Absent]),
            Some(&junit),
        )
        .unwrap();
        let written = std::fs::read_to_string(&json).unwrap();
        let xml = std::fs::read_to_string(&junit).unwrap();
        let missing = write_report(
            Format::Json,
            &results(&[CredentialStatus::Absent]),
            Some(&dir.join("no-such-dir").join("r.json")),
        );
        std::fs::remove_dir_all(&dir).ok();

        let value: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert!(!value.is_null());
        assert!(written.contains("absent"));
        assert!(xml.starts_with("<?xml"), "{xml}");
        assert!(missing.unwrap_err().to_string().starts_with("writing "));
    }

    #[test]
    fn a_missing_local_file_is_unreadable_not_a_network_failure() {
        let err = load("/nonexistent/c2pa-check/missing.jpg", false).unwrap_err();

        assert!(format!("{err:#}").contains("missing.jpg"));
        assert_eq!(
            failure_exit("/nonexistent/c2pa-check/missing.jpg"),
            EXIT_PARSE
        );
        assert_eq!(failure_exit("https://example.com/a.jpg"), EXIT_NETWORK);
        assert_eq!(EXIT_PARSE, 3);
    }

    #[test]
    fn offline_refuses_a_url_as_a_network_failure() {
        let err = load("https://example.com/a.jpg", true).unwrap_err();

        assert!(err.to_string().contains("--offline"));
        assert_eq!(failure_exit("https://example.com/a.jpg"), 4);
    }
}
