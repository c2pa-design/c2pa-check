use std::path::PathBuf;

use c2pa_check_core::report::TrustSelector;
use c2pa_check_core::{TrustBundle, Verifier};
use clap::Subcommand;

const OFFICIAL_URL: &str =
    "https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TRUST-LIST.pem";
const TSA_URL: &str =
    "https://raw.githubusercontent.com/c2pa-org/conformance-public/main/trust-list/C2PA-TSA-TRUST-LIST.pem";
const MIN_CERTS: usize = 20;

#[derive(Subcommand)]
pub enum Action {
    Status,
    Update,
}

fn cache_dir() -> anyhow::Result<PathBuf> {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .ok_or_else(|| anyhow::anyhow!("no cache directory available"))?;

    Ok(base.join("c2pa-check"))
}

pub fn cached() -> anyhow::Result<Option<TrustBundle>> {
    let dir = cache_dir()?;
    let official = dir.join("C2PA-TRUST-LIST.pem");
    if !official.exists() {
        return Ok(None);
    }
    let date = std::fs::read_to_string(dir.join("VERSION")).unwrap_or_default();

    match TrustBundle::from_files(
        &official,
        Some(&dir.join("C2PA-TSA-TRUST-LIST.pem")),
        date.trim(),
    ) {
        Ok(bundle) => Ok(Some(bundle)),
        Err(err) => {
            eprintln!("c2pa-check: ignoring the cached trust list ({err})");

            Ok(None)
        }
    }
}

pub fn active() -> anyhow::Result<TrustBundle> {
    Ok(cached()?.unwrap_or_else(TrustBundle::bundled))
}

pub fn run(action: Action, offline: bool) -> anyhow::Result<u8> {
    match action {
        Action::Status => status(offline),
        Action::Update => update(offline),
    }
}

fn status(offline: bool) -> anyhow::Result<u8> {
    let bundled = TrustBundle::bundled();
    println!(
        "bundled   {} · {} certificates · {} timestamp authorities",
        bundled.version,
        bundled.official_count(),
        bundled.tsa_count()
    );

    let cache = cached()?;
    if let Some(cache) = &cache {
        println!(
            "cached    {} · {} certificates",
            cache.version,
            cache.official_count()
        );
    }
    if offline {
        return Ok(0);
    }

    let in_use = cache.unwrap_or(bundled);

    match crate::fetch::get(OFFICIAL_URL) {
        Ok((body, _)) => {
            let upstream = String::from_utf8_lossy(&body).to_string();
            let digest = c2pa_check_core::digest::hex_sha256(upstream.as_bytes());
            let same = digest == in_use.sha256;
            println!(
                "upstream  {} · {} certificates · {}",
                &digest[..12],
                upstream.matches("-----BEGIN CERTIFICATE-----").count(),
                if same {
                    "identical"
                } else {
                    "newer — run `c2pa-check trust update`"
                }
            );
        }
        Err(err) => println!("upstream  unavailable ({err})"),
    }

    Ok(0)
}

fn update(offline: bool) -> anyhow::Result<u8> {
    if offline {
        anyhow::bail!("--offline cannot update the trust list");
    }

    let (official, _) = crate::fetch::get(OFFICIAL_URL)?;
    let (tsa, _) = crate::fetch::get(TSA_URL)?;

    let text = String::from_utf8_lossy(&official).to_string();
    let count = text.matches("-----BEGIN CERTIFICATE-----").count();
    if count < MIN_CERTS {
        anyhow::bail!("refusing a trust list with only {count} certificates");
    }

    let date = c2pa_check_core::calendar::today();
    let candidate = TrustBundle::from_pem(
        text.clone(),
        String::from_utf8_lossy(&tsa).to_string(),
        &date,
    )?;
    Verifier::new(&candidate, TrustSelector::Official)
        .map_err(|err| anyhow::anyhow!("refusing a trust list the verifier cannot load: {err}"))?;

    let dir = cache_dir()?;
    std::fs::create_dir_all(&dir)?;
    write_atomically(&dir.join("C2PA-TRUST-LIST.pem"), &official)?;
    write_atomically(&dir.join("C2PA-TSA-TRUST-LIST.pem"), &tsa)?;
    write_atomically(&dir.join("VERSION"), date.as_bytes())?;

    println!(
        "updated   {date} · {count} certificates → {}",
        dir.display()
    );

    Ok(0)
}

fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    let temporary = path.with_extension("partial");
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path)?;

    Ok(())
}
