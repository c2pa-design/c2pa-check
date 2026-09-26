use std::io::Read;
use std::net::IpAddr;

use anyhow::{bail, Context};

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REDIRECTS: u32 = 5;

fn routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();

            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || octets[0] == 0
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
                || (octets[0] == 198 && (18..=19).contains(&octets[1]))
                || octets[0] >= 240)
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => routable(IpAddr::V4(v4)),
            None => {
                let segments = v6.segments();

                !(v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (segments[0] & 0xfe00) == 0xfc00
                    || (segments[0] & 0xffc0) == 0xfe80
                    || (segments[0] == 0x2001 && segments[1] == 0x0db8))
            }
        },
    }
}

fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit('@').next().unwrap_or_default();

    match authority.strip_prefix('[') {
        Some(inside) => inside.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    }
}

fn check_host(url: &str) -> anyhow::Result<()> {
    let host = host_of(url);

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !routable(ip) {
            bail!("{host} is not a publicly routable address");
        }
    }

    Ok(())
}

pub fn get(url: &str) -> anyhow::Result<(Vec<u8>, String)> {
    check_host(url)?;

    let response = ureq::get(url)
        .config()
        .max_redirects(MAX_REDIRECTS)
        .build()
        .call()
        .with_context(|| format!("fetching {url}"))?;

    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();

    let mut body = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(MAX_BYTES + 1)
        .read_to_end(&mut body)?;

    if body.len() as u64 > MAX_BYTES {
        bail!("{url} exceeds the {MAX_BYTES} byte limit");
    }

    let mime = if content_type.is_empty() {
        c2pa_check_core::media::mime_from_extension(url).to_string()
    } else {
        content_type
    };

    Ok((body, mime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_is_read_out_of_every_url_shape() {
        assert_eq!(host_of("https://example.com/a.jpg"), "example.com");
        assert_eq!(host_of("https://example.com:8443/a.jpg"), "example.com");
        assert_eq!(
            host_of("https://user:pass@example.com/a.jpg"),
            "example.com"
        );
        assert_eq!(host_of("https://example.com?q=1"), "example.com");
        assert_eq!(host_of("https://example.com"), "example.com");
    }

    #[test]
    fn a_bracketed_address_keeps_its_colons() {
        assert_eq!(host_of("http://[::1]/a.jpg"), "::1");
        assert_eq!(host_of("http://[::1]:8080/a.jpg"), "::1");
        assert_eq!(host_of("http://[2606:4700::1111]/a.jpg"), "2606:4700::1111");
    }

    #[test]
    fn refuses_addresses_a_ci_job_must_not_reach() {
        for url in [
            "http://127.0.0.1/a.jpg",
            "http://169.254.169.254/latest/meta-data",
            "http://10.0.0.1/a.jpg",
            "http://172.16.0.1/a.jpg",
            "http://192.168.1.1/a.jpg",
            "http://100.64.0.1/a.jpg",
            "http://198.18.0.1/a.jpg",
            "http://0.0.0.0/a.jpg",
            "http://255.255.255.255/a.jpg",
        ] {
            assert!(check_host(url).is_err(), "{url} must be refused");
        }
    }

    #[test]
    fn an_ipv6_literal_is_guarded_like_any_other_address() {
        for url in [
            "http://[::1]/a.jpg",
            "http://[::]/a.jpg",
            "http://[fd00::1]/a.jpg",
            "http://[fe80::1]/a.jpg",
            "http://[ff02::1]/a.jpg",
            "http://[2001:db8::1]/a.jpg",
        ] {
            assert!(check_host(url).is_err(), "{url} must be refused");
        }
    }

    #[test]
    fn an_ipv4_mapped_address_cannot_smuggle_a_private_target() {
        for url in [
            "http://[::ffff:127.0.0.1]/a.jpg",
            "http://[::ffff:169.254.169.254]/latest/meta-data",
            "http://[::ffff:10.0.0.1]/a.jpg",
        ] {
            assert!(check_host(url).is_err(), "{url} must be refused");
        }
    }

    #[test]
    fn a_port_or_credentials_do_not_hide_a_blocked_address() {
        assert!(check_host("http://127.0.0.1:8080/a.jpg").is_err());
        assert!(check_host("http://user@127.0.0.1/a.jpg").is_err());
        assert!(check_host("http://[::1]:9000/a.jpg").is_err());
    }

    #[test]
    fn allows_ordinary_public_hosts() {
        assert!(check_host("https://example.com/a.jpg").is_ok());
        assert!(check_host("https://8.8.8.8/a.jpg").is_ok());
        assert!(check_host("https://[2606:4700::1111]/a.jpg").is_ok());
        assert!(check_host("https://cdn.example.com:8443/a.jpg").is_ok());
    }
}
