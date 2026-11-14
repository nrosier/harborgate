//! The one outbound HTTP client factory for Harbor, OIDC, and alert webhooks.
//!
//! Rules from `specs/security.md` ("Outbound HTTP (SSRF)"):
//! - HTTPS only. Plain HTTP is rejected.
//! - No redirects are followed.
//! - Every resolved address is checked against the blocked ranges, on every
//!   connection, so a DNS answer that changes between requests is checked again.
//! - Each class of target has its own environment-only opt-out for private ranges.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::services::github_url::GithubTarget;

/// Outbound target classes. Each has its own opt-out variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    // Harbor and Alerts clients are built in later issues.
    #[allow(dead_code)]
    Harbor,
    Oidc,
    #[allow(dead_code)]
    Alerts,
    /// The GitHub API host. The default `api.github.com` and any other host get the private-range
    /// check, and the opt-out never applies. Only the admin-configured host is exempt, and only
    /// through [`github_client`] (`specs/security.md`, "GitHub base URL").
    GitHub,
    /// The public advisory databases asked for the CVE id behind a GHSA or GO id (#379): the
    /// fixed hosts `api.osv.dev` and `api.github.com`. No token is sent, and there is no opt-out.
    Advisory,
    /// The daily scanner release check (#390): the GitHub latest-release API on the fixed host
    /// `api.github.com` only ([`SCANNER_RELEASE_HOST`]). No token is sent, the configured GitHub
    /// base URL is ignored, and there is no opt-out.
    ScannerRelease,
}

/// The only host the [`TargetClass::ScannerRelease`] client may reach.
pub const SCANNER_RELEASE_HOST: &str = "api.github.com";

/// Errors from the outbound layer. Messages are fixed text and never include the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundError {
    /// The resolved address is in a blocked range for this target class.
    BlockedAddress,
    /// The URL is not `https://`.
    NotHttps,
    /// The client could not be built.
    ClientBuild,
    /// The host name did not resolve.
    Resolve,
    /// The host is not one this target class may reach.
    HostNotAllowed,
}

impl fmt::Display for OutboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OutboundError::BlockedAddress => {
                f.write_str("the target resolves to a blocked private or local address")
            }
            OutboundError::NotHttps => f.write_str("only https:// targets are allowed"),
            OutboundError::ClientBuild => {
                f.write_str("the outbound HTTP client could not be built")
            }
            OutboundError::Resolve => f.write_str("the target host could not be resolved"),
            OutboundError::HostNotAllowed => {
                f.write_str("the target host is not allowed for this request")
            }
        }
    }
}

impl std::error::Error for OutboundError {}

/// Returns true when `ip` is in a range that must not be reached by default:
/// loopback, link-local, private, unspecified, multicast, and the IPv4-mapped forms
/// of those. Ranges follow `specs/security.md`.
pub fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_blocked_v4(v4),
        IpAddr::V6(v6) => {
            // An IPv4-mapped address (::ffff:a.b.c.d) must be judged as IPv4.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_blocked_v4(mapped);
            }
            is_blocked_v6(v6)
        }
    }
}

fn is_blocked_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 0                                  // 0.0.0.0/8 (unspecified and "this network")
        || o[0] == 127                         // 127.0.0.0/8 loopback
        || (o[0] == 169 && o[1] == 254)        // 169.254.0.0/16 link-local, cloud metadata
        || o[0] == 10                          // 10.0.0.0/8 private
        || (o[0] == 172 && (16..=31).contains(&o[1])) // 172.16.0.0/12 private
        || (o[0] == 192 && o[1] == 168)        // 192.168.0.0/16 private
        || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 shared address space (RFC 6598)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)     // 192.0.0.0/24 IETF protocol assignments (RFC 6890)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 benchmarking (RFC 2544)
        || (224..=239).contains(&o[0])         // 224.0.0.0/4 multicast
        || o[0] >= 240 // 240.0.0.0/4 reserved (RFC 1112), includes 255.255.255.255
}

fn is_blocked_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052): judge the embedded IPv4 address.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0 {
        return is_blocked_v4(embedded_v4(s[6], s[7]));
    }
    // Local-use NAT64 prefix 64:ff9b:1::/48 (RFC 8215): blocked entirely.
    if s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001 {
        return true;
    }
    // 6to4 prefix 2002::/16 (RFC 3056): judge the embedded IPv4 address in segments 1 and 2.
    if s[0] == 0x2002 {
        return is_blocked_v4(embedded_v4(s[1], s[2]));
    }
    ip.is_unspecified()                        // ::
        || ip.is_loopback()                    // ::1
        || (s[0] & 0xffc0) == 0xfe80           // fe80::/10 link-local
        || (s[0] & 0xfe00) == 0xfc00           // fc00::/7 unique local (private)
        || (s[0] & 0xff00) == 0xff00 // ff00::/8 multicast
}

/// Builds the IPv4 address held in two IPv6 segments, high half first.
fn embedded_v4(high: u16, low: u16) -> Ipv4Addr {
    let [a, b] = high.to_be_bytes();
    let [c, d] = low.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

/// Filters the resolved addresses. Returns the allowed addresses, or an error when
/// every address is blocked. The class opt-out relaxes the private-range check only.
pub fn filter_addresses(
    addresses: Vec<SocketAddr>,
    class: TargetClass,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, OutboundError> {
    let relaxed = allow_private && class != TargetClass::GitHub;
    let allowed: Vec<SocketAddr> = addresses
        .into_iter()
        .filter(|addr| relaxed || !is_blocked(addr.ip()))
        .collect();
    if allowed.is_empty() {
        Err(OutboundError::BlockedAddress)
    } else {
        Ok(allowed)
    }
}

/// Resolves `host` with the system resolver and applies [`filter_addresses`]. A caller that
/// connects by itself instead of through [`OutboundClient`] (SMTP) must call this before
/// every connection and connect only to an address it returns, so a DNS answer that changes
/// between calls is checked again.
///
/// Blocked addresses are dropped from the answer, not reported. Only an answer in which
/// every address is blocked is an error ([`OutboundError::BlockedAddress`]). So a host with
/// one public and one private address resolves, and the result holds the public one only.
pub async fn resolve_checked(
    host: &str,
    port: u16,
    class: TargetClass,
    allow_private: bool,
) -> Result<Vec<SocketAddr>, OutboundError> {
    let found = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| OutboundError::Resolve)?;
    filter_addresses(found.collect(), class, allow_private)
}

/// Resolves a host with the system resolver and applies [`filter_addresses`].
/// It runs on every connection, so DNS rebinding is checked each time.
struct GuardedResolver {
    class: TargetClass,
    allow_private: bool,
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let class = self.class;
        let allow_private = self.allow_private;
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let found = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let addresses: Vec<SocketAddr> = found.collect();
            let allowed = filter_addresses(addresses, class, allow_private)?;
            let iter: Addrs = Box::new(allowed.into_iter());
            Ok(iter)
        })
    }
}

/// The only outbound client. The inner reqwest client is private, and requests are built
/// only through [`OutboundClient::get`], [`OutboundClient::post`], [`OutboundClient::patch`] and
/// [`OutboundClient::delete`]. Each runs
/// [`check_target`] before a request builder is returned, so a caller cannot send a
/// request that skipped the check, including one to an IP literal.
pub struct OutboundClient {
    inner: reqwest::Client,
    class: TargetClass,
    allow_private: bool,
    /// Set for the GitHub client: the live configured GitHub URLs.
    github: Option<GithubTarget>,
    /// Set for a class limited to one fixed host: any other host is refused before a request.
    fixed_host: Option<&'static str>,
}

impl OutboundClient {
    /// The target check. For the GitHub client the configured API host is trusted (the admin
    /// entered it), so only the HTTPS rule applies to it. Any other host gets the full check.
    fn check(&self, url: &reqwest::Url) -> Result<(), OutboundError> {
        if let Some(target) = &self.github
            && let Some(host) = url.host_str()
            && target.current().trusted_host() == Some(host)
        {
            return require_https(url);
        }
        if let Some(fixed) = self.fixed_host
            && !url
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(fixed))
        {
            return Err(OutboundError::HostNotAllowed);
        }
        check_target(url, self.class, self.allow_private)
    }

    /// A GET request builder for `url`, after the target check.
    pub fn get(&self, url: &reqwest::Url) -> Result<reqwest::RequestBuilder, OutboundError> {
        self.check(url)?;
        Ok(self.inner.get(url.as_str()))
    }

    /// A POST request builder for `url`, after the target check.
    pub fn post(&self, url: &reqwest::Url) -> Result<reqwest::RequestBuilder, OutboundError> {
        self.check(url)?;
        Ok(self.inner.post(url.as_str()))
    }

    /// A PUT request builder for `url`, after the target check. Used only to set the Harbor
    /// project scanner (#224).
    pub fn put(&self, url: &reqwest::Url) -> Result<reqwest::RequestBuilder, OutboundError> {
        self.check(url)?;
        Ok(self.inner.put(url.as_str()))
    }

    /// A PATCH request builder for `url`, after the target check.
    pub fn patch(&self, url: &reqwest::Url) -> Result<reqwest::RequestBuilder, OutboundError> {
        self.check(url)?;
        Ok(self.inner.patch(url.as_str()))
    }

    /// A DELETE request builder for `url`, after the target check. Used only for the GitHub
    /// code scanning analysis deletes (#311 slice 6b).
    pub fn delete(&self, url: &reqwest::Url) -> Result<reqwest::RequestBuilder, OutboundError> {
        self.check(url)?;
        Ok(self.inner.delete(url.as_str()))
    }
}

/// Builds the guarded client for one target class.
///
/// `allow_private` is the class opt-out (`DOCKWARD_ALLOW_PRIVATE_*`). It is false by
/// default. GitHub ignores it and uses [`github_client`].
pub fn client(class: TargetClass, allow_private: bool) -> Result<OutboundClient, OutboundError> {
    Ok(OutboundClient {
        inner: build(
            Arc::new(GuardedResolver {
                class,
                allow_private,
            }),
            None,
        )?,
        class,
        allow_private,
        github: None,
        fixed_host: fixed_host_of(class),
    })
}

/// The fixed host of a class that may reach one host only.
fn fixed_host_of(class: TargetClass) -> Option<&'static str> {
    match class {
        TargetClass::ScannerRelease => Some(SCANNER_RELEASE_HOST),
        TargetClass::Harbor
        | TargetClass::Oidc
        | TargetClass::Alerts
        | TargetClass::GitHub
        | TargetClass::Advisory => None,
    }
}

/// Resolves like [`GuardedResolver`] for the GitHub class, except that the configured GitHub
/// API host is trusted: its resolved addresses are not checked against the private ranges
/// (`specs/security.md`, "GitHub base URL", Decided 2026-11-06, user, #184). Any other host
/// name gets the full check.
struct GithubResolver {
    target: GithubTarget,
}

impl Resolve for GithubResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let trusted = self
            .target
            .current()
            .trusted_host()
            .is_some_and(|host| name.as_str().eq_ignore_ascii_case(host));
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let found = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let addresses: Vec<SocketAddr> = found.collect();
            let allowed = if trusted {
                addresses
            } else {
                filter_addresses(addresses, TargetClass::GitHub, false)?
            };
            let iter: Addrs = Box::new(allowed.into_iter());
            Ok(iter)
        })
    }
}

/// The GitHub client. The host in `target` is trusted; every other host is refused private
/// ranges. The token must still be sent only to a URL that passes
/// [`GithubUrls::is_api_url`], which the callers check before they build a request.
pub fn github_client(target: GithubTarget) -> Result<OutboundClient, OutboundError> {
    Ok(OutboundClient {
        inner: build(
            Arc::new(GithubResolver {
                target: target.clone(),
            }),
            None,
        )?,
        class: TargetClass::GitHub,
        allow_private: false,
        github: Some(target),
        fixed_host: None,
    })
}

fn build(
    resolver: Arc<dyn Resolve>,
    extra_root: Option<reqwest::Certificate>,
) -> Result<reqwest::Client, OutboundError> {
    // `no_proxy()` stops reqwest from reading HTTP_PROXY, HTTPS_PROXY and ALL_PROXY. A proxy
    // would resolve the target host itself, and the guarded resolver would check only the
    // proxy's address.
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(resolver)
        .timeout(Duration::from_secs(30));
    if let Some(root) = extra_root {
        builder = builder.add_root_certificate(root);
    }
    builder.build().map_err(|_| OutboundError::ClientBuild)
}

/// A client that also trusts `root`. Tests only: it lets a loopback TLS test server
/// stand in for a provider. Production code never calls this.
#[cfg(test)]
pub fn client_trusting(
    class: TargetClass,
    allow_private: bool,
    root: reqwest::Certificate,
) -> Result<OutboundClient, OutboundError> {
    Ok(OutboundClient {
        inner: build(
            Arc::new(GuardedResolver {
                class,
                allow_private,
            }),
            Some(root),
        )?,
        class,
        allow_private,
        github: None,
        // A loopback test server stands in for the fixed host.
        fixed_host: None,
    })
}

/// Checks a URL before any request is made: it must be `https://`, and when its host is
/// an IP literal, that address must pass the same range check as a resolved address.
///
/// reqwest and hyper skip the DNS resolver for an IP-literal host, so the resolver
/// alone never sees `https://127.0.0.1/`. This check covers that path. [`OutboundClient`]
/// calls it before every request, and the alert channel save calls it to validate a
/// webhook URL.
pub(crate) fn check_target(
    url: &reqwest::Url,
    class: TargetClass,
    allow_private: bool,
) -> Result<(), OutboundError> {
    require_https(url)?;
    // IPv6 literals come back in brackets, so strip them before parsing.
    let literal = url
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<IpAddr>().ok());
    if let Some(ip) = literal {
        let port = url.port_or_known_default().unwrap_or(443);
        filter_addresses(vec![SocketAddr::new(ip, port)], class, allow_private)?;
    }
    Ok(())
}

/// Rejects a URL that is not `https://` before any request is made.
pub fn require_https(url: &reqwest::Url) -> Result<(), OutboundError> {
    if url.scheme() == "https" {
        Ok(())
    } else {
        Err(OutboundError::NotHttps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> IpAddr {
        match text.parse() {
            Ok(ip) => ip,
            Err(err) => panic!("test IP {text} rejected: {err}"),
        }
    }

    #[test]
    fn every_blocked_ipv4_range_is_blocked() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "224.0.0.1",
            "239.255.255.255",
        ] {
            assert!(is_blocked(v4(ip)), "{ip} should be blocked");
        }
    }

    #[test]
    fn public_ipv4_addresses_are_allowed() {
        for ip in [
            "8.8.8.8",
            "172.15.0.1",
            "172.32.0.1",
            "192.167.1.1",
            "11.0.0.1",
        ] {
            assert!(!is_blocked(v4(ip)), "{ip} should be allowed");
        }
    }

    #[test]
    fn every_blocked_ipv6_range_is_blocked() {
        for ip in [
            "::",
            "::1",
            "fe80::1",
            "febf::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
        ] {
            assert!(is_blocked(v4(ip)), "{ip} should be blocked");
        }
    }

    #[test]
    fn public_ipv6_addresses_are_allowed() {
        for ip in ["2001:4860:4860::8888", "2606:4700::1111"] {
            assert!(!is_blocked(v4(ip)), "{ip} should be allowed");
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_is_judged_as_ipv4() {
        for ip in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(is_blocked(v4(ip)), "{ip} should be blocked");
        }
        assert!(
            !is_blocked(v4("::ffff:8.8.8.8")),
            "public mapped address allowed"
        );
    }

    #[test]
    fn filter_drops_blocked_and_keeps_public() {
        let addresses = vec![
            SocketAddr::new(v4("10.0.0.5"), 443),
            SocketAddr::new(v4("8.8.8.8"), 443),
        ];
        let allowed = filter_addresses(addresses, TargetClass::Harbor, false);
        assert_eq!(allowed, Ok(vec![SocketAddr::new(v4("8.8.8.8"), 443)]));
    }

    #[test]
    fn all_blocked_fails_closed() {
        let addresses = vec![SocketAddr::new(v4("127.0.0.1"), 443)];
        assert_eq!(
            filter_addresses(addresses, TargetClass::Oidc, false),
            Err(OutboundError::BlockedAddress)
        );
    }

    #[test]
    fn opt_out_relaxes_only_its_own_class() {
        let private = || vec![SocketAddr::new(v4("10.1.2.3"), 443)];
        assert!(filter_addresses(private(), TargetClass::Harbor, true).is_ok());
        assert!(filter_addresses(private(), TargetClass::Oidc, true).is_ok());
        assert!(filter_addresses(private(), TargetClass::Alerts, true).is_ok());
        // GitHub never gets the opt-out.
        assert_eq!(
            filter_addresses(private(), TargetClass::GitHub, true),
            Err(OutboundError::BlockedAddress)
        );
    }

    #[test]
    fn opt_out_false_blocks_private_for_harbor() {
        assert_eq!(
            filter_addresses(
                vec![SocketAddr::new(v4("192.168.0.9"), 443)],
                TargetClass::Harbor,
                false
            ),
            Err(OutboundError::BlockedAddress)
        );
    }

    #[test]
    fn require_https_rejects_plain_http_and_accepts_https() {
        let http = reqwest::Url::parse("http://harbor.example.com/api").ok();
        let https = reqwest::Url::parse("https://harbor.example.com/api").ok();
        assert!(matches!(
            http.as_ref().map(require_https),
            Some(Err(OutboundError::NotHttps))
        ));
        assert!(matches!(https.as_ref().map(require_https), Some(Ok(()))));
    }

    #[test]
    fn client_builds_with_redirects_disabled_and_https_only() {
        assert!(client(TargetClass::Harbor, false).is_ok());
        assert!(client(TargetClass::GitHub, false).is_ok());
    }

    #[test]
    fn the_scanner_release_client_reaches_api_github_com_only() {
        let client = match client(TargetClass::ScannerRelease, false) {
            Ok(client) => client,
            Err(err) => panic!("client: {err}"),
        };
        let url = |text: &str| match reqwest::Url::parse(text) {
            Ok(url) => url,
            Err(err) => panic!("url: {err}"),
        };
        let latest = url("https://api.github.com/repos/aquasecurity/trivy/releases/latest");
        assert!(client.get(&latest).is_ok());
        for other in [
            "https://github.com/aquasecurity/trivy",
            "https://api.osv.dev/v1/vulns/x",
            "https://api.github.com.evil.test/",
            "https://8.8.8.8/",
        ] {
            assert_eq!(
                client.get(&url(other)).err(),
                Some(OutboundError::HostNotAllowed),
                "{other}"
            );
        }
        assert_eq!(
            client.get(&url("http://api.github.com/")).err(),
            Some(OutboundError::NotHttps)
        );
    }

    #[tokio::test]
    async fn resolver_refuses_loopback_hostname() {
        // `localhost` resolves to loopback on every supported system. No network access is needed.
        let guard = GuardedResolver {
            class: TargetClass::Harbor,
            allow_private: false,
        };
        let name: Name = match "localhost".parse() {
            Ok(name) => name,
            Err(err) => panic!("test name rejected: {err:?}"),
        };
        let outcome = guard.resolve(name).await;
        let message = match outcome {
            Ok(_) => String::from("<resolved>"),
            Err(err) => err.to_string(),
        };
        assert!(
            message.contains("blocked private or local address"),
            "expected the address filter to refuse it, got: {message}"
        );
    }

    #[tokio::test]
    async fn resolve_checked_refuses_private_hosts() {
        // `localhost` and the IP literals resolve without network access.
        for host in ["localhost", "127.0.0.1", "10.0.0.5", "::1"] {
            assert_eq!(
                resolve_checked(host, 465, TargetClass::Alerts, false).await,
                Err(OutboundError::BlockedAddress),
                "a private host was not refused"
            );
        }
        // The control: the class opt-out lets the same host through, and the port is kept.
        let allowed = resolve_checked("127.0.0.1", 465, TargetClass::Alerts, true).await;
        assert_eq!(
            allowed,
            Ok(vec![SocketAddr::new(v4("127.0.0.1"), 465)]),
            "the opt-out did not allow the host"
        );
        // GitHub never gets the opt-out.
        assert_eq!(
            resolve_checked("127.0.0.1", 465, TargetClass::GitHub, true).await,
            Err(OutboundError::BlockedAddress)
        );
        // A public IP literal passes with the default settings.
        assert_eq!(
            resolve_checked("8.8.8.8", 587, TargetClass::Alerts, false).await,
            Ok(vec![SocketAddr::new(v4("8.8.8.8"), 587)])
        );
    }

    #[test]
    fn redirect_policy_is_no_follow() {
        // The production client is built with Policy::none(). Reqwest does not expose
        // the policy for inspection, so this test asserts the source setting is present.
        let source = include_str!("outbound.rs");
        assert!(source.contains(".redirect(reqwest::redirect::Policy::none())"));
    }

    #[tokio::test]
    async fn plain_http_request_is_refused_before_connecting() {
        let client = match client(TargetClass::Harbor, false) {
            Ok(client) => client,
            Err(err) => panic!("client build failed: {err}"),
        };
        let url = reqwest::Url::parse("http://example.com/").unwrap();
        assert_eq!(client.get(&url).err(), Some(OutboundError::NotHttps));
    }

    #[test]
    fn cgnat_and_reserved_ipv4_ranges_are_blocked() {
        for ip in [
            "100.64.0.1",      // 100.64.0.0/10 shared address space (RFC 6598), first address
            "100.127.255.254", // 100.64.0.0/10, last address
            "192.0.0.8",       // 192.0.0.0/24 IETF protocol assignments (RFC 6890)
            "198.18.0.1",      // 198.18.0.0/15 benchmarking (RFC 2544), first address
            "198.19.255.254",  // 198.18.0.0/15, last address
            "240.0.0.1",       // 240.0.0.0/4 reserved (RFC 1112)
            "255.255.255.255", // limited broadcast, inside 240.0.0.0/4
        ] {
            assert!(is_blocked(v4(ip)), "{ip} should be blocked");
        }
        // The edges of each range stay allowed, so the ranges are not wider than the RFCs.
        for ip in [
            "100.63.255.255",
            "100.128.0.0",
            "192.0.1.1",
            "198.17.255.255",
            "198.20.0.1",
        ] {
            assert!(!is_blocked(v4(ip)), "{ip} should be allowed");
        }
    }

    #[test]
    fn nat64_embedded_address_is_judged_as_ipv4() {
        // 64:ff9b::/96 carries the IPv4 address in the last 32 bits (RFC 6052).
        for ip in [
            "64:ff9b::7f00:1",    // 127.0.0.1
            "64:ff9b::a00:1",     // 10.0.0.1
            "64:ff9b::6440:1",    // 100.64.0.1
            "64:ff9b::a9fe:a9fe", // 169.254.169.254, cloud metadata
            "64:ff9b::",          // 0.0.0.0
        ] {
            assert!(is_blocked(v4(ip)), "{ip} should be blocked");
        }
    }

    #[test]
    fn local_use_nat64_prefix_is_blocked() {
        // 64:ff9b:1::/48 is local-use NAT64 (RFC 8215). It is blocked whatever it embeds.
        for ip in [
            "64:ff9b:1::1",
            "64:ff9b:1:ffff::8",
            "64:ff9b:1::808:808", // embeds a public address, still blocked
        ] {
            assert!(is_blocked(v4(ip)), "{ip} should be blocked");
        }
    }

    #[test]
    fn six_to_four_embedded_address_is_judged_as_ipv4() {
        // 2002::/16 carries the IPv4 address in segments 1 and 2 (RFC 3056).
        for ip in [
            "2002:7f00:1::1",    // 127.0.0.1
            "2002:a9fe:a9fe::1", // 169.254.169.254
            "2002:a00:1::1",     // 10.0.0.1
        ] {
            assert!(is_blocked(v4(ip)), "{ip} should be blocked");
        }
    }

    #[test]
    fn public_nat64_and_6to4_addresses_are_allowed() {
        // Both embed 8.8.8.8, a public address, so both are allowed.
        for ip in ["64:ff9b::808:808", "2002:808:808::1"] {
            assert!(!is_blocked(v4(ip)), "{ip} should be allowed");
        }
    }
}

/// Live-socket tests. Each one runs a loopback TLS server with a generated test
/// certificate and drives the real guarded client. Nothing is written to disk and no
/// key or secret is printed.
#[cfg(test)]
pub(crate) mod socket_tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// Starts a loopback HTTPS server on an ephemeral port. It answers every request
    /// with `response`. Returns the port and the trust root for the test certificate.
    pub(crate) async fn loopback_tls_server(response: &'static str) -> (u16, reqwest::Certificate) {
        loopback_tls_server_with(move |_| response.to_owned()).await
    }

    /// Like [`loopback_tls_server`], but `handler` gets the request head (the request line and
    /// the headers, as text) and returns the whole response. A test uses it to route by path and
    /// to record what the client sent.
    pub(crate) async fn loopback_tls_server_with<F>(handler: F) -> (u16, reqwest::Certificate)
    where
        F: Fn(&str) -> String + Send + Sync + 'static,
    {
        let handler = StdArc::new(handler);
        let names = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
        let certified = match rcgen::generate_simple_self_signed(names) {
            Ok(certified) => certified,
            Err(err) => panic!("test certificate generation failed: {err}"),
        };
        let cert_der = certified.cert.der().clone();
        let key_der =
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let config = match rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der.into())
        {
            Ok(config) => config,
            Err(err) => panic!("test TLS config rejected: {err}"),
        };
        let acceptor = TlsAcceptor::from(StdArc::new(config));
        let listener = match TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(listener) => listener,
            Err(err) => panic!("loopback bind failed: {err}"),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("loopback address unavailable: {err}"),
        };
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let handler = StdArc::clone(&handler);
                tokio::spawn(async move {
                    if let Ok(mut tls) = acceptor.accept(stream).await {
                        let mut head = Vec::new();
                        let mut buf = [0u8; 2048];
                        while !head.windows(4).any(|w| w == b"\r\n\r\n") && head.len() < 16 * 1024 {
                            match tls.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => head.extend_from_slice(&buf[..n]),
                            }
                        }
                        let response = handler(&String::from_utf8_lossy(&head));
                        let _ = tls.write_all(response.as_bytes()).await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });
        let root = match reqwest::Certificate::from_der(cert_der.as_ref()) {
            Ok(root) => root,
            Err(err) => panic!("test root rejected: {err}"),
        };
        (port, root)
    }

    pub(crate) const OK: &str =
        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
    const REDIRECT: &str = "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

    #[tokio::test]
    async fn loopback_is_reached_only_when_the_opt_out_is_set() {
        let (port, root) = loopback_tls_server(OK).await;
        let url = format!("https://127.0.0.1:{port}/");

        // With the operator opt-out, the same server is reached. This is the control
        // that proves the refusal below is the address check and not a broken server.
        let allowed = client_trusting(TargetClass::Oidc, true, root.clone()).unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        assert!(check_target(&parsed, TargetClass::Oidc, true).is_ok());
        let ok = match allowed.get(&parsed) {
            Ok(builder) => builder.send().await,
            Err(err) => panic!("opted-out request refused: {err}"),
        };
        assert!(ok.is_ok(), "the opted-out request should reach the server");

        // Without the opt-out, the IP-literal URL is refused by the target check that
        // every OIDC request runs before it sends (`oidc::HttpProvider`).
        assert_eq!(
            check_target(
                &reqwest::Url::parse(&url).unwrap(),
                TargetClass::Oidc,
                false
            ),
            Err(OutboundError::BlockedAddress),
            "an IP literal in loopback must fail the target check by default"
        );
        drop(root);
    }

    #[tokio::test]
    async fn resolver_refuses_a_hostname_that_resolves_to_loopback() {
        // `localhost` resolves to loopback. The resolver filter refuses it by default.
        let client = client(TargetClass::Oidc, false).unwrap();
        let url = reqwest::Url::parse("https://localhost:1/").unwrap();
        let outcome = match client.get(&url) {
            Ok(builder) => builder.send().await,
            Err(err) => panic!("target check refused a hostname: {err}"),
        };
        assert!(
            outcome.is_err(),
            "a hostname resolving to loopback was reached"
        );
    }

    #[tokio::test]
    async fn plain_http_is_refused_by_the_target_check_and_the_client() {
        let url = reqwest::Url::parse("http://127.0.0.1:1/").unwrap();
        assert_eq!(
            check_target(&url, TargetClass::Oidc, true),
            Err(OutboundError::NotHttps)
        );
        let client = client(TargetClass::Oidc, true).unwrap();
        assert_eq!(client.get(&url).err(), Some(OutboundError::NotHttps));
    }

    #[tokio::test]
    async fn ip_literal_in_loopback_is_refused_by_the_client_before_any_send() {
        // The wrapper runs the target check before it returns a request builder, so an
        // IP literal in loopback never reaches the network. The port is ephemeral and
        // nothing listens on it. The refusal is the address check, not a connection failure.
        let (port, root) = loopback_tls_server(OK).await;
        let url = reqwest::Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
        let client = client_trusting(TargetClass::Oidc, false, root).unwrap();
        assert_eq!(client.get(&url).err(), Some(OutboundError::BlockedAddress));
        assert_eq!(client.post(&url).err(), Some(OutboundError::BlockedAddress));
        assert_eq!(
            client.patch(&url).err(),
            Some(OutboundError::BlockedAddress)
        );
    }

    #[tokio::test]
    async fn patch_refuses_plain_http_and_reaches_an_opted_out_server() {
        let http = reqwest::Url::parse("http://example.com/").unwrap();
        let guarded = client(TargetClass::Oidc, false).unwrap();
        assert_eq!(guarded.patch(&http).err(), Some(OutboundError::NotHttps));

        // The control: with the opt-out, the same guarded PATCH reaches the server.
        let (port, root) = loopback_tls_server(OK).await;
        let url = reqwest::Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
        let allowed = client_trusting(TargetClass::Oidc, true, root).unwrap();
        let response = match allowed.patch(&url) {
            Ok(builder) => builder.send().await.unwrap(),
            Err(err) => panic!("opted-out request refused: {err}"),
        };
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let (port, root) = loopback_tls_server(REDIRECT).await;
        let client = client_trusting(TargetClass::Oidc, true, root).unwrap();
        let url = reqwest::Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
        let response = match client.get(&url) {
            Ok(builder) => builder.send().await.unwrap(),
            Err(err) => panic!("opted-out request refused: {err}"),
        };
        // A followed redirect would target 127.0.0.1:1 and fail. The 302 itself is returned.
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
    }

    #[test]
    fn only_the_admin_set_github_host_skips_the_private_range_check() {
        use crate::services::github_url::{GithubTarget, GithubUrls};
        let literal = |text: &str| reqwest::Url::parse(text).unwrap();
        // A custom host that is a private IP literal: trusted, so the check is skipped for it.
        let custom =
            GithubTarget::new(GithubUrls::from_stored("https://10.1.2.3/api/v3", "").unwrap());
        let client = github_client(custom).unwrap();
        assert!(
            client
                .get(&literal("https://10.1.2.3/api/v3/user/repos"))
                .is_ok()
        );
        // Any other private host is still refused, and plain http is still refused.
        assert_eq!(
            client.get(&literal("https://10.9.9.9/x")).err(),
            Some(OutboundError::BlockedAddress)
        );
        assert_eq!(
            client.get(&literal("http://10.1.2.3/x")).err(),
            Some(OutboundError::NotHttps)
        );
        // The default host keeps the check: a private literal is never exempt.
        let default = github_client(GithubTarget::default()).unwrap();
        assert_eq!(
            default.get(&literal("https://10.1.2.3/x")).err(),
            Some(OutboundError::BlockedAddress)
        );
        assert!(
            default
                .get(&literal("https://api.github.com/user/repos"))
                .is_ok()
        );
    }

    #[test]
    fn private_ip_literals_are_refused_by_the_target_check() {
        for raw in [
            "https://10.0.0.1/",
            "https://169.254.169.254/",
            "https://[::1]/",
            "https://[fd00::1]/",
        ] {
            let url = reqwest::Url::parse(raw).unwrap();
            assert!(
                check_target(&url, TargetClass::Oidc, false).is_err(),
                "{raw} should be refused by default"
            );
        }
    }

    /// Serialises the tests that change process environment variables. In edition 2024,
    /// `set_var` is unsafe because another thread may read the environment at the same time.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn environment_proxy_is_ignored() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // A listener stands in for a proxy. Any connection to it shows the proxy was used.
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(listener) => listener,
            Err(err) => panic!("loopback bind failed: {err}"),
        };
        let port = match listener.local_addr() {
            Ok(addr) => addr.port(),
            Err(err) => panic!("loopback address unavailable: {err}"),
        };
        if let Err(err) = listener.set_nonblocking(true) {
            panic!("could not make the listener non-blocking: {err}");
        }
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => panic!("test runtime failed to start: {err}"),
        };
        let url = match reqwest::Url::parse("https://example.invalid/") {
            Ok(url) => url,
            Err(err) => panic!("test URL rejected: {err}"),
        };

        // SAFETY: the ENV_LOCK guard above serialises environment access in this test
        // binary, so no other test reads or writes HTTPS_PROXY while it is set.
        unsafe { std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{port}")) };
        // The client is built inside the runtime, because reqwest needs a Tokio reactor.
        let outcome = runtime.block_on(async {
            let client = client(TargetClass::Alerts, false)?;
            let builder = client.get(&url)?;
            Ok::<_, OutboundError>(builder.send().await)
        });
        // SAFETY: as above. The lock is still held, so the variable is removed before
        // any assertion can panic.
        unsafe { std::env::remove_var("HTTPS_PROXY") };

        let failed = match outcome {
            Ok(sent) => sent.is_err(),
            Err(err) => panic!("guarded request was refused before sending: {err}"),
        };
        assert!(failed, "example.invalid must not be reachable");
        match listener.accept() {
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("the request went to the HTTPS_PROXY address"),
            Err(err) => panic!("listener accept failed: {err}"),
        }
    }
}
