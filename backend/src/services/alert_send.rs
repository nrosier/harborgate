//! Alert senders: deliver one alert over a webhook or SMTP.
//! Sources: `specs/alerts.md` (Channels), `specs/security.md` (Outbound HTTP, class `alerts`).
//!
//! This module only delivers. When to send and deduplication belong to the alert
//! dispatcher (#33).
//!
//! Outbound rules:
//! - A webhook goes through the guarded client (`outbound::client`), so it is HTTPS only, has
//!   no redirects, and checks every resolved address.
//! - An SMTP send calls [`outbound::resolve_checked`] first and connects to the first checked
//!   address only. The certificate is verified against the configured host name.
//!
//! Errors are [`SendError`]: fixed text plus an error kind. They never carry the URL, a
//! header value, the SMTP password, or a response body.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::{Value, json};

use crate::services::alert_channels::{SmtpConfig, TlsMode, WebhookConfig};
use crate::services::outbound::{self, OutboundClient, OutboundError, TargetClass};
use crate::services::time;

/// Webhook and SMTP delivery both time out after this long.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// The latest instant `time::rfc3339` can format (9999-12-31T23:59:59Z).
const MAX_RFC3339_SECS: i64 = 253_402_300_799;

/// What happened. The two events of `specs/alerts.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertEvent {
    JobFailed,
    CriticalCve,
}

impl AlertEvent {
    /// The wire name used in the webhook body and the mail subject.
    pub fn as_str(self) -> &'static str {
        match self {
            AlertEvent::JobFailed => "job_failed",
            AlertEvent::CriticalCve => "critical_cve",
        }
    }
}

/// One alert to deliver. It carries no token, key, or URL. `error` is text the caller has
/// already made safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub event: AlertEvent,
    /// Unix seconds.
    pub occurred_at: i64,
    pub mapping_id: String,
    /// `<project>/<repository>`.
    pub harbor: String,
    /// `<owner>/<repo>`.
    pub github: String,
    pub cve_id: Option<String>,
    pub severity: Option<String>,
    pub image_tag: Option<String>,
    pub error: Option<String>,
}

impl Alert {
    /// One human-readable sentence, so Slack and Teams incoming webhooks work unchanged.
    /// It never includes the `error` field.
    pub fn text(&self) -> String {
        match self.event {
            AlertEvent::JobFailed => format!(
                "Dockward sync failed for {} to {}.",
                self.harbor, self.github
            ),
            AlertEvent::CriticalCve => {
                let cve = self.cve_id.as_deref().unwrap_or("unknown CVE");
                match self.image_tag.as_deref() {
                    Some(tag) => format!(
                        "Dockward found new CRITICAL {cve} in {}:{tag} for {}.",
                        self.harbor, self.github
                    ),
                    None => format!(
                        "Dockward found new CRITICAL {cve} in {} for {}.",
                        self.harbor, self.github
                    ),
                }
            }
        }
    }

    fn subject(&self) -> String {
        // Line breaks cannot appear in a header, whatever the mapping names contain.
        format!("[Dockward] {} {}", self.event.as_str(), self.harbor).replace(['\r', '\n'], " ")
    }
}

/// The webhook JSON body, in the shape of `specs/alerts.md`. Optional fields that are not
/// set are left out.
pub fn webhook_body(alert: &Alert) -> Value {
    let when = time::rfc3339(alert.occurred_at.clamp(0, MAX_RFC3339_SECS))
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let mut body = json!({
        "event": alert.event.as_str(),
        "occurred_at": when,
        "mapping": {
            "id": alert.mapping_id,
            "harbor": alert.harbor,
            "github": alert.github,
        },
        "text": alert.text(),
    });
    if let Some(map) = body.as_object_mut() {
        for (name, value) in [
            ("cve_id", &alert.cve_id),
            ("severity", &alert.severity),
            ("image_tag", &alert.image_tag),
            ("error", &alert.error),
        ] {
            if let Some(value) = value {
                map.insert(name.to_owned(), Value::String(value.clone()));
            }
        }
    }
    body
}

/// Why a delivery failed. `Display` is fixed text plus the error kind. No variant holds a
/// URL, header value, password, or response body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The target resolves to an address the outbound rules block.
    Blocked,
    /// The target host did not resolve, or the URL is not allowed.
    Target,
    /// The channel config cannot be turned into a request or a message.
    Config,
    /// The webhook answered with a non-2xx status. Only the status is kept.
    Status(u16),
    /// The request or SMTP command timed out.
    Timeout,
    /// The TLS handshake or certificate check failed.
    Tls,
    /// The SMTP server refused the message.
    Rejected { transient: bool },
    /// Any other connection failure.
    Connection,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::Blocked => f.write_str("alert target is a blocked address"),
            SendError::Target => f.write_str("alert target is not allowed or did not resolve"),
            SendError::Config => f.write_str("alert channel config is invalid"),
            SendError::Status(code) => write!(f, "webhook answered with status {code}"),
            SendError::Timeout => f.write_str("alert delivery timed out"),
            SendError::Tls => f.write_str("alert delivery failed the TLS check"),
            SendError::Rejected { transient: true } => {
                f.write_str("smtp server rejected the message (temporary)")
            }
            SendError::Rejected { transient: false } => {
                f.write_str("smtp server rejected the message (permanent)")
            }
            SendError::Connection => f.write_str("alert delivery failed to connect"),
        }
    }
}

impl std::error::Error for SendError {}

impl From<OutboundError> for SendError {
    fn from(error: OutboundError) -> Self {
        match error {
            OutboundError::BlockedAddress => SendError::Blocked,
            OutboundError::NotHttps | OutboundError::Resolve | OutboundError::HostNotAllowed => {
                SendError::Target
            }
            OutboundError::ClientBuild => SendError::Config,
        }
    }
}

/// Delivers `alert` to a webhook through the guarded `alerts` client.
pub async fn send_webhook(
    config: &WebhookConfig,
    alert: &Alert,
    allow_private: bool,
) -> Result<(), SendError> {
    let client = outbound::client(TargetClass::Alerts, allow_private)?;
    send_webhook_with(&client, config, alert).await
}

/// The webhook send on a given guarded client. Tests pass a client that trusts a loopback
/// test certificate. Production code goes through [`send_webhook`].
async fn send_webhook_with(
    client: &OutboundClient,
    config: &WebhookConfig,
    alert: &Alert,
) -> Result<(), SendError> {
    let url = reqwest::Url::parse(&config.url).map_err(|_| SendError::Config)?;
    let mut headers = HeaderMap::new();
    for (name, value) in &config.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| SendError::Config)?;
        let mut value = HeaderValue::from_str(value).map_err(|_| SendError::Config)?;
        // Marks the value as sensitive, so reqwest and hyper never print it.
        value.set_sensitive(true);
        headers.insert(name, value);
    }
    // Set last, so a configured header cannot change the body type.
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let bytes = serde_json::to_vec(&webhook_body(alert)).map_err(|_| SendError::Config)?;

    let response = client
        .post(&url)?
        .headers(headers)
        .body(bytes)
        .timeout(SEND_TIMEOUT)
        .send()
        .await
        .map_err(|error| {
            if error.is_timeout() {
                SendError::Timeout
            } else {
                SendError::Connection
            }
        })?;
    let status = response.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(SendError::Status(status.as_u16()))
    }
}

/// Where and how an SMTP connection is made. It is built from the checked address and the
/// configured host name, and it holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SmtpTarget {
    /// The checked IP address, as text. lettre connects to this, not to the host name.
    server: String,
    port: u16,
    /// The host name the certificate is verified against: the configured host.
    tls_domain: String,
    mode: TlsMode,
}

/// The seam between the address check and lettre: connect to `checked`, verify the
/// certificate for `config.host`.
fn smtp_target(config: &SmtpConfig, checked: SocketAddr) -> SmtpTarget {
    SmtpTarget {
        server: checked.ip().to_string(),
        port: checked.port(),
        tls_domain: config.host.clone(),
        mode: config.tls,
    }
}

fn smtp_transport(
    target: &SmtpTarget,
    credentials: Option<Credentials>,
) -> Result<AsyncSmtpTransport<Tokio1Executor>, SendError> {
    let params = TlsParameters::new(target.tls_domain.clone()).map_err(|_| SendError::Tls)?;
    let tls = match target.mode {
        TlsMode::Implicit => Tls::Wrapper(params),
        TlsMode::Starttls => Tls::Required(params),
    };
    let mut builder =
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(target.server.clone())
            .port(target.port)
            .tls(tls)
            .timeout(Some(SEND_TIMEOUT));
    if let Some(credentials) = credentials {
        builder = builder.credentials(credentials);
    }
    Ok(builder.build())
}

fn smtp_message(config: &SmtpConfig, alert: &Alert) -> Result<Message, SendError> {
    let from: Mailbox = config.from.parse().map_err(|_| SendError::Config)?;
    let mut builder = Message::builder().from(from).subject(alert.subject());
    for address in &config.to {
        let to: Mailbox = address.parse().map_err(|_| SendError::Config)?;
        builder = builder.to(to);
    }
    builder
        .body(format!("{}\n", alert.text()))
        .map_err(|_| SendError::Config)
}

/// Delivers `alert` by SMTP to every `to` address in one message.
///
/// The host is resolved and checked by [`outbound::resolve_checked`] on every call, and the
/// connection goes to the first checked address.
pub async fn send_smtp(
    config: &SmtpConfig,
    alert: &Alert,
    allow_private: bool,
) -> Result<(), SendError> {
    let addresses = outbound::resolve_checked(
        &config.host,
        config.port,
        TargetClass::Alerts,
        allow_private,
    )
    .await?;
    let checked = addresses.first().copied().ok_or(SendError::Target)?;
    let target = smtp_target(config, checked);
    let credentials = match (&config.username, &config.password) {
        (Some(user), password) => Some(Credentials::new(
            user.clone(),
            password.clone().unwrap_or_default(),
        )),
        (None, _) => None,
    };
    let transport = smtp_transport(&target, credentials)?;
    let message = smtp_message(config, alert)?;
    // lettre's own timeout covers only the TCP connect, so the whole send is bounded here.
    tokio::time::timeout(SEND_TIMEOUT, transport.send(message))
        .await
        .map_err(|_| SendError::Timeout)?
        .map(|_| ())
        .map_err(|error| {
            if error.is_timeout() {
                SendError::Timeout
            } else if error.is_tls() {
                SendError::Tls
            } else if error.is_transient() {
                SendError::Rejected { transient: true }
            } else if error.is_permanent() {
                SendError::Rejected { transient: false }
            } else {
                SendError::Connection
            }
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::services::outbound::socket_tests::{OK, loopback_tls_server};

    fn alert(event: AlertEvent) -> Alert {
        Alert {
            event,
            occurred_at: 1_000_000_000,
            mapping_id: "map_1".to_owned(),
            harbor: "proj/repo".to_owned(),
            github: "acme/app".to_owned(),
            cve_id: None,
            severity: None,
            image_tag: None,
            error: None,
        }
    }

    fn smtp_config(host: &str, tls: TlsMode) -> SmtpConfig {
        SmtpConfig {
            host: host.to_owned(),
            port: 465,
            tls,
            username: Some("mailer".to_owned()),
            password: Some("pw-for-test".to_owned()),
            from: "dockward@example.com".to_owned(),
            to: vec!["a@example.com".to_owned(), "b@example.com".to_owned()],
        }
    }

    #[test]
    fn webhook_body_matches_the_spec_shape() {
        let mut full = alert(AlertEvent::CriticalCve);
        full.cve_id = Some("CVE-2026-0001".to_owned());
        full.severity = Some("CRITICAL".to_owned());
        full.image_tag = Some("1.2.3".to_owned());
        let body = webhook_body(&full);
        assert_eq!(
            body,
            json!({
                "event": "critical_cve",
                "occurred_at": "2001-09-09T01:46:40Z",
                "mapping": {"id": "map_1", "harbor": "proj/repo", "github": "acme/app"},
                "cve_id": "CVE-2026-0001",
                "severity": "CRITICAL",
                "image_tag": "1.2.3",
                "text": full.text(),
            })
        );

        let mut failed = alert(AlertEvent::JobFailed);
        failed.error = Some("upload failed".to_owned());
        let body = webhook_body(&failed);
        assert_eq!(body["event"], "job_failed");
        assert_eq!(body["error"], "upload failed");
        // Unset optional fields are absent, not null.
        for name in ["cve_id", "severity", "image_tag"] {
            assert!(body.get(name).is_none(), "an unset field was serialised");
        }
        assert!(body["text"].is_string());
    }

    #[test]
    fn text_is_one_sentence_without_secrets() {
        let mut failed = alert(AlertEvent::JobFailed);
        failed.error = Some("secret-marker-9f3".to_owned());
        let mut cve = alert(AlertEvent::CriticalCve);
        cve.cve_id = Some("CVE-2026-0001".to_owned());
        cve.image_tag = Some("1.2.3".to_owned());
        cve.error = Some("secret-marker-9f3".to_owned());
        for item in [failed, cve] {
            let text = item.text();
            assert!(!text.contains('\n'), "the text spans several lines");
            assert!(text.ends_with('.'), "the text is not a sentence");
            assert_eq!(
                text.matches(". ").count(),
                0,
                "the text has more than one sentence"
            );
            assert!(
                !text.contains("secret-marker-9f3"),
                "the text repeats the error field"
            );
            assert!(!text.contains("https://"), "the text carries a URL");
        }
    }

    #[test]
    fn subject_has_no_line_break_even_if_the_repository_name_has_one() {
        let mut item = alert(AlertEvent::JobFailed);
        item.harbor = "a\r\nBcc: x".to_owned();
        let subject = item.subject();
        assert!(!subject.contains('\r') && !subject.contains('\n'));
        assert_eq!(subject, "[Dockward] job_failed a  Bcc: x");

        // In the built message the text stays inside the Subject header: there is no
        // header of its own named Bcc.
        let config = smtp_config("mail.example.com", TlsMode::Implicit);
        let message = match smtp_message(&config, &item) {
            Ok(message) => message,
            Err(_) => panic!("message build failed"),
        };
        let raw = String::from_utf8_lossy(&message.formatted()).into_owned();
        // The headers end at the first blank line. The body may hold the name as text.
        let headers = raw.split("\r\n\r\n").next().unwrap_or_default();
        assert!(
            !headers.lines().any(|line| line.starts_with("Bcc:")),
            "a line break in the name started a new header"
        );
        assert!(headers.contains("Subject: [Dockward] job_failed a  Bcc: x"));
    }

    #[test]
    fn subject_has_the_event_and_the_harbor_repository() {
        assert_eq!(
            alert(AlertEvent::JobFailed).subject(),
            "[Dockward] job_failed proj/repo"
        );
    }

    #[tokio::test]
    async fn webhook_non_2xx_is_an_error() {
        const SERVER_ERROR: &str = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 17\r\nConnection: close\r\n\r\nbody-with-a-token";
        let channel_alert = alert(AlertEvent::JobFailed);

        let (port, root) = loopback_tls_server(SERVER_ERROR).await;
        let client = match outbound::client_trusting(TargetClass::Alerts, true, root) {
            Ok(client) => client,
            Err(_) => panic!("test client build failed"),
        };
        let config = WebhookConfig {
            url: format!("https://127.0.0.1:{port}/hook"),
            headers: BTreeMap::from([("x-auth".to_owned(), "auth-for-test".to_owned())]),
        };
        let outcome = send_webhook_with(&client, &config, &channel_alert).await;
        assert_eq!(outcome, Err(SendError::Status(500)));
        // The error text has the status only: not the URL, header, or response body.
        let shown = outcome.map_or_else(|error| error.to_string(), |()| String::new());
        assert_eq!(shown, "webhook answered with status 500");

        // The control: a 200 from the same kind of server is delivered.
        let (ok_port, ok_root) = loopback_tls_server(OK).await;
        let ok_client = match outbound::client_trusting(TargetClass::Alerts, true, ok_root) {
            Ok(client) => client,
            Err(_) => panic!("test client build failed"),
        };
        let ok_config = WebhookConfig {
            url: format!("https://127.0.0.1:{ok_port}/hook"),
            headers: BTreeMap::new(),
        };
        assert_eq!(
            send_webhook_with(&ok_client, &ok_config, &channel_alert).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn webhook_to_a_private_address_is_refused_by_default() {
        let config = WebhookConfig {
            url: "https://127.0.0.1:9/hook".to_owned(),
            headers: BTreeMap::new(),
        };
        assert_eq!(
            send_webhook(&config, &alert(AlertEvent::JobFailed), false).await,
            Err(SendError::Blocked)
        );
    }

    #[test]
    fn smtp_uses_the_checked_address_and_the_configured_hostname_for_tls() {
        let checked = SocketAddr::from(([203, 0, 113, 7], 587));
        let config = smtp_config("mail.example.com", TlsMode::Starttls);
        let target = smtp_target(&config, checked);
        // Connects to the checked IP and port, never to the host name.
        assert_eq!(target.server, "203.0.113.7");
        assert_eq!(target.port, 587);
        assert_ne!(target.server, config.host);
        // Verifies the certificate against the configured host name.
        assert_eq!(target.tls_domain, "mail.example.com");
        assert_eq!(target.mode, TlsMode::Starttls);

        let v6 = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 465));
        let implicit = smtp_target(&smtp_config("smtp.example.org", TlsMode::Implicit), v6);
        assert_eq!(implicit.server, "2001:db8::1");
        assert_eq!(implicit.tls_domain, "smtp.example.org");
        assert_eq!(implicit.mode, TlsMode::Implicit);
    }

    #[test]
    fn smtp_message_goes_to_every_recipient_with_the_subject() {
        let config = smtp_config("mail.example.com", TlsMode::Implicit);
        let message = match smtp_message(&config, &alert(AlertEvent::JobFailed)) {
            Ok(message) => message,
            Err(_) => panic!("message build failed"),
        };
        let raw = String::from_utf8_lossy(&message.formatted()).into_owned();
        assert!(raw.contains("Subject: [Dockward] job_failed proj/repo"));
        assert!(raw.contains("a@example.com"));
        assert!(raw.contains("b@example.com"));
    }

    #[tokio::test]
    async fn smtp_to_a_private_host_is_refused_before_connecting() {
        let mut config = smtp_config("127.0.0.1", TlsMode::Implicit);
        // Nothing listens here. The refusal is the address check, not a refused connection.
        config.port = 9;
        assert_eq!(
            send_smtp(&config, &alert(AlertEvent::JobFailed), false).await,
            Err(SendError::Blocked)
        );
    }

    #[test]
    fn send_error_text_is_fixed() {
        for error in [
            SendError::Blocked,
            SendError::Target,
            SendError::Config,
            SendError::Timeout,
            SendError::Tls,
            SendError::Rejected { transient: true },
            SendError::Rejected { transient: false },
            SendError::Connection,
        ] {
            let text = error.to_string();
            assert!(!text.contains("://"), "an error text holds a URL");
            assert!(!text.is_empty());
        }
    }
}
