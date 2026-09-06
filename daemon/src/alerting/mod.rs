use mizn_common::ipc::IpcState;
use std::time::Instant;
use tokio::sync::mpsc;

mod rules;
mod dispatch;

#[derive(Debug, Clone)]
pub struct AlertConfig {
    pub webhook_url: Option<String>,
    pub smtp: Option<SmtpConfig>,
    pub high_bw_threshold: u64,
}

#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub relay:    String,
    pub from:     String,
    pub to:       String,
    pub username: String,
    pub password: String,
}

impl SmtpConfig {
    pub fn from_env() -> Option<Self> {
        Some(SmtpConfig {
            relay:    std::env::var("MIZN_SMTP_RELAY").ok()?,
            from:     std::env::var("MIZN_SMTP_FROM").ok()?,
            to:       std::env::var("MIZN_SMTP_TO").ok()?,
            username: std::env::var("MIZN_SMTP_USER").unwrap_or_default(),
            password: std::env::var("MIZN_SMTP_PASS").unwrap_or_default(),
        })
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            webhook_url:       std::env::var("MIZN_WEBHOOK_URL").ok(),
            smtp:              SmtpConfig::from_env(),
            high_bw_threshold: 100 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Alert {
    #[allow(dead_code)] pub timestamp: Instant,
    pub level:     AlertLevel,
    pub message:   String,
    pub trigger_pcap: bool,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq)]
pub enum AlertLevel { Info, Warning, Critical, }

pub fn spawn(config: AlertConfig) -> (mpsc::UnboundedSender<IpcState>, mpsc::UnboundedReceiver<Alert>) {
    let (state_tx, mut state_rx) = mpsc::unbounded_channel::<IpcState>();
    let (alert_tx, alert_rx)     = mpsc::unbounded_channel::<Alert>();

    tokio::spawn(async move {
        while let Some(state) = state_rx.recv().await {
            let mut alerts: Vec<Alert> = Vec::new();
            rules::evaluate_rules(&state, &config, &mut alerts);

            for alert in alerts {
                if let Some(ref url) = config.webhook_url {
                    let url = url.clone();
                    let msg = alert.message.clone();
                    let lvl = format!("{:?}", alert.level);
                    tokio::spawn(async move { dispatch::dispatch_webhook(&url, &lvl, &msg).await; });
                }

                if let Some(ref smtp) = config.smtp {
                    let smtp = smtp.clone();
                    let msg  = alert.message.clone();
                    tokio::spawn(async move { dispatch::dispatch_smtp(&smtp, &msg).await; });
                }
                let _ = alert_tx.send(alert);
            }
        }
    });

    (state_tx, alert_rx)
}
