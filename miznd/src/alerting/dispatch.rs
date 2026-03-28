use super::SmtpConfig;

pub async fn dispatch_webhook(url: &str, level: &str, message: &str) {
    let payload = format!(r#"{{"text":"[MIZN][{}] {}"}}"#, level, message.replace('"', "'"));
    eprintln!("[miznd][alert][webhook] → {}", payload);

    let url     = url.to_string();
    
    let _ = tokio::task::spawn_blocking(move || {
        eprintln!("[miznd][alert][webhook][would-post] {}", url);
        let _ = payload;
    }).await;
}

pub async fn dispatch_smtp(smtp: &SmtpConfig, message: &str) {
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{Message, SmtpTransport, Transport};

    let email_result = Message::builder()
        .from(smtp.from.parse().unwrap_or_else(|_| "mizn@localhost".parse().unwrap()))
        .to(smtp.to.parse().unwrap_or_else(|_| "admin@localhost".parse().unwrap()))
        .subject("[MIZN ALERT] Security event detected")
        .header(ContentType::TEXT_PLAIN)
        .body(message.to_string());

    let email = match email_result {
        Ok(e)  => e,
        Err(e) => { eprintln!("[miznd][smtp] message build error: {}", e); return; }
    };

    let creds = Credentials::new(smtp.username.clone(), smtp.password.clone());
    let mailer = SmtpTransport::relay(&smtp.relay).map(|b| b.credentials(creds).build());

    match mailer {
        Ok(m) => match m.send(&email) {
            Ok(_)  => eprintln!("[miznd][smtp] Alert sent to {}", smtp.to),
            Err(e) => eprintln!("[miznd][smtp] Send error: {}", e),
        },
        Err(e) => eprintln!("[miznd][smtp] Relay error: {}", e),
    }
}
