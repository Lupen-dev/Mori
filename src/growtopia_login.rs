#![cfg_attr(not(feature = "chromiumoxide"), allow(unused))]
use std::sync::Arc;
use std::time::Duration;
use rand::{thread_rng, Rng};
use regex::Regex;

#[cfg(feature = "chromiumoxide")]
use chromiumoxide::browser::{Browser, BrowserConfig};
#[cfg(feature = "chromiumoxide")]
use chromiumoxide::cdp::browser_protocol::network::EventRequestWillBeSent;
#[cfg(feature = "chromiumoxide")]
use chromiumoxide::handler::Handler;
#[cfg(feature = "chromiumoxide")]
use chromiumoxide::page::Page;
#[cfg(feature = "chromiumoxide")]
use futures::StreamExt;
#[cfg(feature = "chromiumoxide")]
use tokio::sync::mpsc;
#[cfg(feature = "chromiumoxide")]
use tokio::sync::Mutex;

#[derive(Clone, Debug, Default)]
pub struct LoginCredentials {
    pub email: String,
    pub password: String,
    pub recovery_email: Option<String>,
    pub proxy: Option<String>,
    pub headless: bool,
}

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub success: bool,
    pub token: Option<String>,
    pub user_agent: Option<String>,
    pub mac_address: Option<String>,
    pub error: Option<String>,
}

#[cfg(feature = "chromiumoxide")]
struct TokenHandler {
    token: Arc<Mutex<Option<String>>>,
    request_tx: mpsc::Sender<EventRequestWillBeSent>,
}

#[cfg(feature = "chromiumoxide")]
impl Handler for TokenHandler {
    fn handle_event(&mut self, event: chromiumoxide::cdp::CdpEvent) -> Result<(), ()> {
        if let Some(network_event) = event.as_network_request_will_be_sent() {
            let _ = self.request_tx.try_send(network_event.clone());
        }
        Ok(())
    }
}

pub fn generate_random_mac_address() -> String {
    (0..6)
        .map(|_| format!("{:02X}", thread_rng().gen_range(0..=255)))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn generate_rid() -> String {
    (0..16)
        .map(|_| format!("{:02X}", thread_rng().gen_range(0..=255)))
        .collect::<String>()
}

pub fn generate_random_hex(length: usize) -> String {
    let mut rng = thread_rng();
    (0..length)
        .map(|_| format!("{:X}", rng.gen_range(0..16)))
        .collect::<String>()
}

pub async fn perform_google_login(credentials: LoginCredentials) -> LoginResult {
    #[cfg(not(feature = "chromiumoxide"))]
    {
        return LoginResult {
            success: false,
            token: None,
            user_agent: None,
            mac_address: None,
        error: Some("Google login backend not enabled. Enable feature 'chromiumoxide' in Cargo.toml".to_string()),
        };
    }

    #[cfg(feature = "chromiumoxide")]
    {
        let token = Arc::new(Mutex::new(None));
        let (request_tx, mut request_rx) = mpsc::channel(100);

        let mut config_builder = BrowserConfig::builder();
        if !credentials.headless {
            config_builder = config_builder.with_head();
        }
        let mut args = vec![
            "--disable-blink-features=AutomationControlled",
            "--disable-web-security",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-features=IsolateOrigins,site-per-process",
        ];
        if let Some(proxy) = &credentials.proxy {
            if !proxy.is_empty() {
                args.push(&format!("--proxy-server={}", proxy));
            }
        }
        let config = config_builder
            .args(args.iter().map(|s| s.to_string()).collect())
            .build()
            .unwrap();

        let handler = TokenHandler { token: Arc::clone(&token), request_tx };
        let (browser, mut browser_handler) = Browser::launch_with_handler(config, handler)
            .await
            .unwrap();
        let handle = tokio::spawn(async move {
            while let Some(result) = browser_handler.next().await {
                if result.is_err() {
                    break;
                }
            }
        });
        let page = browser.new_page("about:blank").await.unwrap();
        let token_task = tokio::spawn(async move {
            let growtopia_token_regex = Regex::new(r"(?i)growtopia.*?token").unwrap();
            while let Some(request) = request_rx.recv().await {
                let url = request.request.url.clone();
                if url.contains("growtopiagame.com") && url.contains("login") {
                    if let Some(params) = request.request.post_data.clone() {
                        if growtopia_token_regex.is_match(&params) {
                            for param in params.split('&') {
                                if param.to_lowercase().contains("token") {
                                    let parts: Vec<&str> = param.split('=').collect();
                                    if parts.len() >= 2 {
                                        let mut token_value = parts[1].to_string();
                                        if token_value.contains('%') {
                                            token_value = urlencoding::decode(&token_value)
                                                .unwrap_or(token_value)
                                                .to_string();
                                        }
                                        let mut guard = token.lock().await;
                                        *guard = Some(token_value);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let login_result = google_login_flow(&page, &credentials).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        handle.abort();
        token_task.abort();
        let _ = browser.close().await;
        let captured_token = token.lock().await.clone();
        if let Some(token_value) = captured_token {
            LoginResult { success: true, token: Some(token_value), user_agent: Some(generate_random_user_agent()), mac_address: Some(generate_random_mac_address()), error: None }
        } else if let Err(e) = login_result {
            LoginResult { success: false, token: None, user_agent: None, mac_address: None, error: Some(e) }
        } else {
            LoginResult { success: false, token: None, user_agent: None, mac_address: None, error: Some("Login successful but no token captured".to_string()) }
        }
    }
}

fn generate_random_user_agent() -> String {
    let uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36",
    ];
    uas[thread_rng().gen_range(0..uas.len())].to_string()
}

#[cfg(feature = "chromiumoxide")]
async fn google_login_flow(page: &Page, credentials: &LoginCredentials) -> Result<(), String> {
    println!("[Google Login] Starting automation...");
    page
        .goto("https://accounts.google.com/signin/v2/identifier")
        .await
        .map_err(|e| format!("[Google Login] Failed to open login page: {e}"))?;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let email_input = page
        .find_element("#identifierId")
        .await
        .map_err(|_| "[Google Login] Email input not found".to_string())?;
    email_input
        .click()
        .await
        .and_then(|_| email_input.type_str(&credentials.email))
        .await
        .map_err(|e| format!("[Google Login] Failed to enter email: {e}"))?;
    if let Ok(next_btn) = page.find_element("#identifierNext").await {
        next_btn
            .click()
            .await
            .map_err(|e| format!("[Google Login] Failed to click next button: {e}"))?;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let pass_input = page
        .find_element("input[name='password']")
        .await
        .map_err(|_| "[Google Login] Password input not found".to_string())?;
    pass_input
        .click()
        .await
        .and_then(|_| pass_input.type_str(&credentials.password))
        .await
        .map_err(|e| format!("[Google Login] Failed to enter password: {e}"))?;
    if let Ok(next_btn) = page.find_element("#passwordNext").await {
        next_btn
            .click()
            .await
            .map_err(|e| format!("[Google Login] Failed to click password next button: {e}"))?;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    if let Some(recovery) = &credentials.recovery_email {
        if !recovery.is_empty() {
            if let Ok(recovery_input) = page
                .find_element("input[name='knowledgePreregisteredEmailResponse']")
                .await
            {
                let _ = recovery_input
                    .click()
                    .await
                    .and_then(|_| recovery_input.type_str(recovery))
                    .await;
                if let Ok(next_btn) = page.find_element("//button/span[text()='Next']").await {
                    let _ = next_btn.click().await;
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
    }

    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("[Google Login] Login automation complete");
    connect_to_growtopia(page).await?;
    Ok(())
}

#[cfg(feature = "chromiumoxide")]
async fn connect_to_growtopia(page: &Page) -> Result<(), String> {
    println!("[Growtopia] Navigating to Growtopia login...");
    page
        .goto("https://www.growtopiagame.com/google/login")
        .await
        .map_err(|e| format!("[Growtopia] Failed to navigate to Growtopia login: {e}"))?;
    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("[Growtopia] Login process completed");
    Ok(())
}

pub async fn get_meta() -> Option<String> {
    let url = "https://www.growtopia1.com/growtopia/server_data.php";
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .ok()?;
    let mut req = client.post(url);
    req = req
        .header("Host", "www.growtopia1.com")
        .header("User-Agent", "UbiServices_SDK_2022.Release.9_PC64_ansi_static")
        .header("Accept", "*/*")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("Cache-Control", "no-cache")
        .header("Content-Length", "36");
    let data = "version=5.11&platform=0&protocol=216";
    let resp = req.body(data).send().await.ok()?;
    let content = resp.text().await.ok()?;
    let re = Regex::new(r"meta\|([^ \n\r]+)").ok()?;
    re.captures(&content)
        .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_generate_random_mac_address() {
        let mac = generate_random_mac_address();
        assert_eq!(mac.split(':').count(), 6);
    }
    #[test]
    fn test_generate_rid() {
        let rid = generate_rid();
        assert_eq!(rid.len(), 32);
    }
    #[test]
    fn test_generate_random_hex() {
        let hex = generate_random_hex(10);
        assert_eq!(hex.len(), 10);
    }
}
