use gettextrs::gettext;
use std::{collections::HashMap, process::Stdio};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, Lines},
    net::UnixStream,
    process,
    sync::mpsc,
};
use zbus::{interface, zvariant::Value};

use crate::{
    authority::{Identity, PolkitError, Result},
    config::SystemConfig,
    events::{AuthenticationAgentEvent, AuthenticationUserEvent},
};

type HelperReader = BufReader<Box<dyn AsyncRead + Unpin + Send>>;
type HelperWriter = Box<dyn AsyncWrite + Unpin + Send>;

/// Spawn the polkit authentication helper for `user`, returning its stdout
/// reader and stdin writer. Prefers the agent socket, falling back to spawning
/// the helper binary directly.
async fn spawn_helper(
    config: &SystemConfig,
    user: &str,
    cookie: &str,
) -> Result<(HelperReader, HelperWriter)> {
    if let Ok(stream) = UnixStream::connect(config.get_socket_path()).await {
        let (read_half, write_half) = stream.into_split();
        let mut writer: HelperWriter = Box::new(write_half);
        writer.write_all(user.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.write_all(cookie.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        Ok((BufReader::new(Box::new(read_half)), writer))
    } else {
        let mut child = process::Command::new(config.get_helper_path())
            .arg(user)
            .env("LC_ALL", "C")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|_| {
                PolkitError::Failed("Failed to the spawn polkit authentication helper.".to_string())
            })?;

        let stdin = child
            .stdin
            .take()
            .ok_or(PolkitError::Failed("Child did not have stdin.".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or(PolkitError::Failed("Child did not have stdout.".to_string()))?;

        let mut writer: HelperWriter = Box::new(stdin);
        writer.write_all(cookie.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        Ok((BufReader::new(Box::new(stdout)), writer))
    }
}

#[derive(Debug)]
pub struct AuthenticationAgent {
    config: SystemConfig,
    sender: mpsc::Sender<AuthenticationAgentEvent>,
    receiver: mpsc::Receiver<AuthenticationUserEvent>,
}

impl AuthenticationAgent {
    pub fn new(
        sender: mpsc::Sender<AuthenticationAgentEvent>,
        receiver: mpsc::Receiver<AuthenticationUserEvent>,
        config: SystemConfig,
    ) -> Self {
        Self {
            sender,
            receiver,
            config,
        }
    }
}

#[interface(name = "org.freedesktop.PolicyKit1.AuthenticationAgent")]
impl AuthenticationAgent {
    async fn cancel_authentication(&self, cookie: &str) {
        tracing::debug!("received request to cancel authentication for {}", cookie);
        self.sender
            .send(AuthenticationAgentEvent::Canceled {
                cookie: cookie.to_owned(),
            })
            .await
            .unwrap();
    }

    async fn begin_authentication(
        &mut self,
        action_id: &str,
        message: &str,
        icon_name: &str,
        details: HashMap<String, String>,
        cookie: &str,
        identities: Vec<Identity<'_>>,
    ) -> Result<()> {
        tracing::info!("received request to authenticate");
        tracing::debug!(action_id = action_id, message = message, icon_name = icon_name, details = ?details, cookie = cookie, identities = ?identities);

        let mut names: Vec<String> = Vec::new();
        for identity in identities.iter() {
            let details = identity.get_details();
            if identity.get_kind() == "unix-user" {
                let Value::U32(uid) = details["uid"] else {
                    continue;
                };
                if let Ok(Some(u)) = etc_passwd::Passwd::from_uid(uid) {
                    if let Ok(n) = u.name.into_string() {
                        names.push(n);
                    }
                }
            }
        }

        self.sender
            .send(AuthenticationAgentEvent::Started {
                cookie: cookie.to_string(),
                message: message.to_string(),
                names: names.clone(),
            })
            .await
            .map_err(|_| PolkitError::Failed("Failed to send data.".to_string()))?;

        // Clone the sender so the `select!` loop below only ever borrows
        // `self.receiver`, avoiding a double mutable borrow of `self`.
        let sender = self.sender.clone();

        // With a single identity, spawn the helper eagerly so a non-password
        // module (fingerprint, security key) can prompt right away instead of
        // forcing the user to type a password first. With multiple identities we
        // wait for the user to pick one and submit. A failed attempt drops back
        // to the submit-first flow so an instantly-failing module can't busy-loop.
        let mut eager = names.len() == 1;
        let default_user = names.first().cloned();

        'retry: loop {
            // Which user to authenticate as, plus any password already supplied.
            let (username, mut cached_secret): (String, Option<String>) = if eager {
                match &default_user {
                    Some(u) => (u.clone(), None),
                    None => {
                        eager = false;
                        continue 'retry;
                    }
                }
            } else {
                // Wait for the user to choose an identity and submit a password.
                loop {
                    let event = self.receiver.recv().await.ok_or_else(|| {
                        PolkitError::Failed("Failed to receive data. channel closed".to_string())
                    })?;
                    // Match by reference: AuthenticationUserEvent is ZeroizeOnDrop,
                    // so its fields can't be moved out.
                    match &event {
                        AuthenticationUserEvent::Canceled { cookie: c } if c == cookie => {
                            return Err(PolkitError::Cancelled(
                                "User cancelled the authentication.".to_string(),
                            ));
                        }
                        AuthenticationUserEvent::ProvidedPassword {
                            cookie: c,
                            username,
                            password,
                        } if c == cookie => break (username.clone(), Some(password.clone())),
                        _ => continue,
                    }
                }
            };

            let (reader, mut writer) = spawn_helper(&self.config, &username, cookie).await?;
            let mut lines: Lines<HelperReader> = reader.lines();

            let mut last_info: Option<String> = None;
            // True once the helper has asked us for a secret that we have not yet
            // been able to provide (we are waiting on the user to type it).
            let mut awaiting_secret = false;

            loop {
                // If the helper is blocked waiting on a secret and the user has
                // since provided one, hand it over.
                if awaiting_secret {
                    if let Some(secret) = cached_secret.take() {
                        writer.write_all(secret.as_bytes()).await?;
                        writer.write_all(b"\n").await?;
                        awaiting_secret = false;
                    }
                }

                tokio::select! {
                    // Only pull the next helper line when we're not blocked owing
                    // it a secret -- otherwise the helper is waiting on us, not
                    // the other way around.
                    line = lines.next_line(), if !awaiting_secret => {
                        let Some(line) = line? else {
                            // Helper closed the connection without a verdict.
                            break;
                        };
                        tracing::debug!("helper stdout: {}", line);

                        if line
                            .strip_prefix("PAM_PROMPT_ECHO_OFF")
                            .or_else(|| line.strip_prefix("PAM_PROMPT_ECHO_ON"))
                            .is_some()
                        {
                            // The helper wants input. Use a cached password if we
                            // have one; otherwise record that we owe it a response
                            // and wait for the user to provide it.
                            match cached_secret.take() {
                                Some(secret) => {
                                    writer.write_all(secret.as_bytes()).await?;
                                    writer.write_all(b"\n").await?;
                                }
                                None => awaiting_secret = true,
                            }
                        } else if let Some(info) = line.strip_prefix("PAM_TEXT_INFO") {
                            let msg = info.trim().to_string();
                            tracing::debug!("helper info: {}", msg);
                            last_info = Some(msg.clone());
                            sender
                                .send(AuthenticationAgentEvent::Info {
                                    cookie: cookie.to_string(),
                                    message: msg,
                                })
                                .await
                                .ok();
                        } else if let Some(err) = line.strip_prefix("PAM_ERROR_MSG") {
                            let msg = err.trim().to_string();
                            tracing::debug!("helper error: {}", msg);
                            last_info = Some(msg.clone());
                            sender
                                .send(AuthenticationAgentEvent::Info {
                                    cookie: cookie.to_string(),
                                    message: msg,
                                })
                                .await
                                .ok();
                        } else if line.starts_with("SUCCESS") {
                            tracing::debug!("helper replied with success.");
                            sender
                                .send(AuthenticationAgentEvent::AuthorizationSucceeded {
                                    cookie: cookie.to_string(),
                                })
                                .await
                                .ok();
                            return Ok(());
                        } else if line.starts_with("FAILURE") {
                            tracing::debug!("helper replied with failure.");
                            break;
                        }
                    }

                    // The user may act at any time: submit a password (possibly
                    // while a fingerprint/security-key prompt is still pending) or
                    // cancel the whole request.
                    event = self.receiver.recv() => {
                        // Match by reference: AuthenticationUserEvent is
                        // ZeroizeOnDrop, so its fields can't be moved out.
                        match &event {
                            Some(AuthenticationUserEvent::ProvidedPassword {
                                cookie: c,
                                password,
                                ..
                            }) if c == cookie => cached_secret = Some(password.clone()),
                            Some(AuthenticationUserEvent::Canceled { cookie: c })
                                if c == cookie =>
                            {
                                return Err(PolkitError::Cancelled(
                                    "User cancelled the authentication.".to_string(),
                                ));
                            }
                            Some(_) => {}
                            None => {
                                return Err(PolkitError::Failed(
                                    "Failed to receive data. channel closed".to_string(),
                                ));
                            }
                        }
                    }
                }
            }

            // Reached on FAILURE or EOF: prompt the user to retry, then re-run
            // the stack. Fall back to submit-first so an instantly-failing
            // module can't spin.
            let retry_msg = last_info
                .clone()
                .unwrap_or_else(|| gettext("Authentication failed. Please try again."));
            sender
                .send(AuthenticationAgentEvent::AuthorizationRetry {
                    cookie: cookie.to_string(),
                    retry_message: Some(retry_msg),
                })
                .await
                .ok();
            eager = false;
        }
    }
}
