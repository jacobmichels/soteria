use gettextrs::gettext;
use std::{collections::HashMap, process::Stdio};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::UnixStream,
    process,
    sync::mpsc,
};
use zbus::{interface, zvariant::Value};
use zeroize::Zeroizing;

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
        let stdout = child.stdout.take().ok_or(PolkitError::Failed(
            "Child did not have stdout.".to_string(),
        ))?;

        let mut writer: HelperWriter = Box::new(stdin);
        writer.write_all(cookie.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        Ok((BufReader::new(Box::new(stdout)), writer))
    }
}

/// Outcome of a single PAM helper conversation.
#[derive(Debug)]
enum ConversationOutcome {
    /// The helper reported `SUCCESS`.
    Succeeded,
    /// The helper reported `FAILURE`, or closed without a verdict. Carries the
    /// last info/error message seen, used as the retry prompt.
    Failed { last_info: Option<String> },
}

/// Drive one run of the PAM stack via the helper until it reaches a verdict.
///
/// Info and error lines are forwarded as [`AuthenticationAgentEvent::Info`] so
/// non-password methods (fingerprint, security key) are usable; prompts are
/// answered with a secret. `cached_secret` is a password the user supplied
/// before the helper asked for it; if the helper prompts while we have none, we
/// wait for one over `receiver`. Cancellation surfaces as
/// [`PolkitError::Cancelled`].
async fn run_conversation<R, W>(
    reader: R,
    mut writer: W,
    receiver: &mut mpsc::Receiver<AuthenticationUserEvent>,
    sender: &mpsc::Sender<AuthenticationAgentEvent>,
    cookie: &str,
    mut cached_secret: Option<Zeroizing<String>>,
) -> Result<ConversationOutcome>
where
    R: AsyncBufRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut lines = reader.lines();

    let mut last_info: Option<String> = None;
    // Set once the helper has asked for a secret we don't have yet; we're
    // waiting on the user to type it.
    let mut awaiting_secret = false;

    loop {
        // If the helper is blocked waiting on a secret and the user has since
        // provided one, hand it over.
        if awaiting_secret {
            if let Some(secret) = cached_secret.take() {
                writer.write_all(secret.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                writer.flush().await?;
                awaiting_secret = false;
            }
        }

        tokio::select! {
            // Don't read the next line while we owe the helper a secret; it's
            // waiting on us, not the other way around.
            line = lines.next_line(), if !awaiting_secret => {
                let Some(line) = line? else {
                    // Helper closed the connection without a verdict.
                    return Ok(ConversationOutcome::Failed { last_info });
                };
                tracing::debug!("helper stdout: {}", line);

                if let Some(prompt) = line
                    .strip_prefix("PAM_PROMPT_ECHO_OFF")
                    .or_else(|| line.strip_prefix("PAM_PROMPT_ECHO_ON"))
                {
                    // Use a cached password if we have one; otherwise ask the UI
                    // to reveal its entry and wait for the user.
                    match cached_secret.take() {
                        Some(secret) => {
                            writer.write_all(secret.as_bytes()).await?;
                            writer.write_all(b"\n").await?;
                            writer.flush().await?;
                        }
                        None => {
                            awaiting_secret = true;
                            sender
                                .send(AuthenticationAgentEvent::SecretRequested {
                                    cookie: cookie.to_string(),
                                    prompt: prompt.trim().to_string(),
                                })
                                .await
                                .ok();
                        }
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
                    return Ok(ConversationOutcome::Succeeded);
                } else if line.starts_with("FAILURE") {
                    tracing::debug!("helper replied with failure.");
                    return Ok(ConversationOutcome::Failed { last_info });
                }
            }

            // The user may submit a password or cancel at any time, even while a
            // fingerprint/security-key prompt is pending.
            event = receiver.recv() => {
                // Match by reference: AuthenticationUserEvent is ZeroizeOnDrop,
                // so its fields can't be moved out.
                match &event {
                    Some(AuthenticationUserEvent::ProvidedPassword {
                        cookie: c,
                        password,
                        ..
                    }) if c == cookie => cached_secret = Some(Zeroizing::new(password.clone())),
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
            let (username, cached_secret): (String, Option<Zeroizing<String>>) = if eager {
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
                        } if c == cookie => {
                            break (username.clone(), Some(Zeroizing::new(password.clone())))
                        }
                        _ => continue,
                    }
                }
            };

            let (reader, writer) = spawn_helper(&self.config, &username, cookie).await?;

            match run_conversation(
                reader,
                writer,
                &mut self.receiver,
                &sender,
                cookie,
                cached_secret,
            )
            .await?
            {
                ConversationOutcome::Succeeded => {
                    sender
                        .send(AuthenticationAgentEvent::AuthorizationSucceeded {
                            cookie: cookie.to_string(),
                        })
                        .await
                        .ok();
                    return Ok(());
                }
                ConversationOutcome::Failed { last_info } => {
                    // Prompt the user to retry, then re-run the stack. Fall back
                    // to submit-first so an instantly-failing module can't spin.
                    let retry_msg = last_info
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    /// Non-blocking drain of every event currently queued on `rx`.
    fn drain<T>(rx: &mut mpsc::Receiver<T>) -> Vec<T> {
        let mut out = Vec::new();
        while let Ok(event) = rx.try_recv() {
            out.push(event);
        }
        out
    }

    fn provided(cookie: &str, password: &str) -> AuthenticationUserEvent {
        AuthenticationUserEvent::ProvidedPassword {
            cookie: cookie.to_string(),
            username: "alice".to_string(),
            password: password.to_string(),
        }
    }

    // A cached password is forwarded to the helper as soon as it prompts, and
    // SUCCESS becomes a Succeeded outcome.
    #[tokio::test]
    async fn forwards_cached_password_and_reports_success() {
        let (agent_tx, mut agent_rx) = mpsc::channel(16);
        let (_user_tx, mut user_rx) = mpsc::channel(16);
        let reader = BufReader::new(&b"PAM_PROMPT_ECHO_OFF Password:\nSUCCESS\n"[..]);
        let (helper_in, mut helper_out) = tokio::io::duplex(256);

        let outcome = run_conversation(
            reader,
            helper_in,
            &mut user_rx,
            &agent_tx,
            "c1",
            Some(Zeroizing::new("hunter2".to_string())),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, ConversationOutcome::Succeeded));

        let mut written = Vec::new();
        helper_out.read_to_end(&mut written).await.unwrap();
        assert_eq!(written, b"hunter2\n");
        assert!(drain(&mut agent_rx).is_empty());
    }

    // PAM_TEXT_INFO from a non-password module (e.g. a fingerprint prompt) is
    // surfaced as an Info event so the UI can show it.
    #[tokio::test]
    async fn surfaces_pam_text_info_for_nonpassword_methods() {
        let (agent_tx, mut agent_rx) = mpsc::channel(16);
        let (_user_tx, mut user_rx) = mpsc::channel(16);
        let reader =
            BufReader::new(&b"PAM_TEXT_INFO Place your finger on the reader\nSUCCESS\n"[..]);

        let outcome = run_conversation(
            reader,
            tokio::io::sink(),
            &mut user_rx,
            &agent_tx,
            "c1",
            None,
        )
        .await
        .unwrap();

        assert!(matches!(outcome, ConversationOutcome::Succeeded));
        let events = drain(&mut agent_rx);
        assert_eq!(events.len(), 1);
        match &events[0] {
            AuthenticationAgentEvent::Info { cookie, message } => {
                assert_eq!(cookie, "c1");
                assert_eq!(message, "Place your finger on the reader");
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    // PAM_ERROR_MSG is surfaced as an Info event and, on FAILURE, carried back
    // to the caller as the retry message.
    #[tokio::test]
    async fn surfaces_pam_error_and_carries_it_into_failure() {
        let (agent_tx, mut agent_rx) = mpsc::channel(16);
        let (_user_tx, mut user_rx) = mpsc::channel(16);
        let reader = BufReader::new(&b"PAM_ERROR_MSG Fingerprint did not match\nFAILURE\n"[..]);

        let outcome = run_conversation(
            reader,
            tokio::io::sink(),
            &mut user_rx,
            &agent_tx,
            "c1",
            None,
        )
        .await
        .unwrap();

        match outcome {
            ConversationOutcome::Failed { last_info } => {
                assert_eq!(last_info.as_deref(), Some("Fingerprint did not match"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        let events = drain(&mut agent_rx);
        assert!(matches!(
            &events[0],
            AuthenticationAgentEvent::Info { message, .. } if message == "Fingerprint did not match"
        ));
    }

    // The last PAM_TEXT_INFO seen is used as the retry message on FAILURE (the
    // "N minutes until unlock" style message).
    #[tokio::test]
    async fn failure_retry_message_uses_last_info() {
        let (agent_tx, _agent_rx) = mpsc::channel(16);
        let (_user_tx, mut user_rx) = mpsc::channel(16);
        let reader = BufReader::new(&b"PAM_TEXT_INFO Account locked for 5 minutes\nFAILURE\n"[..]);

        let outcome = run_conversation(
            reader,
            tokio::io::sink(),
            &mut user_rx,
            &agent_tx,
            "c1",
            None,
        )
        .await
        .unwrap();

        match outcome {
            ConversationOutcome::Failed { last_info } => {
                assert_eq!(last_info.as_deref(), Some("Account locked for 5 minutes"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    // The helper closing its output without a verdict is treated as a failure
    // with no message to show.
    #[tokio::test]
    async fn eof_without_verdict_is_failure() {
        let (agent_tx, _agent_rx) = mpsc::channel(16);
        let (_user_tx, mut user_rx) = mpsc::channel(16);
        let reader = BufReader::new(&b""[..]);

        let outcome = run_conversation(
            reader,
            tokio::io::sink(),
            &mut user_rx,
            &agent_tx,
            "c1",
            None,
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            ConversationOutcome::Failed { last_info: None }
        ));
    }

    // When the helper prompts and no password has been typed yet, the UI is
    // asked to reveal its entry via SecretRequested (carrying the prompt text).
    #[tokio::test]
    async fn prompt_without_cached_secret_requests_one() {
        let (agent_tx, mut agent_rx) = mpsc::channel(16);
        let (user_tx, mut user_rx) = mpsc::channel(16);
        let reader = BufReader::new(&b"PAM_PROMPT_ECHO_OFF Enter PIN:\nSUCCESS\n"[..]);

        // Supply the secret only after the helper has prompted, so the prompt is
        // observed with an empty cache.
        let drive_tx = user_tx.clone();
        let sender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drive_tx.send(provided("c1", "1234")).await.unwrap();
        });

        let outcome = run_conversation(
            reader,
            tokio::io::sink(),
            &mut user_rx,
            &agent_tx,
            "c1",
            None,
        )
        .await
        .unwrap();
        sender.await.unwrap();

        assert!(matches!(outcome, ConversationOutcome::Succeeded));
        let events = drain(&mut agent_rx);
        assert!(events.iter().any(|e| matches!(
            e,
            AuthenticationAgentEvent::SecretRequested { cookie, prompt }
                if cookie == "c1" && prompt == "Enter PIN:"
        )));
    }

    // A cached secret satisfies the prompt directly, so no SecretRequested is
    // emitted (the UI never needs to reveal an entry).
    #[tokio::test]
    async fn cached_secret_does_not_request_one() {
        let (agent_tx, mut agent_rx) = mpsc::channel(16);
        let (_user_tx, mut user_rx) = mpsc::channel(16);
        let reader = BufReader::new(&b"PAM_PROMPT_ECHO_OFF Password:\nSUCCESS\n"[..]);

        run_conversation(
            reader,
            tokio::io::sink(),
            &mut user_rx,
            &agent_tx,
            "c1",
            Some(Zeroizing::new("hunter2".to_string())),
        )
        .await
        .unwrap();

        assert!(
            !drain(&mut agent_rx)
                .iter()
                .any(|e| matches!(e, AuthenticationAgentEvent::SecretRequested { .. }))
        );
    }

    // The eager flow: the helper prompts before the user has typed anything, so
    // the loop waits and forwards the password once it arrives.
    #[tokio::test]
    async fn accepts_password_submitted_after_prompt() {
        let (agent_tx, mut agent_rx) = mpsc::channel(16);
        let (user_tx, mut user_rx) = mpsc::channel(16);
        let reader = BufReader::new(&b"PAM_PROMPT_ECHO_OFF Password:\nSUCCESS\n"[..]);
        let (helper_in, mut helper_out) = tokio::io::duplex(256);

        // Keep `user_tx` alive so the channel stays open while the conversation
        // runs; only the clone is moved into the task.
        let drive_tx = user_tx.clone();
        let sender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drive_tx.send(provided("c1", "s3cret")).await.unwrap();
        });

        let outcome = run_conversation(reader, helper_in, &mut user_rx, &agent_tx, "c1", None)
            .await
            .unwrap();
        sender.await.unwrap();

        assert!(matches!(outcome, ConversationOutcome::Succeeded));
        let mut written = Vec::new();
        helper_out.read_to_end(&mut written).await.unwrap();
        assert_eq!(written, b"s3cret\n");
        let _ = drain(&mut agent_rx);
    }

    // A cancellation that arrives mid-conversation aborts with Cancelled.
    #[tokio::test]
    async fn cancellation_surfaces_as_cancelled() {
        let (agent_tx, _agent_rx) = mpsc::channel(16);
        let (user_tx, mut user_rx) = mpsc::channel(16);
        // A reader whose write end stays open never yields a line nor EOFs, so
        // the conversation is still running when the cancel arrives.
        let (_keep_open, conv_reader) = tokio::io::duplex(64);
        let reader = BufReader::new(conv_reader);

        // Keep `user_tx` alive so the channel stays open until the cancel lands.
        let drive_tx = user_tx.clone();
        let canceller = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drive_tx
                .send(AuthenticationUserEvent::Canceled {
                    cookie: "c1".to_string(),
                })
                .await
                .unwrap();
        });

        let result = run_conversation(
            reader,
            tokio::io::sink(),
            &mut user_rx,
            &agent_tx,
            "c1",
            None,
        )
        .await;
        canceller.await.unwrap();

        assert!(matches!(result, Err(PolkitError::Cancelled(_))));
    }

    // Events tagged with a different cookie are ignored; only the password for
    // our cookie is forwarded to the helper.
    #[tokio::test]
    async fn ignores_events_for_other_cookies() {
        let (agent_tx, mut agent_rx) = mpsc::channel(16);
        let (user_tx, mut user_rx) = mpsc::channel(16);
        let reader = BufReader::new(&b"PAM_PROMPT_ECHO_OFF Password:\nSUCCESS\n"[..]);
        let (helper_in, mut helper_out) = tokio::io::duplex(256);

        // Keep `user_tx` alive so the channel stays open while the conversation
        // runs; only the clone is moved into the task.
        let drive_tx = user_tx.clone();
        let sender = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drive_tx
                .send(provided("other-cookie", "WRONG"))
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            drive_tx.send(provided("c1", "right")).await.unwrap();
        });

        let outcome = run_conversation(reader, helper_in, &mut user_rx, &agent_tx, "c1", None)
            .await
            .unwrap();
        sender.await.unwrap();

        assert!(matches!(outcome, ConversationOutcome::Succeeded));
        let mut written = Vec::new();
        helper_out.read_to_end(&mut written).await.unwrap();
        assert_eq!(written, b"right\n");
        let _ = drain(&mut agent_rx);
    }
}
