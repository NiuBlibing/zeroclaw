//! Bounded plain-text CLI transport. The dispatch recorder owns persistence;
//! this reader only forwards observations before projecting the display string.
use crate::dispatch::capture::{observe_adapter_event, observe_adapter_response};
use crate::traits::{ChatResponse, StreamChunk, StreamError, StreamEvent};
use anyhow::Context;
use std::process::ExitStatus;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::time::{Duration, timeout};

const MAX_STDOUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 64 * 1024;
const MAX_CLASSIFICATION_CONTEXT: usize = 64 * 1024;

#[derive(Default)]
struct TextCheckpoint {
    context: String,
    published: String,
}

impl TextCheckpoint {
    async fn push(&mut self, text: &str, final_chunk: bool) -> anyhow::Result<()> {
        use zeroclaw_api::session_events::privacy::{classify_text, classify_text_checkpoint};
        self.context.push_str(text);
        anyhow::ensure!(
            self.context.len() <= MAX_CLASSIFICATION_CONTEXT,
            "session_capture_classification_context_limit"
        );
        let classified = if final_chunk {
            classify_text(&self.context)
        } else {
            classify_text_checkpoint(&self.context)
        };
        anyhow::ensure!(
            classified.starts_with(&self.published),
            "session_capture_classification_prefix_changed"
        );
        if classified.len() > self.published.len() {
            observe_adapter_event(&StreamEvent::TextDelta(StreamChunk::delta(
                &classified[self.published.len()..],
            )))
            .await?;
        }
        self.published = classified;
        let cut =
            zeroclaw_api::session_events::privacy::text_checkpoint_context_start(&self.context);
        if cut > 0 {
            let prefix = classify_text(&self.context[..cut]);
            anyhow::ensure!(
                self.published.starts_with(&prefix),
                "session_capture_classification_context_changed"
            );
            self.context.drain(..cut);
            self.published.drain(..prefix.len());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct ProcessFailure {
    pub(crate) protocol: &'static str,
    pub(crate) status: Option<ExitStatus>,
    stderr: String,
    source: Option<anyhow::Error>,
}

impl std::fmt::Display for ProcessFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} process failed ({}); stderr: {}",
            self.protocol,
            self.status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "exit unobserved".into()),
            crate::sanitize_api_error(&self.stderr)
        )
    }
}
impl std::error::Error for ProcessFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| source.as_ref())
    }
}
impl ProcessFailure {
    pub(crate) fn is_exit(&self) -> bool {
        self.source.is_none()
    }
    pub(crate) fn detail(&self) -> serde_json::Value {
        serde_json::json!({
            "protocol":self.protocol, "exit_code":self.status.and_then(|status| status.code()),
            "exit_status":self.status.map(|status| status.to_string()), "stderr":self.stderr,
            "error":self.source.as_ref().map(|error| crate::scrub_secret_patterns(&format!("{error:#}"))),
        })
    }
}

#[derive(Default)]
struct Stdout {
    text: String,
    pending: Vec<u8>,
    checkpoint: TextCheckpoint,
}

impl Stdout {
    async fn accept(&mut self, bytes: &[u8], eof: bool) -> anyhow::Result<()> {
        let received = self
            .text
            .len()
            .checked_add(self.pending.len())
            .and_then(|received| received.checked_add(bytes.len()))
            .context("session_capture_size_overflow")?;
        anyhow::ensure!(
            received <= MAX_STDOUT_BYTES,
            "session_capture_limit_exceeded"
        );
        self.pending.extend_from_slice(bytes);
        let (valid, invalid) = match std::str::from_utf8(&self.pending) {
            Ok(value) => (value.len(), None),
            Err(error) => (error.valid_up_to(), Some(error)),
        };
        if valid != 0 {
            let value = std::str::from_utf8(&self.pending[..valid])?;
            self.checkpoint.push(value, eof).await?;
            self.text.push_str(value);
            self.pending.drain(..valid);
        }
        if let Some(error) = invalid
            && (error.error_len().is_some() || eof)
        {
            self.checkpoint.push("", true).await?;
            return Err(error.into());
        }
        if eof {
            self.checkpoint.push("", true).await?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Stderr {
    bytes: Vec<u8>,
    truncated: bool,
}
impl Stderr {
    fn accept(&mut self, bytes: &[u8]) {
        let accepted = bytes
            .len()
            .min(MAX_STDERR_BYTES.saturating_sub(self.bytes.len()));
        self.bytes.extend_from_slice(&bytes[..accepted]);
        self.truncated |= accepted < bytes.len();
    }
    fn classified(&self) -> String {
        let mut text = zeroclaw_api::session_events::privacy::classify_text(
            &crate::scrub_secret_patterns(&String::from_utf8_lossy(&self.bytes)),
        );
        if self.truncated {
            text.push_str(" [truncated]");
        }
        text
    }
}

pub(crate) async fn run(
    mut child: Child,
    message: &str,
    protocol: &'static str,
    deadline: Duration,
) -> anyhow::Result<String> {
    let mut stdin = child.stdin.take().context("CLI stdin unavailable")?;
    let mut stdout = child.stdout.take().context("CLI stdout unavailable")?;
    let mut stderr = child.stderr.take().context("CLI stderr unavailable")?;
    let mut output = Stdout::default();
    let mut diagnostic = Stderr::default();
    let mut status = None;
    let mut input_result = None;
    let operation = async {
        let input = async move {
            stdin.write_all(message.as_bytes()).await.context("CLI stdin write failed")?;
            stdin.shutdown().await.context("CLI stdin shutdown failed")?;
            drop(stdin);
            Ok::<_, anyhow::Error>(())
        };
        tokio::pin!(input);
        let deadline_at = tokio::time::Instant::now() + deadline;
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        let mut stdout_buffer = [0u8; 8192];
        let mut stderr_buffer = [0u8; 8192];
        while !(stdout_eof && stderr_eof && status.is_some() && input_result.is_some()) {
            // Only raw I/O is raced. Once selected, a persistence await is
            // allowed to finish before a deadline or sibling error is handled.
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline_at) => {
                    return Err(StreamError::ResponseTimeout(format!("{protocol} request timed out after {deadline:?}")).into());
                }
                result = &mut input, if input_result.is_none() => {
                    // A broken input pipe cannot discard already received output.
                    input_result = Some(result);
                }
                result = stdout.read(&mut stdout_buffer), if !stdout_eof => {
                    let count = result.context("CLI stdout read failed")?;
                    stdout_eof = count == 0;
                    output.accept(&stdout_buffer[..count], stdout_eof).await?;
                }
                result = stderr.read(&mut stderr_buffer), if !stderr_eof => {
                    let count = result.context("CLI stderr read failed")?;
                    stderr_eof = count == 0;
                    diagnostic.accept(&stderr_buffer[..count]);
                }
                result = child.wait(), if status.is_none() => {
                    let observed = result.context("CLI process wait failed")?;
                    status = Some(observed);
                    observe_adapter_event(&StreamEvent::ProtocolMetadata(serde_json::json!({
                        "kind":"finish", "protocol":protocol,
                        "exit_code":observed.code(), "success":observed.success(),
                        "exit_status":observed.to_string(),
                    }))).await?;
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    }.await;
    let result = match operation {
        Err(error) => Err(error),
        Ok(()) => {
            let observed = status.context("CLI process exit unobserved")?;
            if observed.success() {
                input_result.context("CLI input outcome unobserved")?
            } else {
                Err(ProcessFailure {
                    protocol,
                    status,
                    stderr: diagnostic.classified(),
                    source: None,
                }
                .into())
            }
        }
    };
    if let Err(mut error) = result {
        let capture_failed = zeroclaw_api::session_events::capture::is_capture_stopped(&error)
            || error.to_string().starts_with("session_capture_");
        if !capture_failed {
            if let Err(flush) = output.checkpoint.push("", true).await {
                error =
                    zeroclaw_api::session_events::capture::capture_stopped(flush.context(format!(
                        "CLI transport failed: {}",
                        crate::sanitize_api_error(&format!("{error:#}"))
                    )));
            } else if !error.is::<ProcessFailure>() {
                error = ProcessFailure {
                    protocol,
                    status,
                    stderr: diagnostic.classified(),
                    source: Some(error),
                }
                .into();
            }
        }
        // Reaping the owned child says nothing about remote execution or
        // escaped descendants. Such invocation outcomes remain unknown.
        let cleanup = async {
            child
                .start_kill()
                .context("CLI process termination failed")?;
            child.wait().await.context("CLI process reap failed")?;
            Ok::<_, anyhow::Error>(())
        };
        return match timeout(Duration::from_secs(2), cleanup).await {
            Ok(Ok(())) => Err(error),
            Ok(Err(cleanup)) => Err(error.context(format!("CLI cleanup failed: {cleanup:#}"))),
            Err(_) => Err(error.context("CLI cleanup timed out")),
        };
    }
    let text = output.text.trim().to_string();
    // All segments already belong to the dispatch recorder; avoid a second
    // append when the legacy string or ChatResponse projection returns.
    observe_adapter_response(
        &ChatResponse {
            text: Some(text.clone()),
            output_blocks: vec![],
            tool_calls: vec![],
            usage: None,
            reasoning_content: None,
        },
        true,
    )
    .await?;
    Ok(text)
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timeout_keeps_its_type_and_reaps_the_owned_child() {
        let mut command = tokio::process::Command::new("sh");
        command
            .args(["-c", "printf 'partial'; exec sleep 60"])
            .kill_on_drop(true)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let child = command.spawn().expect("fixture child");
        let pid = i32::try_from(child.id().expect("PID")).expect("platform PID");
        let error = run(child, "", "fixture_cli", Duration::from_millis(100))
            .await
            .expect_err("deadline");
        assert!(matches!(
            error
                .chain()
                .find_map(|cause| cause.downcast_ref::<StreamError>()),
            Some(StreamError::ResponseTimeout(_))
        ));
        assert_eq!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        );
    }

    #[tokio::test]
    async fn stdout_handles_utf8_split_between_reads() {
        let mut output = Stdout::default();
        for byte in "\u{4e2d}\u{6587} text".bytes() {
            output.accept(&[byte], false).await.expect("byte");
        }
        output.accept(&[], true).await.expect("EOF");
        assert_eq!(output.text, "\u{4e2d}\u{6587} text");
    }

    #[tokio::test]
    async fn unresolved_sensitive_context_stops_at_its_bound() {
        let mut checkpoint = TextCheckpoint::default();
        checkpoint.push("api_key=\"", false).await.expect("key");
        let mut result = Ok(());
        for _ in 0..9 {
            result = checkpoint.push(&"x".repeat(8192), false).await;
            if result.is_err() {
                break;
            }
        }
        assert!(
            result
                .expect_err("bounded sensitive field")
                .to_string()
                .contains("session_capture_classification_context_limit")
        );
    }
}
