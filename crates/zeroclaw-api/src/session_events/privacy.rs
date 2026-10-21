//! Credential classification before canonical history capture. Ordinary content remains plaintext.
/// Single source of truth for `(key_prefix, canonical_model_provider_family)`
/// pairs used by `check_api_key_prefix`. Order matters: longer prefixes
/// must come before shorter ones that share a head (`sk-ant-` and `sk-or-`
/// must precede `sk-`).
pub const KEY_PREFIX_MODEL_PROVIDERS: &[(&str, &str)] = &[
    ("sk-ant-", "anthropic"),
    ("sk-or-", "openrouter"),
    ("sk-", "openai"),
    ("gsk_", "groq"),
    ("pplx-", "perplexity"),
    ("xai-", "xai"),
    ("nvapi-", "nvidia"),
    ("KEY-", "telnyx"),
    ("zcr_", "zerorouter"),
];

fn is_secret_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')
}

fn token_end(input: &str, from: usize) -> usize {
    let mut end = from;
    for (i, c) in input[from..].char_indices() {
        if is_secret_char(c) {
            end = from + i + c.len_utf8();
        } else {
            break;
        }
    }
    end
}

/// Remove credentials from HTTP(S) URLs embedded in error text.
///
/// Query and fragment punctuation cannot safely identify where a credential
/// ends: commas, apostrophes, and parentheses are all legal data. Treat the
/// URL's entire non-whitespace query or fragment tail as sensitive instead.
/// This also covers credential parameter names that the sanitizer does not know
/// about. URL userinfo is likewise always sensitive and is replaced as one unit
/// while retaining the host and path needed for an actionable endpoint
/// diagnostic.
fn scrub_url_credentials(input: &str, diagnostic: bool) -> String {
    let lowercase = input.to_ascii_lowercase();
    let mut scrubbed = String::with_capacity(input.len());
    let mut cursor = 0;

    while cursor < input.len() {
        let remaining = &input[cursor..];
        let remaining_lowercase = &lowercase[cursor..];
        let next_http = remaining_lowercase.find("http://");
        let next_https = remaining_lowercase.find("https://");
        let Some(relative_url_start) = (match (next_http, next_https) {
            (Some(http), Some(https)) => Some(http.min(https)),
            (Some(http), None) => Some(http),
            (None, Some(https)) => Some(https),
            (None, None) => None,
        }) else {
            scrubbed.push_str(remaining);
            break;
        };
        let url_start = cursor + relative_url_start;
        scrubbed.push_str(&input[cursor..url_start]);

        let url_tail = &input[url_start..];
        let url_end = url_start + url_tail.find(char::is_whitespace).unwrap_or(url_tail.len());
        let url_token = &input[url_start..url_end];
        let sensitive_suffix_start = [url_token.find('?'), url_token.find('#')]
            .into_iter()
            .flatten()
            .min()
            .filter(|_| diagnostic);
        let without_query_or_fragment =
            sensitive_suffix_start.map_or(url_token, |suffix_start| &url_token[..suffix_start]);
        let scheme_end = without_query_or_fragment
            .find("://")
            .map_or(0, |separator| separator + 3);
        let authority_end = without_query_or_fragment[scheme_end..]
            .find(['/', '?', '#'])
            .map_or(without_query_or_fragment.len(), |end| scheme_end + end);
        let authority = &without_query_or_fragment[scheme_end..authority_end];
        if let Some(userinfo_end) = authority.rfind('@') {
            scrubbed.push_str(&without_query_or_fragment[..scheme_end]);
            scrubbed.push_str("[REDACTED]@");
            scrubbed.push_str(&without_query_or_fragment[scheme_end + userinfo_end + 1..]);
        } else {
            scrubbed.push_str(without_query_or_fragment);
        }
        cursor = url_end;
    }

    scrubbed
}

/// Scrub known secret-like token prefixes from model_provider error strings.
/// Provider API-key prefixes come from the same canonical table used for
/// credential-family validation; non-provider prefixes cover Slack, GitHub,
/// and Google/Gemini credentials. Complete query strings and fragments are
/// removed from embedded HTTP(S) URLs because either suffix may carry
/// credentials under provider-specific names.
pub fn scrub_secret_patterns(input: &str) -> String {
    let scrubbed = scrub_url_credentials(input, true);
    scrub_token_prefixes(scrubbed)
}

fn secret_prefixes() -> impl Iterator<Item = &'static str> {
    const NON_PROVIDER_SECRET_PREFIXES: &[&str] = &[
        "xoxb-",
        "xoxp-",
        "ghp_",
        "gho_",
        "ghu_",
        "github_pat_",
        "AIza",
    ];

    KEY_PREFIX_MODEL_PROVIDERS
        .iter()
        .map(|(prefix, _)| *prefix)
        .chain(NON_PROVIDER_SECRET_PREFIXES.iter().copied())
}

fn scrub_token_prefixes(mut scrubbed: String) -> String {
    let mut search_from = 0;
    loop {
        let next = secret_prefixes()
            .filter_map(|prefix| {
                let mut from = search_from;
                while let Some(relative) = scrubbed[from..].find(prefix) {
                    let start = from + relative;
                    let content_start = start + prefix.len();
                    let end = token_end(&scrubbed, content_start);
                    if end > content_start {
                        return Some((start, end));
                    }
                    from = content_start;
                }
                None
            })
            .min_by_key(|(start, _)| *start);
        let Some((start, end)) = next else {
            break;
        };
        // Classify the outermost token once; a nested prefix must not rewrite
        // its tail first and leave a credential prefix in the result.
        scrubbed.replace_range(start..end, "[REDACTED]");
        search_from = start + "[REDACTED]".len();
    }
    scrubbed
}
/// Credential-bearing fields are withheld as a whole, irrespective of length
/// or JSON shape. Token usage counters are ordinary non-secret metadata.
pub fn credential_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace('-', "_");
    matches!(
        key.as_str(),
        "authorization"
            | "proxy_authorization"
            | "cookie"
            | "set_cookie"
            | "token"
            | "password"
            | "secret"
            | "credentials"
            | "credential"
            | "private_key"
            | "api_key"
            | "apikey"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "client_secret"
    ) || key.ends_with("_password")
        || key.ends_with("_api_key")
        || key.ends_with("_secret")
        || key.ends_with("_access_token")
}

struct CredentialRange {
    begin: usize,
    value: usize,
    end: usize,
    open: bool,
}

fn credential_ranges(input: &str) -> impl Iterator<Item = CredentialRange> + '_ {
    let bytes = input.as_bytes();
    let mut position = 0;
    std::iter::from_fn(move || {
        while position < bytes.len() {
            if !bytes[position].is_ascii_alphabetic() {
                position += 1;
                continue;
            }
            let begin = position;
            while position < bytes.len()
                && (bytes[position].is_ascii_alphanumeric()
                    || matches!(bytes[position], b'_' | b'-'))
            {
                position += 1;
            }
            if !credential_key(&input[begin..position]) {
                continue;
            }
            let mut separator = position;
            if separator < bytes.len() && matches!(bytes[separator], b'"' | b'\'') {
                separator += 1;
            }
            while separator < bytes.len() && bytes[separator].is_ascii_whitespace() {
                separator += 1;
            }
            if separator == bytes.len() || !matches!(bytes[separator], b':' | b'=') {
                continue;
            }
            let mut value = separator + 1;
            while value < bytes.len() && bytes[value].is_ascii_whitespace() {
                value += 1;
            }
            let mut end = value;
            let open;
            if input[value..].starts_with("[REDACTED]") {
                end = value + "[REDACTED]".len();
                open = false;
            } else if value < bytes.len() && matches!(bytes[value], b'"' | b'\'') {
                let quote = bytes[value];
                value += 1;
                end = value;
                while end < bytes.len() {
                    if bytes[end] == b'\\' {
                        end = (end + 2).min(bytes.len());
                    } else if bytes[end] == quote {
                        break;
                    } else {
                        end += 1;
                    }
                }
                open = end == bytes.len();
            } else {
                while end < bytes.len()
                    && !bytes[end].is_ascii_whitespace()
                    && !matches!(bytes[end], b',' | b';' | b'}' | b']' | b'&' | b'#')
                {
                    end += 1;
                }
                if input[value..end].eq_ignore_ascii_case("bearer")
                    || input[value..end].eq_ignore_ascii_case("basic")
                {
                    while end < bytes.len() && bytes[end].is_ascii_whitespace() {
                        end += 1;
                    }
                    while end < bytes.len()
                        && !bytes[end].is_ascii_whitespace()
                        && !matches!(bytes[end], b',' | b';')
                    {
                        end += 1;
                    }
                }
                open = end == bytes.len();
            }
            position = end;
            return Some(CredentialRange {
                begin,
                value,
                end,
                open,
            });
        }
        None
    })
}

/// Whole-value textual redaction; no prefix of a credential is retained.
pub fn classify_text(input: &str) -> String {
    classify_text_inner(input, false)
}

fn classify_text_inner(input: &str, checkpoint: bool) -> String {
    let input = scrub_token_prefixes(scrub_url_credentials(input, false));
    let mut output = String::with_capacity(input.len());
    let mut copied = 0;
    for field in credential_ranges(&input) {
        output.push_str(&input[copied..field.value]);
        if checkpoint && field.value == input.len() {
            copied = field.value;
            break;
        }
        output.push_str("[REDACTED]");
        copied = field.end;
    }
    output.push_str(&input[copied..]);
    output
}

/// Return the classified prefix stable under further input. A partial known
/// token prefix or URL stays private, and an absent field value cannot create
/// a speculative placeholder before its quoting is known.
pub fn classify_text_checkpoint(input: &str) -> String {
    let lowercase = input.to_ascii_lowercase();
    let mut end = input.len();
    for prefix in secret_prefixes().chain(["http://", "https://"]) {
        let candidate = if prefix.starts_with("http") {
            lowercase.as_str()
        } else {
            input
        };
        for length in 1..=prefix.len() {
            if candidate.ends_with(&prefix[..length]) {
                end = end.min(input.len() - length);
            }
        }
    }
    // A recognized token is already withheld as a whole. Cutting off its last
    // character could turn it back into a bare, non-secret prefix.
    for prefix in secret_prefixes() {
        for (begin, _) in input.match_indices(prefix) {
            let token_end = token_end(input, begin + prefix.len());
            if begin <= end && token_end == input.len() && token_end > begin + prefix.len() {
                end = input.len();
            }
        }
    }
    for scheme in ["http://", "https://"] {
        if let Some(start) = lowercase.rfind(scheme)
            && !input[start..].chars().any(char::is_whitespace)
        {
            end = end.min(start);
        }
    }
    classify_text_inner(&input[..end], true)
}

/// Parser lookbehind comes from the same lexical ranges as classification.
/// Keep unfinished fields, tokens and URLs until their delimiters are known.
pub fn text_checkpoint_context_start(input: &str) -> usize {
    let mut start = input.len().saturating_sub(256);
    while !input.is_char_boundary(start) {
        start -= 1;
    }
    for field in credential_ranges(input) {
        if field.begin < start && (field.open || field.end > start) {
            start = field.begin;
        }
    }
    for prefix in secret_prefixes() {
        for (begin, _) in input.match_indices(prefix) {
            let end = token_end(input, begin + prefix.len());
            if begin < start && end > start {
                start = begin;
            }
        }
    }
    let lowercase = input.to_ascii_lowercase();
    for scheme in ["http://", "https://"] {
        for (begin, _) in lowercase.match_indices(scheme) {
            let end = begin
                + input[begin..]
                    .find(char::is_whitespace)
                    .unwrap_or(input.len() - begin);
            if begin < start && end > start {
                start = begin;
            }
        }
    }
    start
}
pub fn classify_value(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(entries) => Value::Object(
            entries
                .into_iter()
                .map(|(key, value)| {
                    let value = if credential_key(&key) {
                        Value::String("[REDACTED]".into())
                    } else {
                        classify_value(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(entries) => Value::Array(entries.into_iter().map(classify_value).collect()),
        Value::String(value) => Value::String(classify_text(&value)),
        other => other,
    }
}

/// Classify ordinary chat content while preserving provider-owned replay fields.
/// A structured assistant history message has already crossed the adapter's
/// content boundary; signatures and continuation must not be rewritten.
pub fn classify_chat_content(role: &str, content: &str) -> String {
    if role == "assistant"
        && let Ok(mut value) = serde_json::from_str::<serde_json::Value>(content)
        && let Some(object) = value.as_object_mut()
    {
        let replay_keys = [
            "reasoning_content",
            "thinking_blocks",
            "thoughtSignature",
            "encrypted_content",
        ];
        let mut replay = Vec::new();
        for key in replay_keys {
            if let Some(value) = object.remove(key) {
                replay.push((key.to_owned(), value));
            }
        }
        let mut classified = classify_value(value);
        if let Some(object) = classified.as_object_mut() {
            object.extend(replay);
        }
        // serde Value serialization cannot fail.
        return classified.to_string();
    }
    classify_text(content)
}

/// Classify ordinary conversation fields while preserving provider replay bytes.
/// Signed/opaque reasoning is already classified by its owning adapter.
pub fn classify_conversation(
    message: &crate::model_provider::ConversationMessage,
) -> crate::model_provider::ConversationMessage {
    use crate::model_provider::{ChatMessage, ConversationMessage};
    match message {
        ConversationMessage::Chat(chat) => ConversationMessage::Chat(ChatMessage {
            role: chat.role.clone(),
            content: classify_chat_content(&chat.role, &chat.content),
        }),
        ConversationMessage::AssistantToolCalls {
            text,
            tool_calls,
            reasoning_content,
        } => {
            let mut calls = tool_calls.clone();
            for call in &mut calls {
                call.arguments = classify_text(&call.arguments);
            }
            ConversationMessage::AssistantToolCalls {
                text: text.as_deref().map(classify_text),
                tool_calls: calls,
                reasoning_content: reasoning_content.clone(),
            }
        }
        ConversationMessage::ToolResults(results) => {
            let mut results = results.clone();
            for result in &mut results {
                result.content = classify_text(&result.content);
            }
            ConversationMessage::ToolResults(results)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn text_checkpoint_context_compaction_preserves_full_classification() {
        let text = format!(
            "{} ordinary \u{4e2d}\u{6587}\n password=\"{}\n{}\" public=yes\n{} api_key='fixture-secret'\nhttps://user:fixture-secret@example.invalid/{} rest sk-{} tail {}",
            "x".repeat(17000),
            "a".repeat(700),
            "b".repeat(700),
            "x".repeat(900),
            "path".repeat(180),
            "secret".repeat(150),
            "x".repeat(900),
        );
        for chunk_chars in [1, 3, 17, 257, 8192] {
            let mut context = String::new();
            let mut published = String::new();
            let mut captured = String::new();
            let chars: Vec<_> = text.chars().collect();
            for chunk in chars.chunks(chunk_chars) {
                context.extend(chunk);
                let classified = classify_text_checkpoint(&context);
                assert!(
                    classified.starts_with(&published),
                    "chunk size {chunk_chars}, context={context:?}, prior={published:?}, next={classified:?}"
                );
                captured.push_str(&classified[published.len()..]);
                published = classified;
                let cut = text_checkpoint_context_start(&context);
                let prefix = classify_text(&context[..cut]);
                assert!(
                    published.starts_with(&prefix),
                    "invalid compaction, chunk size {chunk_chars}"
                );
                context.drain(..cut);
                published.drain(..prefix.len());
                assert!(context.len() < 8192, "unbounded context");
            }
            let final_text = classify_text(&context);
            assert!(final_text.starts_with(&published));
            captured.push_str(&final_text[published.len()..]);
            assert_eq!(captured, classify_text(&text), "chunk size {chunk_chars}");
        }
    }
    #[test]
    fn text_checkpoints_never_publish_a_credential_prefix_that_later_changes() {
        for text in [
            "ordinary text \u{4e2d}\u{6587} with no credential",
            "prefix sk-fixture-secret trailing text",
            "sk-x",
            "prefix ghp_xai-s",
            "key ghp_fixture-secret trailing text",
            "Authorization: Bearer fixture-secret trailing text",
            "Authorization : Basic fixture-secret trailing text",
            "api_key = 'fixture secret\\' still secret' next=public",
            "{\"api_key\": \"fixture-secret\", \"public\": true}",
            "prefix api_key=fixture-secret trailing text",
            "https://user:fixture-secret@example.invalid/path rest",
            "HTTP://user:fixture-secret@example.invalid/path rest",
            "password=\"multi\nline secret\" next=public",
        ] {
            let complete = classify_text(text);
            let mut previous = String::new();
            for end in 0..=text.len() {
                if !text.is_char_boundary(end) {
                    continue;
                }
                let checkpoint = classify_text_checkpoint(&text[..end]);
                assert!(
                    checkpoint.starts_with(&previous),
                    "nonmonotonic checkpoint for {text:?} at {end}: {previous:?} -> {checkpoint:?}"
                );
                assert!(
                    complete.starts_with(&checkpoint),
                    "premature capture for {text:?} at {end}: {checkpoint:?}"
                );
                previous = checkpoint;
            }
            assert_eq!(
                classify_text(&complete),
                complete,
                "classification must be idempotent"
            );
        }
    }
    #[test]
    fn capture_withholds_short_nested_and_inline_credentials_whole() {
        let value = classify_value(
            serde_json::json!({"api_key":{"nested":"fixture"}, "password":"ab", "status":"ok", "input_tokens":42,
            "text":"Authorization: Bearer abc123 token=x secret=\"小秘密\" next=public"}),
        );
        assert_eq!(value["api_key"], "[REDACTED]");
        assert_eq!(value["password"], "[REDACTED]");
        assert_eq!(value["input_tokens"], 42);
        assert_eq!(
            value["text"],
            "Authorization: [REDACTED] token=[REDACTED] secret=\"[REDACTED]\" next=public"
        );
        assert_eq!(
            classify_text("normal reasoning and file.png"),
            "normal reasoning and file.png"
        );
    }
}
