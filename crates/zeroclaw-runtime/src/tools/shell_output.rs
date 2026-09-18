//! Decoding for bytes captured from shell stdout and stderr.
//!
//! Shells and programs launched by them are not required to use UTF-8. Keep
//! the captured bytes intact until this boundary so every shell execution
//! path applies the same decoding policy.

/// Decode shell output as text without panicking on arbitrary bytes.
///
/// Valid UTF-8 is always preferred. For other byte sequences, use chardetng
/// to select an `encoding_rs` decoder. The final UTF-8 lossy conversion keeps
/// the result representable even when detection returns UTF-8 for malformed
/// or binary input.
pub(crate) fn decode_shell_output(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_owned();
    }

    let mut detector = chardetng::EncodingDetector::new();
    detector.feed(bytes, true);
    let encoding = detector.guess(None, true);
    let (text, _, had_errors) = encoding.decode(bytes);

    if had_errors && std::ptr::eq(encoding, encoding_rs::UTF_8) {
        return String::from_utf8_lossy(bytes).into_owned();
    }

    text.into_owned()
}

#[cfg(test)]
mod tests {
    use super::decode_shell_output;

    #[test]
    fn preserves_valid_utf8() {
        let input = "shell 输出\n";
        assert_eq!(decode_shell_output(input.as_bytes()), input);
    }

    #[test]
    fn decodes_non_utf8_text() {
        // GBK for "中文输出". Repeating the sample gives chardetng enough
        // context to distinguish it from other East Asian encodings.
        let sample = [0xd6, 0xd0, 0xce, 0xc4, 0xca, 0xe4, 0xb3, 0xf6, 0x20];
        let bytes = sample.repeat(8);
        let text = decode_shell_output(&bytes);
        assert!(text.contains("中文输出"), "decoded text: {text:?}");
    }

    #[test]
    fn malformed_bytes_never_panic() {
        let text = decode_shell_output(&[0xff, 0xfe, 0xfd, 0x80]);
        assert!(!text.is_empty());
    }

    #[test]
    fn truncated_utf8_is_safe() {
        let decoded = decode_shell_output(&[b'p', 0xe2, 0x82]);
        assert!(decoded.starts_with('p'));
    }
}
