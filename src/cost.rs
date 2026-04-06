/// Token estimation utilities for cost observability.
///
/// Uses the widely-adopted heuristic of 4 characters per token, which
/// approximates the BPE tokenization used by GPT-4 and Claude models.
/// Estimates are intentionally conservative (rounding up) to avoid under-billing.
use serde_json::Value;

/// Estimate token count for a JSON value using the 4-chars-per-token heuristic.
///
/// Serializes the value to a JSON string and divides by 4, rounding up.
/// Returns 0 for null values.
pub fn estimate_tokens(value: &Value) -> u32 {
    if value.is_null() {
        return 0;
    }
    let len = value.to_string().len();
    len.div_ceil(4) as u32
}

/// Estimate token count for a plain string slice.
pub fn estimate_tokens_str(s: &str) -> u32 {
    s.len().div_ceil(4) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn null_returns_zero() {
        assert_eq!(estimate_tokens(&json!(null)), 0);
    }

    #[test]
    fn empty_object_is_nonzero() {
        // "{}" is 2 chars → ceil(2/4) = 1
        assert_eq!(estimate_tokens(&json!({})), 1);
    }

    #[test]
    fn four_char_string_is_one_token() {
        // "\"test\"" serialized = 6 chars → ceil(6/4) = 2
        let v = json!("test");
        assert_eq!(estimate_tokens(&v), 2);
    }

    #[test]
    fn typical_tool_call_args() {
        let args = json!({"path": "/etc/passwd", "encoding": "utf-8"});
        let tokens = estimate_tokens(&args);
        assert!(tokens > 0);
        // Verify the math: serialize and divide by 4
        let expected = args.to_string().len().div_ceil(4) as u32;
        assert_eq!(tokens, expected);
    }

    #[test]
    fn estimate_tokens_str_rounds_up() {
        assert_eq!(estimate_tokens_str("abc"), 1); // 3 chars → 1
        assert_eq!(estimate_tokens_str("abcd"), 1); // 4 chars → 1
        assert_eq!(estimate_tokens_str("abcde"), 2); // 5 chars → 2
    }

    #[test]
    fn large_response_scales_linearly() {
        let big = json!({"content": "a".repeat(400)});
        let tokens = estimate_tokens(&big);
        // At least 100 tokens for 400+ chars of content
        assert!(tokens >= 100);
    }
}
