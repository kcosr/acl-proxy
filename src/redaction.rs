use crate::config::{RedactionMatch, RedactionProfileConfig};
use regex::{NoExpand, Regex};

#[derive(Debug, Clone)]
pub struct RedactionProfile {
    pub name: String,
    pub replacement: Vec<u8>,
    pub max_body_bytes: usize,
    pub max_decoded_body_bytes: usize,
    pub max_frame_bytes: usize,
    pub max_message_bytes: usize,
    pub allow_permessage_deflate: bool,
    pub unsupported_extensions: RedactionUnsupportedExtensions,
    pub rules: Vec<RedactionRule>,
}

#[derive(Debug, Clone)]
pub struct RedactionRule {
    literals: Vec<Vec<u8>>,
    expressions: Vec<Regex>,
    match_mode: RedactionMatch,
}

pub use crate::config::RedactionUnsupportedExtensions;

#[derive(Debug, thiserror::Error)]
pub enum RedactionError {
    #[error("text payload is not valid UTF-8")]
    InvalidUtf8,
}

impl RedactionProfile {
    pub fn from_config(name: &str, config: &RedactionProfileConfig) -> Self {
        Self {
            name: name.to_string(),
            replacement: config.replacement.as_bytes().to_vec(),
            max_body_bytes: config.max_body_bytes,
            max_decoded_body_bytes: config.max_decoded_body_bytes,
            max_frame_bytes: config.max_frame_bytes,
            max_message_bytes: config.max_message_bytes,
            allow_permessage_deflate: config.allow_permessage_deflate,
            unsupported_extensions: config.unsupported_extensions,
            rules: config
                .rules
                .iter()
                .map(|rule| RedactionRule {
                    literals: rule
                        .literals
                        .iter()
                        .map(|literal| literal.as_bytes().to_vec())
                        .collect(),
                    expressions: rule
                        .expressions
                        .iter()
                        .map(|expression| {
                            Regex::new(expression)
                                .expect("redaction expressions are validated at config load")
                        })
                        .collect(),
                    match_mode: rule.match_mode,
                })
                .collect(),
        }
    }
}

pub fn redact_payload(
    payload: &[u8],
    is_text: bool,
    profile: &RedactionProfile,
) -> Result<(Vec<u8>, usize), RedactionError> {
    let mut output = payload.to_vec();
    let mut redactions = 0;

    for rule in &profile.rules {
        let matches_type = match rule.match_mode {
            RedactionMatch::Text => is_text,
            RedactionMatch::Binary => !is_text,
            RedactionMatch::Both => true,
        };
        if !matches_type {
            continue;
        }

        for literal in &rule.literals {
            redactions += replace_literal(&mut output, literal, &profile.replacement);
        }

        if !rule.expressions.is_empty() {
            let text = std::str::from_utf8(&output).map_err(|_| RedactionError::InvalidUtf8)?;
            let mut replaced = text.to_string();
            for expression in &rule.expressions {
                let matches = expression.find_iter(&replaced).count();
                if matches == 0 {
                    continue;
                }
                redactions += matches;
                replaced = expression
                    .replace_all(
                        &replaced,
                        NoExpand(std::str::from_utf8(&profile.replacement).unwrap()),
                    )
                    .into_owned();
            }
            output = replaced.into_bytes();
        }
    }

    Ok((output, redactions))
}

fn replace_literal(payload: &mut Vec<u8>, literal: &[u8], replacement: &[u8]) -> usize {
    let mut cursor = 0;
    let mut redactions = 0;
    while let Some(relative) = find_subslice(&payload[cursor..], literal) {
        let start = cursor + relative;
        let end = start + literal.len();
        payload.splice(start..end, replacement.iter().copied());
        redactions += 1;
        cursor = start + replacement.len();
    }
    redactions
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RedactionRuleConfig;

    fn profile() -> RedactionProfile {
        RedactionProfile::from_config(
            "test",
            &RedactionProfileConfig {
                replacement: "[REDACTED]".to_string(),
                rules: vec![RedactionRuleConfig {
                    literals: vec!["password".to_string()],
                    expressions: vec![r"token-[0-9]+".to_string()],
                    match_mode: RedactionMatch::Text,
                }],
                ..Default::default()
            },
        )
    }

    #[test]
    fn redacts_literals_and_expressions_with_fixed_replacement() {
        let (output, count) =
            redact_payload(b"password token-123", true, &profile()).expect("redact");

        assert_eq!(count, 2);
        assert_eq!(output, b"[REDACTED] [REDACTED]");
    }

    #[test]
    fn text_expression_requires_utf8() {
        let err = redact_payload(b"\xff token-123", true, &profile()).expect_err("utf8 error");

        assert!(matches!(err, RedactionError::InvalidUtf8));
    }
}
