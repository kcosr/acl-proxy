use http_access_types::CanonicalUrl;

const CONTENT_LENGTH_DIGITS: usize = 20;

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum WebhookRequestHeadError {
    #[error("webhook request head exceeds its reserved transport buffer")]
    BufferTooSmall,
}

pub(crate) fn encode_request_head(
    output: &mut [u8],
    url: &CanonicalUrl,
    content_length: usize,
) -> Result<usize, WebhookRequestHeadError> {
    let mut writer = HeadWriter::new(output);
    writer.push(b"POST ")?;
    writer.push(url.path().as_bytes())?;
    if let Some(query) = url.query() {
        writer.push(b"?")?;
        writer.push(query.as_bytes())?;
    }
    writer.push(b" HTTP/1.1\r\nHost: ")?;
    writer.push(url.authority().as_str().as_bytes())?;
    writer.push(b"\r\nContent-Type: application/json\r\nContent-Length: ")?;
    writer.push_decimal(content_length)?;
    writer.push(b"\r\nConnection: close\r\n\r\n")?;
    Ok(writer.len)
}

struct HeadWriter<'a> {
    output: &'a mut [u8],
    len: usize,
}

impl<'a> HeadWriter<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self { output, len: 0 }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), WebhookRequestHeadError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(WebhookRequestHeadError::BufferTooSmall)?;
        let destination = self
            .output
            .get_mut(self.len..end)
            .ok_or(WebhookRequestHeadError::BufferTooSmall)?;
        destination.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn push_decimal(&mut self, value: usize) -> Result<(), WebhookRequestHeadError> {
        let mut digits = [0u8; CONTENT_LENGTH_DIGITS];
        let mut cursor = digits.len();
        let mut remaining = value;
        loop {
            cursor -= 1;
            digits[cursor] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            if remaining == 0 {
                break;
            }
        }
        self.push(&digits[cursor..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_access_url::canonicalize_http_url;

    #[test]
    fn webhook_request_head_is_canonical_and_exactly_bounded() {
        let url = canonicalize_http_url("https://example.test:8443/a%20b?x=1").unwrap();
        let expected = b"POST /a%20b?x=1 HTTP/1.1\r\nHost: example.test:8443\r\nContent-Type: application/json\r\nContent-Length: 123\r\nConnection: close\r\n\r\n";
        let mut exact = vec![0; expected.len()];
        let len = encode_request_head(&mut exact, &url, 123).unwrap();
        assert_eq!(len, expected.len());
        assert_eq!(&exact, expected);

        let mut short = vec![0; expected.len() - 1];
        assert_eq!(
            encode_request_head(&mut short, &url, 123),
            Err(WebhookRequestHeadError::BufferTooSmall)
        );
    }
}
