use std::io;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use super::response::ControlResponse;

const RESPONSE_HEAD_BYTES: usize = 256;

pub(crate) async fn write_control_response<W>(
    writer: &mut W,
    response: ControlResponse,
    close: bool,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let head = encode_response_head(response, close);
    writer.write_all(head.as_bytes()).await?;
    writer.write_all(response.body()).await?;
    writer.flush().await
}

fn encode_response_head(response: ControlResponse, close: bool) -> EncodedResponseHead {
    let mut head = EncodedResponseHead::new();
    head.push(b"HTTP/1.1 ");
    head.push(status_line(response.status()));
    head.push(b"\r\nContent-Length: ");
    head.push_decimal(response.content_length());
    head.push(b"\r\nCache-Control: ");
    head.push(response.cache_control().as_bytes());
    if let Some(content_type) = response.content_type() {
        head.push(b"\r\nContent-Type: ");
        head.push(content_type.as_bytes());
    }
    if let Some(method) = response.allow() {
        head.push(b"\r\nAllow: ");
        head.push(method.as_str().as_bytes());
    }
    if close {
        head.push(b"\r\nConnection: close");
    }
    head.push(b"\r\n\r\n");
    head
}

fn status_line(status: u16) -> &'static [u8] {
    match status {
        200 => b"200 OK",
        204 => b"204 No Content",
        400 => b"400 Bad Request",
        404 => b"404 Not Found",
        405 => b"405 Method Not Allowed",
        413 => b"413 Payload Too Large",
        415 => b"415 Unsupported Media Type",
        503 => b"503 Service Unavailable",
        _ => unreachable!("control responses use one fixed status set"),
    }
}

struct EncodedResponseHead {
    bytes: [u8; RESPONSE_HEAD_BYTES],
    len: usize,
}

impl EncodedResponseHead {
    fn new() -> Self {
        Self {
            bytes: [0; RESPONSE_HEAD_BYTES],
            len: 0,
        }
    }

    fn push(&mut self, value: &[u8]) {
        let end = self
            .len
            .checked_add(value.len())
            .filter(|end| *end <= self.bytes.len())
            .expect("fixed control response head fits its static buffer");
        self.bytes[self.len..end].copy_from_slice(value);
        self.len = end;
    }

    fn push_decimal(&mut self, mut value: usize) {
        let mut digits = [0u8; 20];
        let mut start = digits.len();
        loop {
            start -= 1;
            digits[start] = b'0' + u8::try_from(value % 10).expect("one decimal digit");
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push(&digits[start..]);
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::response::{AllowedMethod, EmptyResponseStatus};

    #[tokio::test]
    async fn fixed_encoder_covers_every_control_response_shape() {
        let responses = [
            ControlResponse::readiness(true),
            ControlResponse::readiness(false),
            ControlResponse::empty(EmptyResponseStatus::NoContent),
            ControlResponse::empty(EmptyResponseStatus::BadRequest),
            ControlResponse::empty(EmptyResponseStatus::NotFound),
            ControlResponse::method_not_allowed(AllowedMethod::Get),
            ControlResponse::method_not_allowed(AllowedMethod::Post),
            ControlResponse::empty(EmptyResponseStatus::PayloadTooLarge),
            ControlResponse::empty(EmptyResponseStatus::UnsupportedMediaType),
            ControlResponse::empty(EmptyResponseStatus::ServiceUnavailable),
        ];

        for response in responses {
            for close in [false, true] {
                let mut wire = Vec::new();
                write_control_response(&mut wire, response, close)
                    .await
                    .unwrap();
                let head_end = wire
                    .windows(4)
                    .position(|value| value == b"\r\n\r\n")
                    .unwrap()
                    + 4;
                let head = std::str::from_utf8(&wire[..head_end]).unwrap();
                assert!(head.starts_with(&format!("HTTP/1.1 {} ", response.status())));
                assert!(head.contains(&format!(
                    "\r\nContent-Length: {}\r\n",
                    response.content_length()
                )));
                assert!(head.contains("\r\nCache-Control: no-store\r\n"));
                assert_eq!(head.contains("\r\nConnection: close\r\n"), close);
                assert_eq!(&wire[head_end..], response.body());
            }
        }
    }

    #[tokio::test]
    async fn canonical_readiness_and_method_response_bytes_are_exact() {
        let mut readiness = Vec::new();
        write_control_response(&mut readiness, ControlResponse::readiness(true), false)
            .await
            .unwrap();
        assert_eq!(
            readiness,
            b"HTTP/1.1 200 OK\r\nContent-Length: 18\r\nCache-Control: no-store\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ready\"}"
        );

        let mut method = Vec::new();
        write_control_response(
            &mut method,
            ControlResponse::method_not_allowed(AllowedMethod::Post),
            true,
        )
        .await
        .unwrap();
        assert_eq!(
            method,
            b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nCache-Control: no-store\r\nAllow: POST\r\nConnection: close\r\n\r\n"
        );
    }
}
