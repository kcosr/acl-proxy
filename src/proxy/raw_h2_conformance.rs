#![cfg(test)]

use std::collections::HashSet;

use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, Uri, Version};
use http_access_conformance::{
    load_raw_h2_suite, FramingErrorCode, H2Field, RawAccepted, RawField, RawH2Case, RawOutcome,
};
use http_access_types::{BodyFraming, HttpVersion, IngressMode};

use super::authority::reconcile_request;
use super::facts::{body_metadata, validate_request_fact_shape, ValidatedRequestFactShape};
use super::headers::sanitize_product_request;

#[derive(Clone, Copy)]
struct DecodedField<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

#[derive(Debug, Eq, PartialEq)]
struct FieldEvidence {
    name: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
struct ValidatedFactSummary {
    version: HttpVersion,
    method: Vec<u8>,
    url: String,
    headers: usize,
    body: BodyFraming,
}

#[derive(Debug, Eq, PartialEq)]
struct AcceptedEvidence {
    method: Vec<u8>,
    target: Vec<u8>,
    fields: Vec<FieldEvidence>,
    body: Vec<u8>,
    trailers: Vec<FieldEvidence>,
    facts: ValidatedFactSummary,
}

#[derive(Debug, Eq, PartialEq)]
enum AdapterError {
    Framing(FramingErrorCode),
    InvalidDecodedBlock,
    ProductBoundary,
}

#[derive(Default)]
struct PseudoFields<'a> {
    method: Option<&'a [u8]>,
    scheme: Option<&'a [u8]>,
    authority: Option<&'a [u8]>,
    path: Option<&'a [u8]>,
}

fn fixture_fields(fields: &[H2Field]) -> Vec<DecodedField<'_>> {
    fields
        .iter()
        .map(|field| DecodedField {
            name: field.name_hex.as_bytes(),
            value: field.value_hex.as_bytes(),
        })
        .collect()
}

fn adapt_fixture(case: &RawH2Case) -> Result<AcceptedEvidence, AdapterError> {
    let fields = fixture_fields(&case.fields);
    let trailers = fixture_fields(&case.trailers);
    adapt_decoded_fields(&fields, case.body_hex.as_bytes(), &trailers)
}

// This adapter starts after HPACK and HTTP/2 frame decoding. The production h2
// stack owns those wire concerns; this test proves the decoded-field boundary.
fn adapt_decoded_fields(
    fields: &[DecodedField<'_>],
    body: &[u8],
    trailers: &[DecodedField<'_>],
) -> Result<AcceptedEvidence, AdapterError> {
    let (pseudo, ordinary) = split_request_fields(fields)?;
    validate_trailers(trailers)?;
    validate_hop_fields(&ordinary, trailers)?;

    let method = pseudo
        .method
        .ok_or(AdapterError::Framing(FramingErrorCode::MissingPseudoHeader))?;
    let scheme = pseudo
        .scheme
        .ok_or(AdapterError::Framing(FramingErrorCode::MissingPseudoHeader))?;
    let authority = pseudo
        .authority
        .ok_or(AdapterError::Framing(FramingErrorCode::MissingPseudoHeader))?;
    let path = pseudo
        .path
        .ok_or(AdapterError::Framing(FramingErrorCode::MissingPseudoHeader))?;

    let mut request = build_product_request(method, scheme, authority, path, &ordinary)?;
    let target = reconcile_request(&mut request, IngressMode::ExplicitHttp, None, None, None)
        .map_err(|_| AdapterError::ProductBoundary)?;
    let sanitized = sanitize_product_request(request).map_err(|_| AdapterError::ProductBoundary)?;
    let product_headers = super::facts::product_headers(sanitized.head.headers())
        .map_err(|_| AdapterError::ProductBoundary)?;
    let body_facts = body_metadata(Version::HTTP_2, &product_headers)
        .map_err(|_| AdapterError::ProductBoundary)?;
    let shape = validate_request_fact_shape(
        IngressMode::ExplicitHttp,
        sanitized.head.ingress_version(),
        sanitized.head.method(),
        target.url().clone(),
        sanitized.head.headers(),
        body_facts,
        sanitized.head.upgrade_protocol(),
    )
    .map_err(|_| AdapterError::ProductBoundary)?;
    let facts = ValidatedRequestFactShape::into_facts(shape, &product_headers)
        .map_err(|_| AdapterError::ProductBoundary)?;

    Ok(AcceptedEvidence {
        method: method.to_vec(),
        target: path.to_vec(),
        fields: owned_fields(&ordinary),
        body: body.to_vec(),
        trailers: owned_fields(trailers),
        facts: ValidatedFactSummary {
            version: facts.version(),
            method: facts.method().as_str().as_bytes().to_vec(),
            url: facts.url().as_str().to_owned(),
            headers: facts.headers().len(),
            body: facts.body().framing(),
        },
    })
}

fn split_request_fields<'a>(
    fields: &'a [DecodedField<'a>],
) -> Result<(PseudoFields<'a>, Vec<DecodedField<'a>>), AdapterError> {
    let mut pseudo = PseudoFields::default();
    let mut ordinary = Vec::new();
    let mut saw_ordinary = false;

    for field in fields {
        if field.name.starts_with(b":") {
            if saw_ordinary {
                return Err(AdapterError::Framing(FramingErrorCode::PseudoHeaderOrder));
            }
            let slot = match field.name {
                b":method" => &mut pseudo.method,
                b":scheme" => &mut pseudo.scheme,
                b":authority" => &mut pseudo.authority,
                b":path" => &mut pseudo.path,
                _ => return Err(AdapterError::InvalidDecodedBlock),
            };
            if slot.replace(field.value).is_some() {
                return Err(AdapterError::Framing(
                    FramingErrorCode::DuplicatePseudoHeader,
                ));
            }
        } else {
            saw_ordinary = true;
            validate_ordinary_field(field)?;
            ordinary.push(*field);
        }
    }

    Ok((pseudo, ordinary))
}

fn validate_trailers(trailers: &[DecodedField<'_>]) -> Result<(), AdapterError> {
    for field in trailers {
        if field.name.starts_with(b":") {
            return Err(AdapterError::Framing(
                FramingErrorCode::PseudoHeaderInTrailers,
            ));
        }
        validate_ordinary_field(field)?;
    }
    Ok(())
}

fn validate_ordinary_field(field: &DecodedField<'_>) -> Result<(), AdapterError> {
    if field.name.iter().any(u8::is_ascii_uppercase) {
        return Err(AdapterError::InvalidDecodedBlock);
    }
    HeaderName::from_bytes(field.name).map_err(|_| AdapterError::InvalidDecodedBlock)?;
    HeaderValue::from_bytes(field.value).map_err(|_| AdapterError::InvalidDecodedBlock)?;
    Ok(())
}

fn validate_hop_fields(
    fields: &[DecodedField<'_>],
    trailers: &[DecodedField<'_>],
) -> Result<(), AdapterError> {
    let mut all_fields = fields.iter().chain(trailers);
    let mut nominated = HashSet::new();
    let mut saw_connection = false;

    for field in all_fields.clone() {
        if field.name == b"connection" {
            saw_connection = true;
            for token in field.value.split(|byte| *byte == b',') {
                let token = trim_ascii_whitespace(token);
                if token.is_empty() || token.iter().any(u8::is_ascii_uppercase) {
                    return Err(AdapterError::InvalidDecodedBlock);
                }
                HeaderName::from_bytes(token).map_err(|_| AdapterError::InvalidDecodedBlock)?;
                nominated.insert(token.to_vec());
            }
        }
    }

    if all_fields
        .clone()
        .any(|field| field.name != b"connection" && nominated.contains(field.name))
    {
        return Err(AdapterError::Framing(
            FramingErrorCode::ConnectionNominatedField,
        ));
    }
    if saw_connection
        || all_fields.any(|field| {
            matches!(
                field.name,
                b"keep-alive" | b"proxy-connection" | b"transfer-encoding" | b"upgrade"
            )
        })
    {
        return Err(AdapterError::Framing(
            FramingErrorCode::ConnectionSpecificField,
        ));
    }
    Ok(())
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn build_product_request(
    method: &[u8],
    scheme: &[u8],
    authority: &[u8],
    path: &[u8],
    fields: &[DecodedField<'_>],
) -> Result<Request<()>, AdapterError> {
    let method = Method::from_bytes(method).map_err(|_| AdapterError::ProductBoundary)?;
    let scheme = std::str::from_utf8(scheme).map_err(|_| AdapterError::ProductBoundary)?;
    let authority = std::str::from_utf8(authority).map_err(|_| AdapterError::ProductBoundary)?;
    let path = std::str::from_utf8(path).map_err(|_| AdapterError::ProductBoundary)?;
    let uri = format!("{scheme}://{authority}{path}")
        .parse::<Uri>()
        .map_err(|_| AdapterError::ProductBoundary)?;
    let mut request = Request::builder()
        .method(method)
        .version(Version::HTTP_2)
        .uri(uri)
        .body(())
        .map_err(|_| AdapterError::ProductBoundary)?;
    for field in fields {
        let name =
            HeaderName::from_bytes(field.name).map_err(|_| AdapterError::InvalidDecodedBlock)?;
        let value =
            HeaderValue::from_bytes(field.value).map_err(|_| AdapterError::InvalidDecodedBlock)?;
        request
            .headers_mut()
            .try_append(name, value)
            .map_err(|_| AdapterError::ProductBoundary)?;
    }
    Ok(request)
}

fn owned_fields(fields: &[DecodedField<'_>]) -> Vec<FieldEvidence> {
    fields
        .iter()
        .map(|field| FieldEvidence {
            name: field.name.to_vec(),
            value: field.value.to_vec(),
        })
        .collect()
}

fn assert_fields(actual: &[FieldEvidence], expected: &[RawField], case_id: &str) {
    assert_eq!(actual.len(), expected.len(), "{case_id}: field count");
    for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
        assert_eq!(
            actual.name,
            expected.name_hex.as_bytes(),
            "{case_id}: field {index} name"
        );
        assert_eq!(
            actual.value,
            expected.value_hex.as_bytes(),
            "{case_id}: field {index} value"
        );
    }
}

fn assert_accepted(actual: &AcceptedEvidence, expected: &RawAccepted, case_id: &str) {
    assert_eq!(actual.method, expected.method_hex.as_bytes(), "{case_id}");
    assert_eq!(actual.target, expected.target_hex.as_bytes(), "{case_id}");
    assert_eq!(actual.body, expected.body_hex.as_bytes(), "{case_id}");
    assert_fields(&actual.fields, &expected.fields, case_id);
    assert_fields(&actual.trailers, &expected.trailers, case_id);
}

#[derive(Default)]
struct CoveredOutcomes {
    accepted: bool,
    duplicate_pseudo: bool,
    missing_pseudo: bool,
    pseudo_order: bool,
    trailer_pseudo: bool,
    connection_specific: bool,
    connection_nominated: bool,
}

impl CoveredOutcomes {
    fn record(&mut self, expected: &RawOutcome) {
        match expected {
            RawOutcome::Accepted { .. } => self.accepted = true,
            RawOutcome::Rejected { error } => match error {
                FramingErrorCode::DuplicatePseudoHeader => self.duplicate_pseudo = true,
                FramingErrorCode::MissingPseudoHeader => self.missing_pseudo = true,
                FramingErrorCode::PseudoHeaderOrder => self.pseudo_order = true,
                FramingErrorCode::PseudoHeaderInTrailers => self.trailer_pseudo = true,
                FramingErrorCode::ConnectionSpecificField => self.connection_specific = true,
                FramingErrorCode::ConnectionNominatedField => self.connection_nominated = true,
                other => panic!("unexpected raw-H2 outcome category {other:?}"),
            },
        }
    }

    fn assert_complete(self) {
        assert!(self.accepted, "accepted outcome is uncovered");
        assert!(
            self.duplicate_pseudo,
            "duplicate pseudo outcome is uncovered"
        );
        assert!(self.missing_pseudo, "missing pseudo outcome is uncovered");
        assert!(self.pseudo_order, "pseudo ordering outcome is uncovered");
        assert!(self.trailer_pseudo, "trailer pseudo outcome is uncovered");
        assert!(
            self.connection_specific,
            "connection-specific outcome is uncovered"
        );
        assert!(
            self.connection_nominated,
            "connection-nominated outcome is uncovered"
        );
    }
}

#[test]
fn raw_h2_suite_matches_the_decoded_product_boundary() {
    let suite = load_raw_h2_suite().expect("raw-H2 conformance suite");
    let mut covered = CoveredOutcomes::default();

    for case in suite.cases() {
        covered.record(&case.expected);
        match (&case.expected, adapt_fixture(case)) {
            (RawOutcome::Accepted { value }, Ok(actual)) => {
                assert_accepted(&actual, value, &case.id);
                assert_eq!(
                    actual.facts.method,
                    value.method_hex.as_bytes(),
                    "{}",
                    case.id
                );
                assert_eq!(actual.facts.body, BodyFraming::Http2Stream, "{}", case.id);
                assert_eq!(actual.facts.version, HttpVersion::Http2, "{}", case.id);
            }
            (RawOutcome::Rejected { error }, Err(AdapterError::Framing(actual))) => {
                assert_eq!(actual, *error, "{}", case.id);
            }
            (expected, actual) => panic!("{}: expected {expected:?}, got {actual:?}", case.id),
        }
    }

    covered.assert_complete();
}

#[test]
fn accepted_fields_body_and_trailers_survive_fact_materialization() {
    let fields = [
        DecodedField {
            name: b":method",
            value: b"POST",
        },
        DecodedField {
            name: b":scheme",
            value: b"https",
        },
        DecodedField {
            name: b":authority",
            value: b"EXAMPLE.test:443",
        },
        DecodedField {
            name: b":path",
            value: b"/a/../ok?q=%61",
        },
        DecodedField {
            name: b"x-repeat",
            value: b"first",
        },
        DecodedField {
            name: b"x-repeat",
            value: b"second",
        },
    ];
    let trailers = [DecodedField {
        name: b"x-checksum",
        value: b"done",
    }];

    let accepted = adapt_decoded_fields(&fields, b"body", &trailers).expect("accepted H2");
    assert_eq!(accepted.method, b"POST");
    assert_eq!(accepted.target, b"/a/../ok?q=%61");
    assert_eq!(accepted.body, b"body");
    assert_eq!(
        accepted.fields,
        [
            FieldEvidence {
                name: b"x-repeat".to_vec(),
                value: b"first".to_vec(),
            },
            FieldEvidence {
                name: b"x-repeat".to_vec(),
                value: b"second".to_vec(),
            },
        ]
    );
    assert_eq!(
        accepted.trailers,
        [FieldEvidence {
            name: b"x-checksum".to_vec(),
            value: b"done".to_vec(),
        }]
    );
    assert_eq!(
        accepted.facts,
        ValidatedFactSummary {
            version: HttpVersion::Http2,
            method: b"POST".to_vec(),
            url: "https://example.test/ok?q=a".to_owned(),
            headers: 3,
            body: BodyFraming::Http2Stream,
        }
    );
}
