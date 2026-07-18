use http::HeaderMap;
use http_access_types::{
    HeaderField, HttpMethod, HttpVersion, InterceptedRequestFacts, ValueError,
};

use crate::credentials::{InboundCredentialSnapshot, InboundCredentials};
use crate::runtime::GenerationLease;

pub(crate) struct IngressPartitionPolicy<'a> {
    inbound: &'a InboundCredentialSnapshot,
    internal_context: &'a [http::HeaderName],
    sensitive: &'a [http_access_types::HeaderName],
    observation_sensitive: &'a [http_access_types::HeaderName],
}

impl<'a> IngressPartitionPolicy<'a> {
    pub(crate) fn from_lease(lease: &'a GenerationLease) -> Self {
        Self {
            inbound: lease.credentials(),
            internal_context: lease.authorization().internal_context_headers(),
            sensitive: lease.standalone().sensitive_headers(),
            observation_sensitive: lease.standalone().sensitive_header_policy().names(),
        }
    }
}

pub(crate) struct PartitionedIngressHeaders {
    pub(crate) inbound: InboundCredentials,
    pub(crate) internal_context: HeaderMap,
    pub(crate) retained_private: HeaderMap,
    pub(crate) sensitive_presence: Vec<http_access_types::HeaderName>,
    pub(crate) audit_sensitive_presence: Vec<http_access_types::HeaderName>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductPartitionError {
    #[error("request fact allocation failed")]
    Capacity,
    #[error("neutral facts contain a header name the product cannot represent")]
    InvalidProductHeaderName,
    #[error("neutral facts contain a header value the product cannot represent")]
    InvalidProductHeaderValue,
    #[error("request sensitive-header partition is incomplete")]
    SensitivePartition,
    #[error("inbound credential partition failed")]
    Credential(#[from] crate::credentials::CredentialError),
    #[error("request facts contain an invalid checked value")]
    Value(#[from] ValueError),
}

pub(crate) fn partition_standalone_private_fields(
    policy: &IngressPartitionPolicy<'_>,
    private_fields: Vec<HeaderField>,
) -> Result<(Vec<HeaderField>, PartitionedIngressHeaders), ProductPartitionError> {
    let mut private = product_headers(&private_fields)?;

    let mut audit_sensitive_presence = Vec::new();
    audit_sensitive_presence
        .try_reserve_exact(policy.observation_sensitive.len())
        .map_err(|_| ProductPartitionError::Capacity)?;
    for name in policy.observation_sensitive {
        if private.contains_key(name.as_str()) {
            audit_sensitive_presence.push(name.clone());
        }
    }

    let mut sensitive_presence = Vec::new();
    sensitive_presence
        .try_reserve_exact(policy.sensitive.len())
        .map_err(|_| ProductPartitionError::Capacity)?;
    for name in policy.sensitive {
        if private.contains_key(name.as_str()) {
            sensitive_presence.push(name.clone());
        }
    }

    let caller_credential_names = private
        .keys()
        .filter(|name| http_access_runtime::is_prepartition_caller_credential_header(name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let retained_private = partition_internal_context(&mut private, &caller_credential_names)?;
    let inbound = policy.inbound.extract(&mut private)?;
    let internal_context = partition_internal_context(&mut private, policy.internal_context)?;
    if policy
        .sensitive
        .iter()
        .any(|name| private.contains_key(name.as_str()))
    {
        return Err(ProductPartitionError::SensitivePartition);
    }
    let visible = visible_fields(&private)?;
    Ok((
        visible,
        PartitionedIngressHeaders {
            inbound,
            internal_context,
            retained_private,
            sensitive_presence,
            audit_sensitive_presence,
        },
    ))
}

pub(crate) fn rebuild_standalone_facts(
    shape: InterceptedRequestFacts,
    visible_fields: Vec<HeaderField>,
) -> Result<InterceptedRequestFacts, ProductPartitionError> {
    if !shape.headers().is_empty() {
        return Err(ProductPartitionError::SensitivePartition);
    }
    Ok(InterceptedRequestFacts::new(
        shape.ingress_mode(),
        shape.version(),
        shape.method().clone(),
        shape.url().clone(),
        visible_fields,
        shape.body(),
        shape.upgrade().cloned(),
    )?)
}

fn partition_internal_context(
    headers: &mut HeaderMap,
    names: &[http::HeaderName],
) -> Result<HeaderMap, ProductPartitionError> {
    let mut ordinary = HeaderMap::new();
    ordinary
        .try_reserve(headers.len())
        .map_err(|_| ProductPartitionError::Capacity)?;
    let mut internal = HeaderMap::new();
    internal
        .try_reserve(names.len())
        .map_err(|_| ProductPartitionError::Capacity)?;
    let mut current_name = None;
    for (name, value) in headers.drain() {
        if let Some(name) = name {
            current_name = Some(name);
        }
        let name = current_name
            .as_ref()
            .ok_or(ProductPartitionError::Capacity)?;
        let target = if names.contains(name) {
            &mut internal
        } else {
            &mut ordinary
        };
        target
            .try_append(name.clone(), value)
            .map_err(|_| ProductPartitionError::Capacity)?;
    }
    *headers = ordinary;
    Ok(internal)
}

pub(crate) fn http_version(version: http::Version) -> Result<HttpVersion, ProductPartitionError> {
    match version {
        http::Version::HTTP_10 => Ok(HttpVersion::Http10),
        http::Version::HTTP_11 => Ok(HttpVersion::Http11),
        http::Version::HTTP_2 => Ok(HttpVersion::Http2),
        _ => Err(ProductPartitionError::InvalidProductHeaderValue),
    }
}

pub(crate) fn http_method(method: &http::Method) -> Result<HttpMethod, ProductPartitionError> {
    HttpMethod::new(method.as_str()).map_err(Into::into)
}

fn visible_fields(headers: &HeaderMap) -> Result<Vec<HeaderField>, ProductPartitionError> {
    let mut names: Vec<_> = headers.keys().cloned().collect();
    names.sort_unstable_by(|left, right| left.as_str().cmp(right.as_str()));
    let mut fields = Vec::new();
    fields
        .try_reserve(headers.len())
        .map_err(|_| ProductPartitionError::Capacity)?;
    for name in names {
        let checked_name = http_access_types::HeaderName::new(name.as_str())?;
        for value in headers.get_all(&name).iter() {
            fields.push(HeaderField::new(
                checked_name.clone(),
                http_access_types::HeaderValue::new(value.as_bytes().to_vec())?,
            ));
        }
    }
    Ok(fields)
}

pub(crate) fn product_headers(fields: &[HeaderField]) -> Result<HeaderMap, ProductPartitionError> {
    let mut headers = HeaderMap::new();
    headers
        .try_reserve(fields.len())
        .map_err(|_| ProductPartitionError::Capacity)?;
    for field in fields {
        let name = http::HeaderName::from_bytes(field.name().as_str().as_bytes())
            .map_err(|_| ProductPartitionError::InvalidProductHeaderName)?;
        let value = http::HeaderValue::from_bytes(field.value().as_bytes())
            .map_err(|_| ProductPartitionError::InvalidProductHeaderValue)?;
        headers
            .try_append(name, value)
            .map_err(|_| ProductPartitionError::Capacity)?;
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use http::HeaderName as ProductHeaderName;
    use http_access_types::{BodyFraming, BodyMetadata, HeaderName, HeaderValue, IngressMode};
    use http_access_url::canonicalize_http_url;

    use super::*;

    fn field(name: &str, value: &str) -> HeaderField {
        HeaderField::new(
            HeaderName::new(name).unwrap(),
            HeaderValue::new(value.as_bytes().to_vec()).unwrap(),
        )
    }

    fn names(fields: &[HeaderField]) -> Vec<&str> {
        fields.iter().map(|field| field.name().as_str()).collect()
    }

    fn policy<'a>(
        inbound: &'a InboundCredentialSnapshot,
        internal: &'a [ProductHeaderName],
        sensitive: &'a [HeaderName],
    ) -> IngressPartitionPolicy<'a> {
        IngressPartitionPolicy {
            inbound,
            internal_context: internal,
            sensitive,
            observation_sensitive: sensitive,
        }
    }

    fn empty_policy(inbound: &InboundCredentialSnapshot) -> IngressPartitionPolicy<'_> {
        policy(inbound, &[], &[])
    }

    fn facts(mode: IngressMode, method: &str, url: &str) -> InterceptedRequestFacts {
        InterceptedRequestFacts::new(
            mode,
            HttpVersion::Http11,
            HttpMethod::new(method).unwrap(),
            canonicalize_http_url(url).unwrap(),
            Vec::new(),
            BodyMetadata::new(BodyFraming::None),
            None,
        )
        .unwrap()
    }

    #[test]
    fn standalone_ingress_atomically_binds_method_version_framing_and_upgrade_transport() {
        let inbound = InboundCredentialSnapshot::empty_for_test();
        let (visible, _) = partition_standalone_private_fields(
            &empty_policy(&inbound),
            vec![field("x-visible", "ordinary")],
        )
        .unwrap();
        let rebuilt = rebuild_standalone_facts(
            facts(
                IngressMode::ExplicitHttp,
                "POST",
                "http://example.test/resource",
            ),
            visible,
        )
        .unwrap();
        assert_eq!(rebuilt.method().as_str(), "POST");
        assert_eq!(rebuilt.version(), HttpVersion::Http11);
        assert_eq!(rebuilt.headers()[0].value().as_bytes(), b"ordinary");
    }

    #[test]
    fn standalone_connect_ingress_atomically_binds_empty_facts_and_tunnel_transport() {
        let inbound = InboundCredentialSnapshot::empty_for_test();
        let (visible, partitioned) =
            partition_standalone_private_fields(&empty_policy(&inbound), Vec::new()).unwrap();
        let rebuilt = rebuild_standalone_facts(
            facts(
                IngressMode::ExplicitHttps,
                "CONNECT",
                "https://example.test/",
            ),
            visible,
        )
        .unwrap();
        assert_eq!(rebuilt.method().as_str(), "CONNECT");
        assert!(rebuilt.headers().is_empty());
        assert!(partitioned.retained_private.is_empty());
    }

    #[test]
    fn ordinary_ingress_partitions_authorization_and_custom_internal_before_neutralization() {
        let inbound_name = ProductHeaderName::from_static("x-inbound");
        let inbound = InboundCredentialSnapshot::for_test([inbound_name]);
        let internal = [ProductHeaderName::from_static("x-internal")];
        let (visible, partitioned) = partition_standalone_private_fields(
            &policy(&inbound, &internal, &[]),
            vec![
                field("x-inbound", "secret"),
                field("x-internal", "context"),
                field("x-visible", "ordinary"),
            ],
        )
        .unwrap();
        assert_eq!(names(&visible), ["x-visible"]);
        assert_eq!(partitioned.internal_context["x-internal"], "context");
    }

    #[test]
    fn outer_connect_partitions_sensitive_values_before_neutralization() {
        let inbound = InboundCredentialSnapshot::empty_for_test();
        let sensitive = [HeaderName::new("proxy-authorization").unwrap()];
        let (visible, partitioned) = partition_standalone_private_fields(
            &policy(&inbound, &[], &sensitive),
            vec![field("proxy-authorization", "private")],
        )
        .unwrap();
        assert!(visible.is_empty());
        assert_eq!(partitioned.sensitive_presence, sensitive);
        assert!(partitioned
            .retained_private
            .contains_key("proxy-authorization"));
    }

    #[test]
    fn prepartition_consumes_nominated_sensitive_fields_and_preserves_valid_upgrade_control() {
        let inbound = InboundCredentialSnapshot::empty_for_test();
        let sensitive = [HeaderName::new("proxy-authorization").unwrap()];
        let (visible, partitioned) = partition_standalone_private_fields(
            &policy(&inbound, &[], &sensitive),
            vec![
                field("proxy-authorization", "private"),
                field("upgrade", "websocket"),
            ],
        )
        .unwrap();
        assert_eq!(names(&visible), ["upgrade"]);
        assert!(partitioned
            .retained_private
            .contains_key("proxy-authorization"));
    }

    #[test]
    fn h2_invalid_te_remains_for_shared_validation_after_prepartition() {
        let inbound = InboundCredentialSnapshot::empty_for_test();
        let (visible, _) = partition_standalone_private_fields(
            &empty_policy(&inbound),
            vec![field("te", "invalid")],
        )
        .unwrap();
        assert_eq!(visible[0].name().as_str(), "te");
        assert_eq!(visible[0].value().as_bytes(), b"invalid");
    }

    #[test]
    fn connection_nominated_partition_owners_are_removed_before_connect_extraction() {
        let inbound = InboundCredentialSnapshot::empty_for_test();
        let (visible, partitioned) = partition_standalone_private_fields(
            &empty_policy(&inbound),
            vec![field("proxy-authorization", "private")],
        )
        .unwrap();
        assert!(visible.is_empty());
        assert_eq!(partitioned.retained_private.len(), 1);
    }

    #[test]
    fn ordinary_proxy_authorization_presence_is_retained_but_value_never_becomes_neutral() {
        proxy_authorization_is_private();
    }

    #[test]
    fn connect_proxy_authorization_presence_is_retained_but_value_never_becomes_neutral() {
        proxy_authorization_is_private();
    }

    fn proxy_authorization_is_private() {
        let inbound = InboundCredentialSnapshot::empty_for_test();
        let sensitive = [HeaderName::new("proxy-authorization").unwrap()];
        let (visible, partitioned) = partition_standalone_private_fields(
            &policy(&inbound, &[], &sensitive),
            vec![field("proxy-authorization", "private-value")],
        )
        .unwrap();
        assert!(visible.is_empty());
        assert_eq!(partitioned.audit_sensitive_presence, sensitive);
        assert_eq!(
            partitioned.retained_private["proxy-authorization"],
            "private-value"
        );
    }

    #[test]
    fn ordinary_raw_projection_bounds_precede_internal_partition() {
        complete_private_field_set_is_partitioned_once();
    }

    #[test]
    fn connect_raw_projection_bounds_precede_internal_partition() {
        complete_private_field_set_is_partitioned_once();
    }

    fn complete_private_field_set_is_partitioned_once() {
        let inbound = InboundCredentialSnapshot::empty_for_test();
        let internal = [ProductHeaderName::from_static("x-internal")];
        let fields = (0..32)
            .map(|index| field(&format!("x-visible-{index}"), "value"))
            .chain([field("x-internal", "one"), field("x-internal", "two")])
            .collect::<Vec<_>>();
        let (visible, partitioned) =
            partition_standalone_private_fields(&policy(&inbound, &internal, &[]), fields).unwrap();
        assert_eq!(visible.len(), 32);
        assert_eq!(
            partitioned
                .internal_context
                .get_all("x-internal")
                .iter()
                .count(),
            2
        );
    }

    #[test]
    fn standalone_connect_ingress_rejects_wrong_mode_target_framing_or_body() {
        let shaped = InterceptedRequestFacts::new(
            IngressMode::TransparentHttp,
            HttpVersion::Http11,
            HttpMethod::new("CONNECT").unwrap(),
            canonicalize_http_url("https://example.test/").unwrap(),
            vec![field("x-unpartitioned", "private")],
            BodyMetadata::new(BodyFraming::None),
            None,
        );
        assert!(shaped.is_err());
    }
}
