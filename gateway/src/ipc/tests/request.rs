use super::super::tags::REQUEST_MESSAGE;
use super::super::wire::Decoder;
use super::super::{ActionClass, DenialCode, FlowKind, decode_request, encode_request};
use super::support::{request, tags_offset};

#[test]
fn request_round_trip_is_canonical() {
    let expected = request();
    let encoded = encode_request(&expected).expect("encode request");
    assert_eq!(decode_request(&encoded), Ok(expected));
}

#[test]
fn raw_high_load_and_destructive_tags_are_denied() {
    let encoded = encode_request(&request()).expect("encode request");
    let class_offset = tags_offset(&encoded) + 1;
    for tag in [4, 5] {
        let mut mutated = encoded.clone();
        mutated[class_offset] = tag;
        assert_eq!(
            decode_request(&mutated)
                .expect_err("unsupported class")
                .reason,
            DenialCode::UnsupportedActionClass
        );
    }
}

#[test]
fn unknown_action_and_feature_tags_are_denied() {
    let encoded = encode_request(&request()).expect("encode request");
    let action_offset = tags_offset(&encoded);
    let mut unknown_action = encoded.clone();
    unknown_action[action_offset] = 99;
    assert_eq!(
        decode_request(&unknown_action)
            .expect_err("unknown action")
            .reason,
        DenialCode::UnknownActionKind
    );

    let mut decoder = Decoder::new(&encoded, REQUEST_MESSAGE).expect("valid frame");
    decoder.offset = action_offset + 4;
    decoder.optional_string().expect("parent action ID");
    let feature_count_offset = decoder.offset;
    let mut unknown_feature = encoded;
    unknown_feature[feature_count_offset + 1] = 99;
    assert_eq!(
        decode_request(&unknown_feature)
            .expect_err("unknown feature")
            .reason,
        DenialCode::UnknownRequiredFeature
    );

    let mut unknown_flow = encode_request(&request()).expect("encode request");
    unknown_flow[action_offset + 3] = 99;
    assert_eq!(
        decode_request(&unknown_flow)
            .expect_err("unknown child flow")
            .reason,
        DenialCode::InvalidChildFlow
    );
}

#[test]
fn parent_provenance_is_canonical_and_fail_closed() {
    let mut top_level_with_parent = request();
    top_level_with_parent.parent_action_id = Some("action:parent".to_owned());
    top_level_with_parent.bind_canonical_semantics();
    assert_eq!(
        encode_request(&top_level_with_parent),
        Err(DenialCode::InvalidChildFlow)
    );

    let mut orphan_child = request();
    orphan_child.flow_kind = FlowKind::Redirect;
    orphan_child.bind_canonical_semantics();
    assert_eq!(
        encode_request(&orphan_child),
        Err(DenialCode::InvalidChildFlow)
    );

    orphan_child.parent_action_id = Some("action:parent".to_owned());
    orphan_child.bind_canonical_semantics();
    assert_eq!(
        decode_request(&encode_request(&orphan_child).expect("child frame")),
        Ok(orphan_child)
    );
}

#[test]
fn scope_binding_digest_covers_policy_dimensions() {
    let base = request();
    let base_digest = base.scope_binding_digest();
    let mut variants = Vec::new();
    let mut grant = base.clone();
    grant.grant_version += 1;
    variants.push(grant);
    let mut pack = base.clone();
    pack.pack_id = "llm".to_owned();
    variants.push(pack);
    let mut identity = base.clone();
    identity.identity_id = "identity:other".to_owned();
    variants.push(identity);
    let mut tenant = base.clone();
    tenant.tenant_id = Some("tenant:other".to_owned());
    variants.push(tenant);
    let mut family = base.clone();
    family.action_family = "http.other".to_owned();
    variants.push(family);
    let mut host = base.clone();
    host.hostname = "other.localhost".to_owned();
    variants.push(host);
    let mut method = base.clone();
    method.method = "POST".to_owned();
    variants.push(method);
    let mut path = base.clone();
    path.path = "/other".to_owned();
    variants.push(path);
    let mut target = base.clone();
    target.target.set_port(8081);
    variants.push(target);
    let mut child = base;
    child.flow_kind = FlowKind::Redirect;
    child.parent_action_id = Some("action:parent".to_owned());
    variants.push(child);

    assert!(
        variants
            .iter()
            .all(|variant| variant.scope_binding_digest() != base_digest)
    );
}

#[test]
fn state_change_requires_canary_and_cleanup_references() {
    let mut candidate = request();
    candidate.action_class = ActionClass::StateChange;
    candidate.bind_canonical_semantics();
    assert_eq!(
        encode_request(&candidate),
        Err(DenialCode::StateChangeContractMissing)
    );
    candidate.canary_ref = Some("canary:1".to_owned());
    candidate.checkpoint_ref = Some("checkpoint:1".to_owned());
    candidate.cleanup_plan_ref = Some("cleanup:1".to_owned());
    candidate.bind_canonical_semantics();
    assert!(encode_request(&candidate).is_ok());
}
