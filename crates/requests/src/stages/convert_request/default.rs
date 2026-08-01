//! Default production ConvertRequest stage.
//!
//! Mirrors the legacy `crates/router/src/pipeline/request.rs::prepare_request`
//! algorithm, decomposed into a single stage:
//!
//! 1. **Model rewrite** — overwrite `body.model` with the upstream model
//!    selected by Resolve.
//! 2. **Cross-endpoint convert** — when the inbound endpoint differs
//!    from the account's upstream endpoint, run `tokn_convert` to
//!    translate the JSON shape (e.g. Responses → Chat). Pass-through is
//!    free when both endpoints match.
//! 3. **Generation controls** — lower the SDK's typed, provider-neutral
//!    generation controls into the selected endpoint/provider dialect.
//! 4. **Provider [`InputTransformer`]** — give the provider a final
//!    say (e.g. inject the `thinking` block for `glm-4.6`).
//! 5. **Serialize + re-encode** — produce `debug_outbound_body` (the
//!    uncompressed JSON, useful for logs and tests) and
//!    `upstream_wire_body` (re-compressed with the same codec the
//!    inbound used, when any). When the body hasn't changed and an
//!    encoding was present, we keep the original wire bytes to avoid
//!    a needless re-compress.
//!
//! Failures map to permanent [`PipelineError`]s — the upstream body
//! shape isn't going to change between retries.

use crate::event::Stage;
use crate::execution::{ensure_model_supports_reasoning, lower_generation_options, GenerationControlError};
use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::{PipelineError, RequestsError};
use crate::pipeline::stages::{
  require_resolved_endpoint, require_upstream_endpoint, ConvertRequestStage, ConvertedRequest, Extracted, Resolved,
};
use crate::utils::codec::{encode_body_bytes, ContentEncodingKind};
use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value;
use std::sync::Arc;

pub struct DefaultConvertRequest;

#[async_trait]
impl ConvertRequestStage for DefaultConvertRequest {
  async fn convert_request(
    &self,
    ctx: &PipelineCtx,
    extracted: &Extracted,
    resolved: &Resolved,
  ) -> Result<ConvertedRequest, PipelineError> {
    let inbound_endpoint = require_resolved_endpoint(ctx, resolved, Stage::ConvertRequest)?;
    let upstream_endpoint = require_upstream_endpoint(ctx, resolved, Stage::ConvertRequest)?;
    let generation_options = ctx.config.generation_options();
    if let Some(options) = generation_options {
      options
        .validate()
        .map_err(|source| generation_error(GenerationControlError::InvalidOptions { source }))?;
      ensure_model_supports_reasoning(
        upstream_endpoint,
        resolved.account_handle.provider.info().id.as_str(),
        resolved
          .account_handle
          .provider
          .model_info(resolved.upstream_model.as_str())
          .map(|info| info.capabilities.reasoning),
        options,
      )
      .map_err(generation_error)?;
    }
    let mut upstream_body = rewrite_model(&extracted.body_json, resolved.upstream_model.as_str());

    if upstream_endpoint != inbound_endpoint {
      upstream_body = tokn_convert::convert_request(inbound_endpoint, upstream_endpoint, &upstream_body)
        .map_err(|source| perm(RequestsError::RequestConversion { source }))?;
    }

    if let Some(options) = generation_options {
      lower_generation_options(
        &mut upstream_body,
        upstream_endpoint,
        resolved.account_handle.provider.info().id.as_str(),
        resolved.upstream_model.as_str(),
        options,
      )
      .map_err(generation_error)?;
    }

    if let Some(transformer) = resolved.account_handle.provider.input_transformer() {
      upstream_body = transformer
        .transform_input(upstream_endpoint, upstream_body)
        .map_err(|source| perm(RequestsError::ProviderInputTransformer { source }))?;
    }

    let debug_outbound_body = Bytes::from(
      serde_json::to_vec(&upstream_body).map_err(|source| perm(RequestsError::SerializeUpstreamBody { source }))?,
    );

    let unchanged = upstream_body == *extracted.body_json;
    let upstream_wire_body = if unchanged {
      // Reuse the original wire payload — preserves byte-for-byte
      // parity with whatever the client sent (including its
      // content-encoding) and avoids a needless re-compress.
      extracted.raw_body.clone()
    } else {
      maybe_encode(&debug_outbound_body, extracted.content_encoding)?
    };

    Ok(ConvertedRequest {
      upstream_body: Arc::new(upstream_body),
      upstream_wire_body,
      debug_outbound_body,
      content_encoding: extracted.content_encoding,
    })
  }
}

fn maybe_encode(body: &Bytes, encoding: Option<ContentEncodingKind>) -> Result<Bytes, PipelineError> {
  encode_body_bytes(body.as_ref(), encoding).map_err(|source| perm(RequestsError::ReencodeOutboundBody { source }))
}

fn rewrite_model(body: &Value, model: &str) -> Value {
  let mut body = body.clone();
  if let Some(obj) = body.as_object_mut() {
    obj.insert("model".into(), Value::String(model.to_string()));
  }
  body
}

fn perm(source: RequestsError) -> PipelineError {
  PipelineError::permanent(Stage::ConvertRequest, source)
}

fn generation_error(source: GenerationControlError) -> PipelineError {
  perm(source.into())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::event::EventBus;
  use crate::pipeline::config::RunConfig;
  use crate::pipeline::ctx::PipelineCtx;
  use crate::pipeline::stages::{Extracted, Resolved, ResolvedRoute};
  use crate::test_support::{mock_handle, mock_handle_with_provider, MockProvider};
  use crate::utils::codec::{decode_body_bytes, encode_body_bytes, ContentEncodingKind};
  use std::sync::Arc;
  use tokn_core::pipeline::InputTransformer;
  use tokn_core::provider::{Endpoint, Result as ProviderResult};
  use tokn_headers::HeaderMap;

  fn ctx_at(endpoint: Endpoint) -> PipelineCtx {
    PipelineCtx::new("req-cr", endpoint.into(), Arc::new(EventBus::new(64)))
  }

  fn ctx() -> PipelineCtx {
    ctx_at(Endpoint::ChatCompletions)
  }

  fn ctx_with_config(endpoint: Endpoint, config: RunConfig) -> PipelineCtx {
    PipelineCtx::new_with_config("req-cr", endpoint.into(), Arc::new(EventBus::new(64)), Arc::new(config))
  }

  fn extracted_with(
    body: Value,
    encoding: Option<ContentEncodingKind>,
    wire: Bytes,
    initiator: Option<&str>,
  ) -> Extracted {
    Extracted {
      agent_id: None,
      model: smol_str::SmolStr::new("input-model"),
      stream: false,
      session_id: None,
      project_id: None,
      initiator: initiator.map(smol_str::SmolStr::new),
      header_initiator: None,
      route_mode_hint: None,
      headers: HeaderMap::new(),
      raw_body: wire.clone(),
      decoded_body: Bytes::from(serde_json::to_vec(&body).unwrap()),
      body_json: Arc::new(body),
      content_encoding: encoding,
    }
  }

  fn resolved_with(
    handle: Arc<tokn_accounts::AccountHandle>,
    resolved_endpoint: Endpoint,
    upstream_endpoint: Endpoint,
    upstream_model: &str,
  ) -> Resolved {
    Resolved {
      agent_id: None,
      model: smol_str::SmolStr::new("input-model"),
      upstream_model: smol_str::SmolStr::new(upstream_model),
      route: ResolvedRoute::operation(resolved_endpoint, upstream_endpoint),
      account_id: smol_str::SmolStr::new("acct-1"),
      provider_id: smol_str::SmolStr::from(handle.provider.id()),
      account_handle: handle,
    }
  }

  #[tokio::test]
  async fn passthrough_when_endpoints_match_and_no_transformer() {
    let body = serde_json::json!({"model": "input-model", "messages": [{"role":"user","content":"hi"}]});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body.clone(), None, raw.clone(), None);
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();
    assert_eq!(*out.upstream_body, body);
    // Body unchanged → original wire bytes reused verbatim.
    assert_eq!(out.upstream_wire_body, raw);
    assert!(out.content_encoding.is_none());
  }

  #[tokio::test]
  async fn rewrites_model_field() {
    let body = serde_json::json!({"model": "input-model", "messages": []});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "upstream-model-7",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();
    assert_eq!(out.upstream_body["model"], "upstream-model-7");
  }

  #[tokio::test]
  async fn runs_provider_input_transformer() {
    struct Stamp;
    impl InputTransformer for Stamp {
      fn transform_input(&self, _endpoint: Endpoint, mut body: Value) -> ProviderResult<Value> {
        if let Some(obj) = body.as_object_mut() {
          obj.insert("stamped".into(), Value::Bool(true));
        }
        Ok(body)
      }
    }
    let body = serde_json::json!({"model": "input-model"});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let handle = mock_handle_with_provider("acct", MockProvider::new("mock").with_transformer(Stamp));
    let res = resolved_with(
      handle,
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();
    assert_eq!(out.upstream_body["stamped"], true);
  }

  #[tokio::test]
  async fn cross_endpoint_convert_runs_when_endpoints_differ() {
    // Responses → ChatCompletions. We don't assert on the exact shape
    // (that's `tokn_convert`'s responsibility) — just that the body
    // mutated and was re-serialized into `debug_outbound_body`.
    let body = serde_json::json!({
      "model": "input-model",
      "input": [{"role": "user", "content": "hi"}]
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body.clone(), None, raw, None);
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::Responses,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let out = DefaultConvertRequest
      .convert_request(&ctx_at(Endpoint::Responses), &ex, &res)
      .await
      .unwrap();
    assert_ne!(
      *out.upstream_body, body,
      "expected cross-endpoint conversion to mutate body"
    );
    // wire body was re-serialized (not the original raw bytes).
    assert_eq!(out.upstream_wire_body, out.debug_outbound_body);
  }

  #[tokio::test]
  async fn gzip_round_trips_when_body_changes() {
    let body = serde_json::json!({"model": "input-model", "messages": []});
    let compressed = encode_body_bytes(
      serde_json::to_vec(&body).unwrap().as_slice(),
      Some(ContentEncodingKind::Gzip),
    )
    .unwrap();
    let ex = extracted_with(body, Some(ContentEncodingKind::Gzip), compressed, None);
    // Different upstream model → body mutates → we must re-compress.
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "upstream-model-2",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();
    assert_eq!(out.content_encoding, Some(ContentEncodingKind::Gzip));
    let decoded = decode_body_bytes(out.upstream_wire_body.clone(), out.content_encoding).unwrap();
    let v: Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(v["model"], "upstream-model-2");
  }

  #[tokio::test]
  async fn content_encoding_propagates_to_output() {
    let body = serde_json::json!({"model": "input-model"});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, Some(ContentEncodingKind::Zstd), raw, None);
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let out = DefaultConvertRequest.convert_request(&ctx(), &ex, &res).await.unwrap();
    assert_eq!(out.content_encoding, Some(ContentEncodingKind::Zstd));
  }

  #[tokio::test]
  async fn transformer_failure_is_permanent_stage_error() {
    struct Boom;
    impl InputTransformer for Boom {
      fn transform_input(&self, _endpoint: Endpoint, _body: Value) -> ProviderResult<Value> {
        Err(tokn_core::provider::error::Error::Profiles { message: "boom".into() })
      }
    }
    let body = serde_json::json!({"model": "input-model"});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let handle = mock_handle_with_provider("acct", MockProvider::new("mock").with_transformer(Boom));
    let res = resolved_with(
      handle,
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );

    let err = DefaultConvertRequest
      .convert_request(&ctx(), &ex, &res)
      .await
      .unwrap_err();
    assert_eq!(err.stage, Stage::ConvertRequest);
    assert!(!err.recoverable);
    assert!(err.message().contains("boom"));
  }

  #[tokio::test]
  async fn uses_run_config_upstream_endpoint_override_for_cross_endpoint_conversion() {
    let body = serde_json::json!({
      "model": "input-model",
      "input": [{"role": "user", "content": "hi"}]
    });
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body.clone(), None, raw, None);
    let res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::Responses,
      Endpoint::Responses,
      "input-model",
    );
    let ctx = ctx_with_config(
      Endpoint::Responses,
      RunConfig::builder()
        .with_str(crate::pipeline::stages::RUN_UPSTREAM_ENDPOINT_KEY, "chat_completions")
        .build(),
    );

    let out = DefaultConvertRequest
      .convert_request(&ctx, &ex, &res)
      .await
      .expect("convert should use configured upstream endpoint");

    assert_ne!(*out.upstream_body, body);
    assert_eq!(out.upstream_wire_body, out.debug_outbound_body);
  }

  #[tokio::test]
  async fn errors_when_no_resolved_endpoint_is_available() {
    let body = serde_json::json!({"model": "input-model"});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());
    let ex = extracted_with(body, None, raw, None);
    let mut res = resolved_with(
      mock_handle("acct", "mock"),
      Endpoint::ChatCompletions,
      Endpoint::ChatCompletions,
      "input-model",
    );
    res.route = ResolvedRoute::provider_traffic(tokn_core::provider::ProviderRequestKind::Opaque);
    let ctx = PipelineCtx::new(
      "req-cr-missing",
      tokn_core::request_event::RequestEndpoint::custom("/v1/experimental/agents"),
      Arc::new(EventBus::new(64)),
    );

    let err = DefaultConvertRequest
      .convert_request(&ctx, &ex, &res)
      .await
      .unwrap_err();

    assert_eq!(err.stage, Stage::ConvertRequest);
    assert!(!err.recoverable);
    match err.inner() {
      RequestsError::MissingResolvedEndpoint { request_endpoint } => {
        assert_eq!(request_endpoint.as_str(), "/v1/experimental/agents");
      }
      other => panic!("expected MissingResolvedEndpoint, got {other:?}"),
    }
  }

  #[test]
  fn extracted_helper_preserves_user_agent_and_none_initiator() {
    let body = serde_json::json!({"model": "input-model"});
    let raw = Bytes::from(serde_json::to_vec(&body).unwrap());

    assert_eq!(
      extracted_with(body.clone(), None, raw.clone(), None)
        .initiator
        .as_deref(),
      None
    );
    assert_eq!(
      extracted_with(body.clone(), None, raw.clone(), Some("user"))
        .initiator
        .as_deref(),
      Some("user")
    );
    assert_eq!(
      extracted_with(body, None, raw, Some("agent")).initiator.as_deref(),
      Some("agent")
    );
  }
}
