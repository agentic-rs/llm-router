//! Zero-parse ConvertRequest stage.
//!
//! Forwards the inbound body **verbatim** to the upstream:
//! `upstream_wire_body = extracted.raw_body.clone()` (bytes still in their
//! original on-wire encoding). No JSON parse, no model rewrite, no
//! cross-endpoint translation, no provider input transformer.
//!
//! `upstream_body` is set to `Value::Null` because no observer should
//! consume it; subscribers that care about request bodies must read the
//! `Bytes` (`debug_outbound_body` / wire body) instead.

use crate::event::Stage;
use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::{PipelineError, RequestsError};
use crate::pipeline::stages::{require_upstream_endpoint, ConvertRequestStage, ConvertedRequest, Extracted, Resolved};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

pub struct PassthroughConvertRequest;

#[async_trait]
impl ConvertRequestStage for PassthroughConvertRequest {
  async fn convert_request(
    &self,
    ctx: &PipelineCtx,
    extracted: &Extracted,
    resolved: &Resolved,
  ) -> Result<ConvertedRequest, PipelineError> {
    if let Some(options) = ctx.config.generation_options() {
      options.validate().map_err(|source| {
        PipelineError::permanent(
          Stage::ConvertRequest,
          RequestsError::InvalidGenerationOptions { source },
        )
      })?;
      let control = if options.max_output_tokens.is_some() {
        Some("max_output_tokens")
      } else if options.top_k.is_some() {
        Some("top_k")
      } else if options.reasoning.is_some() {
        Some("reasoning")
      } else {
        None
      };
      if let Some(control) = control {
        let endpoint = require_upstream_endpoint(ctx, resolved, Stage::ConvertRequest)?;
        return Err(PipelineError::permanent(
          Stage::ConvertRequest,
          RequestsError::UnsupportedGenerationControl {
            control,
            provider_id: resolved.account_handle.provider.info().id.clone().into(),
            endpoint,
            reason: "verbatim routing cannot lower provider-neutral generation controls",
          },
        ));
      }
    }
    Ok(ConvertedRequest {
      // Sentinel: the body was never parsed. Observers must not treat
      // this as a real upstream body.
      upstream_body: Arc::new(Value::Null),
      upstream_wire_body: extracted.raw_body.clone(),
      debug_outbound_body: extracted.decoded_body.clone(),
      content_encoding: extracted.content_encoding,
    })
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::event::EventBus;
  use crate::pipeline::config::RunConfig;
  use bytes::Bytes;
  use serde_json::json;
  use smol_str::SmolStr;
  use std::sync::Arc;
  use tokn_core::generation::GenerationOptions;
  use tokn_core::provider::Endpoint;
  use tokn_headers::HeaderMap;

  fn ctx() -> PipelineCtx {
    PipelineCtx::new("req", Endpoint::ChatCompletions.into(), Arc::new(EventBus::new(16)))
  }

  fn extracted(raw: Bytes, decoded: Bytes) -> Extracted {
    Extracted {
      agent_id: None,
      model: SmolStr::new("m"),
      stream: false,
      session_id: None,
      project_id: None,
      initiator: None,
      header_initiator: None,
      route_mode_hint: None,
      headers: HeaderMap::new(),
      raw_body: raw,
      decoded_body: decoded,
      body_json: Arc::new(json!(null)),
      content_encoding: None,
    }
  }

  fn resolved() -> Resolved {
    Resolved {
      agent_id: None,
      model: SmolStr::new("m"),
      upstream_model: SmolStr::new("m"),
      route: crate::pipeline::stages::ResolvedRoute::operation(Endpoint::ChatCompletions, Endpoint::ChatCompletions),
      account_id: SmolStr::new("a"),
      provider_id: SmolStr::new("openai"),
      account_handle: crate::test_support::mock_handle("a", "openai"),
    }
  }

  #[tokio::test]
  async fn forwards_bytes_verbatim() {
    let raw = Bytes::from_static(b"\x1f\x8b\x08\x00not-json-just-bytes");
    let decoded = Bytes::from_static(b"{\"model\":\"m\"}");
    let out = PassthroughConvertRequest
      .convert_request(&ctx(), &extracted(raw.clone(), decoded.clone()), &resolved())
      .await
      .unwrap();
    assert_eq!(out.upstream_wire_body, raw);
    assert_eq!(out.debug_outbound_body, decoded);
    assert_eq!(*out.upstream_body, Value::Null, "upstream_body must be null sentinel");
  }

  #[tokio::test]
  async fn rejects_generation_controls_that_require_lowering() {
    let raw = Bytes::from_static(b"{\"model\":\"m\"}");
    let config = RunConfig::builder()
      .with_generation_options(GenerationOptions::new().with_top_k(40))
      .build();
    let ctx = PipelineCtx::new_with_config(
      "req",
      Endpoint::ChatCompletions.into(),
      Arc::new(EventBus::new(16)),
      Arc::new(config),
    );

    let error = PassthroughConvertRequest
      .convert_request(&ctx, &extracted(raw.clone(), raw), &resolved())
      .await
      .unwrap_err();

    assert!(matches!(
      error.inner(),
      RequestsError::UnsupportedGenerationControl {
        control: "top_k",
        endpoint: Endpoint::ChatCompletions,
        ..
      }
    ));
  }

  #[tokio::test]
  async fn rejects_out_of_band_max_output_tokens_even_when_the_wire_contains_a_limit() {
    let raw = Bytes::from_static(b"{\"model\":\"m\",\"max_output_tokens\":64}");
    let config = RunConfig::builder()
      .with_generation_options(GenerationOptions::new().with_max_output_tokens(64))
      .build();
    let ctx = PipelineCtx::new_with_config(
      "req",
      Endpoint::ChatCompletions.into(),
      Arc::new(EventBus::new(16)),
      Arc::new(config),
    );

    let error = PassthroughConvertRequest
      .convert_request(&ctx, &extracted(raw.clone(), raw.clone()), &resolved())
      .await
      .unwrap_err();

    assert!(matches!(
      error.inner(),
      RequestsError::UnsupportedGenerationControl {
        control: "max_output_tokens",
        ..
      }
    ));
  }
}
