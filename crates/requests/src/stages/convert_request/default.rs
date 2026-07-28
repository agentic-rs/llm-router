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

use super::generation::{ensure_model_supports_reasoning, lower_generation_options};
use crate::event::Stage;
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
        .map_err(|source| perm(RequestsError::InvalidGenerationOptions { source }))?;
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
      .map_err(perm)?;
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
      .map_err(perm)?;
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
