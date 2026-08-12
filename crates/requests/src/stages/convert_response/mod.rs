//! No-op ConvertResponse stage. Drops the upstream response and returns an
//! empty buffered placeholder. Pairs with [`NoopSend`](crate::stages::NoopSend);
//! only reachable when the back-half is wired but neither stub has been swapped
//! out yet.

use crate::pipeline::ctx::PipelineCtx;
use crate::pipeline::error::PipelineError;
use crate::pipeline::stages::{ConvertResponseStage, ConvertedBody, ConvertedResponse, ConvertedResponseKind};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use tokn_headers::HeaderMap;

pub mod default;
pub mod passthrough;
pub use default::DefaultConvertResponse;
pub use passthrough::PassthroughConvertResponse;

fn noop_buffered() -> ConvertedResponse {
  ConvertedResponse {
    status: 0,
    headers: HeaderMap::new(),
    kind: ConvertedResponseKind::Managed,
    body: ConvertedBody::Buffered {
      body_json: None,
      body_bytes: Bytes::new(),
    },
  }
}

pub struct NoopConvertResponse;

#[async_trait]
impl ConvertResponseStage for NoopConvertResponse {
  async fn convert_buffered(
    &self,
    _ctx: &PipelineCtx,
    status: u16,
    _headers: HeaderMap,
    _upstream_endpoint: Option<tokn_core::provider::Endpoint>,
    _body: Bytes,
  ) -> Result<ConvertedResponse, PipelineError> {
    let _ = status;
    Ok(noop_buffered())
  }

  async fn convert_stream(
    &self,
    _ctx: &PipelineCtx,
    status: u16,
    _headers: HeaderMap,
    _upstream_endpoint: Option<tokn_core::provider::Endpoint>,
    _body: BoxStream<'static, std::io::Result<Bytes>>,
  ) -> Result<ConvertedResponse, PipelineError> {
    let _ = status;
    Ok(noop_buffered())
  }
}
