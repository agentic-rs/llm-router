mod error;
mod lifecycle;
mod stream;

use crate::error::{native_error, sdk_error, INTERNAL_ERROR, REQUEST_ERROR, SERIALIZATION_ERROR};
use crate::lifecycle::{cancellation_error, CancelReason, Cancellation, ClientState};
use crate::stream::{NativeByteStream, NativeGenerateStream, NativeTextStream};
use napi::bindgen_prelude::{AsyncBlock, AsyncBlockBuilder};
use napi::{Env, Result};
use napi_derive::napi;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::watch;
use tokn_sdk::{
  Client, Endpoint, Event, GenerateRequest, GenerateResponse, RequestOptions, ResponseBody, ToolCall, Usage,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientOptions {
  #[serde(default)]
  config_path: Option<String>,
  #[serde(default)]
  auth_path: Option<String>,
  #[serde(default)]
  profile: Option<String>,
}

#[napi(object)]
pub struct NativeResponse {
  pub status: u32,
  pub headers_json: String,
  pub body_json: String,
}

#[napi]
pub struct NativeCancellation {
  inner: Arc<Cancellation>,
}

impl Default for NativeCancellation {
  fn default() -> Self {
    Self::new()
  }
}

#[napi]
impl NativeCancellation {
  #[napi(constructor)]
  pub fn new() -> Self {
    Self {
      inner: Arc::new(Cancellation::new()),
    }
  }

  #[napi]
  pub fn cancel(&self) {
    self.inner.cancel(CancelReason::User);
  }

  #[napi(getter)]
  pub fn aborted(&self) -> bool {
    self.inner.is_cancelled()
  }
}

#[napi]
pub struct NativeClient {
  state: Arc<ClientState>,
}

#[napi]
pub struct NativeRequestEventStream {
  receiver: Arc<tokio::sync::Mutex<Option<tokio::sync::broadcast::Receiver<Arc<Event>>>>>,
  close_tx: watch::Sender<bool>,
}

async fn next_request_event(
  receiver: Arc<tokio::sync::Mutex<Option<tokio::sync::broadcast::Receiver<Arc<Event>>>>>,
  mut close_rx: watch::Receiver<bool>,
) -> Result<Option<String>> {
  if *close_rx.borrow() {
    return Ok(None);
  }
  let mut receiver = receiver.lock().await;
  let Some(receiver) = receiver.as_mut() else {
    return Ok(None);
  };
  loop {
    let received = tokio::select! {
      biased;
      _ = wait_for_request_event_close(&mut close_rx) => return Ok(None),
      received = receiver.recv() => received,
    };
    match received {
      Ok(event) => {
        let Event::Requests(event) = event.as_ref() else {
          continue;
        };
        let event = serde_json::to_string(event).map_err(|error| {
          native_error(
            SERIALIZATION_ERROR,
            format!("failed to serialize request lifecycle event: {error}"),
          )
        })?;
        return Ok(Some(event));
      }
      Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
        return Err(native_error(
          REQUEST_ERROR,
          format!("request event stream lagged by {count} events"),
        ));
      }
      Err(tokio::sync::broadcast::error::RecvError::Closed) => return Ok(None),
    }
  }
}

async fn close_request_event_stream(
  receiver: Arc<tokio::sync::Mutex<Option<tokio::sync::broadcast::Receiver<Arc<Event>>>>>,
  close_tx: watch::Sender<bool>,
) {
  close_tx.send_replace(true);
  *receiver.lock().await = None;
}

async fn wait_for_request_event_close(close_rx: &mut watch::Receiver<bool>) {
  loop {
    if *close_rx.borrow() || close_rx.changed().await.is_err() {
      return;
    }
  }
}

#[napi]
impl NativeRequestEventStream {
  #[napi]
  pub fn next(&self, env: Env) -> Result<AsyncBlock<Option<String>>> {
    let receiver = self.receiver.clone();
    let close_rx = self.close_tx.subscribe();
    AsyncBlockBuilder::new(next_request_event(receiver, close_rx)).build(&env)
  }

  #[napi]
  pub fn close(&self, env: Env) -> Result<AsyncBlock<()>> {
    let receiver = self.receiver.clone();
    let close_tx = self.close_tx.clone();
    AsyncBlockBuilder::new(async move {
      close_request_event_stream(receiver, close_tx).await;
      Ok(())
    })
    .build(&env)
  }
}

impl Drop for NativeClient {
  fn drop(&mut self) {
    self.state.begin_close();
  }
}

#[napi]
impl NativeClient {
  #[napi(getter)]
  pub fn config_path(&self) -> String {
    self.state.client.config_path().to_string_lossy().into_owned()
  }

  #[napi(getter)]
  pub fn auth_path(&self) -> String {
    self.state.client.auth_path().to_string_lossy().into_owned()
  }

  #[napi]
  pub fn subscribe_events(&self) -> NativeRequestEventStream {
    let (close_tx, _) = watch::channel(false);
    NativeRequestEventStream {
      receiver: Arc::new(tokio::sync::Mutex::new(Some(self.state.client.subscribe_events()))),
      close_tx,
    }
  }

  #[napi]
  pub fn reload(&self, env: Env, cancellation: &NativeCancellation) -> Result<AsyncBlock<()>> {
    let cancellation = cancellation.inner.clone();
    let operation = self.state.register(cancellation.clone())?;
    let client = self.state.client.clone();
    let reload_lock = self.state.reload_lock.clone();
    AsyncBlockBuilder::new(async move {
      let reload_lock = tokio::select! {
        biased;
        reason = cancellation.cancelled() => {
          return Err(cancellation_error(reason));
        }
        reload_lock = reload_lock.lock_owned() => reload_lock,
      };

      let reload = napi::bindgen_prelude::spawn_blocking(move || {
        let _operation = operation;
        let _reload_lock = reload_lock;
        client.reload()
      });
      let result = reload
        .await
        .map_err(|error| native_error(INTERNAL_ERROR, format!("reload task failed: {error}")))?;
      cancellation.error_if_cancelled()?;
      result.map_err(sdk_error)
    })
    .build(&env)
  }

  #[napi]
  pub fn close(&self, env: Env) -> Result<AsyncBlock<()>> {
    let state = self.state.clone();
    AsyncBlockBuilder::new(async move {
      state.close().await;
      Ok(())
    })
    .build(&env)
  }

  #[napi]
  pub fn request(
    &self,
    env: Env,
    endpoint: String,
    body_json: String,
    options_json: Option<String>,
    cancellation: &NativeCancellation,
  ) -> Result<AsyncBlock<NativeResponse>> {
    let endpoint = parse_endpoint(&endpoint)?;
    let body = parse_json(&body_json, "request body")?;
    let options = parse_options(options_json.as_deref())?;
    let cancellation = cancellation.inner.clone();
    let operation = self.state.register(cancellation.clone())?;
    let client = self.state.client.clone();
    AsyncBlockBuilder::new(async move {
      let _operation = operation;
      let response = tokio::select! {
        biased;
        reason = cancellation.cancelled() => return Err(cancellation_error(reason)),
        response = client.execute(endpoint, body, options) => response.map_err(sdk_error)?,
      };
      let headers_json = serde_json::to_string(&response.headers).map_err(|error| {
        native_error(
          SERIALIZATION_ERROR,
          format!("failed to serialize response headers: {error}"),
        )
      })?;
      let body = match response.body {
        ResponseBody::Buffered(body) => body,
        ResponseBody::Stream(_) => {
          return Err(native_error(
            REQUEST_ERROR,
            "provider returned a stream; use Client.stream()",
          ));
        }
      };
      let body_json = String::from_utf8(body.to_vec()).map_err(|error| {
        native_error(
          SERIALIZATION_ERROR,
          format!("provider returned a non-UTF-8 JSON response: {error}"),
        )
      })?;
      Ok(NativeResponse {
        status: u32::from(response.status),
        headers_json,
        body_json,
      })
    })
    .build(&env)
  }

  #[napi]
  pub fn stream(
    &self,
    env: Env,
    endpoint: String,
    body_json: String,
    options_json: Option<String>,
    cancellation: &NativeCancellation,
  ) -> Result<AsyncBlock<NativeByteStream>> {
    let endpoint = parse_endpoint(&endpoint)?;
    let mut body: serde_json::Value = parse_json(&body_json, "request body")?;
    let object = body
      .as_object_mut()
      .ok_or_else(|| native_error(REQUEST_ERROR, "request body must be a JSON object"))?;
    object.insert("stream".into(), serde_json::Value::Bool(true));
    let options = parse_options(options_json.as_deref())?;
    let cancellation = cancellation.inner.clone();
    let operation = self.state.register(cancellation.clone())?;
    let client = self.state.client.clone();
    AsyncBlockBuilder::new(async move {
      let response = tokio::select! {
        biased;
        reason = cancellation.cancelled() => return Err(cancellation_error(reason)),
        response = client.execute(endpoint, body, options) => response.map_err(sdk_error)?,
      };
      let headers_json = serde_json::to_string(&response.headers).map_err(|error| {
        native_error(
          SERIALIZATION_ERROR,
          format!("failed to serialize response headers: {error}"),
        )
      })?;
      let stream = match response.body {
        ResponseBody::Buffered(_) => {
          return Err(native_error(
            REQUEST_ERROR,
            "provider returned a buffered response for a streaming request",
          ));
        }
        ResponseBody::Stream(stream) => stream,
      };
      cancellation.error_if_cancelled()?;
      Ok(NativeByteStream::new(
        response.status,
        headers_json,
        stream,
        operation,
        cancellation,
      ))
    })
    .build(&env)
  }

  #[napi]
  pub fn send_generate(
    &self,
    env: Env,
    request_json: String,
    cancellation: &NativeCancellation,
  ) -> Result<AsyncBlock<String>> {
    let request = parse_generate_request(&request_json)?;
    let cancellation = cancellation.inner.clone();
    let operation = self.state.register(cancellation.clone())?;
    let client = self.state.client.clone();
    AsyncBlockBuilder::new(async move {
      let _operation = operation;
      let response = tokio::select! {
        biased;
        reason = cancellation.cancelled() => return Err(cancellation_error(reason)),
        response = client.send(&request) => response.map_err(sdk_error)?,
      };
      serialize_generate_response(&response).map_err(|error| {
        native_error(
          SERIALIZATION_ERROR,
          format!("failed to serialize generation response: {error}"),
        )
      })
    })
    .build(&env)
  }

  #[napi]
  pub fn generate_stream(
    &self,
    env: Env,
    request_json: String,
    cancellation: &NativeCancellation,
  ) -> Result<AsyncBlock<NativeGenerateStream>> {
    let request = parse_generate_request(&request_json)?;
    let cancellation = cancellation.inner.clone();
    let operation = self.state.register(cancellation.clone())?;
    let client = self.state.client.clone();
    AsyncBlockBuilder::new(async move {
      let stream = tokio::select! {
        biased;
        reason = cancellation.cancelled() => return Err(cancellation_error(reason)),
        stream = client.stream(&request) => stream.map_err(sdk_error)?,
      };
      cancellation.error_if_cancelled()?;
      Ok(NativeGenerateStream::new(stream, operation, cancellation))
    })
    .build(&env)
  }

  #[napi]
  pub fn text_stream(
    &self,
    env: Env,
    request_json: String,
    cancellation: &NativeCancellation,
  ) -> Result<AsyncBlock<NativeTextStream>> {
    let request = parse_generate_request(&request_json)?;
    let cancellation = cancellation.inner.clone();
    let operation = self.state.register(cancellation.clone())?;
    let client = self.state.client.clone();
    AsyncBlockBuilder::new(async move {
      let stream = tokio::select! {
        biased;
        reason = cancellation.cancelled() => return Err(cancellation_error(reason)),
        stream = client.stream_text(&request) => stream.map_err(sdk_error)?,
      };
      cancellation.error_if_cancelled()?;
      Ok(NativeTextStream::new(stream, operation, cancellation))
    })
    .build(&env)
  }
}

#[napi]
pub fn create_client(env: Env, options_json: String) -> Result<AsyncBlock<NativeClient>> {
  let options: ClientOptions = parse_json(&options_json, "client options")?;
  AsyncBlockBuilder::new(async move {
    let client = napi::bindgen_prelude::spawn_blocking(move || {
      let mut builder = Client::builder();
      if let Some(config_path) = options.config_path {
        builder = builder.config_path(config_path);
      }
      if let Some(auth_path) = options.auth_path {
        builder = builder.auth_path(auth_path);
      }
      if let Some(profile) = options.profile {
        builder = builder.profile(profile);
      }
      builder.build()
    })
    .await
    .map_err(|error| native_error(INTERNAL_ERROR, format!("client creation task failed: {error}")))?
    .map_err(sdk_error)?;
    Ok(NativeClient {
      state: ClientState::new(client),
    })
  })
  .build(&env)
}

#[napi]
pub fn native_abi_version() -> u32 {
  1
}

fn parse_endpoint(endpoint: &str) -> Result<Endpoint> {
  match endpoint {
    "responses" => Ok(Endpoint::Responses),
    "chat_completions" => Ok(Endpoint::ChatCompletions),
    "messages" => Ok(Endpoint::Messages),
    _ => Err(native_error(REQUEST_ERROR, format!("unknown endpoint '{endpoint}'"))),
  }
}

fn parse_generate_request(request_json: &str) -> Result<GenerateRequest> {
  parse_json(request_json, "generation request")
}

fn parse_options(options_json: Option<&str>) -> Result<RequestOptions> {
  match options_json {
    Some(options_json) => parse_json(options_json, "request options"),
    None => Ok(RequestOptions::default()),
  }
}

fn parse_json<T>(json: &str, description: &str) -> Result<T>
where
  T: serde::de::DeserializeOwned,
{
  serde_json::from_str(json).map_err(|error| native_error(REQUEST_ERROR, format!("invalid {description}: {error}")))
}

#[derive(Serialize)]
struct SerializableGenerateResponse<'a, H> {
  http_status: u16,
  headers: &'a H,
  id: Option<&'a str>,
  model: Option<&'a str>,
  status: Option<&'a str>,
  finish_reason: Option<&'a str>,
  text: &'a str,
  reasoning: Option<&'a str>,
  tool_calls: &'a [ToolCall],
  usage: &'a Option<Usage>,
  raw: &'a serde_json::Value,
}

fn serialize_generate_response(response: &GenerateResponse) -> serde_json::Result<String> {
  serde_json::to_string(&SerializableGenerateResponse {
    http_status: response.http_status,
    headers: &response.headers,
    id: response.id.as_deref(),
    model: response.model.as_deref(),
    status: response.status.as_deref(),
    finish_reason: response.finish_reason.as_deref(),
    text: &response.text,
    reasoning: response.reasoning.as_deref(),
    tool_calls: &response.tool_calls,
    usage: &response.usage,
    raw: &response.raw,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::time::Duration;

  #[tokio::test]
  async fn closing_request_events_interrupts_pending_read() {
    let (_events, receiver) = tokio::sync::broadcast::channel::<Arc<Event>>(1);
    let receiver = Arc::new(tokio::sync::Mutex::new(Some(receiver)));
    let (close_tx, _) = watch::channel(false);
    let pending = tokio::spawn(next_request_event(receiver.clone(), close_tx.subscribe()));
    tokio::task::yield_now().await;

    tokio::time::timeout(
      Duration::from_millis(100),
      close_request_event_stream(receiver, close_tx),
    )
    .await
    .expect("closing an idle request event stream must not hang");
    let result = tokio::time::timeout(Duration::from_millis(100), pending)
      .await
      .expect("pending request event read must stop after close")
      .expect("request event task must not panic")
      .expect("closing a request event stream must not fail");

    assert!(result.is_none());
  }
}
