use futures_util::{Stream, StreamExt};
use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::{watch, Mutex};
use tokn_sdk::{
  ByteStream, Client, Endpoint, Error as SdkError, GenerateRequest, GenerateResponse, GenerateStream, RequestOptions,
  ResponseBody, TextStream, ToolCall, Usage,
};

pyo3::create_exception!(
  tokn._native,
  ToknError,
  PyRuntimeError,
  "Base exception for errors reported by the tokn SDK."
);
pyo3::create_exception!(
  tokn._native,
  ConfigurationError,
  ToknError,
  "Configuration or profile loading failed."
);
pyo3::create_exception!(
  tokn._native,
  AuthenticationError,
  ToknError,
  "Credential loading or authentication setup failed."
);
pyo3::create_exception!(
  tokn._native,
  RequestError,
  ToknError,
  "The generation request could not be executed."
);
pyo3::create_exception!(
  tokn._native,
  APIStatusError,
  ToknError,
  "The provider returned an unsuccessful HTTP status."
);
pyo3::create_exception!(tokn._native, StreamError, ToknError, "A generation stream failed.");
pyo3::create_exception!(
  tokn._native,
  SerializationError,
  ToknError,
  "The SDK could not serialize or deserialize provider data."
);

#[pyclass(name = "NativeClient")]
struct PyClient {
  inner: Arc<Client>,
}

#[pymethods]
impl PyClient {
  #[new]
  #[pyo3(signature = (config_path=None, auth_path=None, profile=None))]
  fn new(config_path: Option<String>, auth_path: Option<String>, profile: Option<String>) -> PyResult<Self> {
    let mut builder = Client::builder();
    if let Some(path) = config_path {
      builder = builder.config_path(path);
    }
    if let Some(path) = auth_path {
      builder = builder.auth_path(path);
    }
    if let Some(profile) = profile {
      builder = builder.profile(profile);
    }
    let inner = builder.build().map_err(sdk_error)?;
    Ok(Self { inner: Arc::new(inner) })
  }

  fn reload(&self) -> PyResult<()> {
    self.inner.reload().map_err(sdk_error)
  }

  fn config_path(&self) -> String {
    self.inner.config_path().to_string_lossy().into_owned()
  }

  fn auth_path(&self) -> String {
    self.inner.auth_path().to_string_lossy().into_owned()
  }

  #[pyo3(signature = (endpoint, body_json, options_json=None))]
  fn request<'py>(
    &self,
    py: Python<'py>,
    endpoint: &str,
    body_json: &str,
    options_json: Option<&str>,
  ) -> PyResult<Bound<'py, PyAny>> {
    let endpoint = parse_endpoint(endpoint)?;
    let body = serde_json::from_str(body_json).map_err(value_error)?;
    let options = parse_options(options_json)?;
    let client = self.inner.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      let response = client.execute(endpoint, body, options).await.map_err(sdk_error)?;
      let status = response.status;
      let headers = serde_json::to_string(&response.headers).map_err(serialization_error)?;
      let body = match response.body {
        ResponseBody::Buffered(body) => String::from_utf8(body.to_vec())
          .map_err(|error| serialization_error(format!("provider returned a non-UTF-8 JSON response: {error}")))?,
        ResponseBody::Stream(_) => {
          return Err(RequestError::new_err("provider returned a stream; use Client.stream()"));
        }
      };
      Ok((status, headers, body))
    })
  }

  #[pyo3(signature = (endpoint, body_json, options_json=None))]
  fn stream<'py>(
    &self,
    py: Python<'py>,
    endpoint: &str,
    body_json: &str,
    options_json: Option<&str>,
  ) -> PyResult<Bound<'py, PyAny>> {
    let endpoint = parse_endpoint(endpoint)?;
    let mut body: serde_json::Value = serde_json::from_str(body_json).map_err(value_error)?;
    let object = body
      .as_object_mut()
      .ok_or_else(|| PyValueError::new_err("request body must be a JSON object"))?;
    object.insert("stream".into(), serde_json::Value::Bool(true));
    let options = parse_options(options_json)?;
    let client = self.inner.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      let response = client.execute(endpoint, body, options).await.map_err(sdk_error)?;
      let status = response.status;
      let headers = serde_json::to_string(&response.headers).map_err(serialization_error)?;
      match response.body {
        ResponseBody::Buffered(_) => Err(RequestError::new_err(
          "provider returned a buffered response for a streaming request",
        )),
        ResponseBody::Stream(stream) => Ok(PyStream {
          status,
          headers_json: headers,
          stream: Arc::new(ClosableStream::new(stream)),
        }),
      }
    })
  }

  fn send_generate<'py>(&self, py: Python<'py>, request_json: &str) -> PyResult<Bound<'py, PyAny>> {
    let request = parse_generate_request(request_json)?;
    let client = self.inner.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      let response = client.send(&request).await.map_err(sdk_error)?;
      serialize_generate_response(&response).map_err(serialization_error)
    })
  }

  fn stream_generate<'py>(&self, py: Python<'py>, request_json: &str) -> PyResult<Bound<'py, PyAny>> {
    let request = parse_generate_request(request_json)?;
    let client = self.inner.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      let stream = client.stream(&request).await.map_err(sdk_error)?;
      Ok(NativeGenerateStream {
        stream: Arc::new(ClosableStream::new(stream)),
      })
    })
  }

  fn stream_generate_text<'py>(&self, py: Python<'py>, request_json: &str) -> PyResult<Bound<'py, PyAny>> {
    let request = parse_generate_request(request_json)?;
    let client = self.inner.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      let stream = client.stream_text(&request).await.map_err(sdk_error)?;
      Ok(NativeTextStream {
        stream: Arc::new(ClosableStream::new(stream)),
      })
    })
  }
}

#[pyclass(name = "NativeStream")]
struct PyStream {
  #[pyo3(get)]
  status: u16,
  #[pyo3(get)]
  headers_json: String,
  stream: Arc<ClosableStream<ByteStream>>,
}

#[pymethods]
impl PyStream {
  fn next_chunk<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let stream = self.stream.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      match stream.next().await {
        Some(Ok(chunk)) => {
          let bytes = Python::attach(|py| PyBytes::new(py, &chunk).unbind());
          Ok(bytes)
        }
        Some(Err(error)) => Err(StreamError::new_err(format!("stream read failed: {error}"))),
        None => Err(PyStopAsyncIteration::new_err(())),
      }
    })
  }

  fn aclose<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    close_stream(py, self.stream.clone())
  }
}

#[pyclass(name = "NativeGenerateStream")]
struct NativeGenerateStream {
  stream: Arc<ClosableStream<GenerateStream>>,
}

#[pymethods]
impl NativeGenerateStream {
  fn next_event<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let stream = self.stream.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      match stream.next().await {
        Some(Ok(event)) => match serde_json::to_string(&event) {
          Ok(event_json) => Ok(event_json),
          Err(error) => {
            stream.close().await;
            Err(serialization_error(error))
          }
        },
        Some(Err(error)) => Err(sdk_error(error)),
        None => Err(PyStopAsyncIteration::new_err(())),
      }
    })
  }

  fn aclose<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    close_stream(py, self.stream.clone())
  }
}

#[pyclass(name = "NativeTextStream")]
struct NativeTextStream {
  stream: Arc<ClosableStream<TextStream>>,
}

#[pymethods]
impl NativeTextStream {
  fn next_text<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let stream = self.stream.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      match stream.next().await {
        Some(Ok(text)) => Ok(text),
        Some(Err(error)) => Err(sdk_error(error)),
        None => Err(PyStopAsyncIteration::new_err(())),
      }
    })
  }

  fn aclose<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    close_stream(py, self.stream.clone())
  }
}

struct ClosableStream<S> {
  stream: Mutex<Option<S>>,
  next: Mutex<()>,
  close_tx: watch::Sender<bool>,
}

impl<S> ClosableStream<S> {
  fn new(stream: S) -> Self {
    let (close_tx, _) = watch::channel(false);
    Self {
      stream: Mutex::new(Some(stream)),
      next: Mutex::new(()),
      close_tx,
    }
  }

  fn is_closed(&self) -> bool {
    *self.close_tx.borrow()
  }

  async fn close(&self) {
    // The stream mutex is only held for short ownership transitions, never
    // while polling the provider, so close cannot wait on an idle upstream.
    let mut stream = self.stream.lock().await;
    self.close_tx.send_replace(true);
    *stream = None;
  }
}

impl<S, T, E> ClosableStream<S>
where
  S: Stream<Item = Result<T, E>> + Unpin,
{
  async fn next(&self) -> Option<Result<T, E>> {
    // Serialize concurrent Python __anext__ calls without making close wait
    // for the provider poll.
    let _next = self.next.lock().await;
    if self.is_closed() {
      return None;
    }

    let mut stream = {
      let mut stored = self.stream.lock().await;
      if self.is_closed() {
        *stored = None;
        return None;
      }
      let Some(stream) = stored.take() else {
        self.close_tx.send_replace(true);
        return None;
      };
      stream
    };

    let mut close_rx = self.close_tx.subscribe();
    let item = tokio::select! {
      biased;
      _ = wait_for_close(&mut close_rx) => return None,
      item = stream.next() => item,
    };

    if self.is_closed() {
      return None;
    }

    match item {
      Some(Ok(item)) => {
        // This mutex also defines the ordering with close(): either the item
        // is committed first, or close marks the stream closed first and the
        // item is suppressed.
        let mut stored = self.stream.lock().await;
        if self.is_closed() {
          return None;
        }
        *stored = Some(stream);
        Some(Ok(item))
      }
      Some(Err(error)) => {
        self.close().await;
        Some(Err(error))
      }
      None => {
        self.close().await;
        None
      }
    }
  }
}

async fn wait_for_close(close_rx: &mut watch::Receiver<bool>) {
  loop {
    let closed = *close_rx.borrow();
    if closed || close_rx.changed().await.is_err() {
      return;
    }
  }
}

fn close_stream<'py, S>(py: Python<'py>, stream: Arc<ClosableStream<S>>) -> PyResult<Bound<'py, PyAny>>
where
  S: Send + 'static,
{
  pyo3_async_runtimes::tokio::future_into_py(py, async move {
    stream.close().await;
    Ok(())
  })
}

fn parse_endpoint(endpoint: &str) -> PyResult<Endpoint> {
  match endpoint {
    "responses" => Ok(Endpoint::Responses),
    "chat_completions" | "chat-completions" | "chat" => Ok(Endpoint::ChatCompletions),
    "messages" => Ok(Endpoint::Messages),
    _ => Err(PyValueError::new_err(format!("unknown endpoint '{endpoint}'"))),
  }
}

fn parse_generate_request(request_json: &str) -> PyResult<GenerateRequest> {
  serde_json::from_str(request_json).map_err(value_error)
}

fn parse_options(options_json: Option<&str>) -> PyResult<RequestOptions> {
  match options_json {
    Some(options) => serde_json::from_str(options).map_err(value_error),
    None => Ok(RequestOptions::default()),
  }
}

fn value_error(error: impl std::fmt::Display) -> PyErr {
  PyValueError::new_err(error.to_string())
}

fn sdk_error(error: SdkError) -> PyErr {
  let message = error_chain(&error);
  match error {
    SdkError::LoadConfig { .. } | SdkError::BuildEngine { .. } | SdkError::UnknownProfile { .. } => {
      ConfigurationError::new_err(message)
    }
    SdkError::LoadCredentials { .. } => AuthenticationError::new_err(message),
    SdkError::InvalidGenerateRequest { .. }
    | SdkError::BuildGenerateRequest { .. }
    | SdkError::Pipeline { .. }
    | SdkError::UnexpectedStream
    | SdkError::UnexpectedBuffered => RequestError::new_err(message),
    SdkError::GenerateResponseStatus { status, body } => api_status_error(message, status, body),
    SdkError::GenerateStream { .. } | SdkError::DeserializeStreamEvent { .. } => StreamError::new_err(message),
    SdkError::SerializeRequest { .. } | SdkError::DeserializeResponse { .. } => SerializationError::new_err(message),
  }
}

fn error_chain(error: &dyn std::error::Error) -> String {
  let mut message = error.to_string();
  let mut source = error.source();
  while let Some(error) = source {
    message.push_str(": ");
    message.push_str(&error.to_string());
    source = error.source();
  }
  message
}

fn api_status_error(message: String, status: u16, body: String) -> PyErr {
  let error = APIStatusError::new_err(message);
  Python::attach(|py| {
    let value = error.value(py);
    let _ = value.setattr("status", status);
    let _ = value.setattr("body", body);
  });
  error
}

fn serialization_error(error: impl std::fmt::Display) -> PyErr {
  SerializationError::new_err(error.to_string())
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

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
  module.add_class::<PyClient>()?;
  module.add_class::<PyStream>()?;
  module.add_class::<NativeGenerateStream>()?;
  module.add_class::<NativeTextStream>()?;
  module.add("ToknError", module.py().get_type::<ToknError>())?;
  module.add("ConfigurationError", module.py().get_type::<ConfigurationError>())?;
  module.add("AuthenticationError", module.py().get_type::<AuthenticationError>())?;
  module.add("RequestError", module.py().get_type::<RequestError>())?;
  module.add("APIStatusError", module.py().get_type::<APIStatusError>())?;
  module.add("StreamError", module.py().get_type::<StreamError>())?;
  module.add("SerializationError", module.py().get_type::<SerializationError>())?;
  Ok(())
}
