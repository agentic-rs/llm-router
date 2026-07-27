use futures_util::StreamExt;
use pyo3::exceptions::{PyRuntimeError, PyStopAsyncIteration, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokn_sdk::{ByteStream, Client, Endpoint, RequestOptions, ResponseBody};

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
    let inner = builder.build().map_err(runtime_error)?;
    Ok(Self { inner: Arc::new(inner) })
  }

  fn reload(&self) -> PyResult<()> {
    self.inner.reload().map_err(runtime_error)
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
      let response = client.execute(endpoint, body, options).await.map_err(runtime_error)?;
      let status = response.status;
      let headers = serde_json::to_string(&response.headers).map_err(runtime_error)?;
      let body = match response.body {
        ResponseBody::Buffered(body) => String::from_utf8(body.to_vec())
          .map_err(|error| PyRuntimeError::new_err(format!("provider returned a non-UTF-8 JSON response: {error}")))?,
        ResponseBody::Stream(_) => {
          return Err(PyRuntimeError::new_err(
            "provider returned a stream; use Client.stream()",
          ));
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
      let response = client.execute(endpoint, body, options).await.map_err(runtime_error)?;
      let status = response.status;
      let headers = serde_json::to_string(&response.headers).map_err(runtime_error)?;
      match response.body {
        ResponseBody::Buffered(_) => Err(PyRuntimeError::new_err(
          "provider returned a buffered response for a streaming request",
        )),
        ResponseBody::Stream(stream) => Ok(PyStream {
          status,
          headers_json: headers,
          stream: Arc::new(Mutex::new(Some(stream))),
        }),
      }
    })
  }
}

#[pyclass(name = "NativeStream")]
struct PyStream {
  #[pyo3(get)]
  status: u16,
  #[pyo3(get)]
  headers_json: String,
  stream: Arc<Mutex<Option<ByteStream>>>,
}

#[pymethods]
impl PyStream {
  fn next_chunk<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
    let stream = self.stream.clone();
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
      let mut guard = stream.lock().await;
      let Some(stream) = guard.as_mut() else {
        return Err(PyStopAsyncIteration::new_err(()));
      };
      match stream.next().await {
        Some(Ok(chunk)) => {
          let bytes = Python::attach(|py| PyBytes::new(py, &chunk).unbind());
          Ok(bytes)
        }
        Some(Err(error)) => Err(PyRuntimeError::new_err(format!("stream read failed: {error}"))),
        None => {
          *guard = None;
          Err(PyStopAsyncIteration::new_err(()))
        }
      }
    })
  }
}

fn parse_endpoint(endpoint: &str) -> PyResult<Endpoint> {
  match endpoint {
    "responses" => Ok(Endpoint::Responses),
    "chat_completions" | "chat-completions" | "chat" => Ok(Endpoint::ChatCompletions),
    "messages" => Ok(Endpoint::Messages),
    _ => Err(PyValueError::new_err(format!("unknown endpoint '{endpoint}'"))),
  }
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

fn runtime_error(error: impl std::fmt::Display) -> PyErr {
  PyRuntimeError::new_err(error.to_string())
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
  module.add_class::<PyClient>()?;
  module.add_class::<PyStream>()?;
  Ok(())
}
