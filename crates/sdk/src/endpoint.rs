use crate::response::{BufferedResponse, StreamResponse};
use crate::{Client, RequestOptions, Result};
use tokn_endpoint_chat_completions::{ChatRequest, ChatResponse};
use tokn_endpoint_core::Endpoint;
use tokn_endpoint_messages::{MessagesRequest, MessagesResponse};
use tokn_endpoint_responses::{ResponsesRequest, ResponsesResponse};

macro_rules! endpoint_client {
  (
    $name:ident,
    $request:ty,
    $response:ty,
    $endpoint:expr
  ) => {
    pub struct $name<'client> {
      client: &'client Client,
    }

    impl<'client> $name<'client> {
      pub(crate) fn new(client: &'client Client) -> Self {
        Self { client }
      }

      pub async fn create(&self, request: &$request) -> Result<BufferedResponse<$response>> {
        self.create_with(request, RequestOptions::default()).await
      }

      pub async fn create_with(
        &self,
        request: &$request,
        options: RequestOptions,
      ) -> Result<BufferedResponse<$response>> {
        self
          .client
          .execute_typed($endpoint, request, false, options)
          .await?
          .into_json()
      }

      pub async fn stream(&self, request: &$request) -> Result<StreamResponse> {
        self.stream_with(request, RequestOptions::default()).await
      }

      pub async fn stream_with(&self, request: &$request, options: RequestOptions) -> Result<StreamResponse> {
        self
          .client
          .execute_typed($endpoint, request, true, options)
          .await?
          .into_stream()
      }
    }
  };
}

endpoint_client!(Responses, ResponsesRequest, ResponsesResponse, Endpoint::Responses);
endpoint_client!(ChatCompletions, ChatRequest, ChatResponse, Endpoint::ChatCompletions);
endpoint_client!(Messages, MessagesRequest, MessagesResponse, Endpoint::Messages);
