use tokn_core::provider::Endpoint as ProviderEndpoint;
use tokn_endpoint_chat_completions::ChatRequest;
use tokn_endpoint_core::EndpointRequest;
use tokn_endpoint_messages::MessagesRequest;
use tokn_endpoint_responses::ResponsesRequest;

#[test]
fn endpoint_requests_share_the_core_provider_endpoint_identity() {
  let chat: ProviderEndpoint = ChatRequest::ENDPOINT;
  let messages: ProviderEndpoint = MessagesRequest::ENDPOINT;
  let responses: ProviderEndpoint = ResponsesRequest::ENDPOINT;

  assert_eq!(chat, ProviderEndpoint::ChatCompletions);
  assert_eq!(messages, ProviderEndpoint::Messages);
  assert_eq!(responses, ProviderEndpoint::Responses);
}
