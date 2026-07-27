use tokn_sdk::chat_completions::ChatRequest;
use tokn_sdk::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let client = Client::from_default_config()?;
  let request: ChatRequest = serde_json::from_value(serde_json::json!({
    "model": "gpt-5",
    "messages": [{
      "role": "user",
      "content": "Explain why stable SDK boundaries matter."
    }]
  }))?;

  let response = client.chat_completions().create(&request).await?;
  println!("{}", serde_json::to_string_pretty(&response.data)?);
  Ok(())
}
