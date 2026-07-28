use tokn_sdk::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let client = Client::from_default_config()?;
  let response = client
    .generate("gpt-5")
    .prompt("Explain why stable SDK boundaries matter.")
    .send()
    .await?;
  println!("{}", response.text);
  Ok(())
}
