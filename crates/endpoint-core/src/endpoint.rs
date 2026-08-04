use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Identifier for the LLM endpoint a payload belongs to.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endpoint {
  ChatCompletions,
  Responses,
  Messages,
}

impl Endpoint {
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::ChatCompletions => "chat_completions",
      Self::Responses => "responses",
      Self::Messages => "messages",
    }
  }
}

impl std::fmt::Display for Endpoint {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.write_str(self.as_str())
  }
}

impl FromStr for Endpoint {
  type Err = UnknownEndpoint;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "chat_completions" | "chat" | "chat-completions" => Ok(Self::ChatCompletions),
      "responses" => Ok(Self::Responses),
      "messages" => Ok(Self::Messages),
      other => Err(UnknownEndpoint(other.to_string())),
    }
  }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown endpoint: {0}")]
pub struct UnknownEndpoint(pub String);

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn canonical_strings_and_display_match() {
    for (endpoint, canonical) in [
      (Endpoint::ChatCompletions, "chat_completions"),
      (Endpoint::Responses, "responses"),
      (Endpoint::Messages, "messages"),
    ] {
      assert_eq!(endpoint.as_str(), canonical);
      assert_eq!(endpoint.to_string(), canonical);
    }
  }

  #[test]
  fn from_str_accepts_canonical_names_and_compatibility_aliases() {
    for alias in ["chat_completions", "chat", "chat-completions"] {
      assert_eq!(Endpoint::from_str(alias).unwrap(), Endpoint::ChatCompletions);
    }
    assert_eq!(Endpoint::from_str("responses").unwrap(), Endpoint::Responses);
    assert_eq!(Endpoint::from_str("messages").unwrap(), Endpoint::Messages);
  }

  #[test]
  fn from_str_reports_the_unknown_value() {
    let error = Endpoint::from_str("completions").unwrap_err();

    assert_eq!(error.0, "completions");
    assert_eq!(error.to_string(), "unknown endpoint: completions");
  }

  #[test]
  fn serde_round_trips_canonical_names() {
    for endpoint in [Endpoint::ChatCompletions, Endpoint::Responses, Endpoint::Messages] {
      let encoded = serde_json::to_string(&endpoint).unwrap();
      assert_eq!(encoded, format!("\"{}\"", endpoint.as_str()));
      assert_eq!(serde_json::from_str::<Endpoint>(&encoded).unwrap(), endpoint);
    }
  }
}
