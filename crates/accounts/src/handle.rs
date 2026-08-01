use arc_swap::ArcSwap;
use std::sync::Arc;
use tokn_core::account::AccountConfig;
use tokn_core::provider::Provider;
use tracing::debug;

pub struct AccountHandle {
  pub config: ArcSwap<AccountConfig>,
  pub provider: Arc<dyn Provider>,
}

impl AccountHandle {
  /// Construct a credential-bearing provider binding for one account.
  pub fn new(config: Arc<AccountConfig>, provider: Arc<dyn Provider>) -> Self {
    Self {
      config: ArcSwap::from(config),
      provider,
    }
  }

  pub fn id(&self) -> String {
    self.config.load().id.clone()
  }

  /// Notify the underlying provider that an upstream 401 happened so it can
  /// drop any cached short-lived credential.
  pub fn invalidate_credentials(&self) {
    debug!(account = %self.id(), "invalidating credentials due to upstream 401");
    self.provider.on_unauthorized();
  }
}
