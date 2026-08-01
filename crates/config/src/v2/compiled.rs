use tokn_policy::GatewayPlan;

/// A fully decoded and semantically compiled version 2 configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledConfig {
  gateway: GatewayPlan,
  service: ServicePlan,
}

impl CompiledConfig {
  pub(super) fn new(gateway: GatewayPlan, service: ServicePlan) -> Self {
    Self { gateway, service }
  }

  pub fn gateway(&self) -> &GatewayPlan {
    &self.gateway
  }

  pub fn service(&self) -> &ServicePlan {
    &self.service
  }

  pub fn into_parts(self) -> (GatewayPlan, ServicePlan) {
    (self.gateway, self.service)
  }
}

/// Process-wide serving settings that are independent of the routing graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServicePlan {
  outbound: OutboundPlan,
  request_limits: RequestLimitsPlan,
}

impl ServicePlan {
  pub(super) fn new(outbound: OutboundPlan, request_limits: RequestLimitsPlan) -> Self {
    Self {
      outbound,
      request_limits,
    }
  }

  pub fn outbound(&self) -> &OutboundPlan {
    &self.outbound
  }

  pub const fn request_limits(&self) -> RequestLimitsPlan {
    self.request_limits
  }
}

/// Shared outbound proxy policy for control, managed, opaque, and tunnel clients.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundPlan {
  proxy_url: Option<String>,
  no_proxy: Box<[String]>,
  use_system_proxy: bool,
}

impl OutboundPlan {
  pub(super) fn new(proxy_url: Option<String>, no_proxy: Box<[String]>, use_system_proxy: bool) -> Self {
    Self {
      proxy_url,
      no_proxy,
      use_system_proxy,
    }
  }

  pub fn proxy_url(&self) -> Option<&str> {
    self.proxy_url.as_deref()
  }

  pub fn no_proxy(&self) -> &[String] {
    &self.no_proxy
  }

  pub const fn use_system_proxy(&self) -> bool {
    self.use_system_proxy
  }

  pub fn to_http_client_options(&self) -> tokn_core::util::http::HttpClientOptions {
    tokn_core::util::http::HttpClientOptions {
      url: self.proxy_url.clone(),
      no_proxy: self.no_proxy.to_vec(),
      system: self.use_system_proxy,
    }
  }
}

/// Independent bounds for bytes received on the wire and bytes produced by decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestLimitsPlan {
  max_wire_bytes: usize,
  max_decoded_bytes: usize,
}

impl RequestLimitsPlan {
  pub(super) const fn new(max_wire_bytes: usize, max_decoded_bytes: usize) -> Self {
    Self {
      max_wire_bytes,
      max_decoded_bytes,
    }
  }

  pub const fn max_wire_bytes(self) -> usize {
    self.max_wire_bytes
  }

  pub const fn max_decoded_bytes(self) -> usize {
    self.max_decoded_bytes
  }
}
