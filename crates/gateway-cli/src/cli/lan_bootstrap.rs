use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::sync::Arc;
use tokn_router::proxy::{ProxyCa, ProxyPlainHttpHandler, ProxyPlainHttpRequest, ProxyPlainHttpResponse};

const LAN_ROOT_PATH: &str = "/-/lan";
const BOOTSTRAP_JSON_PATH: &str = "/-/lan/bootstrap.json";
const CA_CERT_PATH: &str = "/-/lan/ca.crt";
const ENV_PATH: &str = "/-/lan/env";

#[derive(Clone, Debug)]
pub struct BootstrapState {
  ca_cert_pem: String,
  ca_fingerprint: String,
  api_port: Option<u16>,
  proxy_port: u16,
}

impl BootstrapState {
  pub fn proxy_only(ca: &ProxyCa, proxy_port: u16) -> Result<Self> {
    Self::from_ca(ca, None, proxy_port)
  }

  fn from_ca(ca: &ProxyCa, api_port: Option<u16>, proxy_port: u16) -> Result<Self> {
    let ca_cert_path = ca.cert_path();
    let ca_cert_pem =
      std::fs::read_to_string(&ca_cert_path).with_context(|| format!("read {}", ca_cert_path.display()))?;
    Ok(Self {
      ca_cert_pem,
      ca_fingerprint: ca.fingerprint_sha256(),
      api_port,
      proxy_port,
    })
  }
}

pub fn proxy_plain_http_handler(state: BootstrapState) -> ProxyPlainHttpHandler {
  Arc::new(move |request| proxy_plain_http_response(request, &state))
}

pub fn display_bootstrap_url(bind_host: &str, api_port: u16) -> String {
  let host = bind_host.trim();
  if matches!(host, "0.0.0.0" | "::" | "[::]") {
    return format!("http://<server-lan-ip>:{api_port}{BOOTSTRAP_JSON_PATH}");
  }
  format!("http://{}:{api_port}{BOOTSTRAP_JSON_PATH}", url_host(host))
}

#[derive(Serialize)]
struct BootstrapMetadata {
  #[serde(skip_serializing_if = "Option::is_none")]
  api_url: Option<String>,
  proxy_url: String,
  ca_cert_url: String,
  env_url: String,
  ca_sha256: String,
}

fn proxy_plain_http_response(request: ProxyPlainHttpRequest, state: &BootstrapState) -> Option<ProxyPlainHttpResponse> {
  if request.method != "GET" {
    return None;
  }
  let (path, query) = proxy_target_path_and_query(&request.target)?;
  let response = match path.as_str() {
    LAN_ROOT_PATH | BOOTSTRAP_JSON_PATH => {
      let urls = urls_from_proxy_host(
        request.host.as_deref(),
        state.api_port,
        state.proxy_port,
        state.proxy_port,
      );
      match urls.map(|urls| serde_json::to_string_pretty(&bootstrap_metadata(urls, &state.ca_fingerprint))) {
        Ok(Ok(body)) => ProxyPlainHttpResponse {
          status: "200 OK",
          content_type: "application/json; charset=utf-8",
          body,
        },
        Ok(Err(err)) => bootstrap_bad_request(err.into()),
        Err(err) => bootstrap_bad_request(err),
      }
    }
    CA_CERT_PATH => ProxyPlainHttpResponse {
      status: "200 OK",
      content_type: "application/x-pem-file",
      body: state.ca_cert_pem.clone(),
    },
    ENV_PATH => {
      let shell = shell_from_query(query.as_deref());
      match shell.and_then(|shell| {
        Ok((
          shell,
          urls_from_proxy_host(
            request.host.as_deref(),
            state.api_port,
            state.proxy_port,
            state.proxy_port,
          )?,
        ))
      }) {
        Ok((shell, urls)) => ProxyPlainHttpResponse {
          status: "200 OK",
          content_type: shell.content_type(),
          body: render_env_script(shell, &urls, &state.ca_fingerprint),
        },
        Err(err) => bootstrap_bad_request(err),
      }
    }
    _ => return None,
  };
  Some(response)
}

fn bootstrap_metadata(urls: BootstrapUrls, fingerprint: &str) -> BootstrapMetadata {
  let api_url = urls.api_base.map(|base| format!("{base}/v1"));
  BootstrapMetadata {
    api_url,
    proxy_url: urls.proxy_base,
    ca_cert_url: urls.ca_cert_url,
    env_url: format!("{}{}?shell=sh", urls.bootstrap_base, ENV_PATH),
    ca_sha256: fingerprint.to_string(),
  }
}

fn bootstrap_bad_request(err: anyhow::Error) -> ProxyPlainHttpResponse {
  ProxyPlainHttpResponse {
    status: "400 Bad Request",
    content_type: "text/plain; charset=utf-8",
    body: format!("{err}\n"),
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shell {
  Sh,
  Bash,
  Zsh,
  Fish,
  Pwsh,
}

impl Shell {
  fn parse(value: Option<&str>) -> Result<Self> {
    match value.unwrap_or("sh") {
      "sh" => Ok(Self::Sh),
      "bash" => Ok(Self::Bash),
      "zsh" => Ok(Self::Zsh),
      "fish" => Ok(Self::Fish),
      "pwsh" => Ok(Self::Pwsh),
      other => Err(anyhow!("unsupported shell '{other}'; expected sh|bash|zsh|fish|pwsh")),
    }
  }

  fn content_type(self) -> &'static str {
    match self {
      Self::Pwsh => "text/plain; charset=utf-8",
      _ => "text/x-shellscript; charset=utf-8",
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootstrapUrls {
  api_base: Option<String>,
  bootstrap_base: String,
  proxy_base: String,
  ca_cert_url: String,
  host_for_no_proxy: String,
  host_dir_name: String,
}

fn urls_from_proxy_host(
  raw: Option<&str>,
  api_port: Option<u16>,
  proxy_port: u16,
  bootstrap_port: u16,
) -> Result<BootstrapUrls> {
  let raw = raw.ok_or_else(|| anyhow!("missing Host header"))?;
  let host_port = explicit_port_from_host(raw)?;
  let proxy_port = host_port.unwrap_or(proxy_port);
  let bootstrap_port = host_port.unwrap_or(bootstrap_port);
  urls_from_host(raw, api_port, proxy_port, bootstrap_port)
}

fn urls_from_host(raw: &str, api_port: Option<u16>, proxy_port: u16, bootstrap_port: u16) -> Result<BootstrapUrls> {
  let raw = raw.trim();
  if raw.is_empty() || raw.contains('@') {
    return Err(anyhow!("invalid Host header"));
  }
  let authority: http::uri::Authority = raw.parse().context("invalid Host header authority")?;
  let host = authority.host();
  validate_host(host)?;
  let url_host = url_host(host);
  let bootstrap_base = format!("http://{url_host}:{bootstrap_port}");
  let api_base = api_port.map(|api_port| format!("http://{url_host}:{api_port}"));
  Ok(BootstrapUrls {
    ca_cert_url: format!("{bootstrap_base}{CA_CERT_PATH}"),
    api_base,
    bootstrap_base,
    proxy_base: format!("http://{url_host}:{proxy_port}"),
    host_for_no_proxy: no_proxy_host(host),
    host_dir_name: host_dir_name(host),
  })
}

fn explicit_port_from_host(raw: &str) -> Result<Option<u16>> {
  let raw = raw.trim();
  if raw.is_empty() || raw.contains('@') {
    return Err(anyhow!("invalid Host header"));
  }
  let authority: http::uri::Authority = raw.parse().context("invalid Host header authority")?;
  Ok(authority.port_u16())
}

fn proxy_target_path_and_query(target: &str) -> Option<(String, Option<String>)> {
  let value = target.trim();
  if value.is_empty() {
    return None;
  }
  let path_and_query = if value.starts_with("http://") || value.starts_with("https://") {
    let uri: http::Uri = value.parse().ok()?;
    uri.path_and_query()?.as_str().to_string()
  } else {
    value.to_string()
  };
  let (path, query) = path_and_query
    .split_once('?')
    .map(|(path, query)| (path.to_string(), query.to_string()))
    .unwrap_or((path_and_query, String::new()));
  Some((path, (!query.is_empty()).then_some(query)))
}

fn shell_from_query(query: Option<&str>) -> Result<Shell> {
  for pair in query.unwrap_or_default().split('&') {
    let Some((key, value)) = pair.split_once('=') else {
      continue;
    };
    if key == "shell" {
      return Shell::parse(Some(value));
    }
  }
  Shell::parse(None)
}

fn validate_host(host: &str) -> Result<()> {
  if host.is_empty() {
    return Err(anyhow!("Host header host cannot be empty"));
  }
  let valid = host
    .chars()
    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'));
  if !valid {
    return Err(anyhow!("Host header contains unsupported characters"));
  }
  Ok(())
}

fn url_host(host: &str) -> String {
  let host = host.trim_matches(['[', ']']);
  if host.contains(':') {
    format!("[{host}]")
  } else {
    host.to_string()
  }
}

fn no_proxy_host(host: &str) -> String {
  host.trim_matches(['[', ']']).to_string()
}

fn host_dir_name(host: &str) -> String {
  let host = no_proxy_host(host);
  host
    .chars()
    .map(|c| {
      if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
        c
      } else {
        '_'
      }
    })
    .collect()
}

fn render_env_script(shell: Shell, urls: &BootstrapUrls, fingerprint: &str) -> String {
  match shell {
    Shell::Sh | Shell::Bash | Shell::Zsh => render_sh_env(urls, fingerprint),
    Shell::Fish => render_fish_env(urls, fingerprint),
    Shell::Pwsh => render_pwsh_env(urls, fingerprint),
  }
}

fn no_proxy_value(host: &str) -> String {
  format!("localhost,127.0.0.1,::1,{host}")
}

fn render_sh_env(urls: &BootstrapUrls, fingerprint: &str) -> String {
  let no_proxy = no_proxy_value(&urls.host_for_no_proxy);
  let api_export = urls
    .api_base
    .as_ref()
    .map(|api_base| format!("export OPENAI_BASE_URL={}\n", sh_quote(&format!("{api_base}/v1"))))
    .unwrap_or_default();
  let api_echo = urls
    .api_base
    .as_ref()
    .map(|_| {
      r#"echo "tokn-router API endpoint: $OPENAI_BASE_URL"
"#
    })
    .unwrap_or_default();
  let bootstrap_api_export = urls
    .api_base
    .as_ref()
    .map(|api_base| format!("export OPENAI_BASE_URL={}\n", sh_quote(&format!("{api_base}/v1"))))
    .unwrap_or_default();
  format!(
    r#"# Expected tokn-router CA fingerprint: {fingerprint}
TOKN_ROUTER_LAN_DIR="${{XDG_CONFIG_HOME:-$HOME/.config}}/tokn-router/lan/{host_dir}"
TOKN_ROUTER_CA_DIR="$TOKN_ROUTER_LAN_DIR/ca"
TOKN_ROUTER_CA_CERT="$TOKN_ROUTER_CA_DIR/ca.crt"
TOKN_ROUTER_CA_BUNDLE="$TOKN_ROUTER_CA_DIR/ca-bundle.crt"
TOKN_ROUTER_ENV="$TOKN_ROUTER_LAN_DIR/env.sh"
mkdir -p "$TOKN_ROUTER_CA_DIR"
TOKN_ROUTER_LAN_DIR="$(cd "$TOKN_ROUTER_LAN_DIR" && pwd -P)" || {{ echo "tokn-router: cannot resolve $TOKN_ROUTER_LAN_DIR" >&2; return 1 2>/dev/null || exit 1; }}
TOKN_ROUTER_CA_DIR="$TOKN_ROUTER_LAN_DIR/ca"
TOKN_ROUTER_CA_CERT="$TOKN_ROUTER_CA_DIR/ca.crt"
TOKN_ROUTER_CA_BUNDLE="$TOKN_ROUTER_CA_DIR/ca-bundle.crt"
TOKN_ROUTER_ENV="$TOKN_ROUTER_LAN_DIR/env.sh"
curl -fsSL {ca_url} -o "$TOKN_ROUTER_CA_CERT"
TOKN_ROUTER_CA_SHA256=""
if command -v sha256sum >/dev/null 2>&1; then
  TOKN_ROUTER_CA_SHA256="$(sha256sum "$TOKN_ROUTER_CA_CERT" | awk '{{print $1}}')"
elif command -v shasum >/dev/null 2>&1; then
  TOKN_ROUTER_CA_SHA256="$(shasum -a 256 "$TOKN_ROUTER_CA_CERT" | awk '{{print $1}}')"
elif command -v openssl >/dev/null 2>&1; then
  TOKN_ROUTER_CA_SHA256="$(openssl dgst -sha256 -r "$TOKN_ROUTER_CA_CERT" | awk '{{print $1}}')"
else
  echo "tokn-router: cannot verify CA fingerprint; install sha256sum, shasum, or openssl" >&2
  return 1 2>/dev/null || exit 1
fi
if [ "$TOKN_ROUTER_CA_SHA256" != {fingerprint_value} ]; then
  echo "tokn-router: CA fingerprint mismatch for $TOKN_ROUTER_CA_CERT" >&2
  echo "expected: {fingerprint}" >&2
  echo "actual:   $TOKN_ROUTER_CA_SHA256" >&2
  return 1 2>/dev/null || exit 1
fi
TOKN_ROUTER_SYSTEM_CA=""
for candidate in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/pki/tls/cacert.pem /etc/ssl/cert.pem; do
  if [ -f "$candidate" ]; then
    TOKN_ROUTER_SYSTEM_CA="$candidate"
    break
  fi
done
if [ -n "$TOKN_ROUTER_SYSTEM_CA" ]; then
  cat "$TOKN_ROUTER_SYSTEM_CA" "$TOKN_ROUTER_CA_CERT" > "$TOKN_ROUTER_CA_BUNDLE"
else
  cp "$TOKN_ROUTER_CA_CERT" "$TOKN_ROUTER_CA_BUNDLE"
fi
{api_export}
export HTTP_PROXY={proxy_url}
export HTTPS_PROXY={proxy_url}
export NO_PROXY={no_proxy}
export NODE_EXTRA_CA_CERTS="$TOKN_ROUTER_CA_CERT"
export SSL_CERT_FILE="$TOKN_ROUTER_CA_BUNDLE"
export REQUESTS_CA_BUNDLE="$TOKN_ROUTER_CA_BUNDLE"
export CURL_CA_BUNDLE="$TOKN_ROUTER_CA_BUNDLE"
export GIT_SSL_CAINFO="$TOKN_ROUTER_CA_BUNDLE"
tokn_router_sh_quote() {{
  printf "'"
  printf "%s" "$1" | sed "s/'/'\\\\''/g"
  printf "'"
}}
{{
  printf 'TOKN_ROUTER_LAN_DIR=%s\n' "$(tokn_router_sh_quote "$TOKN_ROUTER_LAN_DIR")"
  printf 'TOKN_ROUTER_CA_DIR="$TOKN_ROUTER_LAN_DIR/ca"\n'
  printf 'TOKN_ROUTER_CA_CERT="$TOKN_ROUTER_CA_DIR/ca.crt"\n'
  printf 'TOKN_ROUTER_CA_BUNDLE="$TOKN_ROUTER_CA_DIR/ca-bundle.crt"\n'
  printf 'TOKN_ROUTER_CA_SHA256=%s\n' {fingerprint_value}
{bootstrap_api_export_printf}  printf 'export HTTP_PROXY=%s\n' {proxy_url}
  printf 'export HTTPS_PROXY=%s\n' {proxy_url}
  printf 'export NO_PROXY=%s\n' {no_proxy}
  printf 'export NODE_EXTRA_CA_CERTS="$TOKN_ROUTER_CA_CERT"\n'
  printf 'export SSL_CERT_FILE="$TOKN_ROUTER_CA_BUNDLE"\n'
  printf 'export REQUESTS_CA_BUNDLE="$TOKN_ROUTER_CA_BUNDLE"\n'
  printf 'export CURL_CA_BUNDLE="$TOKN_ROUTER_CA_BUNDLE"\n'
  printf 'export GIT_SSL_CAINFO="$TOKN_ROUTER_CA_BUNDLE"\n'
}} > "$TOKN_ROUTER_ENV"
echo "tokn-router CA sha256: $TOKN_ROUTER_CA_SHA256"
{api_echo}echo "tokn-router proxy endpoint: $HTTPS_PROXY"
echo "tokn-router env file: $TOKN_ROUTER_ENV"
echo "tokn-router next shell: . $TOKN_ROUTER_ENV"
"#,
    host_dir = urls.host_dir_name,
    ca_url = sh_quote(&urls.ca_cert_url),
    fingerprint_value = sh_quote(fingerprint),
    api_export = api_export,
    api_echo = api_echo,
    bootstrap_api_export_printf = bootstrap_api_export
      .lines()
      .map(|line| format!("  printf '%s\\n' {}\n", sh_quote(line)))
      .collect::<String>(),
    proxy_url = sh_quote(&urls.proxy_base),
    no_proxy = sh_quote(&no_proxy),
  )
}

fn render_fish_env(urls: &BootstrapUrls, fingerprint: &str) -> String {
  let no_proxy = no_proxy_value(&urls.host_for_no_proxy);
  let api_export = urls
    .api_base
    .as_ref()
    .map(|api_base| format!("set -gx OPENAI_BASE_URL {}\n", sh_quote(&format!("{api_base}/v1"))))
    .unwrap_or_default();
  let api_echo = urls
    .api_base
    .as_ref()
    .map(|_| {
      r#"echo "tokn-router API endpoint: $OPENAI_BASE_URL"
"#
    })
    .unwrap_or_default();
  let bootstrap_api_export = urls
    .api_base
    .as_ref()
    .map(|api_base| format!("set -gx OPENAI_BASE_URL {}\n", sh_quote(&format!("{api_base}/v1"))))
    .unwrap_or_default();
  format!(
    r#"# Expected tokn-router CA fingerprint: {fingerprint}
set -q XDG_CONFIG_HOME; or set XDG_CONFIG_HOME "$HOME/.config"
set -gx TOKN_ROUTER_LAN_DIR "$XDG_CONFIG_HOME/tokn-router/lan/{host_dir}"
set -gx TOKN_ROUTER_CA_DIR "$TOKN_ROUTER_LAN_DIR/ca"
set -gx TOKN_ROUTER_CA_CERT "$TOKN_ROUTER_CA_DIR/ca.crt"
set -gx TOKN_ROUTER_CA_BUNDLE "$TOKN_ROUTER_CA_DIR/ca-bundle.crt"
set -gx TOKN_ROUTER_ENV "$TOKN_ROUTER_LAN_DIR/env.fish"
mkdir -p "$TOKN_ROUTER_CA_DIR"
set -gx TOKN_ROUTER_LAN_DIR (cd "$TOKN_ROUTER_LAN_DIR"; and pwd -P)
if test -z "$TOKN_ROUTER_LAN_DIR"
  echo "tokn-router: cannot resolve LAN directory" >&2
  return 1
end
set -gx TOKN_ROUTER_CA_DIR "$TOKN_ROUTER_LAN_DIR/ca"
set -gx TOKN_ROUTER_CA_CERT "$TOKN_ROUTER_CA_DIR/ca.crt"
set -gx TOKN_ROUTER_CA_BUNDLE "$TOKN_ROUTER_CA_DIR/ca-bundle.crt"
set -gx TOKN_ROUTER_ENV "$TOKN_ROUTER_LAN_DIR/env.fish"
curl -fsSL {ca_url} -o "$TOKN_ROUTER_CA_CERT"
set -l ca_sha256
if command -q sha256sum
  set ca_sha256 (sha256sum "$TOKN_ROUTER_CA_CERT" | awk '{{print $1}}')
else if command -q shasum
  set ca_sha256 (shasum -a 256 "$TOKN_ROUTER_CA_CERT" | awk '{{print $1}}')
else if command -q openssl
  set ca_sha256 (openssl dgst -sha256 -r "$TOKN_ROUTER_CA_CERT" | awk '{{print $1}}')
else
  echo "tokn-router: cannot verify CA fingerprint; install sha256sum, shasum, or openssl" >&2
  return 1
end
if test "$ca_sha256" != {fingerprint_value}
  echo "tokn-router: CA fingerprint mismatch for $TOKN_ROUTER_CA_CERT" >&2
  echo "expected: {fingerprint}" >&2
  echo "actual:   $ca_sha256" >&2
  return 1
end
set -l system_ca
for candidate in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/pki/tls/cacert.pem /etc/ssl/cert.pem
  if test -f "$candidate"
    set system_ca "$candidate"
    break
  end
end
if test -n "$system_ca"
  cat "$system_ca" "$TOKN_ROUTER_CA_CERT" > "$TOKN_ROUTER_CA_BUNDLE"
else
  cp "$TOKN_ROUTER_CA_CERT" "$TOKN_ROUTER_CA_BUNDLE"
end
{api_export}
set -gx HTTP_PROXY {proxy_url}
set -gx HTTPS_PROXY {proxy_url}
set -gx NO_PROXY {no_proxy}
set -gx NODE_EXTRA_CA_CERTS "$TOKN_ROUTER_CA_CERT"
set -gx SSL_CERT_FILE "$TOKN_ROUTER_CA_BUNDLE"
set -gx REQUESTS_CA_BUNDLE "$TOKN_ROUTER_CA_BUNDLE"
set -gx CURL_CA_BUNDLE "$TOKN_ROUTER_CA_BUNDLE"
set -gx GIT_SSL_CAINFO "$TOKN_ROUTER_CA_BUNDLE"
begin
  printf 'set -gx TOKN_ROUTER_LAN_DIR %s\n' (string escape -- "$TOKN_ROUTER_LAN_DIR")
  printf 'set -gx TOKN_ROUTER_CA_DIR "$TOKN_ROUTER_LAN_DIR/ca"\n'
  printf 'set -gx TOKN_ROUTER_CA_CERT "$TOKN_ROUTER_CA_DIR/ca.crt"\n'
  printf 'set -gx TOKN_ROUTER_CA_BUNDLE "$TOKN_ROUTER_CA_DIR/ca-bundle.crt"\n'
  printf 'set -gx TOKN_ROUTER_CA_SHA256 %s\n' {fingerprint_value}
{bootstrap_api_export_printf}  printf 'set -gx HTTP_PROXY %s\n' {proxy_url}
  printf 'set -gx HTTPS_PROXY %s\n' {proxy_url}
  printf 'set -gx NO_PROXY %s\n' {no_proxy}
  printf 'set -gx NODE_EXTRA_CA_CERTS %s\n' (string escape -- "$TOKN_ROUTER_CA_CERT")
  printf 'set -gx SSL_CERT_FILE %s\n' (string escape -- "$TOKN_ROUTER_CA_BUNDLE")
  printf 'set -gx REQUESTS_CA_BUNDLE %s\n' (string escape -- "$TOKN_ROUTER_CA_BUNDLE")
  printf 'set -gx CURL_CA_BUNDLE %s\n' (string escape -- "$TOKN_ROUTER_CA_BUNDLE")
  printf 'set -gx GIT_SSL_CAINFO %s\n' (string escape -- "$TOKN_ROUTER_CA_BUNDLE")
end > "$TOKN_ROUTER_ENV"
echo "tokn-router CA sha256: $ca_sha256"
{api_echo}echo "tokn-router proxy endpoint: $HTTPS_PROXY"
echo "tokn-router env file: $TOKN_ROUTER_ENV"
echo "tokn-router next shell: source $TOKN_ROUTER_ENV"
"#,
    host_dir = urls.host_dir_name,
    ca_url = sh_quote(&urls.ca_cert_url),
    fingerprint_value = sh_quote(fingerprint),
    api_export = api_export,
    api_echo = api_echo,
    bootstrap_api_export_printf = bootstrap_api_export
      .lines()
      .map(|line| format!("  printf '%s\\n' {}\n", sh_quote(line)))
      .collect::<String>(),
    proxy_url = sh_quote(&urls.proxy_base),
    no_proxy = sh_quote(&no_proxy),
  )
}

fn render_pwsh_env(urls: &BootstrapUrls, fingerprint: &str) -> String {
  let no_proxy = no_proxy_value(&urls.host_for_no_proxy);
  let api_export = urls
    .api_base
    .as_ref()
    .map(|api_base| format!("$Env:OPENAI_BASE_URL = {}\n", pwsh_quote(&format!("{api_base}/v1"))))
    .unwrap_or_default();
  let api_echo = urls
    .api_base
    .as_ref()
    .map(|_| {
      r#"Write-Host "tokn-router API endpoint: $Env:OPENAI_BASE_URL"
"#
    })
    .unwrap_or_default();
  let bootstrap_api_export = urls
    .api_base
    .as_ref()
    .map(|api_base| format!("$Env:OPENAI_BASE_URL = {}\n", pwsh_quote(&format!("{api_base}/v1"))))
    .unwrap_or_default();
  format!(
    r#"# Expected tokn-router CA fingerprint: {fingerprint}
$configHome = if ($Env:XDG_CONFIG_HOME) {{ $Env:XDG_CONFIG_HOME }} else {{ Join-Path $HOME ".config" }}
$lanDir = Join-Path $configHome {lan_path}
$caDir = Join-Path $lanDir "ca"
$caCert = Join-Path $caDir "ca.crt"
$caBundle = Join-Path $caDir "ca-bundle.crt"
$envFile = Join-Path $lanDir "env.ps1"
New-Item -ItemType Directory -Force -Path $caDir | Out-Null
$lanDir = (Resolve-Path -LiteralPath $lanDir).Path
$caDir = Join-Path $lanDir "ca"
$caCert = Join-Path $caDir "ca.crt"
$caBundle = Join-Path $caDir "ca-bundle.crt"
$envFile = Join-Path $lanDir "env.ps1"
Invoke-WebRequest -UseBasicParsing -Uri {ca_url} -OutFile $caCert
$caSha256 = (Get-FileHash -Algorithm SHA256 -Path $caCert).Hash.ToLowerInvariant()
if ($caSha256 -ne {fingerprint_value}) {{
  Write-Error "tokn-router: CA fingerprint mismatch for $caCert`nexpected: {fingerprint}`nactual:   $caSha256"
  exit 1
}}
$systemCa = @("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cacert.pem", "/etc/ssl/cert.pem") | Where-Object {{ Test-Path $_ }} | Select-Object -First 1
if ($systemCa) {{
  Get-Content $systemCa, $caCert | Set-Content $caBundle
}} else {{
  Copy-Item $caCert $caBundle
}}
{api_export}
$Env:TOKN_ROUTER_LAN_DIR = $lanDir
$Env:TOKN_ROUTER_CA_DIR = $caDir
$Env:TOKN_ROUTER_CA_CERT = $caCert
$Env:TOKN_ROUTER_CA_BUNDLE = $caBundle
$Env:TOKN_ROUTER_CA_SHA256 = {fingerprint_value}
$Env:HTTP_PROXY = {proxy_url}
$Env:HTTPS_PROXY = {proxy_url}
$Env:NO_PROXY = {no_proxy}
$Env:NODE_EXTRA_CA_CERTS = $caCert
$Env:SSL_CERT_FILE = $caBundle
$Env:REQUESTS_CA_BUNDLE = $caBundle
$Env:CURL_CA_BUNDLE = $caBundle
$Env:GIT_SSL_CAINFO = $caBundle
function Quote-ToknPowerShellValue([string]$Value) {{ "'" + $Value.Replace("'", "''") + "'" }}
$envLines = @(
  '$Env:TOKN_ROUTER_LAN_DIR = ' + (Quote-ToknPowerShellValue $lanDir),
  '$Env:TOKN_ROUTER_CA_DIR = Join-Path $Env:TOKN_ROUTER_LAN_DIR "ca"',
  '$Env:TOKN_ROUTER_CA_CERT = Join-Path $Env:TOKN_ROUTER_CA_DIR "ca.crt"',
  '$Env:TOKN_ROUTER_CA_BUNDLE = Join-Path $Env:TOKN_ROUTER_CA_DIR "ca-bundle.crt"',
  '$Env:TOKN_ROUTER_CA_SHA256 = ' + {fingerprint_value},
{bootstrap_api_export_array_entry}  '$Env:HTTP_PROXY = ' + {proxy_url},
  '$Env:HTTPS_PROXY = ' + {proxy_url},
  '$Env:NO_PROXY = ' + {no_proxy},
  '$Env:NODE_EXTRA_CA_CERTS = ' + (Quote-ToknPowerShellValue $caCert),
  '$Env:SSL_CERT_FILE = ' + (Quote-ToknPowerShellValue $caBundle),
  '$Env:REQUESTS_CA_BUNDLE = ' + (Quote-ToknPowerShellValue $caBundle),
  '$Env:CURL_CA_BUNDLE = ' + (Quote-ToknPowerShellValue $caBundle),
  '$Env:GIT_SSL_CAINFO = ' + (Quote-ToknPowerShellValue $caBundle)
)
$envLines | Set-Content -Path $envFile
Write-Host "tokn-router CA sha256: $caSha256"
{api_echo}Write-Host "tokn-router proxy endpoint: $Env:HTTPS_PROXY"
Write-Host "tokn-router env file: $envFile"
Write-Host "tokn-router next shell: . $envFile"
"#,
    lan_path = pwsh_quote(&format!("tokn-router/lan/{}", urls.host_dir_name)),
    ca_url = pwsh_quote(&urls.ca_cert_url),
    fingerprint_value = pwsh_quote(fingerprint),
    api_export = api_export,
    api_echo = api_echo,
    bootstrap_api_export_array_entry = bootstrap_api_export
      .lines()
      .map(|line| format!("  {},\n", pwsh_quote(line)))
      .collect::<String>(),
    proxy_url = pwsh_quote(&urls.proxy_base),
    no_proxy = pwsh_quote(&no_proxy),
  )
}

fn sh_quote(value: &str) -> String {
  format!("'{}'", value.replace('\'', "'\\''"))
}

fn pwsh_quote(value: &str) -> String {
  format!("'{}'", value.replace('\'', "''"))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn test_state() -> BootstrapState {
    BootstrapState {
      ca_cert_pem: "-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n".into(),
      ca_fingerprint: "abc123".into(),
      api_port: Some(4141),
      proxy_port: 4142,
    }
  }

  #[test]
  fn concrete_host_produces_api_and_proxy_urls() {
    let urls = urls_from_host("192.168.1.10:4141", Some(4141), 4142, 4141).unwrap();
    assert_eq!(urls.api_base.as_deref(), Some("http://192.168.1.10:4141"));
    assert_eq!(urls.bootstrap_base, "http://192.168.1.10:4141");
    assert_eq!(urls.proxy_base, "http://192.168.1.10:4142");
    assert_eq!(urls.ca_cert_url, "http://192.168.1.10:4141/-/lan/ca.crt");
  }

  #[test]
  fn wildcard_display_uses_lan_ip_template() {
    assert_eq!(
      display_bootstrap_url("0.0.0.0", 4141),
      "http://<server-lan-ip>:4141/-/lan/bootstrap.json"
    );
    assert_eq!(
      display_bootstrap_url("[::]", 4141),
      "http://<server-lan-ip>:4141/-/lan/bootstrap.json"
    );
    assert_eq!(
      display_bootstrap_url("lan-router.local", 4141),
      "http://lan-router.local:4141/-/lan/bootstrap.json"
    );
  }

  #[test]
  fn request_host_drives_urls_even_for_wildcard_bind() {
    let urls = urls_from_host("lan-router.local:4141", Some(4141), 4142, 4141).unwrap();
    assert_eq!(urls.api_base.as_deref(), Some("http://lan-router.local:4141"));
    assert_eq!(urls.proxy_base, "http://lan-router.local:4142");
  }

  #[test]
  fn ipv6_host_formats_urls_and_no_proxy_host() {
    let urls = urls_from_host("[fd00::10]:4141", Some(4141), 4142, 4141).unwrap();
    assert_eq!(urls.api_base.as_deref(), Some("http://[fd00::10]:4141"));
    assert_eq!(urls.proxy_base, "http://[fd00::10]:4142");
    assert_eq!(urls.host_for_no_proxy, "fd00::10");
    assert_eq!(urls.host_dir_name, "fd00__10");
  }

  #[test]
  fn rejects_shell_injection_host() {
    let err =
      urls_from_host("lan.local;touch /tmp/nope:4141", Some(4141), 4142, 4141).expect_err("host should be rejected");
    assert!(err.to_string().contains("invalid Host header"));
  }

  #[test]
  fn rejects_empty_and_userinfo_hosts() {
    assert!(urls_from_host("", Some(4141), 4142, 4141).is_err());
    assert!(urls_from_host("user@lan.local:4141", Some(4141), 4142, 4141).is_err());
  }

  #[test]
  fn shell_parsing_and_content_types_are_explicit() {
    assert_eq!(Shell::parse(None).unwrap(), Shell::Sh);
    assert_eq!(Shell::parse(Some("bash")).unwrap(), Shell::Bash);
    assert_eq!(Shell::parse(Some("zsh")).unwrap(), Shell::Zsh);
    assert_eq!(Shell::parse(Some("fish")).unwrap(), Shell::Fish);
    assert_eq!(Shell::parse(Some("pwsh")).unwrap(), Shell::Pwsh);
    assert!(Shell::parse(Some("cmd")).is_err());
    assert_eq!(Shell::Sh.content_type(), "text/x-shellscript; charset=utf-8");
    assert_eq!(Shell::Pwsh.content_type(), "text/plain; charset=utf-8");
  }

  #[test]
  fn env_includes_server_host_in_no_proxy() {
    let urls = urls_from_host("lan-router.local:4141", Some(4141), 4142, 4141).unwrap();
    let script = render_env_script(Shell::Sh, &urls, "abc123");
    assert!(script.contains("TOKN_ROUTER_CA_SHA256"));
    assert!(script.contains("CA fingerprint mismatch"));
    assert!(script.contains("NO_PROXY='localhost,127.0.0.1,::1,lan-router.local'"));
    assert!(
      script.contains("TOKN_ROUTER_LAN_DIR=\"${XDG_CONFIG_HOME:-$HOME/.config}/tokn-router/lan/lan-router.local\"")
    );
    assert!(script.contains("TOKN_ROUTER_LAN_DIR=\"$(cd \"$TOKN_ROUTER_LAN_DIR\" && pwd -P)\""));
    assert!(script.contains("TOKN_ROUTER_CA_DIR=\"$TOKN_ROUTER_LAN_DIR/ca\""));
    assert!(script.contains("TOKN_ROUTER_ENV=\"$TOKN_ROUTER_LAN_DIR/env.sh\""));
    assert!(script.contains("printf 'TOKN_ROUTER_LAN_DIR=%s\\n' \"$(tokn_router_sh_quote \"$TOKN_ROUTER_LAN_DIR\")\""));
    assert!(script.contains("printf 'TOKN_ROUTER_CA_DIR=\"$TOKN_ROUTER_LAN_DIR/ca\"\\n'"));
    assert!(script.contains("printf 'TOKN_ROUTER_CA_SHA256=%s\\n' 'abc123'"));
    assert!(script.contains("tokn-router CA sha256: $TOKN_ROUTER_CA_SHA256"));
    assert!(script.contains("tokn-router API endpoint: $OPENAI_BASE_URL"));
    assert!(script.contains("tokn-router proxy endpoint: $HTTPS_PROXY"));
    assert!(script.contains("tokn-router env file: $TOKN_ROUTER_ENV"));
    assert!(script.contains("tokn-router next shell: . $TOKN_ROUTER_ENV"));
    assert!(
      script.find("CA fingerprint mismatch").unwrap() < script.find("export NODE_EXTRA_CA_CERTS").unwrap(),
      "fingerprint verification must happen before trust exports"
    );
    assert!(
      script.find("export GIT_SSL_CAINFO").unwrap() < script.find("tokn-router CA sha256").unwrap(),
      "success output must happen after trust exports"
    );
  }

  #[test]
  fn env_renderers_quote_shell_values() {
    let urls = BootstrapUrls {
      api_base: Some("http://lan-router.local:4141".into()),
      bootstrap_base: "http://lan-router.local:4141".into(),
      proxy_base: "http://lan-router.local:4142".into(),
      ca_cert_url: "http://lan-router.local:4141/-/lan/ca.crt".into(),
      host_for_no_proxy: "lan-router.local".into(),
      host_dir_name: "lan-router.local".into(),
    };
    let fish = render_env_script(Shell::Fish, &urls, "abc123");
    assert!(fish.contains("set -l ca_sha256"));
    assert!(fish.contains("CA fingerprint mismatch"));
    assert!(fish.contains("set -gx OPENAI_BASE_URL 'http://lan-router.local:4141/v1'"));
    assert!(fish.contains("set -gx HTTPS_PROXY 'http://lan-router.local:4142'"));
    assert!(fish.contains("set -gx TOKN_ROUTER_LAN_DIR \"$XDG_CONFIG_HOME/tokn-router/lan/lan-router.local\""));
    assert!(fish.contains("set -gx TOKN_ROUTER_LAN_DIR (cd \"$TOKN_ROUTER_LAN_DIR\"; and pwd -P)"));
    assert!(fish.contains("set -gx TOKN_ROUTER_CA_DIR \"$TOKN_ROUTER_LAN_DIR/ca\""));
    assert!(fish.contains("set -gx TOKN_ROUTER_ENV \"$TOKN_ROUTER_LAN_DIR/env.fish\""));
    assert!(fish.contains("printf 'set -gx TOKN_ROUTER_LAN_DIR %s\\n' (string escape -- \"$TOKN_ROUTER_LAN_DIR\")"));
    assert!(fish.contains("printf 'set -gx TOKN_ROUTER_CA_DIR \"$TOKN_ROUTER_LAN_DIR/ca\"\\n'"));
    assert!(fish.contains("printf 'set -gx TOKN_ROUTER_CA_SHA256 %s\\n' 'abc123'"));
    assert!(fish.contains("tokn-router CA sha256: $ca_sha256"));
    assert!(fish.contains("tokn-router API endpoint: $OPENAI_BASE_URL"));
    assert!(fish.contains("tokn-router proxy endpoint: $HTTPS_PROXY"));
    assert!(fish.contains("tokn-router env file: $TOKN_ROUTER_ENV"));
    assert!(fish.contains("tokn-router next shell: source $TOKN_ROUTER_ENV"));
    assert!(
      fish.find("CA fingerprint mismatch").unwrap() < fish.find("set -gx NODE_EXTRA_CA_CERTS").unwrap(),
      "fingerprint verification must happen before fish trust exports"
    );
    assert!(
      fish.find("set -gx GIT_SSL_CAINFO").unwrap() < fish.find("tokn-router CA sha256").unwrap(),
      "fish success output must happen after trust exports"
    );

    let pwsh = render_env_script(Shell::Pwsh, &urls, "abc123");
    assert!(pwsh.contains("Get-FileHash -Algorithm SHA256"));
    assert!(pwsh.contains("CA fingerprint mismatch"));
    assert!(pwsh.contains("$Env:OPENAI_BASE_URL = 'http://lan-router.local:4141/v1'"));
    assert!(pwsh.contains("$Env:HTTPS_PROXY = 'http://lan-router.local:4142'"));
    assert!(pwsh.contains("$lanDir = Join-Path $configHome 'tokn-router/lan/lan-router.local'"));
    assert!(pwsh.contains("$lanDir = (Resolve-Path -LiteralPath $lanDir).Path"));
    assert!(pwsh.contains("$caDir = Join-Path $lanDir \"ca\""));
    assert!(pwsh.contains("$envFile = Join-Path $lanDir \"env.ps1\""));
    assert!(pwsh.contains("'$Env:TOKN_ROUTER_LAN_DIR = ' + (Quote-ToknPowerShellValue $lanDir)"));
    assert!(pwsh.contains("'$Env:TOKN_ROUTER_CA_DIR = Join-Path $Env:TOKN_ROUTER_LAN_DIR \"ca\"'"));
    assert!(pwsh.contains("'$Env:TOKN_ROUTER_CA_SHA256 = ' + 'abc123'"));
    assert!(pwsh.contains("tokn-router CA sha256: $caSha256"));
    assert!(pwsh.contains("tokn-router API endpoint: $Env:OPENAI_BASE_URL"));
    assert!(pwsh.contains("tokn-router proxy endpoint: $Env:HTTPS_PROXY"));
    assert!(pwsh.contains("tokn-router env file: $envFile"));
    assert!(pwsh.contains("tokn-router next shell: . $envFile"));
    assert!(
      pwsh.find("CA fingerprint mismatch").unwrap() < pwsh.find("$Env:NODE_EXTRA_CA_CERTS").unwrap(),
      "fingerprint verification must happen before PowerShell trust exports"
    );
    assert!(
      pwsh.find("$Env:GIT_SSL_CAINFO").unwrap() < pwsh.find("tokn-router CA sha256").unwrap(),
      "PowerShell success output must happen after trust exports"
    );
  }

  #[test]
  fn quote_helpers_escape_single_quotes() {
    assert_eq!(sh_quote("a'b"), "'a'\\''b'");
    assert_eq!(pwsh_quote("a'b"), "'a''b'");
  }

  #[test]
  fn proxy_handler_serves_bootstrap_json_from_proxy_host() {
    let handler = proxy_plain_http_handler(test_state());
    let response = handler(ProxyPlainHttpRequest {
      method: "GET".into(),
      target: BOOTSTRAP_JSON_PATH.into(),
      host: Some("lan-router.local:4142".into()),
    })
    .unwrap();

    assert_eq!(response.status, "200 OK");
    assert_eq!(response.content_type, "application/json; charset=utf-8");
    let json: serde_json::Value = serde_json::from_str(&response.body).unwrap();
    assert_eq!(json["api_url"], "http://lan-router.local:4141/v1");
    assert_eq!(json["proxy_url"], "http://lan-router.local:4142");
    assert_eq!(json["ca_cert_url"], "http://lan-router.local:4142/-/lan/ca.crt");
    assert_eq!(json["env_url"], "http://lan-router.local:4142/-/lan/env?shell=sh");
    assert_eq!(json["ca_sha256"], "abc123");
  }

  #[test]
  fn proxy_handler_uses_host_port_for_proxy_bootstrap_urls() {
    let handler = proxy_plain_http_handler(test_state());
    let response = handler(ProxyPlainHttpRequest {
      method: "GET".into(),
      target: "/-/lan/env?shell=sh".into(),
      host: Some("127.0.0.1:5152".into()),
    })
    .unwrap();

    assert_eq!(response.status, "200 OK");
    assert!(response
      .body
      .contains("export OPENAI_BASE_URL='http://127.0.0.1:4141/v1'"));
    assert!(response.body.contains("export HTTP_PROXY='http://127.0.0.1:5152'"));
    assert!(response.body.contains("export HTTPS_PROXY='http://127.0.0.1:5152'"));
    assert!(response
      .body
      .contains("curl -fsSL 'http://127.0.0.1:5152/-/lan/ca.crt'"));
  }

  #[test]
  fn proxy_only_handler_omits_api_url_and_openai_base_url() {
    let mut state = test_state();
    state.api_port = None;
    let handler = proxy_plain_http_handler(state);
    let metadata = handler(ProxyPlainHttpRequest {
      method: "GET".into(),
      target: LAN_ROOT_PATH.into(),
      host: Some("lan-router.local:4142".into()),
    })
    .unwrap();
    let json: serde_json::Value = serde_json::from_str(&metadata.body).unwrap();
    assert!(json.get("api_url").is_none());
    assert_eq!(json["proxy_url"], "http://lan-router.local:4142");

    let env = handler(ProxyPlainHttpRequest {
      method: "GET".into(),
      target: "/-/lan/env?shell=sh".into(),
      host: Some("lan-router.local:4142".into()),
    })
    .unwrap();
    assert!(env.body.contains("export HTTPS_PROXY='http://lan-router.local:4142'"));
    assert!(env.body.contains("tokn-router CA sha256: $TOKN_ROUTER_CA_SHA256"));
    assert!(env.body.contains("tokn-router proxy endpoint: $HTTPS_PROXY"));
    assert!(!env.body.contains("OPENAI_BASE_URL"));
  }

  #[test]
  fn proxy_handler_rejects_malformed_host_without_shell_injection() {
    let handler = proxy_plain_http_handler(test_state());
    let response = handler(ProxyPlainHttpRequest {
      method: "GET".into(),
      target: "/-/lan/env?shell=sh".into(),
      host: Some("lan.local;touch /tmp/nope:4142".into()),
    })
    .unwrap();

    assert_eq!(response.status, "400 Bad Request");
    assert!(response.body.contains("invalid Host header"));
  }

  #[test]
  fn bootstrap_state_loads_public_ca_from_generated_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca = tokn_router::proxy::load_or_generate_ca(dir.path(), false).unwrap();
    let state = BootstrapState::proxy_only(&ca, 4142).unwrap();
    assert!(state.ca_cert_pem.contains("BEGIN CERTIFICATE"));
    assert_eq!(state.ca_fingerprint, ca.fingerprint_sha256());
  }
}
