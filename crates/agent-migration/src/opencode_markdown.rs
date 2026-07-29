use crate::adapter::ProviderRoute;
use crate::adapters::opencode::{generated_provider_id, projected_model_reference};
use crate::projection::{AgentConfigProjection, ModelReferenceRule, ProviderPublication};
use anyhow::{bail, Context, Result};
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use tokn_config::{AgentAccountSource, RouteMode};

const CONFIG_FILENAMES: [&str; 3] = ["config.json", "opencode.json", "opencode.jsonc"];
const MARKDOWN_COLLECTION_DIRS: [&str; 6] = ["agent", "agents", "command", "commands", "mode", "modes"];

pub(crate) fn opencode_config_root(home: &Path) -> PathBuf {
  scoped_xdg_home(home, "XDG_CONFIG_HOME")
    .unwrap_or_else(|| home.join(".config"))
    .join("opencode")
}

pub(crate) fn opencode_data_root(home: &Path) -> PathBuf {
  scoped_xdg_home(home, "XDG_DATA_HOME")
    .unwrap_or_else(|| home.join(".local/share"))
    .join("opencode")
}

/// XDG variables describe the current process user. Combining them with an
/// alternate agent home could make a caller inspect or rewrite the current
/// user's OpenCode installation instead of the requested home.
fn scoped_xdg_home(home: &Path, name: &str) -> Option<PathBuf> {
  let current_home = directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf());
  xdg_home_for_agent_home(home, current_home.as_deref(), absolute_xdg_home(name))
}

fn xdg_home_for_agent_home(home: &Path, current_home: Option<&Path>, xdg_home: Option<PathBuf>) -> Option<PathBuf> {
  current_home
    .filter(|current_home| same_path(home, current_home))
    .and(xdg_home)
}

fn absolute_xdg_home(name: &str) -> Option<PathBuf> {
  std::env::var_os(name)
    .map(PathBuf::from)
    .filter(|path| path.is_absolute())
}

#[derive(Debug, Clone)]
pub(crate) struct OpenCodePreflight {
  home: PathBuf,
  managed_config_path: PathBuf,
  account_source: AgentAccountSource,
  mode: RouteMode,
  credential_routes: Vec<ProviderRoute>,
  publications: Vec<ProviderPublication>,
  model_reference_rules: Vec<ModelReferenceRule>,
}

impl OpenCodePreflight {
  pub(crate) fn new(
    home: &Path,
    managed_config_path: &Path,
    account_source: AgentAccountSource,
    projection: &AgentConfigProjection<'_>,
  ) -> Self {
    Self {
      home: home.to_path_buf(),
      managed_config_path: managed_config_path.to_path_buf(),
      account_source,
      mode: projection.mode,
      credential_routes: projection.credential_routes.to_vec(),
      publications: projection.publications.to_vec(),
      model_reference_rules: projection.model_reference_rules.to_vec(),
    }
  }

  /// Validate OpenCode inputs that the managed `opencode.json[c]` edit cannot
  /// rewrite. This runs while planning and again immediately before apply so
  /// a changed environment or global Markdown file cannot silently bypass the
  /// generated provider topology.
  pub(crate) fn validate(&self) -> Result<()> {
    self.validate_auth_override()?;
    let mut issues = Vec::new();
    self.validate_secondary_configs(&mut issues)?;
    self.validate_global_markdown(&mut issues)?;
    if issues.is_empty() {
      return Ok(());
    }

    issues.sort_by(|left, right| {
      (&left.location, &left.current, &left.reason).cmp(&(&right.location, &right.current, &right.reason))
    });
    issues.dedup();
    let details = issues
      .iter()
      .map(UnsafeReference::display)
      .collect::<Vec<_>>()
      .join("\n");
    bail!(
      "OpenCode has global model references that cannot be migrated from outside the managed config:\n\
       {details}\n\
       update these references to a published generated model, then retry"
    )
  }

  fn validate_auth_override(&self) -> Result<()> {
    if self.account_source == AgentAccountSource::Agent && std::env::var_os("OPENCODE_AUTH_CONTENT").is_some() {
      bail!(
        "cannot link OpenCode-owned accounts while OPENCODE_AUTH_CONTENT is set: OpenCode would keep using the environment credential while Tokn migrates {}; unset the override or link with --use-main-accounts",
        opencode_data_root(&self.home).join("auth.json").display()
      );
    }
    if self.account_source == AgentAccountSource::Agent {
      let auth_path = opencode_data_root(&self.home).join("auth.json");
      if auth_path.exists() {
        let raw =
          fs::read_to_string(&auth_path).with_context(|| format!("reading OpenCode auth {}", auth_path.display()))?;
        let auth: JsonValue =
          serde_json::from_str(&raw).with_context(|| format!("parsing OpenCode auth {}", auth_path.display()))?;
        if auth
          .as_object()
          .is_some_and(|auth| auth.values().any(is_well_known_auth))
        {
          bail!(
            "cannot link OpenCode-owned accounts while {} contains a wellknown auth record because its remote config cannot be migrated safely; remove that record or link with --use-main-accounts",
            auth_path.display()
          );
        }
      }
    }
    Ok(())
  }

  fn validate_secondary_configs(&self, issues: &mut Vec<UnsafeReference>) -> Result<()> {
    let legacy_config_path = opencode_config_root(&self.home).join("config");
    if legacy_config_path.exists() {
      bail!(
        "legacy OpenCode config {} can override the generated provider after linking; start OpenCode once to migrate it, then retry",
        legacy_config_path.display()
      );
    }
    if self.managed_config_path.exists() {
      let value = crate::jsonc::read_jsonc(&self.managed_config_path)?;
      validate_relevant_substitutions(&self.managed_config_path.display().to_string(), &value)?;
    }

    let mut paths = secondary_config_paths(&self.home)?;
    paths.sort();
    paths.dedup();
    for path in paths {
      if same_path(&path, &self.managed_config_path) || !path.exists() {
        continue;
      }
      let value = crate::jsonc::read_jsonc(&path)?;
      self.validate_config_value(&path.display().to_string(), &value, issues)?;
    }

    if let Some(raw) = std::env::var_os("OPENCODE_CONFIG_CONTENT") {
      let raw = raw.to_string_lossy();
      if !raw.trim().is_empty() {
        let source_name = Path::new("OPENCODE_CONFIG_CONTENT");
        let value = crate::jsonc::parse_jsonc(&raw, source_name)
          .context("parsing OPENCODE_CONFIG_CONTENT as OpenCode JSON config")?;
        self.validate_config_value("OPENCODE_CONFIG_CONTENT", &value, issues)?;
      }
    }
    Ok(())
  }

  fn validate_config_value(&self, source: &str, value: &JsonValue, issues: &mut Vec<UnsafeReference>) -> Result<()> {
    let Some(config) = value.as_object() else {
      bail!("secondary OpenCode config {source} must contain a JSON object");
    };
    validate_relevant_substitutions(source, value)?;

    for (path, reference) in selected_model_references(value) {
      if let Some(issue) = self.reference_issue(format!("{source}:{path}"), &reference) {
        issues.push(issue);
      }
    }

    let transferred_sources = self
      .credential_routes
      .iter()
      .filter(|route| route.transfer_source_auth)
      .map(|route| route.source_provider_id.as_str())
      .collect::<BTreeSet<_>>();
    if let Some(providers) = config.get("provider") {
      let Some(providers) = providers.as_object() else {
        bail!("secondary OpenCode config {source} property 'provider' must contain an object");
      };
      if let Some((provider_id, _)) = providers.iter().find(|(provider_id, _)| {
        generated_provider_id(provider_id) || transferred_sources.contains(provider_id.as_str())
      }) {
        bail!(
          "secondary OpenCode config {source} defines gateway-managed provider '{provider_id}'; move or remove that definition before linking"
        );
      }
    }

    let active_provider_ids = self
      .publications
      .iter()
      .map(|publication| publication.provider_id.as_str())
      .collect::<BTreeSet<_>>();
    if let Some(enabled) = config.get("enabled_providers") {
      let enabled = policy_values(enabled, source, "enabled_providers")?;
      if let Some(provider_id) = active_provider_ids
        .iter()
        .find(|provider_id| !enabled.contains(**provider_id))
      {
        bail!(
          "secondary OpenCode config {source} enabled_providers omits generated provider '{provider_id}'; add it or remove the restrictive policy"
        );
      }
      if let Some(provider_id) = transferred_sources
        .iter()
        .find(|provider_id| enabled.contains(**provider_id))
      {
        bail!(
          "secondary OpenCode config {source} enabled_providers retains transferred source provider '{provider_id}'; remove it before linking"
        );
      }
    }
    if let Some(disabled) = config.get("disabled_providers") {
      let disabled = policy_values(disabled, source, "disabled_providers")?;
      if let Some(provider_id) = disabled.iter().find(|provider_id| {
        active_provider_ids.contains(provider_id.as_str())
          || generated_provider_id(provider_id)
          || transferred_sources.contains(provider_id.as_str())
      }) {
        bail!(
          "secondary OpenCode config {source} disabled_providers contains gateway-managed provider '{provider_id}'; remove it before linking"
        );
      }
    }
    Ok(())
  }

  fn validate_global_markdown(&self, issues: &mut Vec<UnsafeReference>) -> Result<()> {
    let mut markdown_paths = global_markdown_paths(&self.home)?;
    markdown_paths.sort();
    markdown_paths.dedup();
    for path in markdown_paths {
      let Some(current) = frontmatter_model(&path)? else {
        continue;
      };
      if let Some(issue) = self.reference_issue(path.display().to_string(), &current) {
        issues.push(issue);
      }
    }
    Ok(())
  }

  fn reference_issue(&self, location: String, current: &str) -> Option<UnsafeReference> {
    let (source_provider_id, source_model_id) = current.split_once('/')?;
    if source_model_id.is_empty() {
      let is_managed = generated_provider_id(source_provider_id)
        || self
          .credential_routes
          .iter()
          .any(|route| route.source_provider_id == source_provider_id);
      return is_managed.then(|| UnsafeReference {
        location,
        current: current.to_string(),
        suggested: None,
        reason: "the model id is empty".to_string(),
      });
    }

    if let Some((suggested, _, _)) = projected_model_reference(&self.model_reference_rules, current) {
      let target_is_published = published_model(&self.publications, &suggested);
      if !target_is_published {
        return Some(UnsafeReference {
          location,
          current: current.to_string(),
          suggested: None,
          reason: format!("the projected model is not in the generated {:?} catalogue", self.mode),
        });
      }
      if suggested != current {
        return Some(UnsafeReference {
          location,
          current: current.to_string(),
          suggested: Some(suggested),
          reason: "this source is outside the managed OpenCode config".to_string(),
        });
      }
      return None;
    }

    if generated_provider_id(source_provider_id) {
      let is_active = self
        .publications
        .iter()
        .any(|publication| publication.provider_id == source_provider_id);
      return Some(UnsafeReference {
        location,
        current: current.to_string(),
        suggested: None,
        reason: if is_active {
          "the model is not in the active generated provider catalogue".to_string()
        } else {
          "the generated provider is stale for the desired link topology".to_string()
        },
      });
    }

    let source_is_managed = self
      .credential_routes
      .iter()
      .any(|route| route.source_provider_id == source_provider_id);
    source_is_managed.then(|| UnsafeReference {
      location,
      current: current.to_string(),
      suggested: None,
      reason: "the source provider cannot be mapped unambiguously by the desired link".to_string(),
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct UnsafeReference {
  location: String,
  current: String,
  suggested: Option<String>,
  reason: String,
}

impl UnsafeReference {
  fn display(&self) -> String {
    match &self.suggested {
      Some(suggested) if suggested != &self.current => {
        format!(
          "  - {}: model '{}' -> '{}' ({})",
          self.location, self.current, suggested, self.reason
        )
      }
      _ => format!("  - {}: model '{}' ({})", self.location, self.current, self.reason),
    }
  }
}

fn published_model(publications: &[ProviderPublication], reference: &str) -> bool {
  let Some((provider_id, model_id)) = reference.split_once('/') else {
    return false;
  };
  publications
    .iter()
    .find(|publication| publication.provider_id == provider_id)
    .is_some_and(|publication| publication.models.contains_key(model_id))
}

fn policy_values(value: &JsonValue, source: &str, name: &str) -> Result<BTreeSet<String>> {
  let Some(values) = value.as_array() else {
    bail!("secondary OpenCode config {source} property '{name}' must contain an array of provider ids");
  };
  values
    .iter()
    .map(|value| {
      value
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("secondary OpenCode config {source} property '{name}' must contain only provider ids"))
    })
    .collect()
}

fn is_well_known_auth(value: &JsonValue) -> bool {
  value
    .as_object()
    .and_then(|auth| auth.get("type"))
    .and_then(JsonValue::as_str)
    == Some("wellknown")
}

fn validate_relevant_substitutions(source: &str, value: &JsonValue) -> Result<()> {
  for (path, reference) in selected_model_references(value) {
    if contains_config_substitution(&reference) {
      bail!(
        "OpenCode config {source}:{path} uses a model substitution that cannot be snapshotted safely; replace it with an explicit model reference before linking"
      );
    }
  }
  let Some(config) = value.as_object() else {
    return Ok(());
  };
  for name in ["enabled_providers", "disabled_providers"] {
    let Some(value) = config.get(name) else {
      continue;
    };
    let has_substitution = value.as_array().is_some_and(|values| {
      values
        .iter()
        .filter_map(JsonValue::as_str)
        .any(contains_config_substitution)
    }) || value.as_str().is_some_and(contains_config_substitution);
    if has_substitution {
      bail!(
        "OpenCode config {source} property '{name}' uses a substitution that cannot be snapshotted safely; use explicit provider ids before linking"
      );
    }
  }
  Ok(())
}

fn contains_config_substitution(value: &str) -> bool {
  value.contains("{env:") || value.contains("{file:")
}

fn selected_model_references(value: &JsonValue) -> Vec<(String, String)> {
  let Some(config) = value.as_object() else {
    return Vec::new();
  };
  let mut selected = Vec::new();
  for name in ["model", "small_model"] {
    if let Some(reference) = config.get(name).and_then(JsonValue::as_str) {
      selected.push((format!("$.{name}"), reference.to_string()));
    }
  }
  for collection_name in ["agent", "command", "mode"] {
    let Some(collection) = config.get(collection_name).and_then(JsonValue::as_object) else {
      continue;
    };
    for (entry_name, entry) in collection {
      if let Some(reference) = entry
        .as_object()
        .and_then(|entry| entry.get("model"))
        .and_then(JsonValue::as_str)
      {
        selected.push((format!("$.{collection_name}.{entry_name}.model"), reference.to_string()));
      }
    }
  }
  selected
}

fn secondary_config_paths(home: &Path) -> Result<Vec<PathBuf>> {
  let mut paths = Vec::new();
  for root in global_config_roots(home)? {
    for filename in CONFIG_FILENAMES {
      paths.push(root.join(filename));
    }
  }
  if let Some(path) = env_path("OPENCODE_CONFIG")? {
    paths.push(path);
  }
  Ok(paths)
}

fn global_config_roots(home: &Path) -> Result<Vec<PathBuf>> {
  let mut roots = vec![opencode_config_root(home), home.join(".opencode")];
  if let Some(path) = env_path("OPENCODE_CONFIG_DIR")? {
    roots.push(path);
  }
  roots.sort();
  roots.dedup();
  Ok(roots)
}

fn env_path(name: &str) -> Result<Option<PathBuf>> {
  let Some(raw) = std::env::var_os(name) else {
    return Ok(None);
  };
  if raw.is_empty() {
    return Ok(None);
  }
  let path = PathBuf::from(raw);
  if path.is_absolute() {
    return Ok(Some(path));
  }
  std::path::absolute(&path)
    .map(Some)
    .with_context(|| format!("resolving relative {name} path {}", path.display()))
}

fn same_path(left: &Path, right: &Path) -> bool {
  left == right
    || left
      .canonicalize()
      .ok()
      .zip(right.canonicalize().ok())
      .is_some_and(|(left, right)| left == right)
}

#[cfg(test)]
pub(crate) fn diagnostic_mentions_markdown_path(message: &str, expected: &Path) -> bool {
  message.lines().any(|line| {
    let Some((location, _)) = line
      .trim_start()
      .strip_prefix("- ")
      .and_then(|line| line.split_once(": model '"))
    else {
      return false;
    };
    same_path(Path::new(location), expected)
  })
}

fn global_markdown_paths(home: &Path) -> Result<Vec<PathBuf>> {
  let mut paths = Vec::new();
  let mut visited = BTreeSet::new();
  for root in global_config_roots(home)? {
    for collection in MARKDOWN_COLLECTION_DIRS {
      let recursive = !matches!(collection, "mode" | "modes");
      collect_markdown_paths(&root.join(collection), recursive, &mut visited, &mut paths)?;
    }
  }
  Ok(paths)
}

fn collect_markdown_paths(
  directory: &Path,
  recursive: bool,
  visited: &mut BTreeSet<PathBuf>,
  paths: &mut Vec<PathBuf>,
) -> Result<()> {
  let canonical = match directory.canonicalize() {
    Ok(canonical) => canonical,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
    Err(error) => {
      return Err(error)
        .with_context(|| format!("resolving global OpenCode Markdown directory '{}'", directory.display()));
    }
  };
  if !visited.insert(canonical) {
    return Ok(());
  }
  let entries = match fs::read_dir(directory) {
    Ok(entries) => entries,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
    Err(error) => {
      return Err(error)
        .with_context(|| format!("reading global OpenCode Markdown directory '{}'", directory.display()));
    }
  };

  for entry in entries {
    let entry = entry.with_context(|| {
      format!(
        "reading an entry from global OpenCode Markdown directory '{}'",
        directory.display()
      )
    })?;
    let path = entry.path();
    let file_type = entry
      .file_type()
      .with_context(|| format!("reading file type for global OpenCode path '{}'", path.display()))?;
    let metadata = if file_type.is_symlink() {
      Some(
        entry
          .metadata()
          .with_context(|| format!("following global OpenCode Markdown symlink '{}'", path.display()))?,
      )
    } else {
      None
    };
    let is_directory = file_type.is_dir() || metadata.as_ref().is_some_and(|metadata| metadata.is_dir());
    if is_directory {
      if recursive {
        collect_markdown_paths(&path, recursive, visited, paths)?;
      }
      continue;
    }
    let is_file = file_type.is_file() || metadata.is_some_and(|metadata| metadata.is_file());
    if is_file && is_markdown_path(&path) {
      paths.push(path);
    }
  }
  Ok(())
}

fn is_markdown_path(path: &Path) -> bool {
  path
    .extension()
    .and_then(|extension| extension.to_str())
    .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
}

fn frontmatter_model(path: &Path) -> Result<Option<String>> {
  let source =
    fs::read_to_string(path).with_context(|| format!("reading global OpenCode Markdown file '{}'", path.display()))?;
  let source = source.strip_prefix('\u{feff}').unwrap_or(&source);
  let mut lines = source.lines();
  if lines.next().map(str::trim) != Some("---") {
    return Ok(None);
  }

  let mut yaml = String::new();
  let mut closed = false;
  for line in lines {
    if line.trim() == "---" {
      closed = true;
      break;
    }
    yaml.push_str(line);
    yaml.push('\n');
  }
  if !closed {
    bail!(
      "global OpenCode Markdown file '{}' has unclosed YAML frontmatter",
      path.display()
    );
  }

  match serde_yaml::from_str::<YamlValue>(&yaml) {
    Ok(mut frontmatter) => {
      frontmatter.apply_merge().with_context(|| {
        format!(
          "resolving YAML merge keys in global OpenCode Markdown file '{}'",
          path.display()
        )
      })?;
      Ok(model_from_yaml(&frontmatter))
    }
    Err(_) => Ok(tolerant_frontmatter_model(&yaml)),
  }
}

fn model_from_yaml(frontmatter: &YamlValue) -> Option<String> {
  frontmatter
    .as_mapping()?
    .get(YamlValue::String("model".to_string()))?
    .as_str()
    .map(str::trim)
    .filter(|model| !model.is_empty())
    .map(str::to_string)
}

fn tolerant_frontmatter_model(yaml: &str) -> Option<String> {
  for line in yaml.lines() {
    if line.trim_start() != line {
      continue;
    }
    let Some(raw) = line.strip_prefix("model:") else {
      continue;
    };
    let raw = raw.trim();
    if raw.is_empty() {
      return None;
    }
    if let Ok(value) = serde_yaml::from_str::<YamlValue>(raw) {
      if let Some(model) = value.as_str().map(str::trim).filter(|model| !model.is_empty()) {
        return Some(model.to_string());
      }
    }
    let value = raw
      .split_once(" #")
      .map_or(raw, |(value, _)| value)
      .trim()
      .trim_matches(['\'', '"']);
    return (!value.is_empty()).then(|| value.to_string());
  }
  None
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::projection::{ModelReferenceMatch, PublishedModel, SHARED_PROVIDER_ID};
  use std::collections::BTreeMap;
  use tempfile::TempDir;

  fn route(source: &str, provider: &str, transfer_source_auth: bool) -> ProviderRoute {
    ProviderRoute {
      source_provider_id: source.to_string(),
      gateway_provider_id: provider.to_string(),
      account_id: "account".to_string(),
      profile: "opencode".to_string(),
      base_url: format!("http://127.0.0.1:4141/opencode-{provider}/v1"),
      transfer_source_auth,
    }
  }

  fn publication(provider: &str, models: &[&str]) -> ProviderPublication {
    ProviderPublication {
      provider_id: provider.to_string(),
      display_name: provider.to_string(),
      base_url: "http://127.0.0.1:4141/opencode/v1".to_string(),
      models: models
        .iter()
        .map(|model| {
          (
            (*model).to_string(),
            PublishedModel {
              name: (*model).to_string(),
            },
          )
        })
        .collect::<BTreeMap<_, _>>(),
    }
  }

  fn preflight(
    home: &Path,
    mode: RouteMode,
    routes: Vec<ProviderRoute>,
    publications: Vec<ProviderPublication>,
    rules: Vec<ModelReferenceRule>,
  ) -> OpenCodePreflight {
    OpenCodePreflight {
      home: home.to_path_buf(),
      managed_config_path: home.join(".config/opencode/opencode.jsonc"),
      account_source: AgentAccountSource::Main,
      mode,
      credential_routes: routes,
      publications,
      model_reference_rules: rules,
    }
  }

  fn rule(source: &str, target: &str, prefix: Option<&str>) -> ModelReferenceRule {
    ModelReferenceRule {
      source_provider_id: source.to_string(),
      source_model_match: ModelReferenceMatch::Any,
      target_provider_id: target.to_string(),
      target_model_prefix: prefix.map(str::to_string),
      allow_missing_model: false,
    }
  }

  fn write_markdown(home: &Path, relative: &str, contents: &str) -> PathBuf {
    let path = home.join(relative);
    fs::create_dir_all(path.parent().expect("test path has a parent")).unwrap();
    fs::write(&path, contents).unwrap();
    path
  }

  #[test]
  fn scans_agents_commands_and_modes_in_both_global_roots() {
    let temp = TempDir::new().unwrap();
    let roots = [".config/opencode", ".opencode"];
    let mut paths = Vec::new();
    for root in roots {
      for collection in MARKDOWN_COLLECTION_DIRS {
        let relative = if matches!(collection, "mode" | "modes") {
          format!("{root}/{collection}/reviewer.md")
        } else {
          format!("{root}/{collection}/nested/reviewer.md")
        };
        paths.push(write_markdown(
          temp.path(),
          &relative,
          "---\nmodel: openai/gpt-5\n---\n",
        ));
      }
    }
    let preflight = preflight(
      temp.path(),
      RouteMode::Route,
      vec![route("openai", "openai", false)],
      vec![publication(SHARED_PROVIDER_ID, &["gpt-5"])],
      vec![rule("openai", SHARED_PROVIDER_ID, None)],
    );

    let error = preflight.validate().unwrap_err();
    let message = error.to_string();
    for path in paths {
      assert!(diagnostic_mentions_markdown_path(&message, &path), "{message}");
    }
    assert!(message.contains("model 'openai/gpt-5' -> 'tokn-router/gpt-5'"));
  }

  #[test]
  fn suggestions_follow_shared_exact_and_pinned_rules() {
    let temp = TempDir::new().unwrap();
    let cases = [
      (
        RouteMode::Route,
        SHARED_PROVIDER_ID.to_string(),
        None,
        "gpt-5".to_string(),
        "tokn-router/gpt-5",
      ),
      (
        RouteMode::Exact,
        SHARED_PROVIDER_ID.to_string(),
        Some("openai"),
        "openai/gpt-5".to_string(),
        "tokn-router/openai/gpt-5",
      ),
      (
        RouteMode::Switch,
        "tokn-router-openai".to_string(),
        None,
        "gpt-5".to_string(),
        "tokn-router-openai/gpt-5",
      ),
    ];
    for (mode, target, prefix, published_model_id, expected) in cases {
      let location = format!(".config/opencode/agent/{mode:?}.md");
      write_markdown(temp.path(), &location, "---\nmodel: openai/gpt-5\n---\n");
      let preflight = preflight(
        temp.path(),
        mode,
        vec![route("openai", "openai", false)],
        vec![publication(&target, &[&published_model_id])],
        vec![rule("openai", &target, prefix)],
      );
      let issue = preflight
        .reference_issue(location, "openai/gpt-5")
        .expect("direct provider reference needs migration");
      assert_eq!(issue.suggested.as_deref(), Some(expected));
    }
  }

  #[test]
  fn accepts_active_generated_markdown_reference() {
    let temp = TempDir::new().unwrap();
    write_markdown(
      temp.path(),
      ".config/opencode/agent/main.md",
      "---\nmodel: tokn-router/gpt-5\n---\n",
    );
    let preflight = preflight(
      temp.path(),
      RouteMode::Route,
      vec![route("openai", "openai", false)],
      vec![publication(SHARED_PROVIDER_ID, &["gpt-5"])],
      vec![rule(SHARED_PROVIDER_ID, SHARED_PROVIDER_ID, None)],
    );

    preflight.validate().unwrap();
  }

  #[test]
  fn rejects_stale_generated_markdown_reference_on_topology_change() {
    let temp = TempDir::new().unwrap();
    let path = write_markdown(
      temp.path(),
      ".opencode/modes/review.md",
      "---\nmodel: tokn-router-openai/gpt-5\n---\n",
    );
    let preflight = preflight(
      temp.path(),
      RouteMode::Route,
      vec![route("openai", "openai", false)],
      vec![publication(SHARED_PROVIDER_ID, &["gpt-5"])],
      Vec::new(),
    );

    let error = preflight.validate().unwrap_err();
    let message = error.to_string();
    assert!(diagnostic_mentions_markdown_path(&message, &path), "{message}");
    assert!(message.contains("stale"));
  }

  #[test]
  fn resolves_yaml_merge_keys_and_tolerates_parser_fallback() {
    let temp = TempDir::new().unwrap();
    let merged = write_markdown(
      temp.path(),
      ".config/opencode/agent/merged.md",
      "---\ndefaults: &defaults\n  model: openai/gpt-5\n<<: *defaults\n---\n",
    );
    assert_eq!(frontmatter_model(&merged).unwrap().as_deref(), Some("openai/gpt-5"));

    let fallback = write_markdown(
      temp.path(),
      ".config/opencode/agent/fallback.md",
      "---\ndescription: fallback parser\nmodel: openai/gpt-5 # valid model\nbroken: [\n---\n",
    );
    assert_eq!(frontmatter_model(&fallback).unwrap().as_deref(), Some("openai/gpt-5"));
  }

  #[test]
  fn rejects_unsafe_secondary_config_models_providers_and_policies() {
    let temp = TempDir::new().unwrap();
    let preflight = preflight(
      temp.path(),
      RouteMode::Route,
      vec![route("openai", "openai", true)],
      vec![publication(SHARED_PROVIDER_ID, &["gpt-5"])],
      vec![rule("openai", SHARED_PROVIDER_ID, None)],
    );
    let mut issues = Vec::new();
    preflight
      .validate_config_value(
        "config.json",
        &serde_json::json!({"model": "openai/gpt-5"}),
        &mut issues,
      )
      .unwrap();
    assert_eq!(issues.len(), 1);
    assert_eq!(issues[0].suggested.as_deref(), Some("tokn-router/gpt-5"));

    for value in [
      serde_json::json!({"provider": {"tokn-router": {}}}),
      serde_json::json!({"provider": {"openai": {}}}),
      serde_json::json!({"enabled_providers": ["openai"]}),
      serde_json::json!({"disabled_providers": ["tokn-router"]}),
    ] {
      let error = preflight
        .validate_config_value("config.json", &value, &mut Vec::new())
        .unwrap_err();
      assert!(
        error.to_string().contains("gateway-managed")
          || error.to_string().contains("omits generated")
          || error.to_string().contains("transferred")
      );
    }
  }

  #[test]
  fn config_root_honors_only_absolute_xdg_paths() {
    let home = Path::new("/tmp/test-home");
    assert_eq!(absolute_xdg_home("TOKN_TEST_XDG_THAT_IS_NOT_SET"), None);
    assert!(opencode_config_root(home).ends_with("opencode"));
    assert!(opencode_data_root(home).ends_with("opencode"));
  }

  #[test]
  fn alternate_agent_home_does_not_inherit_process_xdg_paths() {
    let current_home = Path::new("/users/current");
    let alternate_home = Path::new("/users/alternate");
    let xdg_home = PathBuf::from("/xdg/config");

    assert_eq!(
      xdg_home_for_agent_home(current_home, Some(current_home), Some(xdg_home.clone())),
      Some(xdg_home)
    );
    assert_eq!(
      xdg_home_for_agent_home(alternate_home, Some(current_home), Some(PathBuf::from("/xdg/config"))),
      None
    );
  }
}
