use crate::adapter::ProviderRoute;
use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokn_accounts::registry::Registry;
use tokn_config::{Account, RouteMode};
use tokn_core::provider::Endpoint;

pub(crate) const SHARED_PROVIDER_ID: &str = "tokn-router";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublishedModel {
  pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderPublication {
  pub provider_id: String,
  pub display_name: String,
  pub base_url: String,
  pub models: BTreeMap<String, PublishedModel>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct OpenCodePublicationPlan {
  pub publications: Vec<ProviderPublication>,
  pub model_reference_rules: Vec<ModelReferenceRule>,
  pub providers_without_models: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ModelReferenceMatch {
  Exact(String),
  EndpointIncompatible(Vec<EndpointModelRule>),
  Prefix(String),
  Any,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointModelRule {
  pub pattern: String,
  pub allows_endpoint: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelReferenceRule {
  pub source_provider_id: String,
  pub source_model_match: ModelReferenceMatch,
  pub target_provider_id: String,
  pub target_model_prefix: Option<String>,
  pub allow_missing_model: bool,
}

pub(crate) struct AgentConfigProjection<'a> {
  pub target_base_url: &'a str,
  pub mode: RouteMode,
  pub previous_mode: Option<RouteMode>,
  pub credential_routes: &'a [ProviderRoute],
  pub publications: &'a [ProviderPublication],
  pub model_reference_rules: &'a [ModelReferenceRule],
}

struct ProviderCatalogue {
  display_name: String,
  models: BTreeMap<String, PublishedModel>,
  known_model_ids: BTreeSet<String>,
  allows_unknown_models: bool,
  endpoint_model_rules: Vec<EndpointModelRule>,
}

pub(crate) fn compile_opencode_publications(
  mode: RouteMode,
  previous_mode: Option<RouteMode>,
  previous_provider_ids: Option<&[String]>,
  target_base_url: &str,
  accounts: &[Account],
  routes: &[ProviderRoute],
  endpoint: Endpoint,
) -> Result<OpenCodePublicationPlan> {
  validate_route_provider_ids(routes, mode)?;
  let catalogues = provider_catalogues(accounts, routes, mode, endpoint)?;
  let providers_without_models = catalogues
    .iter()
    .filter(|(_, catalogue)| catalogue.models.is_empty())
    .map(|(provider_id, _)| provider_id.clone())
    .collect();
  let (publications, model_reference_rules) = if is_verbatim_mode(mode) {
    compile_pinned_publications(previous_mode, previous_provider_ids, routes, &catalogues)?
  } else {
    compile_shared_publication(
      mode,
      previous_mode,
      previous_provider_ids,
      target_base_url,
      routes,
      &catalogues,
    )?
  };
  Ok(OpenCodePublicationPlan {
    publications,
    model_reference_rules,
    providers_without_models,
  })
}

fn validate_route_provider_ids(routes: &[ProviderRoute], mode: RouteMode) -> Result<()> {
  for route in routes {
    for (kind, provider_id) in [
      ("source", route.source_provider_id.as_str()),
      ("gateway", route.gateway_provider_id.as_str()),
    ] {
      if provider_id.is_empty() || provider_id.trim() != provider_id || provider_id.contains('/') {
        bail!("OpenCode {kind} provider id '{provider_id}' cannot be published safely");
      }
    }
  }
  if mode == RouteMode::Exact {
    let ambiguous_sources = ambiguous_source_provider_ids(routes);
    if let Some(source_provider_id) = ambiguous_sources.iter().find(|source_provider_id| {
      routes.iter().any(|route| {
        route.source_provider_id == **source_provider_id && (route.transfer_source_auth || !route.account_id.is_empty())
      })
    }) {
      let gateway_provider_ids = routes
        .iter()
        .filter(|route| route.source_provider_id == **source_provider_id)
        .map(|route| route.gateway_provider_id.as_str())
        .collect::<BTreeSet<_>>();
      bail!(
        "OpenCode source provider '{source_provider_id}' represents multiple gateway providers ({}) and cannot be relinked unambiguously in exact mode; select one with --provider-filter",
        gateway_provider_ids.into_iter().collect::<Vec<_>>().join(", ")
      );
    }
  }
  Ok(())
}

fn provider_catalogues(
  accounts: &[Account],
  routes: &[ProviderRoute],
  mode: RouteMode,
  endpoint: Endpoint,
) -> Result<BTreeMap<String, ProviderCatalogue>> {
  let registry = Registry::builtin();
  let mut catalogues = BTreeMap::new();
  for account in accounts.iter().filter(|account| account.enabled) {
    let provider = registry
      .build(Arc::new(account.clone()))
      .with_context(|| format!("building provider catalogue from account '{}'", account.id))?;
    let provider_id = provider.info().id.clone();
    if catalogues.contains_key(&provider_id) {
      continue;
    }
    let known_model_ids = provider
      .info()
      .default_models
      .iter()
      .map(|model| model.id.clone())
      .collect();
    let allows_unknown_models = provider.has_model("__tokn_router_unknown_model_probe__");
    let endpoint_model_rules = endpoint_model_rules(provider.endpoint_rules().unwrap_or_default(), endpoint);
    let models = provider
      .info()
      .default_models
      .iter()
      .filter(|model| is_generation_model(model))
      .filter(|model| !is_verbatim_mode(mode) || provider.has_endpoint(&model.id, endpoint))
      .map(|model| {
        (
          model.id.clone(),
          PublishedModel {
            name: model.name.clone(),
          },
        )
      })
      .collect();
    catalogues.insert(
      provider_id,
      ProviderCatalogue {
        display_name: provider.info().display_name.to_string(),
        models,
        known_model_ids,
        allows_unknown_models,
        endpoint_model_rules,
      },
    );
  }
  let enabled_provider_ids = accounts
    .iter()
    .filter(|account| account.enabled)
    .map(|account| account.provider.as_str())
    .collect::<BTreeSet<_>>();
  for provider_id in routes
    .iter()
    .map(|route| route.gateway_provider_id.as_str())
    .collect::<BTreeSet<_>>()
  {
    let has_credentialless_route = routes
      .iter()
      .any(|route| route.gateway_provider_id == provider_id && route.account_id.is_empty());
    let publish_static_models = enabled_provider_ids.contains(provider_id) || has_credentialless_route;
    let descriptor = registry
      .resolve(provider_id)
      .with_context(|| format!("building static OpenCode catalogue for provider '{provider_id}'"))?;
    let default_models = tokn_catalogue::default_models_for(provider_id);
    let fallback_known_model_ids = default_models
      .iter()
      .map(|model| model.id.clone())
      .collect::<BTreeSet<_>>();
    let fallback_models = default_models
      .into_iter()
      .filter(|_| publish_static_models)
      .filter(is_generation_model)
      .filter(|model| {
        !is_verbatim_mode(mode)
          || tokn_core::provider::match_endpoint_rule(
            descriptor.model_endpoint_rules.unwrap_or_default(),
            &model.id,
            endpoint,
          )
          .unwrap_or_else(|| descriptor.endpoints.iter().any(|spec| spec.endpoint == endpoint))
      })
      .map(|model| (model.id, PublishedModel { name: model.name }))
      .collect::<BTreeMap<_, _>>();
    let catalogue = catalogues
      .entry(provider_id.to_string())
      .or_insert_with(|| ProviderCatalogue {
        display_name: descriptor.display_name.to_string(),
        models: BTreeMap::new(),
        known_model_ids: BTreeSet::new(),
        allows_unknown_models: provider_id == tokn_core::provider::ID_LLAMA_CPP,
        endpoint_model_rules: endpoint_model_rules(descriptor.model_endpoint_rules.unwrap_or_default(), endpoint),
      });
    catalogue.known_model_ids.extend(fallback_known_model_ids);
    for (model_id, model) in fallback_models {
      catalogue.models.entry(model_id).or_insert(model);
    }
  }
  Ok(catalogues)
}

fn compile_shared_publication(
  mode: RouteMode,
  previous_mode: Option<RouteMode>,
  previous_provider_ids: Option<&[String]>,
  target_base_url: &str,
  routes: &[ProviderRoute],
  catalogues: &BTreeMap<String, ProviderCatalogue>,
) -> Result<(Vec<ProviderPublication>, Vec<ModelReferenceRule>)> {
  let mut models = BTreeMap::new();
  for (provider_id, catalogue) in catalogues {
    for (model_id, model) in &catalogue.models {
      let published_id = if mode == RouteMode::Exact {
        format!("{provider_id}/{model_id}")
      } else {
        model_id.clone()
      };
      models.entry(published_id).or_insert_with(|| PublishedModel {
        name: if mode == RouteMode::Exact {
          format!("{} ({})", model.name, catalogue.display_name)
        } else {
          model.name.clone()
        },
      });
    }
  }
  let mut rules = Vec::new();
  let ambiguous_sources = ambiguous_source_provider_ids(routes);
  for route in routes {
    if mode == RouteMode::Exact && ambiguous_sources.contains(route.source_provider_id.as_str()) {
      // Main-account routes may share an OpenCode source namespace (OpenAI and
      // Codex both use `openai`). Their generated exact model ids are
      // gateway-qualified, but an existing direct source selection is
      // inherently ambiguous and must not be rewritten.
      continue;
    }
    insert_reference_rule(
      &mut rules,
      ModelReferenceRule {
        source_provider_id: route.source_provider_id.clone(),
        source_model_match: ModelReferenceMatch::Any,
        target_provider_id: SHARED_PROVIDER_ID.to_string(),
        target_model_prefix: (mode == RouteMode::Exact).then(|| route.gateway_provider_id.clone()),
        allow_missing_model: catalogue_allows_unknown_models(catalogues, &route.gateway_provider_id),
      },
    )?;
  }
  if mode == RouteMode::Exact {
    add_shared_prefix_rules(&mut rules, routes, catalogues, SHARED_PROVIDER_ID, true)?;
  } else {
    let provider_scope_is_safe = !matches!(
      normalized_mode(previous_mode),
      Some(RouteMode::Route | RouteMode::Fuzzy)
    ) || same_provider_scope(previous_provider_ids, routes);
    insert_reference_rule(
      &mut rules,
      ModelReferenceRule {
        source_provider_id: SHARED_PROVIDER_ID.to_string(),
        source_model_match: ModelReferenceMatch::Any,
        target_provider_id: SHARED_PROVIDER_ID.to_string(),
        target_model_prefix: None,
        allow_missing_model: provider_scope_is_safe
          && catalogues.values().any(|catalogue| catalogue.allows_unknown_models),
      },
    )?;
  }
  add_shared_known_model_rejections(&mut rules, mode, previous_mode, routes, catalogues)?;
  if previous_mode.is_some_and(is_verbatim_mode) {
    let current_provider_ids = routes
      .iter()
      .map(|route| route.gateway_provider_id.as_str())
      .collect::<BTreeSet<_>>();
    for provider_id in previous_provider_ids.unwrap_or_default() {
      insert_reference_rule(
        &mut rules,
        ModelReferenceRule {
          source_provider_id: pinned_provider_id(provider_id),
          source_model_match: ModelReferenceMatch::Any,
          target_provider_id: SHARED_PROVIDER_ID.to_string(),
          target_model_prefix: (mode == RouteMode::Exact).then(|| provider_id.to_string()),
          allow_missing_model: current_provider_ids.contains(provider_id.as_str())
            && catalogue_allows_unknown_models(catalogues, provider_id),
        },
      )?;
    }
  }
  match (normalized_mode(previous_mode), mode) {
    (Some(RouteMode::Exact), RouteMode::Exact) => {}
    (Some(RouteMode::Exact), RouteMode::Route | RouteMode::Fuzzy) => {
      add_shared_prefix_rules(&mut rules, routes, catalogues, SHARED_PROVIDER_ID, false)?;
    }
    (Some(RouteMode::Route | RouteMode::Fuzzy), RouteMode::Exact) => {
      add_unique_catalogue_model_rules(&mut rules, catalogues, SHARED_PROVIDER_ID, true)?;
    }
    (Some(RouteMode::Route | RouteMode::Fuzzy), RouteMode::Route | RouteMode::Fuzzy) => {}
    _ => {}
  }
  Ok((
    vec![ProviderPublication {
      provider_id: SHARED_PROVIDER_ID.to_string(),
      display_name: "Tokn Router".to_string(),
      base_url: target_base_url.to_string(),
      models,
    }],
    rules,
  ))
}

fn compile_pinned_publications(
  previous_mode: Option<RouteMode>,
  previous_provider_ids: Option<&[String]>,
  routes: &[ProviderRoute],
  catalogues: &BTreeMap<String, ProviderCatalogue>,
) -> Result<(Vec<ProviderPublication>, Vec<ModelReferenceRule>)> {
  let mut publications = BTreeMap::new();
  for route in routes {
    let provider_id = pinned_provider_id(&route.gateway_provider_id);
    let catalogue = catalogues.get(&route.gateway_provider_id);
    let publication = ProviderPublication {
      provider_id: provider_id.clone(),
      display_name: catalogue
        .map(|catalogue| format!("Tokn Router ({})", catalogue.display_name))
        .unwrap_or_else(|| format!("Tokn Router ({})", route.gateway_provider_id)),
      base_url: route.base_url.clone(),
      models: catalogue.map(|catalogue| catalogue.models.clone()).unwrap_or_default(),
    };
    if let Some(existing) = publications.get(&provider_id) {
      if existing != &publication {
        bail!(
          "provider '{}' resolves to more than one generated OpenCode endpoint",
          route.gateway_provider_id
        );
      }
    } else {
      publications.insert(provider_id, publication);
    }
  }
  let mut rules = Vec::new();
  for route in routes {
    let target_provider_id = pinned_provider_id(&route.gateway_provider_id);
    insert_reference_rule(
      &mut rules,
      ModelReferenceRule {
        source_provider_id: route.source_provider_id.clone(),
        source_model_match: ModelReferenceMatch::Any,
        target_provider_id: target_provider_id.clone(),
        target_model_prefix: None,
        allow_missing_model: true,
      },
    )?;
    insert_reference_rule(
      &mut rules,
      ModelReferenceRule {
        source_provider_id: target_provider_id.clone(),
        source_model_match: ModelReferenceMatch::Any,
        target_provider_id,
        target_model_prefix: None,
        allow_missing_model: true,
      },
    )?;
  }
  add_pinned_known_model_rejections(&mut rules, previous_mode, routes, catalogues)?;
  match normalized_mode(previous_mode) {
    Some(RouteMode::Exact) => {
      for route in routes {
        insert_reference_rule(
          &mut rules,
          ModelReferenceRule {
            source_provider_id: SHARED_PROVIDER_ID.to_string(),
            source_model_match: ModelReferenceMatch::Prefix(route.gateway_provider_id.clone()),
            target_provider_id: pinned_provider_id(&route.gateway_provider_id),
            target_model_prefix: None,
            allow_missing_model: true,
          },
        )?;
      }
    }
    Some(RouteMode::Route | RouteMode::Fuzzy) if publications.len() == 1 => {
      let target_provider_id = publications
        .keys()
        .next()
        .expect("single publication has a key")
        .clone();
      let allow_missing_model = pinned_publication_allows_unknown_models(routes, catalogues, &target_provider_id);
      insert_reference_rule(
        &mut rules,
        ModelReferenceRule {
          source_provider_id: SHARED_PROVIDER_ID.to_string(),
          source_model_match: ModelReferenceMatch::Any,
          target_provider_id,
          target_model_prefix: None,
          allow_missing_model,
        },
      )?;
    }
    Some(RouteMode::Route | RouteMode::Fuzzy) => {
      for (provider_id, catalogue) in catalogues {
        for model_id in catalogue.models.keys() {
          let owners = catalogues
            .iter()
            .filter(|(_, candidate)| candidate.models.contains_key(model_id))
            .count();
          if owners == 1 {
            insert_reference_rule(
              &mut rules,
              ModelReferenceRule {
                source_provider_id: SHARED_PROVIDER_ID.to_string(),
                source_model_match: ModelReferenceMatch::Exact(model_id.clone()),
                target_provider_id: pinned_provider_id(provider_id),
                target_model_prefix: None,
                allow_missing_model: false,
              },
            )?;
          }
        }
      }
    }
    None if previous_mode.is_some_and(is_verbatim_mode) && publications.len() == 1 => {
      let target_provider_id = publications
        .keys()
        .next()
        .expect("single publication has a key")
        .clone();
      let allow_missing_model = pinned_publication_allows_unknown_models(routes, catalogues, &target_provider_id);
      for previous_provider_id in previous_provider_ids.unwrap_or_default() {
        let source_provider_id = pinned_provider_id(previous_provider_id);
        if source_provider_id == target_provider_id {
          continue;
        }
        insert_reference_rule(
          &mut rules,
          ModelReferenceRule {
            source_provider_id,
            source_model_match: ModelReferenceMatch::Any,
            target_provider_id: target_provider_id.clone(),
            target_model_prefix: None,
            allow_missing_model,
          },
        )?;
      }
    }
    _ => {}
  }
  Ok((publications.into_values().collect(), rules))
}

fn same_provider_scope(previous_provider_ids: Option<&[String]>, routes: &[ProviderRoute]) -> bool {
  let Some(previous_provider_ids) = previous_provider_ids else {
    return false;
  };
  let previous = previous_provider_ids
    .iter()
    .map(String::as_str)
    .collect::<BTreeSet<_>>();
  let current = routes
    .iter()
    .map(|route| route.gateway_provider_id.as_str())
    .collect::<BTreeSet<_>>();
  previous == current
}

fn ambiguous_source_provider_ids(routes: &[ProviderRoute]) -> BTreeSet<&str> {
  let mut gateways_by_source = BTreeMap::<&str, BTreeSet<&str>>::new();
  for route in routes {
    gateways_by_source
      .entry(&route.source_provider_id)
      .or_default()
      .insert(&route.gateway_provider_id);
  }
  gateways_by_source
    .into_iter()
    .filter_map(|(source_provider_id, gateway_provider_ids)| {
      (gateway_provider_ids.len() > 1).then_some(source_provider_id)
    })
    .collect()
}

fn is_generation_model(model: &tokn_core::provider::ModelInfo) -> bool {
  // Models.dev represents embeddings and image generators as text-capable too,
  // but neither exposes a chat-generation control. OpenCode's picker should
  // contain models that can actually serve an agent conversation.
  model.capabilities.output.text
    && (model.capabilities.temperature || model.capabilities.reasoning || model.capabilities.toolcall)
}

fn endpoint_model_rules(rules: &[tokn_core::provider::EndpointRule], endpoint: Endpoint) -> Vec<EndpointModelRule> {
  rules
    .iter()
    .map(|rule| EndpointModelRule {
      pattern: rule.pattern.to_string(),
      allows_endpoint: rule.endpoints.contains(&endpoint),
    })
    .collect()
}

fn normalized_mode(mode: Option<RouteMode>) -> Option<RouteMode> {
  match mode {
    Some(RouteMode::Exact) => Some(RouteMode::Exact),
    Some(RouteMode::Fuzzy) => Some(RouteMode::Fuzzy),
    Some(RouteMode::Route) => Some(RouteMode::Route),
    Some(RouteMode::Passthrough | RouteMode::Switch) => None,
    None => None,
  }
}

fn add_shared_prefix_rules(
  rules: &mut Vec<ModelReferenceRule>,
  routes: &[ProviderRoute],
  catalogues: &BTreeMap<String, ProviderCatalogue>,
  target_provider_id: &str,
  retain_prefix: bool,
) -> Result<()> {
  for provider_id in routes
    .iter()
    .map(|route| route.gateway_provider_id.as_str())
    .collect::<BTreeSet<_>>()
  {
    insert_reference_rule(
      rules,
      ModelReferenceRule {
        source_provider_id: SHARED_PROVIDER_ID.to_string(),
        source_model_match: ModelReferenceMatch::Prefix(provider_id.to_string()),
        target_provider_id: target_provider_id.to_string(),
        target_model_prefix: retain_prefix.then(|| provider_id.to_string()),
        allow_missing_model: catalogue_allows_unknown_models(catalogues, provider_id),
      },
    )?;
  }
  Ok(())
}

fn catalogue_allows_unknown_models(catalogues: &BTreeMap<String, ProviderCatalogue>, provider_id: &str) -> bool {
  catalogues
    .get(provider_id)
    .is_some_and(|catalogue| catalogue.allows_unknown_models)
}

fn pinned_publication_allows_unknown_models(
  routes: &[ProviderRoute],
  catalogues: &BTreeMap<String, ProviderCatalogue>,
  target_provider_id: &str,
) -> bool {
  routes
    .iter()
    .find(|route| pinned_provider_id(&route.gateway_provider_id) == target_provider_id)
    .is_some_and(|route| catalogue_allows_unknown_models(catalogues, &route.gateway_provider_id))
}

fn add_unique_catalogue_model_rules(
  rules: &mut Vec<ModelReferenceRule>,
  catalogues: &BTreeMap<String, ProviderCatalogue>,
  target_provider_id: &str,
  qualify_target: bool,
) -> Result<()> {
  let mut owners: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
  for (provider_id, catalogue) in catalogues {
    for model_id in catalogue.models.keys() {
      owners.entry(model_id).or_default().push(provider_id);
    }
  }
  for (model_id, providers) in owners {
    let [provider_id] = providers.as_slice() else {
      continue;
    };
    insert_reference_rule(
      rules,
      ModelReferenceRule {
        source_provider_id: SHARED_PROVIDER_ID.to_string(),
        source_model_match: ModelReferenceMatch::Exact(model_id.to_string()),
        target_provider_id: target_provider_id.to_string(),
        target_model_prefix: qualify_target.then(|| (*provider_id).to_string()),
        allow_missing_model: false,
      },
    )?;
  }
  Ok(())
}

fn add_shared_known_model_rejections(
  rules: &mut Vec<ModelReferenceRule>,
  mode: RouteMode,
  previous_mode: Option<RouteMode>,
  routes: &[ProviderRoute],
  catalogues: &BTreeMap<String, ProviderCatalogue>,
) -> Result<()> {
  let ambiguous_sources = ambiguous_source_provider_ids(routes);
  for route in routes {
    let Some(catalogue) = catalogues.get(&route.gateway_provider_id) else {
      continue;
    };
    for model_id in unpublished_model_ids(catalogue) {
      if mode != RouteMode::Exact || !ambiguous_sources.contains(route.source_provider_id.as_str()) {
        insert_reference_rule(
          rules,
          ModelReferenceRule {
            source_provider_id: route.source_provider_id.clone(),
            source_model_match: ModelReferenceMatch::Exact(model_id.clone()),
            target_provider_id: SHARED_PROVIDER_ID.to_string(),
            target_model_prefix: (mode == RouteMode::Exact).then(|| route.gateway_provider_id.clone()),
            allow_missing_model: false,
          },
        )?;
      }

      let current_shared_model_id = if mode == RouteMode::Exact {
        format!("{}/{model_id}", route.gateway_provider_id)
      } else {
        model_id.clone()
      };
      if mode == RouteMode::Exact || !model_is_published_by_any_provider(catalogues, model_id) {
        insert_reference_rule(
          rules,
          ModelReferenceRule {
            source_provider_id: SHARED_PROVIDER_ID.to_string(),
            source_model_match: ModelReferenceMatch::Exact(current_shared_model_id),
            target_provider_id: SHARED_PROVIDER_ID.to_string(),
            target_model_prefix: None,
            allow_missing_model: false,
          },
        )?;
      }

      if previous_mode.is_some_and(is_verbatim_mode) {
        insert_reference_rule(
          rules,
          ModelReferenceRule {
            source_provider_id: pinned_provider_id(&route.gateway_provider_id),
            source_model_match: ModelReferenceMatch::Exact(model_id.clone()),
            target_provider_id: SHARED_PROVIDER_ID.to_string(),
            target_model_prefix: (mode == RouteMode::Exact).then(|| route.gateway_provider_id.clone()),
            allow_missing_model: false,
          },
        )?;
      }

      if previous_mode == Some(RouteMode::Exact) && mode != RouteMode::Exact {
        insert_reference_rule(
          rules,
          ModelReferenceRule {
            source_provider_id: SHARED_PROVIDER_ID.to_string(),
            source_model_match: ModelReferenceMatch::Exact(format!("{}/{model_id}", route.gateway_provider_id)),
            target_provider_id: SHARED_PROVIDER_ID.to_string(),
            target_model_prefix: None,
            allow_missing_model: false,
          },
        )?;
      }
    }
  }

  if matches!(previous_mode, Some(RouteMode::Route | RouteMode::Fuzzy)) && mode == RouteMode::Exact {
    for model_id in globally_unpublished_model_ids(catalogues) {
      let provider_id = catalogues
        .iter()
        .find(|(_, catalogue)| catalogue.known_model_ids.contains(model_id))
        .map(|(provider_id, _)| provider_id)
        .expect("globally unpublished model came from a provider");
      insert_reference_rule(
        rules,
        ModelReferenceRule {
          source_provider_id: SHARED_PROVIDER_ID.to_string(),
          source_model_match: ModelReferenceMatch::Exact(model_id.clone()),
          target_provider_id: SHARED_PROVIDER_ID.to_string(),
          target_model_prefix: Some(provider_id.clone()),
          allow_missing_model: false,
        },
      )?;
    }
  }
  Ok(())
}

fn add_pinned_known_model_rejections(
  rules: &mut Vec<ModelReferenceRule>,
  previous_mode: Option<RouteMode>,
  routes: &[ProviderRoute],
  catalogues: &BTreeMap<String, ProviderCatalogue>,
) -> Result<()> {
  for route in routes {
    let Some(catalogue) = catalogues.get(&route.gateway_provider_id) else {
      continue;
    };
    let target_provider_id = pinned_provider_id(&route.gateway_provider_id);
    if !catalogue.endpoint_model_rules.is_empty() {
      for source_provider_id in [&route.source_provider_id, &target_provider_id] {
        insert_reference_rule(
          rules,
          ModelReferenceRule {
            source_provider_id: source_provider_id.clone(),
            source_model_match: ModelReferenceMatch::EndpointIncompatible(catalogue.endpoint_model_rules.clone()),
            target_provider_id: target_provider_id.clone(),
            target_model_prefix: None,
            allow_missing_model: false,
          },
        )?;
      }
    }
    for model_id in unpublished_model_ids(catalogue) {
      for source_provider_id in [&route.source_provider_id, &target_provider_id] {
        insert_reference_rule(
          rules,
          ModelReferenceRule {
            source_provider_id: source_provider_id.clone(),
            source_model_match: ModelReferenceMatch::Exact(model_id.clone()),
            target_provider_id: target_provider_id.clone(),
            target_model_prefix: None,
            allow_missing_model: false,
          },
        )?;
      }
      if previous_mode == Some(RouteMode::Exact) {
        insert_reference_rule(
          rules,
          ModelReferenceRule {
            source_provider_id: SHARED_PROVIDER_ID.to_string(),
            source_model_match: ModelReferenceMatch::Exact(format!("{}/{model_id}", route.gateway_provider_id)),
            target_provider_id: target_provider_id.clone(),
            target_model_prefix: None,
            allow_missing_model: false,
          },
        )?;
      }
    }
  }
  Ok(())
}

fn unpublished_model_ids(catalogue: &ProviderCatalogue) -> impl Iterator<Item = &String> {
  catalogue
    .known_model_ids
    .iter()
    .filter(|model_id| !catalogue.models.contains_key(*model_id))
}

fn globally_unpublished_model_ids(catalogues: &BTreeMap<String, ProviderCatalogue>) -> impl Iterator<Item = &String> {
  catalogues
    .values()
    .flat_map(|catalogue| catalogue.known_model_ids.iter())
    .filter(|model_id| !model_is_published_by_any_provider(catalogues, model_id))
}

fn model_is_published_by_any_provider(catalogues: &BTreeMap<String, ProviderCatalogue>, model_id: &str) -> bool {
  catalogues
    .values()
    .any(|catalogue| catalogue.models.contains_key(model_id))
}

fn insert_reference_rule(rules: &mut Vec<ModelReferenceRule>, rule: ModelReferenceRule) -> Result<()> {
  if let Some(existing) = rules.iter().find(|existing| {
    existing.source_provider_id == rule.source_provider_id && existing.source_model_match == rule.source_model_match
  }) {
    if existing != &rule {
      return Err(anyhow!(
        "OpenCode provider '{}' maps the same model selection to more than one gateway provider",
        rule.source_provider_id
      ));
    }
    return Ok(());
  }
  rules.push(rule);
  Ok(())
}

fn pinned_provider_id(provider_id: &str) -> String {
  format!("{SHARED_PROVIDER_ID}-{provider_id}")
}

fn is_verbatim_mode(mode: RouteMode) -> bool {
  matches!(mode, RouteMode::Passthrough | RouteMode::Switch)
}

pub(crate) fn publication_ids(publications: &[ProviderPublication]) -> BTreeSet<&str> {
  publications
    .iter()
    .map(|publication| publication.provider_id.as_str())
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;
  use tokn_core::provider::{ID_DEEPSEEK, ID_OPENAI};
  use tokn_core::util::secret::Secret;

  fn account(id: &str, provider: &str) -> Account {
    Account {
      id: id.into(),
      provider: provider.into(),
      enabled: true,
      tier: tokn_core::account::AccountTier::Active,
      tags: Vec::new(),
      label: None,
      base_url: None,
      headers: Default::default(),
      auth_type: None,
      username: None,
      api_key: Some(Secret::new("test-key".into())),
      api_key_expires_at: None,
      access_token: None,
      access_token_expires_at: None,
      id_token: None,
      refresh_token: None,
      provider_account_id: None,
      extra: Default::default(),
      refresh_url: None,
      last_refresh: None,
      settings: toml::Table::new(),
    }
  }

  fn route(source: &str, provider: &str, profile: &str) -> ProviderRoute {
    ProviderRoute {
      source_provider_id: source.into(),
      gateway_provider_id: provider.into(),
      account_id: String::new(),
      profile: profile.into(),
      base_url: format!("http://127.0.0.1:4141/{profile}/v1"),
      transfer_source_auth: false,
    }
  }

  #[test]
  fn route_deduplicates_models_under_one_provider() {
    let accounts = [account("openai", ID_OPENAI), account("deepseek", ID_DEEPSEEK)];
    let routes = [
      route(ID_OPENAI, ID_OPENAI, "opencode-openai"),
      route(ID_DEEPSEEK, ID_DEEPSEEK, "opencode-deepseek"),
    ];
    let plan = compile_opencode_publications(
      RouteMode::Route,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &accounts,
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let publications = plan.publications;
    let rules = plan.model_reference_rules;

    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0].provider_id, SHARED_PROVIDER_ID);
    assert!(publications[0].models.contains_key("gpt-5"));
    assert!(publications[0]
      .models
      .keys()
      .any(|model| model.starts_with("deepseek-")));
    for source_provider_id in [ID_OPENAI, ID_DEEPSEEK] {
      assert!(rules.iter().any(|rule| {
        rule.source_provider_id == source_provider_id
          && rule.source_model_match == ModelReferenceMatch::Any
          && rule.target_provider_id == SHARED_PROVIDER_ID
      }));
    }
  }

  #[test]
  fn exact_allows_credentialless_gateway_providers_that_share_one_opencode_namespace() {
    let codex_provider_id = tokn_core::provider::ID_CODEX;
    let accounts = [account("openai", ID_OPENAI), account("codex", codex_provider_id)];
    let routes = [
      route(ID_OPENAI, ID_OPENAI, "opencode"),
      route(ID_OPENAI, codex_provider_id, "opencode"),
    ];

    let plan = compile_opencode_publications(
      RouteMode::Exact,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &accounts,
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    let publication = &plan.publications[0];
    assert!(publication.models.contains_key("openai/gpt-5"));
    assert!(publication.models.keys().any(|model_id| model_id.starts_with("codex/")));
    assert!(!plan
      .model_reference_rules
      .iter()
      .any(|rule| rule.source_provider_id == ID_OPENAI));
    for gateway_provider_id in [ID_OPENAI, codex_provider_id] {
      assert!(plan.model_reference_rules.iter().any(|rule| {
        rule.source_provider_id == SHARED_PROVIDER_ID
          && rule.source_model_match == ModelReferenceMatch::Prefix(gateway_provider_id.to_string())
          && rule.target_model_prefix.as_deref() == Some(gateway_provider_id)
      }));
    }
  }

  #[test]
  fn exact_rejects_agent_owned_or_transferred_ambiguous_source_namespaces() {
    for (account_id, transfer_source_auth) in [("agent-account", false), ("", true)] {
      let mut routes = [
        route(ID_OPENAI, ID_OPENAI, "opencode"),
        route(ID_OPENAI, tokn_core::provider::ID_CODEX, "opencode"),
      ];
      routes[0].account_id = account_id.to_string();
      routes[0].transfer_source_auth = transfer_source_auth;

      let error = compile_opencode_publications(
        RouteMode::Exact,
        None,
        None,
        "http://127.0.0.1:4141/opencode/v1",
        &[],
        &routes,
        Endpoint::ChatCompletions,
      )
      .unwrap_err();

      assert!(error.to_string().contains("represents multiple gateway providers"));
      assert!(error.to_string().contains("--provider-filter"));
    }
  }

  #[test]
  fn routes_without_materialized_accounts_use_the_static_catalogue() {
    let routes = [route(ID_OPENAI, ID_OPENAI, "opencode")];
    let plan = compile_opencode_publications(
      RouteMode::Route,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let publications = plan.publications;

    assert!(publications[0].models.contains_key("gpt-5"));
  }

  #[test]
  fn publication_excludes_embedding_and_image_generation_models() {
    let routes = [route(ID_OPENAI, ID_OPENAI, "opencode")];
    let plan = compile_opencode_publications(
      RouteMode::Route,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    let models = &plan.publications[0].models;
    assert!(models.contains_key("gpt-5"));
    assert!(!models.keys().any(|model| model.starts_with("text-embedding")));
    assert!(!models.keys().any(|model| model.contains("gpt-image")));
  }

  #[test]
  fn known_non_chat_models_are_rejected_instead_of_treated_as_custom() {
    let routes = [route(ID_OPENAI, ID_OPENAI, "opencode")];
    let plan = compile_opencode_publications(
      RouteMode::Route,
      Some(RouteMode::Route),
      Some(&[ID_OPENAI.to_string()]),
      "http://127.0.0.1:4141/opencode/v1",
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    for source_provider_id in [ID_OPENAI, SHARED_PROVIDER_ID] {
      for model_id in ["text-embedding-3-large", "gpt-image-1"] {
        assert!(plan.model_reference_rules.iter().any(|rule| {
          rule.source_provider_id == source_provider_id
            && rule.source_model_match == ModelReferenceMatch::Exact(model_id.to_string())
            && !rule.allow_missing_model
        }));
      }
    }
    assert!(!plan.model_reference_rules.iter().any(|rule| {
      rule.source_model_match == ModelReferenceMatch::Exact("organization/custom-model".to_string())
        && !rule.allow_missing_model
    }));
  }

  #[test]
  fn raw_endpoint_incompatible_models_are_rejected_for_direct_and_generated_selections() {
    let provider_id = tokn_core::provider::ID_GITHUB_COPILOT;
    let routes = [route(provider_id, provider_id, "opencode-github-copilot")];
    let plan = compile_opencode_publications(
      RouteMode::Switch,
      Some(RouteMode::Switch),
      Some(&[provider_id.to_string()]),
      "http://127.0.0.1:4141/opencode/v1",
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    assert!(!plan.publications[0].models.contains_key("gpt-5"));
    for source_provider_id in [provider_id.to_string(), pinned_provider_id(provider_id)] {
      assert!(
        plan.model_reference_rules.iter().any(|rule| {
          rule.source_provider_id == source_provider_id
            && !rule.allow_missing_model
            && matches!(&rule.source_model_match, ModelReferenceMatch::EndpointIncompatible(rules)
              if rules
                .iter()
                .find(|endpoint_rule| tokn_core::provider::glob_match(&endpoint_rule.pattern, "gpt-5"))
                .is_some_and(|endpoint_rule| !endpoint_rule.allows_endpoint))
        }),
        "missing endpoint rejection for {source_provider_id}"
      );
    }
  }

  #[test]
  fn providers_with_dynamic_catalogues_are_reported() {
    let routes = [route(
      tokn_core::provider::ID_LLAMA_CPP,
      tokn_core::provider::ID_LLAMA_CPP,
      "opencode",
    )];
    let plan = compile_opencode_publications(
      RouteMode::Route,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    assert!(plan.publications[0].models.is_empty());
    assert_eq!(
      plan.providers_without_models,
      [tokn_core::provider::ID_LLAMA_CPP.to_string()]
    );
  }

  #[test]
  fn disabled_imported_accounts_do_not_seed_the_static_catalogue() {
    let mut disabled = account("disabled-openai", ID_OPENAI);
    disabled.enabled = false;
    let mut disabled_route = route(ID_OPENAI, ID_OPENAI, "opencode-openai");
    disabled_route.account_id = disabled.id.clone();
    let plan = compile_opencode_publications(
      RouteMode::Route,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &[disabled],
      &[disabled_route],
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let publications = plan.publications;

    assert!(publications[0].models.is_empty());
  }

  #[test]
  fn provider_ids_with_slashes_cannot_be_projected_into_opencode() {
    let routes = [route("openai", "provider/with-slash", "opencode")];
    let error = compile_opencode_publications(
      RouteMode::Route,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap_err();

    assert!(error.to_string().contains("cannot be published safely"));
  }

  #[test]
  fn duplicate_models_collapse_in_route_and_remain_distinct_in_exact() {
    let routes = [
      route(
        tokn_core::provider::ID_GITHUB_COPILOT,
        tokn_core::provider::ID_GITHUB_COPILOT,
        "opencode-github-copilot",
      ),
      route(ID_OPENAI, ID_OPENAI, "opencode-openai"),
    ];
    let catalogues = BTreeMap::from([
      (
        tokn_core::provider::ID_GITHUB_COPILOT.to_string(),
        ProviderCatalogue {
          display_name: "GitHub Copilot".to_string(),
          models: BTreeMap::from([(
            "shared-model".to_string(),
            PublishedModel {
              name: "Shared model".to_string(),
            },
          )]),
          known_model_ids: BTreeSet::from(["shared-model".to_string()]),
          allows_unknown_models: false,
          endpoint_model_rules: Vec::new(),
        },
      ),
      (
        ID_OPENAI.to_string(),
        ProviderCatalogue {
          display_name: "OpenAI".to_string(),
          models: BTreeMap::from([(
            "shared-model".to_string(),
            PublishedModel {
              name: "Shared model".to_string(),
            },
          )]),
          known_model_ids: BTreeSet::from(["shared-model".to_string()]),
          allows_unknown_models: false,
          endpoint_model_rules: Vec::new(),
        },
      ),
    ]);
    let (route_publications, _) = compile_shared_publication(
      RouteMode::Route,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &routes,
      &catalogues,
    )
    .unwrap();
    assert_eq!(
      route_publications[0]
        .models
        .keys()
        .filter(|model_id| model_id.as_str() == "shared-model")
        .count(),
      1
    );

    let (exact_publications, _) = compile_shared_publication(
      RouteMode::Exact,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &routes,
      &catalogues,
    )
    .unwrap();
    assert!(exact_publications[0].models.contains_key("github-copilot/shared-model"));
    assert!(exact_publications[0].models.contains_key("openai/shared-model"));
    assert_ne!(
      exact_publications[0].models["github-copilot/shared-model"].name,
      exact_publications[0].models["openai/shared-model"].name
    );
  }

  #[test]
  fn exact_qualifies_models_inside_the_shared_provider() {
    let accounts = [account("openai", ID_OPENAI), account("deepseek", ID_DEEPSEEK)];
    let routes = [
      route(ID_OPENAI, ID_OPENAI, "opencode-openai"),
      route(ID_DEEPSEEK, ID_DEEPSEEK, "opencode-deepseek"),
    ];
    let plan = compile_opencode_publications(
      RouteMode::Exact,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &accounts,
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let publications = plan.publications;
    let rules = plan.model_reference_rules;

    assert!(publications[0].models.contains_key("openai/gpt-5"));
    assert!(publications[0]
      .models
      .keys()
      .any(|model| model.starts_with("deepseek/deepseek-")));
    assert_eq!(
      rules
        .iter()
        .find(|rule| rule.source_provider_id == ID_DEEPSEEK)
        .and_then(|rule| rule.target_model_prefix.as_deref()),
      Some(ID_DEEPSEEK)
    );
  }

  #[test]
  fn switch_publishes_one_provider_per_target() {
    let accounts = [account("openai", ID_OPENAI), account("deepseek", ID_DEEPSEEK)];
    let routes = [
      route(ID_OPENAI, ID_OPENAI, "opencode-openai"),
      route(ID_DEEPSEEK, ID_DEEPSEEK, "opencode-deepseek"),
    ];
    let plan = compile_opencode_publications(
      RouteMode::Switch,
      None,
      None,
      "http://127.0.0.1:4141/opencode/v1",
      &accounts,
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let publications = plan.publications;

    assert_eq!(
      publications
        .iter()
        .map(|publication| publication.provider_id.as_str())
        .collect::<Vec<_>>(),
      vec!["tokn-router-deepseek", "tokn-router-openai"]
    );
  }

  #[test]
  fn normalized_modes_compile_generated_provider_relink_rules() {
    let accounts = [account("openai", ID_OPENAI), account("deepseek", ID_DEEPSEEK)];
    let routes = [
      route(ID_OPENAI, ID_OPENAI, "opencode-openai"),
      route(ID_DEEPSEEK, ID_DEEPSEEK, "opencode-deepseek"),
    ];

    let route_plan = compile_opencode_publications(
      RouteMode::Route,
      Some(RouteMode::Exact),
      Some(&[ID_OPENAI.into(), ID_DEEPSEEK.into()]),
      "http://127.0.0.1:4141/opencode/v1",
      &accounts,
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let route_rules = route_plan.model_reference_rules;
    assert!(!route_rules
      .iter()
      .any(|rule| rule.source_provider_id == "tokn-router-openai"));
    assert!(route_rules.iter().any(|rule| {
      rule.source_provider_id == SHARED_PROVIDER_ID
        && rule.source_model_match == ModelReferenceMatch::Prefix(ID_OPENAI.to_string())
        && rule.target_model_prefix.is_none()
    }));

    let exact_plan = compile_opencode_publications(
      RouteMode::Exact,
      Some(RouteMode::Route),
      Some(&[ID_OPENAI.into(), ID_DEEPSEEK.into()]),
      "http://127.0.0.1:4141/opencode/v1",
      &accounts,
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let exact_rules = exact_plan.model_reference_rules;
    assert!(exact_rules.iter().any(|rule| {
      rule.source_provider_id == SHARED_PROVIDER_ID && matches!(rule.source_model_match, ModelReferenceMatch::Exact(_))
    }));
  }

  #[test]
  fn pinned_mode_maps_shared_models_only_when_the_target_is_unambiguous() {
    let accounts = [account("openai", ID_OPENAI), account("deepseek", ID_DEEPSEEK)];
    let routes = [
      route(ID_OPENAI, ID_OPENAI, "opencode-openai"),
      route(ID_DEEPSEEK, ID_DEEPSEEK, "opencode-deepseek"),
    ];
    let multi_plan = compile_opencode_publications(
      RouteMode::Switch,
      Some(RouteMode::Route),
      Some(&[ID_OPENAI.into(), ID_DEEPSEEK.into()]),
      "http://127.0.0.1:4141/opencode/v1",
      &accounts,
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let multi_rules = multi_plan.model_reference_rules;
    assert!(!multi_rules.iter().any(|rule| {
      rule.source_provider_id == SHARED_PROVIDER_ID && rule.source_model_match == ModelReferenceMatch::Any
    }));

    let single_plan = compile_opencode_publications(
      RouteMode::Switch,
      Some(RouteMode::Route),
      Some(&[ID_OPENAI.into()]),
      "http://127.0.0.1:4141/opencode/v1",
      &accounts[..1],
      &routes[..1],
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let single_rules = single_plan.model_reference_rules;
    assert!(single_rules.iter().any(|rule| {
      rule.source_provider_id == SHARED_PROVIDER_ID
        && rule.source_model_match == ModelReferenceMatch::Any
        && rule.target_provider_id == "tokn-router-openai"
        && !rule.allow_missing_model
    }));
  }

  #[test]
  fn pinned_relinks_preserve_custom_models_for_an_open_target_catalogue() {
    let provider_id = tokn_core::provider::ID_LLAMA_CPP;
    let routes = [route(provider_id, provider_id, "opencode")];
    let generated_provider_id = pinned_provider_id(provider_id);

    for previous_mode in [RouteMode::Route, RouteMode::Fuzzy] {
      for mode in [RouteMode::Switch, RouteMode::Passthrough] {
        let plan = compile_opencode_publications(
          mode,
          Some(previous_mode),
          Some(&[provider_id.to_string()]),
          "http://127.0.0.1:4141/opencode/v1",
          &[],
          &routes,
          Endpoint::ChatCompletions,
        )
        .unwrap();

        assert!(plan.model_reference_rules.iter().any(|rule| {
          rule.source_provider_id == SHARED_PROVIDER_ID
            && rule.source_model_match == ModelReferenceMatch::Any
            && rule.target_provider_id == generated_provider_id
            && rule.allow_missing_model
        }));
      }
    }

    for previous_mode in [RouteMode::Switch, RouteMode::Passthrough] {
      let plan = compile_opencode_publications(
        RouteMode::Switch,
        Some(previous_mode),
        Some(&[ID_OPENAI.to_string()]),
        "http://127.0.0.1:4141/opencode/v1",
        &[],
        &routes,
        Endpoint::ChatCompletions,
      )
      .unwrap();

      assert!(plan.model_reference_rules.iter().any(|rule| {
        rule.source_provider_id == pinned_provider_id(ID_OPENAI)
          && rule.source_model_match == ModelReferenceMatch::Any
          && rule.target_provider_id == generated_provider_id
          && rule.allow_missing_model
      }));
    }
  }

  #[test]
  fn normalized_relink_preserves_custom_models_only_for_open_providers_with_unchanged_scope() {
    fn shared_fallback(plan: &OpenCodePublicationPlan) -> &ModelReferenceRule {
      plan
        .model_reference_rules
        .iter()
        .find(|rule| {
          rule.source_provider_id == SHARED_PROVIDER_ID && rule.source_model_match == ModelReferenceMatch::Any
        })
        .expect("normalized relink has a shared fallback")
    }

    let provider_id = tokn_core::provider::ID_LLAMA_CPP;
    let routes = [route(provider_id, provider_id, "opencode")];
    let unchanged = compile_opencode_publications(
      RouteMode::Route,
      Some(RouteMode::Route),
      Some(&[provider_id.to_string()]),
      "http://127.0.0.1:4141/opencode/v1",
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let narrowed = compile_opencode_publications(
      RouteMode::Route,
      Some(RouteMode::Route),
      Some(&[provider_id.to_string(), ID_DEEPSEEK.to_string()]),
      "http://127.0.0.1:4141/opencode/v1",
      &[],
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();
    let static_routes = [route(ID_OPENAI, ID_OPENAI, "opencode")];
    let static_provider = compile_opencode_publications(
      RouteMode::Route,
      Some(RouteMode::Route),
      Some(&[ID_OPENAI.to_string()]),
      "http://127.0.0.1:4141/opencode/v1",
      &[],
      &static_routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    assert!(shared_fallback(&unchanged).allow_missing_model);
    assert!(!shared_fallback(&narrowed).allow_missing_model);
    assert!(!shared_fallback(&static_provider).allow_missing_model);
  }

  #[test]
  fn raw_to_normalized_relink_rejects_unknown_models_for_static_providers() {
    let accounts = [account("openai", ID_OPENAI)];
    let routes = [route(ID_OPENAI, ID_OPENAI, "opencode")];

    for mode in [RouteMode::Route, RouteMode::Fuzzy, RouteMode::Exact] {
      for previous_mode in [RouteMode::Switch, RouteMode::Passthrough] {
        let plan = compile_opencode_publications(
          mode,
          Some(previous_mode),
          Some(&[ID_OPENAI.to_string(), ID_DEEPSEEK.to_string()]),
          "http://127.0.0.1:4141/opencode/v1",
          &accounts,
          &routes,
          Endpoint::ChatCompletions,
        )
        .unwrap();

        let retained = plan
          .model_reference_rules
          .iter()
          .find(|rule| rule.source_provider_id == "tokn-router-openai")
          .expect("retained provider has a transition rule");
        assert!(!retained.allow_missing_model);
        assert_eq!(
          retained.target_model_prefix.as_deref(),
          (mode == RouteMode::Exact).then_some(ID_OPENAI)
        );

        let removed = plan
          .model_reference_rules
          .iter()
          .find(|rule| rule.source_provider_id == "tokn-router-deepseek")
          .expect("removed provider has a rejecting transition rule");
        assert!(!removed.allow_missing_model);
        assert_eq!(
          removed.target_model_prefix.as_deref(),
          (mode == RouteMode::Exact).then_some(ID_DEEPSEEK)
        );
      }
    }
  }

  #[test]
  fn raw_main_provider_retarget_maps_only_models_in_the_new_catalogue() {
    let accounts = [account("deepseek", ID_DEEPSEEK)];
    let routes = [route(ID_DEEPSEEK, ID_DEEPSEEK, "opencode")];
    let plan = compile_opencode_publications(
      RouteMode::Switch,
      Some(RouteMode::Switch),
      Some(&[ID_OPENAI.to_string()]),
      "http://127.0.0.1:4141/opencode/v1",
      &accounts,
      &routes,
      Endpoint::ChatCompletions,
    )
    .unwrap();

    assert!(plan.model_reference_rules.iter().any(|rule| {
      rule.source_provider_id == "tokn-router-openai"
        && rule.source_model_match == ModelReferenceMatch::Any
        && rule.target_provider_id == "tokn-router-deepseek"
        && !rule.allow_missing_model
    }));
  }
}
