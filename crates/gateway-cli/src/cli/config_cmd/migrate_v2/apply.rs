use super::{backup, plan_output, AuthPreimage, MigrateV2Args, PreparedMigration};
use anyhow::{bail, Context, Error, Result};
use std::path::{Path, PathBuf};
use tokn_auth::{AuthStore, AuthStoreLock};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ApplyCheckpoint {
  BackedUp,
  CredentialsDurable,
  BeforeActivation,
  Activated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ApplyReport {
  pub(super) config_path: PathBuf,
  pub(super) backup_path: PathBuf,
  pub(super) backup_created: bool,
  pub(super) auth_created: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplyProgress {
  Acknowledged,
  BackedUp,
  CredentialsDurable,
  ActivationAttempted,
  Activated,
}

pub(super) struct ApplyFailure {
  source: Error,
  progress: ApplyProgress,
  config_path: PathBuf,
  auth_path: PathBuf,
  auth_created: bool,
}

impl ApplyFailure {
  pub(super) fn activation_may_have_completed(&self) -> bool {
    matches!(
      self.progress,
      ApplyProgress::ActivationAttempted | ApplyProgress::Activated
    )
  }

  pub(super) fn auth_created(&self) -> bool {
    self.auth_created
  }

  pub(super) fn config_path(&self) -> &Path {
    &self.config_path
  }

  pub(super) fn auth_path(&self) -> &Path {
    &self.auth_path
  }

  pub(super) fn into_error(self) -> Error {
    self.source
  }
}

/// Apply a prepared migration monotonically, with the root config rename as
/// the only activation point.
pub(super) fn apply(
  prepared: &PreparedMigration,
  args: &MigrateV2Args,
  legacy_contents: &[u8],
  checkpoint: &mut dyn FnMut(ApplyCheckpoint) -> Result<()>,
) -> std::result::Result<ApplyReport, ApplyFailure> {
  let config_path = prepared.legacy.snapshot.root().to_path_buf();
  let auth_path = prepared.auth_path.clone();
  let mut progress = ApplyProgress::Acknowledged;
  let mut auth_created = false;
  apply_inner(
    prepared,
    args,
    legacy_contents,
    checkpoint,
    &mut progress,
    &mut auth_created,
  )
  .map_err(|source| ApplyFailure {
    source,
    progress,
    config_path,
    auth_path,
    auth_created,
  })
}

fn apply_inner(
  prepared: &PreparedMigration,
  args: &MigrateV2Args,
  legacy_contents: &[u8],
  checkpoint: &mut dyn FnMut(ApplyCheckpoint) -> Result<()>,
  progress: &mut ApplyProgress,
  auth_created: &mut bool,
) -> Result<ApplyReport> {
  let snapshot = &prepared.legacy.snapshot;
  if snapshot.root_preimage() != Some(legacy_contents) {
    bail!("prepared legacy config preimage does not match the apply input");
  }

  // Every workflow that may hold both guards uses this order.
  let config_lock = tokn_config::lock_config_file(snapshot.root()).context("lock legacy config for migration")?;
  snapshot
    .validate_locked(&config_lock)
    .context("revalidate legacy config after acquiring its lock")?;
  let auth_lock = AuthStoreLock::acquire(Some(&prepared.auth_path)).context("lock modern credential sources")?;
  snapshot
    .validate_locked(&config_lock)
    .context("revalidate legacy config after acquiring credential lock")?;

  let mut store = AuthStore::load_locked(&auth_lock).context("load locked modern credential sources")?;
  if AuthPreimage::capture(&store) != prepared.auth_preimage {
    bail!("modern credential sources changed after migration preflight; retry the command");
  }
  store
    .validate_locked(&auth_lock)
    .context("revalidate modern credential sources before backup")?;

  let backup = backup::ensure_legacy_backup(snapshot.root(), legacy_contents)?;
  *progress = ApplyProgress::BackedUp;
  checkpoint(ApplyCheckpoint::BackedUp).context("migration interrupted after creating the legacy backup")?;
  snapshot
    .validate_locked(&config_lock)
    .context("revalidate legacy config after backup")?;
  store
    .validate_locked(&auth_lock)
    .context("revalidate modern credential sources after backup")?;

  if !store.has_persisted_sources() {
    for account in &prepared.embedded_accounts {
      store
        .upsert_in_main(account.clone())
        .with_context(|| format!("stage embedded account `{}` in modern auth", account.id))?;
    }
    store
      .save_locked(&auth_lock)
      .context("make embedded credentials durable before config activation")?;
    *auth_created = store.has_persisted_sources();
  }
  *progress = ApplyProgress::CredentialsDurable;
  checkpoint(ApplyCheckpoint::CredentialsDurable).context("migration interrupted after making credentials durable")?;

  let durable_store = AuthStore::load_locked(&auth_lock).context("reload durable modern credential sources")?;
  let durable_output = plan_output(&prepared.legacy.config, &durable_store.accounts, snapshot.root(), args)
    .context("preflight generated config against durable credentials")?;
  if durable_output != prepared.output {
    bail!("generated version 2 config changed after credentials became durable; retry the command");
  }
  snapshot
    .validate_locked(&config_lock)
    .context("revalidate legacy config before activation")?;
  durable_store
    .validate_locked(&auth_lock)
    .context("revalidate durable credentials before activation")?;
  checkpoint(ApplyCheckpoint::BeforeActivation).context("migration interrupted before config activation")?;
  snapshot
    .validate_locked(&config_lock)
    .context("revalidate legacy config at activation")?;
  durable_store
    .validate_locked(&auth_lock)
    .context("revalidate durable credentials at activation")?;

  // Once the atomic writer starts, an error can no longer prove that the
  // destination was not renamed (for example, a parent-directory sync can
  // fail after the rename). Report every later failure conservatively.
  *progress = ApplyProgress::ActivationAttempted;
  config_lock
    .replace_contents_if_unchanged(Some(legacy_contents), prepared.output.rendered.as_bytes())
    .context("activate generated version 2 config")?;
  *progress = ApplyProgress::Activated;
  checkpoint(ApplyCheckpoint::Activated).context("migration interrupted after config activation")?;

  let readback = std::fs::read(config_lock.path())
    .with_context(|| format!("read activated version 2 config `{}`", snapshot.root().display()))?;
  if readback != prepared.output.rendered.as_bytes() {
    bail!(
      "activated config `{}` does not contain the exact generated version 2 bytes",
      snapshot.root().display()
    );
  }
  let readback = std::str::from_utf8(&readback)
    .with_context(|| format!("read activated config `{}` as UTF-8", snapshot.root().display()))?;
  let compiled = tokn_config::v2::parse(readback, snapshot.root()).context("parse activated version 2 config")?;
  tokn_router::runtime::link_builtin_gateway_runtime(compiled.gateway(), &durable_store.accounts)
    .context("link activated version 2 gateway runtime")?;
  durable_store
    .validate_locked(&auth_lock)
    .context("revalidate credentials after config activation")?;

  Ok(ApplyReport {
    config_path: snapshot.root().to_path_buf(),
    backup_path: backup.path,
    backup_created: backup.created,
    auth_created: *auth_created,
  })
}
