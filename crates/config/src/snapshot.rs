use super::{Config, ConfigFileLock, ConfigSources, Error, Result};
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

/// An effective legacy configuration bracketed by an exact source snapshot.
#[derive(Clone)]
pub struct StableLoadedConfig {
  pub config: Config,
  pub snapshot: ConfigSourcesSnapshot,
}

impl std::fmt::Debug for StableLoadedConfig {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("StableLoadedConfig")
      .field("snapshot", &self.snapshot)
      .finish_non_exhaustive()
  }
}

/// Exact source paths and bytes contributing to an effective configuration.
///
/// Source bytes are intentionally private. The root preimage is exposed for
/// guarded whole-config migration, while fragment bytes are retained only for
/// exact validation.
#[derive(Clone)]
pub struct ConfigSourcesSnapshot {
  root: PathBuf,
  canonical_root: Option<PathBuf>,
  root_preimage: Option<Vec<u8>>,
  fragment_dir: PathBuf,
  fragment_dir_exists: bool,
  fragments: Vec<PathBuf>,
  fragment_preimages: Vec<Vec<u8>>,
}

impl PartialEq for ConfigSourcesSnapshot {
  fn eq(&self, other: &Self) -> bool {
    self.root == other.root
      && self.root_preimage == other.root_preimage
      && self.fragment_dir == other.fragment_dir
      && self.fragment_dir_exists == other.fragment_dir_exists
      && self.fragments == other.fragments
      && self.fragment_preimages == other.fragment_preimages
  }
}

impl Eq for ConfigSourcesSnapshot {}

impl std::fmt::Debug for ConfigSourcesSnapshot {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("ConfigSourcesSnapshot")
      .field("root", &self.root)
      .field("root_present", &self.root_preimage.is_some())
      .field("fragment_dir", &self.fragment_dir)
      .field("fragment_dir_exists", &self.fragment_dir_exists)
      .field("fragments", &self.fragments)
      .finish()
  }
}

impl ConfigSourcesSnapshot {
  /// Primary configuration path, which may have been missing when captured.
  pub fn root(&self) -> &Path {
    &self.root
  }

  /// Exact primary configuration bytes, or `None` when it was missing.
  pub fn root_preimage(&self) -> Option<&[u8]> {
    self.root_preimage.as_deref()
  }

  /// Directory from which effective agent fragments were discovered.
  pub fn fragment_dir(&self) -> &Path {
    &self.fragment_dir
  }

  /// Whether the fragment directory existed when captured.
  pub fn fragment_dir_exists(&self) -> bool {
    self.fragment_dir_exists
  }

  /// Sorted fragment paths contributing to the effective configuration.
  pub fn fragments(&self) -> &[PathBuf] {
    &self.fragments
  }

  /// Require the complete source set and every exact source byte to remain
  /// unchanged.
  pub fn validate(&self) -> Result<()> {
    let current = Self::capture(&self.root)?;
    if current == *self {
      Ok(())
    } else {
      Err(Error::ConfigSourcesChanged {
        path: self.root.clone(),
      })
    }
  }

  /// Validate under an already-held writer lock for this snapshot's root.
  pub fn validate_locked(&self, lock: &ConfigFileLock) -> Result<()> {
    let snapshot_root = match &self.canonical_root {
      Some(path) => path.clone(),
      None => super::canonical_config_path(&self.root)?,
    };
    if snapshot_root != lock.path() {
      return Err(Error::ConfigSnapshotLockMismatch {
        snapshot_root: self.root.clone(),
        lock_root: lock.path().to_path_buf(),
      });
    }
    lock.validate_identity()?;
    let validation = self.validate();
    lock.validate_identity()?;
    validation
  }

  fn capture(root: &Path) -> Result<Self> {
    let before = Self::capture_once(root)?;
    let after = Self::capture_once(root)?;
    if before == after {
      Ok(before)
    } else {
      Err(Error::ConfigSourcesChanged {
        path: root.to_path_buf(),
      })
    }
  }

  fn capture_once(root: &Path) -> Result<Self> {
    let canonical_root = snapshot_root_identity(root)?;
    let root_preimage = read_optional_source(root)?;
    let fragment_dir = super::paths::config_fragment_dir(root);
    let discovered = discover_fragment_paths(&fragment_dir)?;
    let fragment_preimages = discovered
      .paths
      .iter()
      .map(|path| read_source(path))
      .collect::<Result<Vec<_>>>()?;
    Ok(Self {
      root: root.to_path_buf(),
      canonical_root,
      root_preimage,
      fragment_dir,
      fragment_dir_exists: discovered.directory_exists,
      fragments: discovered.paths,
      fragment_preimages,
    })
  }

  fn matches_loaded_sources(&self, sources: &ConfigSources) -> bool {
    self.root == sources.root && self.fragment_dir == sources.fragment_dir && self.fragments == sources.fragments
  }
}

fn snapshot_root_identity(root: &Path) -> Result<Option<PathBuf>> {
  let file_name = root.file_name().ok_or_else(|| Error::InvalidConfigLockPath {
    path: root.to_path_buf(),
  })?;
  let parent = super::config_parent(root);
  match std::fs::canonicalize(parent) {
    Ok(parent) => Ok(Some(parent.join(file_name))),
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
    Err(source) => Err(Error::Read {
      path: parent.to_path_buf(),
      source,
    }),
  }
}

impl Config {
  /// Load the effective legacy configuration only when the exact root and
  /// fragment sources remain stable across the complete load.
  pub fn load_stable(explicit: Option<&Path>) -> Result<StableLoadedConfig> {
    let root = super::resolve_config_path(explicit)?;
    let before = ConfigSourcesSnapshot::capture(&root)?;
    let loaded = Self::load_with_sources(Some(&root))?;
    let after = ConfigSourcesSnapshot::capture(&root)?;
    if before != after || !before.matches_loaded_sources(&loaded.sources) {
      return Err(Error::ConfigSourcesChanged { path: root });
    }
    Ok(StableLoadedConfig {
      config: loaded.config,
      snapshot: before,
    })
  }
}

struct DiscoveredFragments {
  directory_exists: bool,
  paths: Vec<PathBuf>,
}

pub(super) fn load_fragment_paths(fragment_dir: &Path) -> Result<Vec<PathBuf>> {
  Ok(discover_fragment_paths(fragment_dir)?.paths)
}

fn discover_fragment_paths(fragment_dir: &Path) -> Result<DiscoveredFragments> {
  let directory_metadata = match std::fs::symlink_metadata(fragment_dir) {
    Ok(metadata) if metadata.file_type().is_symlink() => {
      return Err(Error::ConfigSourceSymlink {
        path: fragment_dir.to_path_buf(),
      });
    }
    Ok(metadata) if !metadata.is_dir() => {
      return Err(Error::InvalidConfigSourceType {
        path: fragment_dir.to_path_buf(),
        expected: "a directory",
      });
    }
    Ok(metadata) => metadata,
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
      return Ok(DiscoveredFragments {
        directory_exists: false,
        paths: Vec::new(),
      });
    }
    Err(source) => {
      return Err(Error::Read {
        path: fragment_dir.to_path_buf(),
        source,
      });
    }
  };

  let entries = std::fs::read_dir(fragment_dir).map_err(|source| Error::Read {
    path: fragment_dir.to_path_buf(),
    source,
  })?;
  let mut fragments = Vec::new();
  for entry in entries {
    let entry = entry.map_err(|source| Error::Read {
      path: fragment_dir.to_path_buf(),
      source,
    })?;
    let path = entry.path();
    if !path.extension().is_some_and(|extension| extension == "toml") {
      continue;
    }
    match std::fs::symlink_metadata(&path) {
      Ok(metadata) if metadata.file_type().is_symlink() => {
        return Err(Error::ConfigSourceSymlink { path });
      }
      Ok(metadata) if metadata.is_file() => fragments.push(path),
      Ok(_) => {}
      Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
        return Err(Error::ConfigSourceChanged { path });
      }
      Err(source) => return Err(Error::Read { path, source }),
    }
  }
  validate_directory_identity(fragment_dir, &directory_metadata)?;
  fragments.sort();
  Ok(DiscoveredFragments {
    directory_exists: true,
    paths: fragments,
  })
}

fn read_optional_source(path: &Path) -> Result<Option<Vec<u8>>> {
  match source_metadata(path)? {
    Some(metadata) => read_opened_source(path, &metadata).map(Some),
    None => Ok(None),
  }
}

fn read_source(path: &Path) -> Result<Vec<u8>> {
  let metadata = source_metadata(path)?.ok_or_else(|| Error::ConfigSourceChanged {
    path: path.to_path_buf(),
  })?;
  read_opened_source(path, &metadata)
}

fn source_metadata(path: &Path) -> Result<Option<Metadata>> {
  match std::fs::symlink_metadata(path) {
    Ok(metadata) if metadata.file_type().is_symlink() => Err(Error::ConfigSourceSymlink {
      path: path.to_path_buf(),
    }),
    Ok(metadata) if !metadata.is_file() => Err(Error::InvalidConfigSourceType {
      path: path.to_path_buf(),
      expected: "a regular file",
    }),
    Ok(metadata) => Ok(Some(metadata)),
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
    Err(source) => Err(Error::Read {
      path: path.to_path_buf(),
      source,
    }),
  }
}

fn read_opened_source(path: &Path, initial: &Metadata) -> Result<Vec<u8>> {
  let mut file = File::open(path).map_err(|source| Error::Read {
    path: path.to_path_buf(),
    source,
  })?;
  validate_file_identity(path, &file, initial)?;
  let mut contents = Vec::new();
  file.read_to_end(&mut contents).map_err(|source| Error::Read {
    path: path.to_path_buf(),
    source,
  })?;
  validate_file_identity(path, &file, initial)?;
  Ok(contents)
}

fn validate_file_identity(path: &Path, file: &File, initial: &Metadata) -> Result<()> {
  let opened = file.metadata().map_err(|source| Error::Read {
    path: path.to_path_buf(),
    source,
  })?;
  let linked = source_metadata(path)?.ok_or_else(|| Error::ConfigSourceChanged {
    path: path.to_path_buf(),
  })?;
  if !super::metadata_is_same_file(initial, &opened) || !super::metadata_is_same_file(&opened, &linked) {
    return Err(Error::ConfigSourceChanged {
      path: path.to_path_buf(),
    });
  }
  Ok(())
}

fn validate_directory_identity(path: &Path, initial: &Metadata) -> Result<()> {
  let current = match std::fs::symlink_metadata(path) {
    Ok(metadata) if metadata.file_type().is_symlink() => {
      return Err(Error::ConfigSourceSymlink {
        path: path.to_path_buf(),
      });
    }
    Ok(metadata) if !metadata.is_dir() => {
      return Err(Error::InvalidConfigSourceType {
        path: path.to_path_buf(),
        expected: "a directory",
      });
    }
    Ok(metadata) => metadata,
    Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
      return Err(Error::ConfigSourceChanged {
        path: path.to_path_buf(),
      });
    }
    Err(source) => {
      return Err(Error::Read {
        path: path.to_path_buf(),
        source,
      });
    }
  };
  if !super::metadata_is_same_file(initial, &current) {
    return Err(Error::ConfigSourceChanged {
      path: path.to_path_buf(),
    });
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::lock_config_file;

  const ROOT_CONTENTS: &str = concat!(
    "# sentinel-root-secret\n",
    "[server]\nport = 5151\n",
    "[proxy]\nurl = \"http://user:sentinel-proxy-password@127.0.0.1:8080\"\n",
  );

  fn write_fragment(root: &Path, agent: &str, marker: &str) -> PathBuf {
    let path = crate::paths::agent_config_fragment_path(root, agent);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
      &path,
      format!(
        "# {marker}\n[agents.{agent}]\nprofile = \"{agent}\"\n\n[profiles.{agent}]\nagent_id = \"{agent}\"\nmode = \"route\"\n"
      ),
    )
    .unwrap();
    path
  }

  fn assert_sources_changed(snapshot: &ConfigSourcesSnapshot) {
    let error = snapshot.validate().unwrap_err();
    assert!(matches!(error, Error::ConfigSourcesChanged { path } if path == snapshot.root()));
  }

  #[test]
  fn stable_load_captures_exact_root_and_sorted_fragments_without_debugging_contents() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    std::fs::write(&root, ROOT_CONTENTS).unwrap();
    let zeta = write_fragment(&root, "zeta", "sentinel-zeta-secret");
    let alpha = write_fragment(&root, "alpha", "sentinel-alpha-secret");
    let fragment_dir = crate::paths::config_fragment_dir(&root);
    std::fs::write(fragment_dir.join("ignored.txt"), "ignored").unwrap();
    std::fs::write(fragment_dir.join("ignored.TOML"), "ignored").unwrap();

    let loaded = Config::load_stable(Some(&root)).unwrap();

    assert_eq!(loaded.config.server.port, 5151);
    assert_eq!(loaded.snapshot.root(), root);
    assert_eq!(loaded.snapshot.root_preimage(), Some(ROOT_CONTENTS.as_bytes()));
    assert_eq!(loaded.snapshot.fragment_dir(), fragment_dir);
    assert!(loaded.snapshot.fragment_dir_exists());
    assert_eq!(loaded.snapshot.fragments(), &[alpha, zeta]);
    loaded.snapshot.validate().unwrap();
    let debug = format!("{:?}", loaded.snapshot);
    assert!(!debug.contains("sentinel-root-secret"));
    assert!(!debug.contains("sentinel-proxy-password"));
    assert!(!debug.contains("sentinel-alpha-secret"));
    assert!(!debug.contains("sentinel-zeta-secret"));
    assert!(!format!("{loaded:?}").contains("sentinel-proxy-password"));
    assert!(!dir.path().join(".config.toml.lock").exists());

    std::fs::write(fragment_dir.join("added-but-ignored.json"), "ignored").unwrap();
    loaded.snapshot.validate().unwrap();
  }

  #[test]
  fn stable_load_supports_a_missing_root_without_creating_its_parent() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("missing");
    let root = parent.join("config.toml");

    let loaded = Config::load_stable(Some(&root)).unwrap();

    assert_eq!(loaded.snapshot.root(), root);
    assert_eq!(loaded.snapshot.root_preimage(), None);
    assert!(!loaded.snapshot.fragment_dir_exists());
    assert!(loaded.snapshot.fragments().is_empty());
    assert!(!parent.exists());

    let lock = lock_config_file(&root).unwrap();
    loaded.snapshot.validate_locked(&lock).unwrap();
  }

  #[test]
  fn stable_load_applies_fragments_when_the_root_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    let fragment = write_fragment(&root, "alpha", "alpha");

    let loaded = Config::load_stable(Some(&root)).unwrap();

    assert_eq!(loaded.snapshot.root_preimage(), None);
    assert_eq!(loaded.snapshot.fragments(), &[fragment]);
    assert!(loaded.config.agents.contains_key("alpha"));
    assert!(!root.exists());
  }

  #[test]
  fn snapshot_detects_root_creation_removal_and_byte_edits() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    std::fs::write(&root, ROOT_CONTENTS).unwrap();
    let existing = Config::load_stable(Some(&root)).unwrap().snapshot;

    std::fs::write(&root, "[server]\nport = 6262\n").unwrap();
    assert_sources_changed(&existing);

    std::fs::write(&root, ROOT_CONTENTS).unwrap();
    let removed = Config::load_stable(Some(&root)).unwrap().snapshot;
    std::fs::remove_file(&root).unwrap();
    assert_sources_changed(&removed);

    let missing = Config::load_stable(Some(&root)).unwrap().snapshot;
    std::fs::write(&root, ROOT_CONTENTS).unwrap();
    assert_sources_changed(&missing);
  }

  #[test]
  fn snapshot_detects_fragment_add_remove_rename_and_byte_edits() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    std::fs::write(&root, ROOT_CONTENTS).unwrap();
    let alpha = write_fragment(&root, "alpha", "alpha");

    let edited = Config::load_stable(Some(&root)).unwrap().snapshot;
    std::fs::write(&alpha, "changed bytes").unwrap();
    assert_sources_changed(&edited);

    std::fs::remove_file(&alpha).unwrap();
    let empty = Config::load_stable(Some(&root)).unwrap().snapshot;
    let alpha = write_fragment(&root, "alpha", "alpha");
    assert_sources_changed(&empty);

    let removed = Config::load_stable(Some(&root)).unwrap().snapshot;
    std::fs::remove_file(&alpha).unwrap();
    assert_sources_changed(&removed);

    let alpha = write_fragment(&root, "alpha", "alpha");
    let renamed = Config::load_stable(Some(&root)).unwrap().snapshot;
    let beta = alpha.with_file_name("beta.toml");
    std::fs::rename(&alpha, &beta).unwrap();
    assert_sources_changed(&renamed);
  }

  #[test]
  fn snapshot_detects_fragment_directory_presence_changes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    std::fs::write(&root, ROOT_CONTENTS).unwrap();
    let missing = Config::load_stable(Some(&root)).unwrap().snapshot;
    let fragment_dir = crate::paths::config_fragment_dir(&root);

    std::fs::create_dir(&fragment_dir).unwrap();
    assert_sources_changed(&missing);

    let existing = Config::load_stable(Some(&root)).unwrap().snapshot;
    std::fs::remove_dir(&fragment_dir).unwrap();
    assert_sources_changed(&existing);
  }

  #[test]
  fn locked_validation_rejects_the_wrong_root_and_accepts_parent_aliases() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("nested");
    std::fs::create_dir(&parent).unwrap();
    let root = parent.join("config.toml");
    let other = parent.join("other.toml");
    std::fs::write(&root, ROOT_CONTENTS).unwrap();
    std::fs::write(&other, ROOT_CONTENTS).unwrap();
    let snapshot = Config::load_stable(Some(&root)).unwrap().snapshot;
    let wrong_lock = lock_config_file(&other).unwrap();

    let error = snapshot.validate_locked(&wrong_lock).unwrap_err();
    assert!(matches!(
      error,
      Error::ConfigSnapshotLockMismatch { snapshot_root, .. } if snapshot_root == root
    ));
    drop(wrong_lock);

    let alias = parent.join("../nested/config.toml");
    let alias_lock = lock_config_file(&alias).unwrap();
    snapshot.validate_locked(&alias_lock).unwrap();
  }

  #[test]
  fn locked_validation_rejects_a_replaced_lock_inode() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    std::fs::write(&root, ROOT_CONTENTS).unwrap();
    let snapshot = Config::load_stable(Some(&root)).unwrap().snapshot;
    let lock = lock_config_file(&root).unwrap();
    let lock_path = lock.lock_path.clone();
    std::fs::remove_file(&lock_path).unwrap();
    std::fs::write(&lock_path, "replacement lock inode").unwrap();

    let error = snapshot.validate_locked(&lock).unwrap_err();

    assert!(matches!(error, Error::ConfigLockChanged { path, .. } if path == root));
  }

  #[cfg(unix)]
  #[test]
  fn stable_load_rejects_a_root_symlink_without_parsing_its_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    let target = dir.path().join("target.toml");
    std::fs::write(&target, "not valid toml = [").unwrap();
    symlink(&target, &root).unwrap();

    let error = Config::load_stable(Some(&root)).unwrap_err();

    assert!(matches!(error, Error::ConfigSourceSymlink { path } if path == root));
    assert_eq!(std::fs::read_to_string(target).unwrap(), "not valid toml = [");
  }

  #[cfg(unix)]
  #[test]
  fn stable_load_rejects_a_fragment_directory_symlink_without_visiting_its_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    std::fs::write(&root, ROOT_CONTENTS).unwrap();
    let fragment_dir = crate::paths::config_fragment_dir(&root);
    let target = dir.path().join("target.d");
    std::fs::create_dir(&target).unwrap();
    std::fs::write(target.join("invalid.toml"), "not valid toml = [").unwrap();
    symlink(&target, &fragment_dir).unwrap();

    let error = Config::load_stable(Some(&root)).unwrap_err();

    assert!(matches!(error, Error::ConfigSourceSymlink { path } if path == fragment_dir));
    assert_eq!(
      std::fs::read_to_string(target.join("invalid.toml")).unwrap(),
      "not valid toml = ["
    );
  }

  #[cfg(unix)]
  #[test]
  fn stable_load_rejects_a_fragment_leaf_symlink_without_parsing_its_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("config.toml");
    std::fs::write(&root, ROOT_CONTENTS).unwrap();
    let fragment_dir = crate::paths::config_fragment_dir(&root);
    std::fs::create_dir(&fragment_dir).unwrap();
    let target = dir.path().join("target.toml");
    std::fs::write(&target, "not valid toml = [").unwrap();
    let fragment = fragment_dir.join("alpha.toml");
    symlink(&target, &fragment).unwrap();

    let error = Config::load_stable(Some(&root)).unwrap_err();

    assert!(matches!(error, Error::ConfigSourceSymlink { path } if path == fragment));
    assert_eq!(std::fs::read_to_string(target).unwrap(), "not valid toml = [");
  }
}
