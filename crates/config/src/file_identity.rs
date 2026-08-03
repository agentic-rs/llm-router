//! Stable identity checks for files and directories used by guarded config IO.

use std::fs::File;
use std::io;
use std::path::Path;

/// A stable identity for one opened filesystem object.
///
/// Unix uses the device/inode pair and Windows uses the stable Win32 handle
/// information exposed by `same-file`. Keeping this behind one type avoids
/// relying on unstable Windows methods from `std::os::windows::fs::MetadataExt`.
#[cfg(any(unix, windows))]
#[derive(Debug, Eq, PartialEq)]
pub struct FileIdentity(same_file::Handle);

/// Fallback identity for targets where the standard library does not expose
/// a portable file identity primitive. The existing guarded IO behavior on
/// those targets is preserved.
#[cfg(not(any(unix, windows)))]
#[derive(Debug, Eq, PartialEq)]
pub struct FileIdentity;

impl FileIdentity {
  /// Open a path and capture its filesystem identity.
  pub fn from_path(path: &Path) -> io::Result<Self> {
    #[cfg(any(unix, windows))]
    {
      same_file::Handle::from_path(path).map(Self)
    }
    #[cfg(not(any(unix, windows)))]
    {
      let _ = path;
      Ok(Self)
    }
  }

  /// Capture the filesystem identity of an already opened file without
  /// changing ownership of the caller's handle.
  pub fn from_file(file: &File) -> io::Result<Self> {
    #[cfg(any(unix, windows))]
    {
      same_file::Handle::from_file(file.try_clone()?).map(Self)
    }
    #[cfg(not(any(unix, windows)))]
    {
      let _ = file;
      Ok(Self)
    }
  }
}

#[cfg(test)]
mod tests {
  use super::FileIdentity;
  use std::fs::File;

  #[test]
  fn path_and_open_handle_have_the_same_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "schema_version = 2\n").unwrap();

    let path_identity = FileIdentity::from_path(&path).unwrap();
    let file = File::open(&path).unwrap();

    assert_eq!(path_identity, FileIdentity::from_file(&file).unwrap());
  }

  #[test]
  fn distinct_paths_have_distinct_identities() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.toml");
    let second = directory.path().join("second.toml");
    std::fs::write(&first, "first").unwrap();
    std::fs::write(&second, "second").unwrap();

    assert_ne!(
      FileIdentity::from_path(&first).unwrap(),
      FileIdentity::from_path(&second).unwrap()
    );
  }

  #[test]
  fn missing_paths_preserve_the_io_error() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing.toml");

    let error = FileIdentity::from_path(&missing).unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
  }

  #[test]
  fn hard_links_share_one_identity() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.toml");
    let alias = directory.path().join("alias.toml");
    std::fs::write(&first, "schema_version = 2\n").unwrap();
    std::fs::hard_link(&first, &alias).unwrap();

    assert_eq!(
      FileIdentity::from_path(&first).unwrap(),
      FileIdentity::from_path(&alias).unwrap()
    );
  }

  #[test]
  fn cloned_open_handles_share_one_identity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    std::fs::write(&path, "schema_version = 2\n").unwrap();
    let file = File::open(&path).unwrap();
    let cloned = file.try_clone().unwrap();

    assert_eq!(
      FileIdentity::from_file(&file).unwrap(),
      FileIdentity::from_file(&cloned).unwrap()
    );
  }

  #[test]
  fn open_handle_keeps_its_identity_after_path_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let archived = directory.path().join("config.toml.old");
    std::fs::write(&path, "first").unwrap();
    let file = File::open(&path).unwrap();
    let opened = FileIdentity::from_file(&file).unwrap();

    std::fs::rename(&path, &archived).unwrap();
    std::fs::write(&path, "replacement").unwrap();

    assert_eq!(opened, FileIdentity::from_path(&archived).unwrap());
    assert_ne!(opened, FileIdentity::from_path(&path).unwrap());
  }
}
