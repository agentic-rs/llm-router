//! Select the models.dev catalogue snapshot embedded at build time.
//!
//! Strategy (in order):
//!   1. If `MODELS_DEV_SNAPSHOT` is set, copy that file into `OUT_DIR`. This
//!      is the explicit development and airgapped override.
//!   2. Otherwise, copy the committed snapshot from
//!      `crates/catalogue/vendor`.
//!
//! Builds must not fetch a mutable remote snapshot: doing so would make tests
//! and release artifacts depend on build time and network availability. The
//! application can still refresh the embedded baseline through the runtime
//! catalogue update path.
//!
//! The chosen file's path is exposed to the crate as
//! `env!("MODELS_DEV_SNAPSHOT_PATH")` so `include_bytes!` can embed it.

use std::env;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

fn main() {
  println!("cargo:rerun-if-env-changed=MODELS_DEV_SNAPSHOT");
  println!("cargo:rerun-if-changed=build.rs");

  let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set by cargo"));
  let dest = out_dir.join("models.dev.json");
  let vendored = PathBuf::from("vendor/models.dev.json");

  // 1. Explicit override wins.
  if let Some(p) = env::var_os("MODELS_DEV_SNAPSHOT") {
    let src = PathBuf::from(&p);
    println!("cargo:rerun-if-changed={}", src.display());
    fs::copy(&src, &dest).unwrap_or_else(|e| panic!("MODELS_DEV_SNAPSHOT={} could not be read: {e}", src.display()));
    ensure_sane(&dest);
    emit(&dest);
    return;
  }

  // 2. Ordinary builds embed the reviewed, committed baseline.
  println!("cargo:rerun-if-changed={}", vendored.display());
  ensure_sane(&vendored);
  fs::copy(&vendored, &dest)
    .unwrap_or_else(|e| panic!("vendored snapshot {} could not be copied: {e}", vendored.display()));
  emit(&dest);
}

fn ensure_sane(p: &Path) {
  let mut file =
    fs::File::open(p).unwrap_or_else(|e| panic!("models.dev snapshot at {} could not be opened: {e}", p.display()));
  let mut buf = Vec::new();
  file
    .read_to_end(&mut buf)
    .unwrap_or_else(|e| panic!("models.dev snapshot at {} could not be read: {e}", p.display()));

  if buf.is_empty() {
    panic!("models.dev snapshot at {} is empty", p.display());
  }

  let first_non_ws = buf.iter().copied().find(|b| !b.is_ascii_whitespace());
  if first_non_ws != Some(b'{') {
    panic!(
      "models.dev snapshot at {} does not look like a JSON object",
      p.display()
    );
  }
}

fn emit(p: &Path) {
  println!("cargo:rustc-env=MODELS_DEV_SNAPSHOT_PATH={}", p.display());
}
