use std::path::PathBuf;

pub const TOKN_DIR: &str = ".tokn";
pub const ROUTER_DIR: &str = "router";

pub fn router_home() -> Option<PathBuf> {
  std::env::var_os("TOKN_ROUTER_HOME")
    .filter(|path| !path.is_empty())
    .map(PathBuf::from)
    .or_else(|| directories::BaseDirs::new().map(|dirs| dirs.home_dir().join(TOKN_DIR).join(ROUTER_DIR)))
}

pub fn config_dir() -> Option<PathBuf> {
  router_home()
}

pub fn data_dir() -> Option<PathBuf> {
  router_home()
}

pub fn cache_dir() -> Option<PathBuf> {
  router_home().map(|dir| dir.join("cache"))
}
