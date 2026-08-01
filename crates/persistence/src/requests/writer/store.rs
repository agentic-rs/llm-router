use super::WriteResult;
use crate::requests::open_day_db;
use crate::Result;
use rusqlite::{Connection, Transaction};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::Duration;

const CONNECTION_CACHE_CAPACITY: usize = 3;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct RequestStore {
  dir: PathBuf,
  connections: HashMap<String, Connection>,
  order: VecDeque<String>,
}

impl RequestStore {
  pub(super) fn open(dir: PathBuf) -> Result<Self> {
    std::fs::create_dir_all(&dir)?;
    Ok(Self {
      dir,
      connections: HashMap::new(),
      order: VecDeque::new(),
    })
  }

  pub(super) fn transaction<T>(
    &mut self,
    day: &str,
    operation: impl FnOnce(&Transaction<'_>) -> WriteResult<T>,
  ) -> WriteResult<T> {
    let connection = self.connection(day)?;
    let transaction = connection.transaction()?;
    let value = operation(&transaction)?;
    transaction.commit()?;
    Ok(value)
  }

  fn connection(&mut self, day: &str) -> WriteResult<&mut Connection> {
    if !self.connections.contains_key(day) {
      if self.order.len() == CONNECTION_CACHE_CAPACITY {
        if let Some(evicted) = self.order.pop_front() {
          self.connections.remove(&evicted);
        }
      }
      let connection = open_day_db(&self.dir.join(format!("{day}.db")))?;
      connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
      self.connections.insert(day.to_string(), connection);
    }
    self.order.retain(|entry| entry != day);
    self.order.push_back(day.to_string());
    self
      .connections
      .get_mut(day)
      .ok_or_else(|| super::RequestWriteError::lifecycle("unknown", "request day connection disappeared after opening"))
  }
}
