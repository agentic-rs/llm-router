//! Session affinity map used by linked account-pool runtimes to keep
//! multi-turn conversations (tool-call follow-ups, OpenAI Responses
//! `previous_response_id`, Anthropic extended-thinking continuations) on the
//! same selected runtime value.
//!
//! Lookup semantics are tri-state via [`Lookup`]:
//! - `Hit(value)` — session known and still within TTL.
//! - `Expired` — session was known, the affinity TTL elapsed, but the entry is
//!   still retained for debug/observability.
//! - `Unknown` — first-use; the caller selects a value and records it.
//!
//! Entries use a single last-touch timestamp. [`SessionAffinityPlan`] supplies
//! a live TTL plus an additional retention duration for expired bindings. Once
//! an entry exceeds the combined retention TTL it is forgotten and a future
//! request with the same id is treated as a brand new session.
//!
//! In-memory only — by design. Cross-restart affinity would need durable
//! state, which we explicitly chose not to keep here.
//!
//! Concurrency: a single `RwLock<HashMap<…>>` covers both lookup and write
//! paths. Write rate is one per request (record on success / on retry); read
//! rate is the same. No contention concern at expected throughput. Fully stale
//! retained entries are swept opportunistically during normal traffic.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokn_policy::SessionAffinityPlan;

#[derive(Debug, PartialEq, Eq)]
pub enum Lookup<V> {
  Hit(V),
  Expired,
  Unknown,
}

#[derive(Debug)]
struct Entry<V, I> {
  value: V,
  /// When this binding was last successfully touched.
  stamped_at: I,
}

#[doc(hidden)]
pub trait Clock {
  type Instant: Copy;
  type Duration: Copy + Ord;

  fn now(&self) -> Self::Instant;
  fn elapsed(&self, stamped_at: Self::Instant) -> Self::Duration;
}

#[doc(hidden)]
pub struct SystemClock;

impl Clock for SystemClock {
  type Instant = Instant;
  type Duration = Duration;

  fn now(&self) -> Instant {
    Instant::now()
  }

  fn elapsed(&self, stamped_at: Instant) -> Duration {
    stamped_at.elapsed()
  }
}

pub struct Affinity<V: Clone, C: Clock = SystemClock> {
  map: RwLock<HashMap<String, Entry<V, C::Instant>>>,
  ttl: C::Duration,
  retained_ttl: C::Duration,
  gc_every: usize,
  ops_since_gc: AtomicUsize,
  clock: C,
}

impl<V: Clone> Affinity<V, SystemClock> {
  /// Construct affinity from compiled policy semantics.
  ///
  /// `expired_retention` is additional time after the live TTL. Saturation
  /// keeps an extreme configuration from wrapping to a shorter retention TTL.
  pub fn from_session_plan(plan: SessionAffinityPlan) -> Self {
    let retained_ttl = plan.ttl().saturating_add(plan.expired_retention());
    Self::with_clock(plan.ttl(), retained_ttl, SystemClock)
  }
}

impl<V: Clone, C: Clock> Affinity<V, C> {
  fn with_clock(ttl: C::Duration, retained_ttl: C::Duration, clock: C) -> Self {
    Self {
      map: RwLock::new(HashMap::new()),
      ttl,
      retained_ttl: std::cmp::max(ttl, retained_ttl),
      gc_every: 1024,
      ops_since_gc: AtomicUsize::new(0),
      clock,
    }
  }

  fn maybe_sweep_expired(&self) {
    if self.ops_since_gc.fetch_add(1, Ordering::Relaxed) + 1 < self.gc_every {
      return;
    }
    self.ops_since_gc.store(0, Ordering::Relaxed);
    let mut g = self.map.write();
    g.retain(|_, entry| self.clock.elapsed(entry.stamped_at) < self.retained_ttl);
  }

  /// Look up `key`. Side-effect: fully stale retained entries are removed.
  pub fn lookup(&self, key: &str) -> Lookup<V> {
    self.maybe_sweep_expired();
    {
      let g = self.map.read();
      if let Some(e) = g.get(key) {
        let age = self.clock.elapsed(e.stamped_at);
        if age < self.ttl {
          return Lookup::Hit(e.value.clone());
        }
        if age < self.retained_ttl {
          return Lookup::Expired;
        }
      } else {
        return Lookup::Unknown;
      }
    }
    let mut g = self.map.write();
    match g.get(key) {
      Some(e) => {
        let age = self.clock.elapsed(e.stamped_at);
        if age < self.ttl {
          Lookup::Hit(e.value.clone())
        } else if age < self.retained_ttl {
          Lookup::Expired
        } else {
          g.remove(key);
          Lookup::Unknown
        }
      }
      None => Lookup::Unknown,
    }
  }

  /// Bind `key` to `value` (sliding-window refresh on repeat calls).
  pub fn record(&self, key: &str, value: impl Into<V>) {
    self.maybe_sweep_expired();
    let mut g = self.map.write();
    g.insert(
      key.to_string(),
      Entry {
        value: value.into(),
        stamped_at: self.clock.now(),
      },
    );
  }

  #[cfg(test)]
  fn len(&self) -> usize {
    self.map.read().len()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::cell::Cell;

  fn ms(value: u64) -> u64 {
    value
  }

  struct FakeClock {
    now: Cell<u64>,
  }

  impl FakeClock {
    fn new() -> Self {
      Self { now: Cell::new(0) }
    }

    fn advance(&self, delta: u64) {
      self.now.set(self.now.get() + delta);
    }
  }

  impl Clock for FakeClock {
    type Instant = u64;
    type Duration = u64;

    fn now(&self) -> u64 {
      self.now.get()
    }

    fn elapsed(&self, stamped_at: u64) -> u64 {
      self.now() - stamped_at
    }
  }

  fn test_affinity(ttl: u64, retained_ttl: u64) -> Affinity<String, FakeClock> {
    let mut affinity = Affinity::<String, FakeClock>::with_clock(ttl, retained_ttl, FakeClock::new());
    affinity.gc_every = 4;
    affinity
  }

  #[test]
  fn unknown_then_hit_then_expired() {
    let a = test_affinity(ms(100), ms(300));
    assert_eq!(a.lookup("k1"), Lookup::Unknown);
    a.record("k1", "acct-a");
    assert_eq!(a.lookup("k1"), Lookup::Hit("acct-a".into()));
    a.clock.advance(ms(140));
    assert_eq!(a.lookup("k1"), Lookup::Expired);
  }

  #[test]
  fn record_refreshes_expired_entry() {
    let a = test_affinity(ms(80), ms(400));
    a.record("k", "old");
    a.clock.advance(ms(120));
    assert_eq!(a.lookup("k"), Lookup::Expired);
    a.record("k", "new");
    assert_eq!(a.lookup("k"), Lookup::Hit("new".into()));
  }

  #[test]
  fn retained_entry_eventually_forgotten_from_last_touch() {
    let a = test_affinity(ms(40), ms(120));
    a.record("k", "x");
    a.clock.advance(ms(70));
    assert_eq!(a.lookup("k"), Lookup::Expired);
    a.clock.advance(ms(95));
    assert_eq!(a.lookup("k"), Lookup::Unknown);
  }

  #[test]
  fn zero_retention_skips_expired_state() {
    let a = test_affinity(ms(40), ms(0));
    a.record("k", "x");
    a.clock.advance(ms(41));
    assert_eq!(a.lookup("k"), Lookup::Unknown);
  }

  #[test]
  fn sliding_window_keeps_session_alive() {
    let a = test_affinity(ms(150), ms(400));
    a.record("k", "acct");
    for _ in 0..4 {
      a.clock.advance(ms(140));
      assert_eq!(a.lookup("k"), Lookup::Hit("acct".into()));
      a.record("k", "acct"); // refresh
    }
    a.clock.advance(ms(149));
    assert_eq!(a.lookup("k"), Lookup::Hit("acct".into()));
    a.clock.advance(ms(2));
    assert_eq!(a.lookup("k"), Lookup::Expired);
  }

  #[test]
  fn opportunistic_gc_removes_cold_expired_entries() {
    let a = test_affinity(ms(40), ms(20));
    a.record("stale", "acct");
    assert_eq!(a.len(), 1);
    a.clock.advance(ms(70));
    a.record("fresh-1", "acct");
    a.record("fresh-2", "acct");
    a.record("fresh-3", "acct");
    assert!(a.len() <= 3);
  }

  #[test]
  fn stores_non_string_values() {
    let a = Affinity::<u32, FakeClock>::with_clock(ms(40), ms(120), FakeClock::new());
    a.record("k", 42_u32);
    assert_eq!(a.lookup("k"), Lookup::Hit(42));
  }

  #[test]
  fn session_plan_retention_is_additional_after_ttl() {
    let a = Affinity::<String>::from_session_plan(SessionAffinityPlan::new(
      Duration::from_secs(40),
      Duration::from_secs(20),
    ));
    assert_eq!(a.ttl, Duration::from_secs(40));
    assert_eq!(a.retained_ttl, Duration::from_secs(60));
  }

  #[test]
  fn session_plan_retention_addition_saturates() {
    let a = Affinity::<String>::from_session_plan(SessionAffinityPlan::new(Duration::MAX, Duration::from_nanos(1)));
    assert_eq!(a.retained_ttl, Duration::MAX);
  }
}
