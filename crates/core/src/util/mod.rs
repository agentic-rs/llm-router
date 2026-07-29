pub mod digest;
pub mod http;
pub mod initiator;
pub mod paths;
pub mod redact;
pub mod secret;
pub mod timefmt;
pub mod version;

pub fn now_unix_ms() -> i64 {
  let ns = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
  (ns / 1_000_000) as i64
}
