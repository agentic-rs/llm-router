//! Conversions between [`crate::HeaderMap`] and [`reqwest::header::HeaderMap`]
//! used at the wire boundary.
//!
//! `reqwest::header::HeaderName` lowercases its input internally, so the
//! original casing of names is **not** preserved when crossing the boundary
//! in either direction. Order is preserved going `crate::HeaderMap ->
//! reqwest::header::HeaderMap` (we use `append`); the reverse direction
//! preserves whatever order `reqwest`'s iterator yields (insertion order in
//! practice).

use crate::map::HeaderMap;
use crate::value::HeaderValue;
use reqwest::header::{HeaderMap as ReqMap, HeaderName as ReqName, HeaderValue as ReqValue};

impl From<HeaderMap> for ReqMap {
  fn from(value: HeaderMap) -> Self {
    let mut out = ReqMap::with_capacity(value.len());
    for (name, val) in value {
      let Ok(rn) = ReqName::from_bytes(name.as_str().as_bytes()) else {
        continue;
      };
      let Ok(rv) = ReqValue::from_str(val.as_str()) else {
        continue;
      };
      out.append(rn, rv);
    }
    out
  }
}

impl From<&ReqMap> for HeaderMap {
  fn from(value: &ReqMap) -> Self {
    let mut out = HeaderMap::with_capacity(value.len());
    for (name, val) in value {
      let Ok(s) = val.to_str() else { continue };
      out.append(name.as_str(), HeaderValue::from_string(s.to_string()));
    }
    out
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn round_trip_preserves_values_and_count() {
    let mut m = HeaderMap::new();
    m.insert("Authorization", "Bearer abc");
    m.insert("Content-Type", "application/json");
    m.insert("X-Session-Id", "ses_42");
    let r: ReqMap = m.clone().into();
    assert_eq!(r.len(), 3);
    assert_eq!(r.get("authorization").unwrap().to_str().unwrap(), "Bearer abc");
    let back: HeaderMap = (&r).into();
    assert_eq!(back.len(), 3);
    assert_eq!(back.get("authorization").unwrap().as_str(), "Bearer abc");
  }

  #[test]
  fn duplicates_round_trip() {
    let mut m = HeaderMap::new();
    m.append("Set-Cookie", "a=1");
    m.append("Set-Cookie", "b=2");
    let r: ReqMap = m.into();
    let all: Vec<_> = r.get_all("set-cookie").iter().map(|v| v.to_str().unwrap()).collect();
    assert_eq!(all, vec!["a=1", "b=2"]);

    let back: HeaderMap = (&r).into();
    let all: Vec<_> = back.get_all("set-cookie").map(HeaderValue::as_str).collect();
    assert_eq!(all, vec!["a=1", "b=2"]);
  }
}
