pub(crate) const V2_SCHEMA_VERSION: i64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigSchema {
  LegacyUnversioned,
  V2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchemaMarkerError {
  NonInteger,
  Unsupported(i64),
}

pub(crate) fn detect_toml(document: &toml::Value) -> Result<ConfigSchema, SchemaMarkerError> {
  classify(
    document
      .get("schema_version")
      .map(|value| value.as_integer().ok_or(SchemaMarkerError::NonInteger)),
  )
}

pub(crate) fn detect_edit(document: &toml_edit::DocumentMut) -> Result<ConfigSchema, SchemaMarkerError> {
  classify(
    document
      .get("schema_version")
      .map(|value| value.as_integer().ok_or(SchemaMarkerError::NonInteger)),
  )
}

fn classify(marker: Option<Result<i64, SchemaMarkerError>>) -> Result<ConfigSchema, SchemaMarkerError> {
  let Some(version) = marker else {
    return Ok(ConfigSchema::LegacyUnversioned);
  };
  let version = version?;
  if version == V2_SCHEMA_VERSION {
    Ok(ConfigSchema::V2)
  } else {
    Err(SchemaMarkerError::Unsupported(version))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn classifies_only_unversioned_legacy_and_integer_v2() {
    let legacy: toml::Value = toml::from_str("[server]\nport = 4141\n").unwrap();
    let v2: toml::Value = toml::from_str("schema_version = 2\n").unwrap();
    let invalid: toml::Value = toml::from_str("schema_version = \"2\"\n").unwrap();
    let unsupported: toml::Value = toml::from_str("schema_version = 3\n").unwrap();

    assert_eq!(detect_toml(&legacy), Ok(ConfigSchema::LegacyUnversioned));
    assert_eq!(detect_toml(&v2), Ok(ConfigSchema::V2));
    assert_eq!(detect_toml(&invalid), Err(SchemaMarkerError::NonInteger));
    assert_eq!(detect_toml(&unsupported), Err(SchemaMarkerError::Unsupported(3)));
  }
}
