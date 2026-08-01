use bytes::Bytes;

#[derive(Debug, Clone)]
pub struct MessageRecord {
  pub role: String,
  pub status: Option<u16>,
  pub parts: Vec<PartRecord>,
}

#[derive(Debug, Clone)]
pub struct PartRecord {
  pub part_type: String,
  pub content: Bytes,
}
