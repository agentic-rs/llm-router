//! Comment-preserving key traversal shared by config get, set, and unset.

use anyhow::{anyhow, bail, Result};
use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table, TableLike};

pub(super) fn lookup<'a>(doc: &'a DocumentMut, segments: &[String]) -> Option<&'a Item> {
  // Legacy --account selectors address [[accounts]] by id, not array index.
  if segments.len() >= 2 && segments[0] == "accounts" {
    let entry = doc
      .get("accounts")?
      .as_array_of_tables()?
      .iter()
      .find(|table| table.get("id").and_then(Item::as_str) == Some(segments[1].as_str()))?;
    return lookup_in_table(entry, &segments[2..]);
  }
  lookup_in_table(doc.as_table(), segments)
}

fn lookup_in_table<'a>(table: &'a dyn TableLike, segments: &[String]) -> Option<&'a Item> {
  let (head, rest) = segments.split_first()?;
  let mut item = table.get(head)?;
  for segment in rest {
    item = item.as_table_like()?.get(segment)?;
  }
  Some(item)
}

pub(super) fn insert(doc: &mut DocumentMut, segments: &[String], new: Item) -> Result<()> {
  if segments.len() >= 2 && segments[0] == "accounts" {
    let entry = ensure_account(doc, &segments[1])?;
    return insert_into_table(entry, &segments[2..], new);
  }
  insert_into_table(doc.as_table_mut(), segments, new)
}

fn insert_into_table(table: &mut dyn TableLike, segments: &[String], mut new: Item) -> Result<()> {
  let Some((head, rest)) = segments.split_first() else {
    bail!("empty key");
  };
  if rest.is_empty() {
    if let Some(existing) = table.get_mut(head) {
      // Replacing through TableLike::insert reformats the key. Mutate only the
      // value and retain its surrounding whitespace and trailing comments.
      if let (Some(old_value), Some(new_value)) = (existing.as_value(), new.as_value_mut()) {
        *new_value.decor_mut() = old_value.decor().clone();
      }
      *existing = new;
    } else {
      table.insert(head, new);
    }
    return Ok(());
  }

  if table.get(head).is_none() {
    // TableLike converts this to an inline table when the parent is inline.
    table.insert(head, Item::Table(Table::new()));
  }
  let next = table
    .get_mut(head)
    .and_then(Item::as_table_like_mut)
    .ok_or_else(|| anyhow!("`{head}` is not a table"))?;
  insert_into_table(next, rest, new)
}

pub(super) fn remove(doc: &mut DocumentMut, segments: &[String]) -> bool {
  if segments.len() >= 2 && segments[0] == "accounts" {
    let Some(accounts) = doc.get_mut("accounts").and_then(Item::as_array_of_tables_mut) else {
      return false;
    };
    let Some(entry) = accounts
      .iter_mut()
      .find(|table| table.get("id").and_then(Item::as_str) == Some(segments[1].as_str()))
    else {
      return false;
    };
    return remove_from_table(entry, &segments[2..]);
  }
  remove_from_table(doc.as_table_mut(), segments)
}

fn remove_from_table(table: &mut dyn TableLike, segments: &[String]) -> bool {
  let Some((head, rest)) = segments.split_first() else {
    return false;
  };
  if rest.is_empty() {
    return table.remove(head).is_some();
  }
  let Some(inner) = table.get_mut(head).and_then(Item::as_table_like_mut) else {
    return false;
  };
  remove_from_table(inner, rest)
}

fn ensure_account<'a>(doc: &'a mut DocumentMut, id: &str) -> Result<&'a mut Table> {
  if doc.get("accounts").is_none() {
    doc.insert("accounts", Item::ArrayOfTables(ArrayOfTables::new()));
  }
  let accounts = doc
    .get_mut("accounts")
    .and_then(Item::as_array_of_tables_mut)
    .ok_or_else(|| anyhow!("`accounts` is not an array of tables"))?;
  let existing_index = accounts
    .iter()
    .position(|table| table.get("id").and_then(Item::as_str) == Some(id));
  let index = match existing_index {
    Some(index) => index,
    None => {
      let mut table = Table::new();
      table.insert("id", value(id));
      accounts.push(table);
      accounts.len() - 1
    }
  };
  Ok(accounts.get_mut(index).expect("existing or newly inserted account"))
}
