use super::codec::encode_event;
use super::event::SseEvent;
use crate::error::Result;
use bytes::Bytes;
use eventsource_stream::Eventsource;
use futures_util::{Stream, StreamExt};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

type EventStream = Pin<Box<dyn Stream<Item = std::io::Result<SseEvent>> + Send>>;
type ByteStream = Pin<Box<dyn Stream<Item = std::io::Result<Bytes>> + Send>>;

pub trait EventTransformer: Send {
  fn transform(&mut self, event: SseEvent) -> Result<Vec<SseEvent>>;

  fn finish(&mut self) -> Result<Vec<SseEvent>> {
    Ok(Vec::new())
  }
}

pub struct SsePipeline {
  source: ByteStream,
  transformers: Vec<Box<dyn EventTransformer>>,
}

impl SsePipeline {
  /// Create a pipeline from a byte stream.
  pub fn from_stream<S>(source: S) -> Self
  where
    S: Stream<Item = io::Result<Bytes>> + Send + 'static,
  {
    Self {
      source: Box::pin(source),
      transformers: Vec::new(),
    }
  }

  /// Create a pipeline from an HTTP response.
  pub fn from_response(resp: reqwest::Response) -> Self {
    Self::from_stream(resp.bytes_stream().map(|item| item.map_err(io::Error::other)))
  }

  pub fn with_transformer<T>(mut self, transformer: T) -> Self
  where
    T: EventTransformer + 'static,
  {
    self.transformers.push(Box::new(transformer));
    self
  }

  pub fn run(self) -> ByteStream {
    let source: EventStream = self
      .source
      .eventsource()
      .map(|item| match item {
        Ok(event) => Ok(SseEvent::from(event)),
        Err(err) => Err(io::Error::other(err.to_string())),
      })
      .boxed();
    Box::pin(PipelineStream::new(source, self.transformers))
  }
}

struct PipelineStream {
  source: EventStream,
  transformers: Vec<Box<dyn EventTransformer>>,
  pending: VecDeque<std::io::Result<Bytes>>,
  source_done: bool,
}

impl PipelineStream {
  fn new(source: EventStream, transformers: Vec<Box<dyn EventTransformer>>) -> Self {
    Self {
      source,
      transformers,
      pending: VecDeque::new(),
      source_done: false,
    }
  }

  fn process_event(&mut self, event: SseEvent) -> std::io::Result<()> {
    let transformed = self.apply_transformers(vec![event], 0)?;
    for event in transformed {
      let encoded = encode_event(&event);
      if !encoded.is_empty() {
        self.pending.push_back(Ok(encoded));
      }
    }
    Ok(())
  }

  fn apply_transformers(&mut self, mut events: Vec<SseEvent>, start: usize) -> std::io::Result<Vec<SseEvent>> {
    for idx in start..self.transformers.len() {
      let mut next = Vec::new();
      for event in events {
        next.extend(self.transformers[idx].transform(event).map_err(std::io::Error::other)?);
      }
      events = next;
    }
    Ok(events)
  }

  fn finish_transformers(&mut self) -> std::io::Result<()> {
    for idx in 0..self.transformers.len() {
      let events = self.transformers[idx].finish().map_err(std::io::Error::other)?;
      for event in self.apply_transformers(events, idx + 1)? {
        let encoded = encode_event(&event);
        if !encoded.is_empty() {
          self.pending.push_back(Ok(encoded));
        }
      }
    }
    Ok(())
  }
}

impl Stream for PipelineStream {
  type Item = std::io::Result<Bytes>;

  fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    loop {
      if let Some(item) = self.pending.pop_front() {
        return Poll::Ready(Some(item));
      }
      if self.source_done {
        return Poll::Ready(None);
      }

      match self.source.as_mut().poll_next(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Some(Ok(event))) => {
          if let Err(err) = self.process_event(event) {
            self.pending.push_back(Err(err));
            self.source_done = true;
          }
        }
        Poll::Ready(Some(Err(err))) => {
          self.pending.push_back(Err(err));
          self.source_done = true;
        }
        Poll::Ready(None) => {
          if let Err(err) = self.finish_transformers() {
            self.pending.push_back(Err(err));
          }
          self.source_done = true;
        }
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::error::Result;
  use bytes::BytesMut;
  use futures_util::{stream, StreamExt};

  struct AppendTransformer(&'static str);

  impl EventTransformer for AppendTransformer {
    fn transform(&mut self, mut event: SseEvent) -> Result<Vec<SseEvent>> {
      if !event.is_done() {
        event.data.push_str(self.0);
      }
      Ok(vec![event])
    }
  }

  #[test]
  fn pipeline_applies_transformers_in_order() {
    let body = futures::executor::block_on(async move {
      SsePipeline::from_stream(stream::iter(vec![
        Ok(Bytes::from_static(b"data: hello\n\n")),
        Ok(Bytes::from_static(b"data: [DONE]\n\n")),
      ]))
      .with_transformer(AppendTransformer("-a"))
      .with_transformer(AppendTransformer("-b"))
      .run()
      .collect::<Vec<_>>()
      .await
      .into_iter()
      .collect::<std::result::Result<Vec<_>, _>>()
      .unwrap()
      .into_iter()
      .fold(BytesMut::new(), |mut out, chunk| {
        out.extend_from_slice(&chunk);
        out
      })
      .freeze()
    });
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("data: hello-a-b"));
    assert!(text.contains("data: [DONE]"));
  }
}
