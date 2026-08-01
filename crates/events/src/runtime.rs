//! Reliable, ordered delivery for gateway events.
//!
//! A hub has one bounded ingress queue and one dedicated dispatcher thread.
//! Consumers are fixed before the hub starts, so the first accepted event is
//! observed by the same consumer set as the last one. The dispatcher assigns a
//! hub-wide sequence and calls consumers synchronously in registration order.

use std::any::Any;
use std::error::Error;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};

use thiserror::Error;
use tokio::sync::{mpsc, oneshot, watch};

const DEFAULT_CAPACITY: usize = 1_024;

/// Error type returned by an [`EventConsumer`].
pub type ConsumerResult = Result<(), Box<dyn Error + Send + Sync + 'static>>;

/// A monotonically increasing sequence assigned immediately before dispatch.
///
/// Sequence zero means that no event has reached the dispatcher yet. Accepted
/// events start at sequence one.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventSeq(u64);

impl EventSeq {
  /// The value used before the first event is dispatched.
  pub const ZERO: Self = Self(0);

  /// Returns the numeric sequence value.
  #[must_use]
  pub const fn get(self) -> u64 {
    self.0
  }
}

impl fmt::Display for EventSeq {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.0.fmt(formatter)
  }
}

/// Event-level delivery accounting.
///
/// An event is delivered only after every registered consumer handled it
/// successfully. If one consumer fails, that event and every queued event are
/// counted as undelivered.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeliveryStats {
  pub accepted: u64,
  pub delivered: u64,
  pub undelivered: u64,
}

impl DeliveryStats {
  fn from_counts(accepted: u64, delivered: u64) -> Self {
    Self {
      accepted,
      delivered,
      undelivered: accepted.saturating_sub(delivered),
    }
  }
}

/// Synchronous consumer invoked by the dedicated dispatcher thread.
pub trait EventConsumer<E>: Send + 'static {
  /// Stable diagnostic name used in terminal failure reports.
  fn name(&self) -> &str;

  /// Handles one event.
  fn handle(&mut self, sequence: EventSeq, event: &E) -> ConsumerResult;

  /// Flushes any consumer-owned buffers or transactions.
  fn flush(&mut self) -> ConsumerResult {
    Ok(())
  }
}

/// Operation being performed when a consumer failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumerOperation {
  Handle,
  Flush,
}

impl fmt::Display for ConsumerOperation {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Handle => formatter.write_str("handling an event"),
      Self::Flush => formatter.write_str("flushing"),
    }
  }
}

/// How a consumer terminated delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumerFailureKind {
  Error(Arc<str>),
  Panic(Arc<str>),
}

impl fmt::Display for ConsumerFailureKind {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Error(message) => write!(formatter, "returned an error: {message}"),
      Self::Panic(message) => write!(formatter, "panicked: {message}"),
    }
  }
}

/// Terminal consumer failure shared by the hub and all publisher clones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HubFailure {
  pub consumer_name: Arc<str>,
  /// Sequence being handled, or the latest sequence when flushing.
  pub sequence: EventSeq,
  pub operation: ConsumerOperation,
  pub kind: ConsumerFailureKind,
  pub stats: DeliveryStats,
}

impl fmt::Display for HubFailure {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      formatter,
      "event consumer `{}` failed while {} at sequence {}: {} (accepted {}, delivered {}, undelivered {})",
      self.consumer_name,
      self.operation,
      self.sequence,
      self.kind,
      self.stats.accepted,
      self.stats.delivered,
      self.stats.undelivered
    )
  }
}

impl Error for HubFailure {}

/// Current delivery runtime state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HubStatus {
  Running,
  Closing,
  Closed(DeliveryStats),
  Failed(Arc<HubFailure>),
}

/// Builds a statically registered event hub.
pub struct HubBuilder<E> {
  capacity: usize,
  consumers: Vec<Box<dyn EventConsumer<E>>>,
}

impl<E> Default for HubBuilder<E> {
  fn default() -> Self {
    Self {
      capacity: DEFAULT_CAPACITY,
      consumers: Vec::new(),
    }
  }
}

impl<E> HubBuilder<E> {
  #[must_use]
  pub fn new() -> Self {
    Self::default()
  }

  #[must_use]
  pub fn capacity(mut self, capacity: usize) -> Self {
    self.capacity = capacity;
    self
  }

  #[must_use]
  pub fn consumer<C>(mut self, consumer: C) -> Self
  where
    C: EventConsumer<E>,
  {
    self.consumers.push(Box::new(consumer));
    self
  }
}

impl<E> HubBuilder<E>
where
  E: Send + 'static,
{
  /// Starts the dispatcher after validating the complete consumer set.
  pub fn start(self) -> Result<(Publisher<E>, EventHub<E>), HubBuildError> {
    if self.capacity == 0 {
      return Err(HubBuildError::ZeroCapacity);
    }
    if self.consumers.is_empty() {
      return Err(HubBuildError::NoConsumers);
    }

    let consumers = self
      .consumers
      .into_iter()
      .map(|consumer| RegisteredConsumer {
        name: Arc::from(consumer.name()),
        consumer,
      })
      .collect();
    let state = Arc::new(SharedState::new());
    let (sender, receiver) = mpsc::channel(self.capacity);
    let dispatcher_state = Arc::clone(&state);
    let dispatcher = thread::Builder::new()
      .name("tokn-event-dispatch".to_owned())
      .spawn(move || dispatch(receiver, consumers, dispatcher_state))
      .map_err(HubBuildError::SpawnDispatcher)?;

    let publisher = Publisher {
      sender: sender.clone(),
      state: Arc::clone(&state),
    };
    let hub = EventHub {
      sender,
      state,
      dispatcher: Some(dispatcher),
    };
    Ok((publisher, hub))
  }
}

#[derive(Debug, Error)]
pub enum HubBuildError {
  #[error("event hub capacity must be greater than zero")]
  ZeroCapacity,
  #[error("event hub requires at least one consumer")]
  NoConsumers,
  #[error("failed to spawn event dispatcher thread")]
  SpawnDispatcher(#[source] std::io::Error),
}

/// Cloneable event publisher with bounded, backpressured ingress.
pub struct Publisher<E> {
  sender: mpsc::Sender<Message<E>>,
  state: Arc<SharedState>,
}

impl<E> Clone for Publisher<E> {
  fn clone(&self) -> Self {
    Self {
      sender: self.sender.clone(),
      state: Arc::clone(&self.state),
    }
  }
}

impl<E> fmt::Debug for Publisher<E> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("Publisher")
      .field("status", &self.status())
      .finish_non_exhaustive()
  }
}

impl<E> Publisher<E> {
  #[must_use]
  pub fn status(&self) -> HubStatus {
    self.state.status()
  }

  /// Waits until a consumer fails, or reports that the hub closed cleanly.
  ///
  /// The status subscription is race-safe even when failure happens before or
  /// during this call.
  pub async fn wait_failed(&self) -> Result<Arc<HubFailure>, WaitFailedError> {
    self.state.wait_failed().await
  }

  /// Publishes an event, waiting honestly for bounded queue capacity.
  pub async fn publish(&self, event: E) -> Result<(), PublishError<E>> {
    match self.state.status() {
      HubStatus::Running => {}
      HubStatus::Failed(failure) => return Err(PublishError::Failed { event, failure }),
      HubStatus::Closing | HubStatus::Closed(_) => return Err(PublishError::Closed(event)),
    }
    let permit = match self.sender.clone().reserve_owned().await {
      Ok(permit) => permit,
      Err(_) => return Err(self.classify_publish_error(event)),
    };
    let mut admission = self.state.lock();
    match &admission.status {
      InternalStatus::Running => {
        permit.send(Message::Event(event));
        admission.accepted = admission
          .accepted
          .checked_add(1)
          .expect("event acceptance counter overflowed");
        Ok(())
      }
      InternalStatus::Failed(failure) => Err(PublishError::Failed {
        event,
        failure: Arc::clone(failure),
      }),
      InternalStatus::Closing | InternalStatus::Closed(_) => Err(PublishError::Closed(event)),
    }
  }

  /// Attempts to publish without waiting for queue capacity.
  pub fn try_publish(&self, event: E) -> Result<(), TryPublishError<E>> {
    let mut admission = self.state.lock();
    match &admission.status {
      InternalStatus::Failed(failure) => {
        return Err(TryPublishError::Failed {
          event,
          failure: Arc::clone(failure),
        });
      }
      InternalStatus::Closing | InternalStatus::Closed(_) => return Err(TryPublishError::Closed(event)),
      InternalStatus::Running => {}
    }

    match self.sender.try_send(Message::Event(event)) {
      Ok(()) => {
        admission.accepted = admission
          .accepted
          .checked_add(1)
          .expect("event acceptance counter overflowed");
        Ok(())
      }
      Err(mpsc::error::TrySendError::Full(Message::Event(event))) => Err(TryPublishError::Full(event)),
      Err(mpsc::error::TrySendError::Closed(Message::Event(event))) => {
        drop(admission);
        Err(self.classify_try_publish_error(event))
      }
      Err(_) => unreachable!("publisher only sends event messages through try_publish"),
    }
  }

  /// Places a barrier in the ingress queue and flushes every consumer after all
  /// events ahead of that barrier have been delivered.
  pub async fn flush(&self) -> Result<DeliveryStats, FlushError> {
    match self.state.status() {
      HubStatus::Running => {}
      HubStatus::Failed(failure) => return Err(FlushError::Failed(failure)),
      HubStatus::Closing | HubStatus::Closed(_) => return Err(FlushError::Closed),
    }
    let permit = self
      .sender
      .clone()
      .reserve_owned()
      .await
      .map_err(|_| self.classify_flush_error())?;
    let (completion_tx, completion_rx) = oneshot::channel();
    {
      let admission = self.state.lock();
      match &admission.status {
        InternalStatus::Running => {
          permit.send(Message::Flush(completion_tx));
        }
        InternalStatus::Failed(failure) => return Err(FlushError::Failed(Arc::clone(failure))),
        InternalStatus::Closing | InternalStatus::Closed(_) => return Err(FlushError::Closed),
      }
    }
    completion_rx.await.unwrap_or_else(|_| Err(self.classify_flush_error()))
  }

  fn classify_publish_error(&self, event: E) -> PublishError<E> {
    match self.state.status() {
      HubStatus::Failed(failure) => PublishError::Failed { event, failure },
      HubStatus::Running | HubStatus::Closing | HubStatus::Closed(_) => PublishError::Closed(event),
    }
  }

  fn classify_try_publish_error(&self, event: E) -> TryPublishError<E> {
    match self.state.status() {
      HubStatus::Failed(failure) => TryPublishError::Failed { event, failure },
      HubStatus::Running | HubStatus::Closing | HubStatus::Closed(_) => TryPublishError::Closed(event),
    }
  }

  fn classify_flush_error(&self) -> FlushError {
    match self.state.status() {
      HubStatus::Failed(failure) => FlushError::Failed(failure),
      HubStatus::Running | HubStatus::Closing | HubStatus::Closed(_) => FlushError::Closed,
    }
  }
}

/// Owns the dispatcher thread and coordinates graceful shutdown.
pub struct EventHub<E> {
  sender: mpsc::Sender<Message<E>>,
  state: Arc<SharedState>,
  dispatcher: Option<JoinHandle<()>>,
}

impl<E> EventHub<E> {
  #[must_use]
  pub fn status(&self) -> HubStatus {
    self.state.status()
  }

  /// Waits until a consumer fails, or reports that the hub closed cleanly.
  pub async fn wait_failed(&self) -> Result<Arc<HubFailure>, WaitFailedError> {
    self.state.wait_failed().await
  }

  /// Stops admission, drains all accepted events, flushes consumers, and joins
  /// the dispatcher thread.
  ///
  /// Shutdown runs in an owned task so cancelling the caller cannot strand a
  /// detached dispatcher or leave the hub permanently half-closed.
  pub async fn shutdown(self) -> Result<DeliveryStats, ShutdownError>
  where
    E: Send + 'static,
  {
    tokio::spawn(async move { self.shutdown_inner().await })
      .await
      .map_err(|error| ShutdownError::ShutdownTask(Arc::from(error.to_string())))?
  }

  async fn shutdown_inner(mut self) -> Result<DeliveryStats, ShutdownError> {
    let initial = match self.state.status() {
      HubStatus::Running => None,
      HubStatus::Closing => Some(Err(ShutdownError::Closed)),
      HubStatus::Closed(stats) => Some(Ok(stats)),
      HubStatus::Failed(failure) => Some(Err(ShutdownError::Failed(failure))),
    };

    let outcome = if let Some(outcome) = initial {
      outcome
    } else if let Ok(permit) = self.sender.clone().reserve_owned().await {
      let (completion_tx, completion_rx) = oneshot::channel();
      let started = {
        let mut admission = self.state.lock();
        match &admission.status {
          InternalStatus::Running => {
            admission.status = InternalStatus::Closing;
            // Publish while the admission lock is still held. Otherwise a
            // dispatcher failure could publish `Failed` between this state
            // transition and the notification, only to be overwritten by a
            // stale `Closing` update.
            self.state.publish_status(HubStatus::Closing);
            permit.send(Message::Shutdown(completion_tx));
            true
          }
          InternalStatus::Closing | InternalStatus::Closed(_) | InternalStatus::Failed(_) => false,
        }
      };
      if started {
        completion_rx.await.unwrap_or_else(|_| self.shutdown_state())
      } else {
        self.shutdown_state()
      }
    } else {
      self.shutdown_state()
    };

    let dispatcher = self
      .dispatcher
      .take()
      .expect("event hub always owns its dispatcher until shutdown");
    let join_result = tokio::task::spawn_blocking(move || dispatcher.join())
      .await
      .map_err(|error| ShutdownError::JoinDispatcher(Arc::from(error.to_string())))?;
    match join_result {
      Ok(()) => outcome,
      Err(payload) => Err(ShutdownError::DispatcherPanicked(panic_message(payload))),
    }
  }

  fn shutdown_state(&self) -> Result<DeliveryStats, ShutdownError> {
    match self.state.status() {
      HubStatus::Closed(stats) => Ok(stats),
      HubStatus::Failed(failure) => Err(ShutdownError::Failed(failure)),
      HubStatus::Running | HubStatus::Closing => Err(ShutdownError::DispatcherStopped),
    }
  }
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum FlushError {
  #[error("event hub is closed")]
  Closed,
  #[error("event hub failed: {0}")]
  Failed(Arc<HubFailure>),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ShutdownError {
  #[error("event hub is already closing")]
  Closed,
  #[error("event hub failed: {0}")]
  Failed(Arc<HubFailure>),
  #[error("event dispatcher stopped without reporting completion")]
  DispatcherStopped,
  #[error("event hub shutdown task failed: {0}")]
  ShutdownTask(Arc<str>),
  #[error("failed to join the event dispatcher task: {0}")]
  JoinDispatcher(Arc<str>),
  #[error("event dispatcher panicked: {0}")]
  DispatcherPanicked(Arc<str>),
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum WaitFailedError {
  #[error("event hub closed without a consumer failure")]
  Closed(DeliveryStats),
}

/// Error returned by [`Publisher::publish`]. The original event is retained.
pub enum PublishError<E> {
  Closed(E),
  Failed { event: E, failure: Arc<HubFailure> },
}

impl<E> PublishError<E> {
  #[must_use]
  pub fn into_event(self) -> E {
    match self {
      Self::Closed(event) | Self::Failed { event, .. } => event,
    }
  }
}

impl<E> fmt::Debug for PublishError<E> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Closed(_) => formatter.write_str("PublishError::Closed(..)"),
      Self::Failed { failure, .. } => formatter.debug_tuple("PublishError::Failed").field(failure).finish(),
    }
  }
}

impl<E> fmt::Display for PublishError<E> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Closed(_) => formatter.write_str("event hub is closed"),
      Self::Failed { failure, .. } => write!(formatter, "event hub failed: {failure}"),
    }
  }
}

impl<E> Error for PublishError<E> {}

/// Error returned by [`Publisher::try_publish`]. The original event is retained.
pub enum TryPublishError<E> {
  Full(E),
  Closed(E),
  Failed { event: E, failure: Arc<HubFailure> },
}

impl<E> TryPublishError<E> {
  #[must_use]
  pub fn into_event(self) -> E {
    match self {
      Self::Full(event) | Self::Closed(event) | Self::Failed { event, .. } => event,
    }
  }
}

impl<E> fmt::Debug for TryPublishError<E> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Full(_) => formatter.write_str("TryPublishError::Full(..)"),
      Self::Closed(_) => formatter.write_str("TryPublishError::Closed(..)"),
      Self::Failed { failure, .. } => formatter.debug_tuple("TryPublishError::Failed").field(failure).finish(),
    }
  }
}

impl<E> fmt::Display for TryPublishError<E> {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Full(_) => formatter.write_str("event hub ingress is full"),
      Self::Closed(_) => formatter.write_str("event hub is closed"),
      Self::Failed { failure, .. } => write!(formatter, "event hub failed: {failure}"),
    }
  }
}

impl<E> Error for TryPublishError<E> {}

struct RegisteredConsumer<E> {
  name: Arc<str>,
  consumer: Box<dyn EventConsumer<E>>,
}

enum Message<E> {
  Event(E),
  Flush(oneshot::Sender<Result<DeliveryStats, FlushError>>),
  Shutdown(oneshot::Sender<Result<DeliveryStats, ShutdownError>>),
}

struct SharedState {
  admission: Mutex<Admission>,
  status_updates: watch::Sender<HubStatus>,
}

impl SharedState {
  fn new() -> Self {
    let (status_updates, _) = watch::channel(HubStatus::Running);
    Self {
      admission: Mutex::new(Admission {
        status: InternalStatus::Running,
        accepted: 0,
        delivered: 0,
        latest_sequence: EventSeq::ZERO,
      }),
      status_updates,
    }
  }

  fn lock(&self) -> MutexGuard<'_, Admission> {
    self.admission.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
  }

  fn status(&self) -> HubStatus {
    let admission = self.lock();
    match &admission.status {
      InternalStatus::Running => HubStatus::Running,
      InternalStatus::Closing => HubStatus::Closing,
      InternalStatus::Closed(stats) => HubStatus::Closed(*stats),
      InternalStatus::Failed(failure) => HubStatus::Failed(Arc::clone(failure)),
    }
  }

  async fn wait_failed(&self) -> Result<Arc<HubFailure>, WaitFailedError> {
    let mut updates = self.status_updates.subscribe();
    loop {
      match updates.borrow_and_update().clone() {
        HubStatus::Failed(failure) => return Ok(failure),
        HubStatus::Closed(stats) => return Err(WaitFailedError::Closed(stats)),
        HubStatus::Running | HubStatus::Closing => {}
      }
      if updates.changed().await.is_err() {
        return match self.status() {
          HubStatus::Failed(failure) => Ok(failure),
          HubStatus::Closed(stats) => Err(WaitFailedError::Closed(stats)),
          HubStatus::Running | HubStatus::Closing => {
            unreachable!("shared state owns the status sender while a waiter can borrow it")
          }
        };
      }
    }
  }

  fn publish_status(&self, status: HubStatus) {
    self.status_updates.send_replace(status);
  }

  fn barrier_stats(&self) -> DeliveryStats {
    let delivered = self.lock().delivered;
    DeliveryStats::from_counts(delivered, delivered)
  }

  fn note_sequence(&self, sequence: EventSeq) {
    self.lock().latest_sequence = sequence;
  }

  fn note_delivery(&self) {
    let mut admission = self.lock();
    admission.delivered = admission
      .delivered
      .checked_add(1)
      .expect("event delivery counter overflowed");
  }

  fn fail(
    &self,
    consumer_name: Arc<str>,
    sequence: EventSeq,
    operation: ConsumerOperation,
    kind: ConsumerFailureKind,
  ) -> Arc<HubFailure> {
    let failure = {
      let mut admission = self.lock();
      if let InternalStatus::Failed(failure) = &admission.status {
        return Arc::clone(failure);
      }
      let failure = Arc::new(HubFailure {
        consumer_name,
        sequence,
        operation,
        kind,
        stats: DeliveryStats::from_counts(admission.accepted, admission.delivered),
      });
      admission.status = InternalStatus::Failed(Arc::clone(&failure));
      failure
    };
    self.publish_status(HubStatus::Failed(Arc::clone(&failure)));
    failure
  }

  fn close(&self) -> DeliveryStats {
    let stats = {
      let mut admission = self.lock();
      let stats = DeliveryStats::from_counts(admission.accepted, admission.delivered);
      admission.status = InternalStatus::Closed(stats);
      stats
    };
    self.publish_status(HubStatus::Closed(stats));
    stats
  }

  fn latest_sequence(&self) -> EventSeq {
    self.lock().latest_sequence
  }
}

struct Admission {
  status: InternalStatus,
  accepted: u64,
  delivered: u64,
  latest_sequence: EventSeq,
}

enum InternalStatus {
  Running,
  Closing,
  Closed(DeliveryStats),
  Failed(Arc<HubFailure>),
}

fn dispatch<E>(
  mut receiver: mpsc::Receiver<Message<E>>,
  mut consumers: Vec<RegisteredConsumer<E>>,
  state: Arc<SharedState>,
) where
  E: Send + 'static,
{
  let mut next_sequence = 1_u64;
  while let Some(message) = receiver.blocking_recv() {
    match message {
      Message::Event(event) => {
        let sequence = EventSeq(next_sequence);
        next_sequence = next_sequence.checked_add(1).expect("event sequence counter overflowed");
        state.note_sequence(sequence);
        if let Err(failure) = handle_event(&mut consumers, sequence, &event, &state) {
          flush_consumers_best_effort(&mut consumers);
          terminate_failed(&mut receiver, failure);
          return;
        }
        state.note_delivery();
      }
      Message::Flush(completion) => match flush_consumers(&mut consumers, &state) {
        Ok(()) => {
          let _ = completion.send(Ok(state.barrier_stats()));
        }
        Err(failure) => {
          let _ = completion.send(Err(FlushError::Failed(Arc::clone(&failure))));
          terminate_failed(&mut receiver, failure);
          return;
        }
      },
      Message::Shutdown(completion) => {
        match flush_consumers(&mut consumers, &state) {
          Ok(()) => {
            receiver.close();
            let stats = state.close();
            let _ = completion.send(Ok(stats));
            drain_closed(&mut receiver, None);
          }
          Err(failure) => {
            let _ = completion.send(Err(ShutdownError::Failed(Arc::clone(&failure))));
            terminate_failed(&mut receiver, failure);
          }
        }
        return;
      }
    }
  }

  if let Err(failure) = flush_consumers(&mut consumers, &state) {
    let _ = failure;
  } else {
    state.close();
  }
}

fn handle_event<E: 'static>(
  consumers: &mut [RegisteredConsumer<E>],
  sequence: EventSeq,
  event: &E,
  state: &SharedState,
) -> Result<(), Arc<HubFailure>> {
  for registered in consumers {
    if let Err(kind) = invoke_consumer(|| registered.consumer.handle(sequence, event)) {
      return Err(state.fail(Arc::clone(&registered.name), sequence, ConsumerOperation::Handle, kind));
    }
  }
  Ok(())
}

fn flush_consumers<E: 'static>(
  consumers: &mut [RegisteredConsumer<E>],
  state: &SharedState,
) -> Result<(), Arc<HubFailure>> {
  let mut first_failure = None;
  for registered in consumers {
    if let Err(kind) = invoke_consumer(|| registered.consumer.flush()) {
      if first_failure.is_none() {
        first_failure = Some(state.fail(
          Arc::clone(&registered.name),
          state.latest_sequence(),
          ConsumerOperation::Flush,
          kind,
        ));
      }
    }
  }
  match first_failure {
    Some(failure) => Err(failure),
    None => Ok(()),
  }
}

fn flush_consumers_best_effort<E: 'static>(consumers: &mut [RegisteredConsumer<E>]) {
  for registered in consumers {
    let _ = invoke_consumer(|| registered.consumer.flush());
  }
}

fn invoke_consumer(operation: impl FnOnce() -> ConsumerResult) -> Result<(), ConsumerFailureKind> {
  match catch_unwind(AssertUnwindSafe(|| {
    operation().map_err(|error| ConsumerFailureKind::Error(Arc::from(error.to_string())))
  })) {
    Ok(result) => result,
    Err(payload) => Err(ConsumerFailureKind::Panic(panic_message(payload))),
  }
}

fn terminate_failed<E>(receiver: &mut mpsc::Receiver<Message<E>>, failure: Arc<HubFailure>) {
  receiver.close();
  drain_closed(receiver, Some(failure));
}

fn drain_closed<E>(receiver: &mut mpsc::Receiver<Message<E>>, failure: Option<Arc<HubFailure>>) {
  while let Some(message) = receiver.blocking_recv() {
    match message {
      Message::Event(_) => {}
      Message::Flush(completion) => {
        let result = match &failure {
          Some(failure) => Err(FlushError::Failed(Arc::clone(failure))),
          None => Err(FlushError::Closed),
        };
        let _ = completion.send(result);
      }
      Message::Shutdown(completion) => {
        let result = match &failure {
          Some(failure) => Err(ShutdownError::Failed(Arc::clone(failure))),
          None => Err(ShutdownError::Closed),
        };
        let _ = completion.send(result);
      }
    }
  }
}

fn panic_message(payload: Box<dyn Any + Send>) -> Arc<str> {
  match payload.downcast::<String>() {
    Ok(message) => Arc::from(*message),
    Err(payload) => match payload.downcast::<&'static str>() {
      Ok(message) => Arc::from(*message),
      Err(_) => Arc::from("non-string panic payload"),
    },
  }
}

#[cfg(test)]
mod tests {
  use std::io;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::{mpsc as std_mpsc, Condvar};
  use std::time::Duration;

  use super::*;

  type Records = Arc<Mutex<Vec<(&'static str, EventSeq, u64)>>>;

  struct RecordingConsumer {
    name: &'static str,
    records: Records,
    flushes: Option<Arc<AtomicUsize>>,
  }

  impl EventConsumer<u64> for RecordingConsumer {
    fn name(&self) -> &str {
      self.name
    }

    fn handle(&mut self, sequence: EventSeq, event: &u64) -> ConsumerResult {
      self.records.lock().unwrap().push((self.name, sequence, *event));
      Ok(())
    }

    fn flush(&mut self) -> ConsumerResult {
      if let Some(flushes) = &self.flushes {
        flushes.fetch_add(1, Ordering::SeqCst);
      }
      Ok(())
    }
  }

  #[tokio::test]
  async fn fans_out_in_registration_order_with_global_sequences() {
    let records = Arc::new(Mutex::new(Vec::new()));
    let (publisher, hub) = HubBuilder::new()
      .capacity(8)
      .consumer(RecordingConsumer {
        name: "first",
        records: Arc::clone(&records),
        flushes: None,
      })
      .consumer(RecordingConsumer {
        name: "second",
        records: Arc::clone(&records),
        flushes: None,
      })
      .start()
      .unwrap();

    for event in 10..13 {
      publisher.publish(event).await.unwrap();
    }
    assert_eq!(
      publisher.flush().await.unwrap(),
      DeliveryStats {
        accepted: 3,
        delivered: 3,
        undelivered: 0,
      }
    );
    assert_eq!(
      *records.lock().unwrap(),
      vec![
        ("first", EventSeq(1), 10),
        ("second", EventSeq(1), 10),
        ("first", EventSeq(2), 11),
        ("second", EventSeq(2), 11),
        ("first", EventSeq(3), 12),
        ("second", EventSeq(3), 12),
      ]
    );
    assert_eq!(hub.shutdown().await.unwrap().delivered, 3);
  }

  #[test]
  fn rejects_empty_consumer_set_and_zero_capacity() {
    assert!(matches!(
      HubBuilder::<u64>::new().start(),
      Err(HubBuildError::NoConsumers)
    ));
    assert!(matches!(
      HubBuilder::new()
        .capacity(0)
        .consumer(RecordingConsumer {
          name: "only",
          records: Arc::new(Mutex::new(Vec::new())),
          flushes: None,
        })
        .start(),
      Err(HubBuildError::ZeroCapacity)
    ));
  }

  struct BlockingConsumer {
    started: Option<std_mpsc::Sender<()>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
  }

  impl EventConsumer<u64> for BlockingConsumer {
    fn name(&self) -> &str {
      "blocking"
    }

    fn handle(&mut self, _sequence: EventSeq, _event: &u64) -> ConsumerResult {
      if let Some(started) = self.started.take() {
        started.send(()).unwrap();
      }
      let (open, condition) = &*self.gate;
      let mut open = open.lock().unwrap();
      while !*open {
        open = condition.wait(open).unwrap();
      }
      Ok(())
    }
  }

  #[tokio::test]
  async fn try_publish_reports_full_without_losing_the_event() {
    let (started_tx, started_rx) = std_mpsc::channel();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (publisher, hub) = HubBuilder::new()
      .capacity(1)
      .consumer(BlockingConsumer {
        started: Some(started_tx),
        gate: Arc::clone(&gate),
      })
      .start()
      .unwrap();

    publisher.publish(1).await.unwrap();
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    publisher.try_publish(2).unwrap();
    let error = publisher.try_publish(3).unwrap_err();
    assert!(matches!(error, TryPublishError::Full(3)));

    let (open, condition) = &*gate;
    *open.lock().unwrap() = true;
    condition.notify_all();
    assert_eq!(publisher.flush().await.unwrap().delivered, 2);
    hub.shutdown().await.unwrap();
  }

  #[tokio::test]
  async fn flush_is_an_in_band_consumer_barrier() {
    let records = Arc::new(Mutex::new(Vec::new()));
    let flushes = Arc::new(AtomicUsize::new(0));
    let (publisher, hub) = HubBuilder::new()
      .consumer(RecordingConsumer {
        name: "writer",
        records: Arc::clone(&records),
        flushes: Some(Arc::clone(&flushes)),
      })
      .start()
      .unwrap();

    publisher.publish(7).await.unwrap();
    publisher.publish(8).await.unwrap();
    assert_eq!(publisher.flush().await.unwrap().delivered, 2);
    assert_eq!(records.lock().unwrap().len(), 2);
    assert_eq!(flushes.load(Ordering::SeqCst), 1);
    hub.shutdown().await.unwrap();
    assert_eq!(flushes.load(Ordering::SeqCst), 2);
  }

  struct BlockingFlushConsumer {
    records: Records,
    started: Option<std_mpsc::Sender<()>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
  }

  impl EventConsumer<u64> for BlockingFlushConsumer {
    fn name(&self) -> &str {
      "blocking-flush"
    }

    fn handle(&mut self, sequence: EventSeq, event: &u64) -> ConsumerResult {
      self.records.lock().unwrap().push(("blocking-flush", sequence, *event));
      Ok(())
    }

    fn flush(&mut self) -> ConsumerResult {
      let Some(started) = self.started.take() else {
        return Ok(());
      };
      started.send(()).unwrap();
      let (open, condition) = &*self.gate;
      let mut open = open.lock().unwrap();
      while !*open {
        open = condition.wait(open).unwrap();
      }
      Ok(())
    }
  }

  #[tokio::test]
  async fn flush_stats_cover_only_the_delivered_barrier_prefix() {
    let records = Arc::new(Mutex::new(Vec::new()));
    let (started_tx, started_rx) = std_mpsc::channel();
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let (publisher, hub) = HubBuilder::new()
      .consumer(BlockingFlushConsumer {
        records,
        started: Some(started_tx),
        gate: Arc::clone(&gate),
      })
      .start()
      .unwrap();

    publisher.publish(1).await.unwrap();
    let flush = {
      let publisher = publisher.clone();
      tokio::spawn(async move { publisher.flush().await })
    };
    tokio::task::yield_now().await;
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    publisher.publish(2).await.unwrap();

    let (open, condition) = &*gate;
    *open.lock().unwrap() = true;
    condition.notify_all();
    assert_eq!(
      flush.await.unwrap().unwrap(),
      DeliveryStats {
        accepted: 1,
        delivered: 1,
        undelivered: 0,
      }
    );
    assert_eq!(publisher.flush().await.unwrap().delivered, 2);
    hub.shutdown().await.unwrap();
  }

  struct FailingConsumer {
    fail_at: u64,
    flushes: Arc<AtomicUsize>,
  }

  impl EventConsumer<u64> for FailingConsumer {
    fn name(&self) -> &str {
      "database"
    }

    fn handle(&mut self, _sequence: EventSeq, event: &u64) -> ConsumerResult {
      if *event == self.fail_at {
        Err(Box::new(io::Error::other("disk full")))
      } else {
        Ok(())
      }
    }

    fn flush(&mut self) -> ConsumerResult {
      self.flushes.fetch_add(1, Ordering::SeqCst);
      Ok(())
    }
  }

  #[tokio::test]
  async fn consumer_error_is_terminal_and_accounts_for_accepted_events() {
    let failing_flushes = Arc::new(AtomicUsize::new(0));
    let trailing_flushes = Arc::new(AtomicUsize::new(0));
    let (publisher, hub) = HubBuilder::new()
      .consumer(FailingConsumer {
        fail_at: 2,
        flushes: Arc::clone(&failing_flushes),
      })
      .consumer(RecordingConsumer {
        name: "trailing",
        records: Arc::new(Mutex::new(Vec::new())),
        flushes: Some(Arc::clone(&trailing_flushes)),
      })
      .start()
      .unwrap();

    publisher.publish(1).await.unwrap();
    publisher.flush().await.unwrap();
    publisher.publish(2).await.unwrap();
    let failure = match publisher.flush().await.unwrap_err() {
      FlushError::Failed(failure) => failure,
      FlushError::Closed => panic!("expected terminal failure"),
    };
    assert_eq!(failure.consumer_name.as_ref(), "database");
    assert_eq!(failure.sequence, EventSeq(2));
    assert_eq!(failure.operation, ConsumerOperation::Handle);
    assert!(matches!(&failure.kind, ConsumerFailureKind::Error(message) if message.as_ref() == "disk full"));
    assert_eq!(
      failure.stats,
      DeliveryStats {
        accepted: 2,
        delivered: 1,
        undelivered: 1,
      }
    );
    assert!(matches!(
      publisher.try_publish(99),
      Err(TryPublishError::Failed { event: 99, .. })
    ));
    assert_eq!(failing_flushes.load(Ordering::SeqCst), 2);
    assert_eq!(trailing_flushes.load(Ordering::SeqCst), 2);
    assert!(matches!(hub.shutdown().await, Err(ShutdownError::Failed(observed)) if observed == failure));
  }

  #[tokio::test]
  async fn wait_failed_observes_failure_without_another_publish() {
    let (publisher, hub) = HubBuilder::new()
      .consumer(FailingConsumer {
        fail_at: 1,
        flushes: Arc::new(AtomicUsize::new(0)),
      })
      .start()
      .unwrap();
    let waiter = {
      let publisher = publisher.clone();
      tokio::spawn(async move { publisher.wait_failed().await })
    };

    publisher.publish(1).await.unwrap();
    let failure = waiter.await.unwrap().unwrap();
    assert_eq!(failure.consumer_name.as_ref(), "database");
    assert_eq!(failure.sequence, EventSeq(1));
    assert!(matches!(hub.shutdown().await, Err(ShutdownError::Failed(_))));
  }

  struct PanickingConsumer;

  impl EventConsumer<u64> for PanickingConsumer {
    fn name(&self) -> &str {
      "progress"
    }

    fn handle(&mut self, _sequence: EventSeq, _event: &u64) -> ConsumerResult {
      panic!("render exploded")
    }
  }

  #[tokio::test]
  async fn consumer_panic_is_captured_as_terminal_failure() {
    let (publisher, hub) = HubBuilder::new().consumer(PanickingConsumer).start().unwrap();

    publisher.publish(1).await.unwrap();
    let failure = match publisher.flush().await.unwrap_err() {
      FlushError::Failed(failure) => failure,
      FlushError::Closed => panic!("expected terminal failure"),
    };
    assert_eq!(failure.consumer_name.as_ref(), "progress");
    assert_eq!(failure.sequence, EventSeq(1));
    assert!(matches!(&failure.kind, ConsumerFailureKind::Panic(message) if message.as_ref() == "render exploded"));
    assert!(matches!(hub.shutdown().await, Err(ShutdownError::Failed(_))));
  }

  #[derive(Debug)]
  struct PanickingDisplayError;

  impl fmt::Display for PanickingDisplayError {
    fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      panic!("error display exploded")
    }
  }

  impl Error for PanickingDisplayError {}

  struct PanickingErrorDisplayConsumer {
    fail_flush: bool,
  }

  impl EventConsumer<u64> for PanickingErrorDisplayConsumer {
    fn name(&self) -> &str {
      "panicking-error-display"
    }

    fn handle(&mut self, _sequence: EventSeq, _event: &u64) -> ConsumerResult {
      if self.fail_flush {
        Ok(())
      } else {
        Err(Box::new(PanickingDisplayError))
      }
    }

    fn flush(&mut self) -> ConsumerResult {
      if self.fail_flush {
        Err(Box::new(PanickingDisplayError))
      } else {
        Ok(())
      }
    }
  }

  #[tokio::test]
  async fn panicking_handle_error_display_is_a_terminal_consumer_panic() {
    let (publisher, hub) = HubBuilder::new()
      .consumer(PanickingErrorDisplayConsumer { fail_flush: false })
      .start()
      .unwrap();

    publisher.publish(1).await.unwrap();
    let failure = publisher.wait_failed().await.unwrap();
    assert_eq!(failure.operation, ConsumerOperation::Handle);
    assert!(
      matches!(&failure.kind, ConsumerFailureKind::Panic(message) if message.as_ref() == "error display exploded")
    );
    assert!(matches!(
      publisher.publish(2).await,
      Err(PublishError::Failed { event: 2, .. })
    ));
    assert!(matches!(hub.shutdown().await, Err(ShutdownError::Failed(_))));
  }

  #[tokio::test]
  async fn panicking_flush_error_display_is_a_terminal_consumer_panic() {
    let (publisher, hub) = HubBuilder::new()
      .consumer(PanickingErrorDisplayConsumer { fail_flush: true })
      .start()
      .unwrap();

    publisher.publish(1).await.unwrap();
    let failure = match publisher.flush().await.unwrap_err() {
      FlushError::Failed(failure) => failure,
      FlushError::Closed => panic!("expected terminal failure"),
    };
    assert_eq!(failure.operation, ConsumerOperation::Flush);
    assert!(
      matches!(&failure.kind, ConsumerFailureKind::Panic(message) if message.as_ref() == "error display exploded")
    );
    assert!(matches!(hub.shutdown().await, Err(ShutdownError::Failed(_))));
  }

  struct SteppedConsumer {
    started: std_mpsc::Sender<u64>,
    releases: std_mpsc::Receiver<()>,
  }

  impl EventConsumer<u64> for SteppedConsumer {
    fn name(&self) -> &str {
      "stepped"
    }

    fn handle(&mut self, _sequence: EventSeq, event: &u64) -> ConsumerResult {
      self.started.send(*event).unwrap();
      self
        .releases
        .recv_timeout(Duration::from_secs(2))
        .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)
    }
  }

  #[tokio::test]
  async fn cancelled_shutdown_still_closes_and_rejects_late_publication() {
    let (started_tx, started_rx) = std_mpsc::channel();
    let (release_tx, release_rx) = std_mpsc::channel();
    let (publisher, hub) = HubBuilder::new()
      .capacity(1)
      .consumer(SteppedConsumer {
        started: started_tx,
        releases: release_rx,
      })
      .start()
      .unwrap();

    publisher.publish(1).await.unwrap();
    assert_eq!(started_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
    publisher.publish(2).await.unwrap();

    let shutdown = tokio::spawn(hub.shutdown());
    tokio::task::yield_now().await;
    shutdown.abort();

    release_tx.send(()).unwrap();
    assert_eq!(started_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
    for _ in 0..100 {
      if matches!(publisher.status(), HubStatus::Closing) {
        break;
      }
      tokio::task::yield_now().await;
    }
    assert!(matches!(publisher.status(), HubStatus::Closing));
    assert!(matches!(
      tokio::time::timeout(Duration::from_secs(1), publisher.publish(3))
        .await
        .unwrap(),
      Err(PublishError::Closed(3))
    ));

    release_tx.send(()).unwrap();
    assert!(matches!(
      tokio::time::timeout(Duration::from_secs(1), publisher.wait_failed())
        .await
        .unwrap(),
      Err(WaitFailedError::Closed(DeliveryStats {
        accepted: 2,
        delivered: 2,
        undelivered: 0,
      }))
    ));
  }

  #[tokio::test]
  async fn shutdown_drains_and_closes_every_publisher_clone() {
    let records = Arc::new(Mutex::new(Vec::new()));
    let (publisher, hub) = HubBuilder::new()
      .capacity(2)
      .consumer(RecordingConsumer {
        name: "writer",
        records,
        flushes: None,
      })
      .start()
      .unwrap();
    let late_publisher = publisher.clone();

    for event in 0..20 {
      publisher.publish(event).await.unwrap();
    }
    let stats = hub.shutdown().await.unwrap();
    assert_eq!(
      stats,
      DeliveryStats {
        accepted: 20,
        delivered: 20,
        undelivered: 0,
      }
    );
    assert!(matches!(
      late_publisher.publish(21).await,
      Err(PublishError::Closed(21))
    ));
  }
}
