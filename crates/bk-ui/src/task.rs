//! Background work: every call into the data interface runs here.
//!
//! [`DataClient`] owns the [`ProgramSource`] and a few worker threads. A
//! view asks for something with [`DataClient::request`] and gets a
//! [`Pending`] handle at once; it polls the handle each frame and draws a
//! placeholder until the value arrives, so no frame ever waits on the
//! source (ADR-012). When a result lands the client calls the waker the
//! shell installed, which asks egui for a repaint.
//!
//! The wake-up contract, which the shell relies on:
//!
//! - The result is stored, and [`DataClient::busy`] no longer counts the
//!   request, *before* the waker is called. Whatever frame the waker causes
//!   sees the value, so a result can never sit unseen until the next input
//!   event. The converse is not promised: the UI may poll the value before
//!   the waker has run (the wake-up then costs one spare frame).
//! - [`DataClient::set_waker`] calls the new waker once, so a result stored
//!   before a waker was installed (or while an old one was being replaced)
//!   is still noticed.
//! - A task that panics is a bug, but it must not cost a worker thread or
//!   leave a placeholder up for ever (ADR-009): the panic is caught, logged,
//!   and the handle receives [`TaskOutput::task_panicked`] (for the data
//!   interface's results, [`SourceError::TaskPanicked`]).
//!
//! Dropping a [`Pending`] cancels the request if it has not started: a
//! listing page scrolled past before a worker reached it costs nothing.
//! Newer requests are served first, because the newest request is what the
//! user is looking at.
//!
//! Long work that the user should see and be able to stop (searches) is a
//! [`Job`]: it has a name and progress and is listed in the status bar.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use parking_lot::{Condvar, Mutex};

use crate::model::{Command, ProgramSource, SourceError, SourceResult};

/// Called when a result is ready (the shell repaints).
pub type Waker = Arc<dyn Fn() + Send + Sync>;

type Work = Box<dyn FnOnce(&dyn ProgramSource) + Send>;

/// A value a background task can produce, including when it panicked.
///
/// Every request's result type implements this so that a panicking task
/// still delivers something the view can show (an error) instead of
/// leaving its placeholder up for ever.
pub trait TaskOutput: Send + 'static {
    /// The value delivered when the task panicked with `message`.
    fn task_panicked(message: String) -> Self;
}

impl<T: Send + 'static> TaskOutput for SourceResult<T> {
    fn task_panicked(message: String) -> Self {
        Err(SourceError::TaskPanicked(message))
    }
}

/// Number of worker threads.
const WORKERS: usize = 3;

#[derive(Default)]
struct Queue {
    jobs: Mutex<(VecDeque<Work>, bool)>,
    ready: Condvar,
}

/// A request in flight, or its result.
#[derive(Debug)]
pub struct Pending<T> {
    slot: Arc<Mutex<Option<T>>>,
    value: Option<T>,
}

impl<T> Pending<T> {
    /// The value, once it has arrived. Never blocks.
    pub fn poll(&mut self) -> Option<&T> {
        if self.value.is_none() {
            self.value = self.slot.lock().take();
        }
        self.value.as_ref()
    }

    /// The value if [`Self::poll`] has already received it.
    pub fn peek(&self) -> Option<&T> {
        self.value.as_ref()
    }

    /// Takes the value out once it has arrived.
    pub fn take(&mut self) -> Option<T> {
        self.poll();
        self.value.take()
    }

    /// A handle that is already complete (tests, cached values).
    pub fn ready(value: T) -> Self {
        Self {
            slot: Arc::new(Mutex::new(None)),
            value: Some(value),
        }
    }
}

/// Progress of a [`Job`], shared between the worker and the UI.
#[derive(Debug, Default)]
pub struct Progress {
    cancelled: AtomicBool,
    /// Per-mille done.
    done: AtomicU32,
    finished: AtomicBool,
}

impl Progress {
    /// Whether the user asked to stop. Long work checks this often.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Records progress as a fraction in `0.0..=1.0`.
    pub fn set(&self, fraction: f32) {
        let f = (fraction.clamp(0.0, 1.0) * 1000.0) as u32;
        self.done.store(f, Ordering::Relaxed);
    }

    /// Progress so far, `0.0..=1.0`.
    pub fn fraction(&self) -> f32 {
        self.done.load(Ordering::Relaxed) as f32 / 1000.0
    }

    /// Asks the work to stop.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Whether the work has ended.
    pub fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Relaxed)
    }
}

/// Long work with a name and progress, shown in the status bar.
#[derive(Debug, Clone)]
pub struct Job {
    /// What the job does ("Search Memory: 48 89 e5").
    pub name: Arc<str>,
    /// Its progress.
    pub progress: Arc<Progress>,
}

/// Runs [`ProgramSource`] calls off the UI thread.
#[derive(Clone)]
pub struct DataClient {
    source: Arc<dyn ProgramSource>,
    queue: Arc<Queue>,
    waker: Arc<Mutex<Option<Waker>>>,
    running: Arc<AtomicUsize>,
    revision: Arc<AtomicU64>,
    jobs: Arc<Mutex<Vec<Job>>>,
    _shutdown: Arc<Shutdown>,
}

impl std::fmt::Debug for DataClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataClient")
            .field("source", &self.source)
            .field("running", &self.running.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl DataClient {
    /// Starts the worker threads for `source`.
    pub fn new(source: Arc<dyn ProgramSource>) -> Self {
        let queue = Arc::new(Queue::default());
        let client = Self {
            source,
            _shutdown: Arc::new(Shutdown(Arc::clone(&queue))),
            queue,
            waker: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicUsize::new(0)),
            revision: Arc::new(AtomicU64::new(0)),
            jobs: Arc::new(Mutex::new(Vec::new())),
        };
        for i in 0..WORKERS {
            let queue = Arc::clone(&client.queue);
            let source = Arc::clone(&client.source);
            let spawned = std::thread::Builder::new()
                .name(format!("bk-ui-data-{i}"))
                .spawn(move || worker(&queue, source.as_ref()));
            if let Err(e) = spawned {
                tracing::error!("cannot start data worker: {e}");
            }
        }
        client
    }

    /// Installs the function called whenever a result arrives, and calls it
    /// once.
    ///
    /// The extra call closes the gap between a request finishing and a
    /// waker being installed: a worker that read the waker before this
    /// call stored its result before it, so the frame this call schedules
    /// sees that result; a worker that reads it afterwards calls the new
    /// waker itself.
    pub fn set_waker(&self, waker: Waker) {
        let installed = Arc::clone(&waker);
        *self.waker.lock() = Some(waker);
        installed();
    }

    /// Program facts (cheap: implementations keep them in memory).
    pub fn info(&self) -> crate::model::ProgramInfo {
        self.source.info()
    }

    /// Number of requests queued or running (for the status bar and tests).
    ///
    /// When it reads 0, every request made before has stored its result.
    pub fn busy(&self) -> usize {
        self.running.load(Ordering::Acquire)
    }

    /// Edit counter: bumped after every applied [`Command`]. Views compare
    /// it with the revision their cached data was fetched at.
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    /// Runs `f` against the source on a worker thread.
    ///
    /// If `f` panics, the handle receives [`TaskOutput::task_panicked`].
    pub fn request<T: TaskOutput>(
        &self,
        f: impl FnOnce(&dyn ProgramSource) -> T + Send + 'static,
    ) -> Pending<T> {
        let slot = Arc::new(Mutex::new(None));
        let weak: Weak<Mutex<Option<T>>> = Arc::downgrade(&slot);
        self.running.fetch_add(1, Ordering::Relaxed);
        // Created now, so that the count is given back even if the work is
        // dropped unrun (shutdown) or panics.
        let done = Done {
            running: Arc::clone(&self.running),
            waker: Arc::clone(&self.waker),
            wake: false,
        };
        self.push(Box::new(move |src| {
            // Moves the whole guard into the closure; a bare `done.wake`
            // below would capture only that field and drop the guard (and
            // the count) as soon as `request` returns.
            let mut done = done;
            // Nobody is waiting any more: skip the work.
            let Some(slot) = weak.upgrade() else {
                return;
            };
            // The closure is dropped, not used again, after a panic, and
            // the source's own state is behind locks that do not poison:
            // nothing observes a half-updated value.
            let v = match catch_unwind(AssertUnwindSafe(|| f(src))) {
                Ok(v) => v,
                Err(payload) => {
                    let message = panic_message(payload.as_ref());
                    tracing::error!("background task panicked: {message}");
                    T::task_panicked(message)
                }
            };
            *slot.lock() = Some(v);
            drop(slot);
            done.wake = true;
            // `done` drops here: count, then wake (see the module docs).
        }));
        Pending { slot, value: None }
    }

    /// Applies an edit, bumping the revision when it succeeds.
    pub fn apply(&self, command: Command) -> Pending<SourceResult<()>> {
        let revision = Arc::clone(&self.revision);
        self.request(move |src| {
            let r = src.apply(&command);
            if r.is_ok() {
                revision.fetch_add(1, Ordering::AcqRel);
            }
            r
        })
    }

    /// Starts long, cancellable work, listed in the status bar until done.
    pub fn job<T: TaskOutput>(
        &self,
        name: impl Into<Arc<str>>,
        f: impl FnOnce(&dyn ProgramSource, &Progress) -> T + Send + 'static,
    ) -> (Job, Pending<T>) {
        let job = Job {
            name: name.into(),
            progress: Arc::new(Progress::default()),
        };
        self.jobs.lock().push(job.clone());
        // Ends the job however the work ends: finished, panicked, or
        // dropped unrun because its handle was dropped.
        let ended = JobEnded {
            progress: Arc::clone(&job.progress),
            jobs: Arc::clone(&self.jobs),
        };
        let pending = self.request(move |src| {
            // The whole guard, not just the field used below (see `Done`).
            let ended = ended;
            f(src, &ended.progress)
        });
        (job, pending)
    }

    /// Jobs still running.
    pub fn jobs(&self) -> Vec<Job> {
        self.jobs.lock().clone()
    }

    fn push(&self, work: Work) {
        let mut q = self.queue.jobs.lock();
        q.0.push_back(work);
        drop(q);
        self.queue.ready.notify_one();
    }
}

/// Gives a request's count back and, if it delivered a result, wakes the
/// UI, in that order; on drop, so a panic or an unrun request cannot leak
/// the count (which would leave the busy spinner up).
struct Done {
    running: Arc<AtomicUsize>,
    waker: Arc<Mutex<Option<Waker>>>,
    wake: bool,
}

impl Drop for Done {
    fn drop(&mut self) {
        // Release: a `busy()` that reads the new count also sees the result.
        self.running.fetch_sub(1, Ordering::Release);
        if self.wake {
            // Called outside the lock, so a waker can never deadlock
            // against `set_waker`.
            let waker = self.waker.lock().clone();
            if let Some(w) = waker {
                w();
            }
        }
    }
}

/// Marks a [`Job`] finished and removes it from the status bar on drop.
struct JobEnded {
    progress: Arc<Progress>,
    jobs: Arc<Mutex<Vec<Job>>>,
}

impl Drop for JobEnded {
    fn drop(&mut self) {
        self.progress.finished.store(true, Ordering::Relaxed);
        self.jobs
            .lock()
            .retain(|j| !Arc::ptr_eq(&j.progress, &self.progress));
    }
}

/// The text of a panic payload (`panic!` gives a `&str` or a `String`).
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_owned()
    }
}

/// Stops the workers when the last clone of a [`DataClient`] is dropped.
struct Shutdown(Arc<Queue>);

impl Drop for Shutdown {
    fn drop(&mut self) {
        self.0.jobs.lock().1 = true;
        self.0.ready.notify_all();
    }
}

fn worker(queue: &Queue, source: &dyn ProgramSource) {
    loop {
        let work = {
            let mut q = queue.jobs.lock();
            loop {
                if q.1 {
                    return;
                }
                // Newest first: it is what the user is looking at now.
                if let Some(w) = q.0.pop_back() {
                    break w;
                }
                queue.ready.wait(&mut q);
            }
        };
        work(source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::DemoProgram;
    use std::time::{Duration, Instant};

    const DEADLINE: Duration = Duration::from_secs(10);

    fn client() -> DataClient {
        DataClient::new(Arc::new(DemoProgram::licd().unwrap()))
    }

    /// Spins until `done()` holds; fails after [`DEADLINE`].
    fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + DEADLINE;
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting: {what}");
            std::thread::yield_now();
        }
    }

    fn wait<T>(p: &mut Pending<T>) -> &T {
        wait_until("request did not finish", || p.poll().is_some());
        p.poll().unwrap()
    }

    /// A waker that counts the calls made from threads other than the
    /// test's, and records `busy()` as each call saw it.
    fn counting_waker(client: &DataClient) -> (Waker, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let main = std::thread::current().id();
        let woken = Arc::new(AtomicUsize::new(0));
        let busy_seen = Arc::new(AtomicUsize::new(usize::MAX));
        let running = Arc::clone(&client.running);
        let (w, b) = (Arc::clone(&woken), Arc::clone(&busy_seen));
        let waker: Waker = Arc::new(move || {
            if std::thread::current().id() != main {
                b.store(running.load(Ordering::Acquire), Ordering::Relaxed);
                // Release: pairs with the test's Acquire load below.
                w.fetch_add(1, Ordering::Release);
            }
        });
        (waker, woken, busy_seen)
    }

    #[test]
    fn requests_complete_off_thread_and_wake() {
        let client = client();
        let (waker, woken, busy_seen) = counting_waker(&client);
        client.set_waker(waker);
        let main = std::thread::current().id();
        let mut p = client.request(move |s| {
            assert_ne!(std::thread::current().id(), main);
            s.listing_len()
        });
        assert!(*wait(&mut p).as_ref().unwrap() > 1000);
        // The contract is "store, then wake": seeing the value does not
        // mean the waker has run yet, only that it will. Wait for it (this
        // still fails if a worker never calls the waker).
        wait_until("the waker was not called", || {
            woken.load(Ordering::Acquire) >= 1
        });
        // By the time the waker ran, the request no longer counted as busy.
        assert_eq!(busy_seen.load(Ordering::Relaxed), 0);
        assert_eq!(client.busy(), 0);
    }

    #[test]
    fn a_result_stored_before_the_waker_is_installed_still_wakes() {
        let client = client();
        let mut p = client.request(|s| s.listing_len());
        assert!(wait(&mut p).is_ok());
        // The worker found no waker. Installing one must signal the result
        // that is already there, or the UI would not repaint for it.
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        client.set_waker(Arc::new(move || {
            c.fetch_add(1, Ordering::Relaxed);
        }));
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_panicking_request_delivers_an_error_and_frees_its_worker() {
        let client = client();
        let (waker, woken, _) = counting_waker(&client);
        client.set_waker(waker);
        // One panic per worker: if a panic still killed its thread, the
        // last request below would never run.
        let mut panics: Vec<Pending<SourceResult<u64>>> = (0..WORKERS)
            .map(|_| client.request(|_| -> SourceResult<u64> { panic!("deliberate test panic") }))
            .collect();
        for p in &mut panics {
            match wait(p) {
                Err(SourceError::TaskPanicked(m)) => assert!(m.contains("deliberate"), "{m}"),
                other => panic!("expected TaskPanicked, got {other:?}"),
            }
        }
        let mut after = client.request(|s| s.listing_len());
        assert!(wait(&mut after).is_ok());
        wait_until("busy count not given back", || client.busy() == 0);
        wait_until("panicked requests did not wake", || {
            woken.load(Ordering::Acquire) > WORKERS
        });
    }

    #[test]
    fn a_dropped_request_gives_its_count_back() {
        let client = client();
        let gate = Arc::new(AtomicBool::new(false));
        // Occupy every worker so the next request stays queued.
        let blockers: Vec<_> = (0..WORKERS)
            .map(|_| {
                let g = Arc::clone(&gate);
                client.request(move |_| -> SourceResult<()> {
                    let deadline = Instant::now() + DEADLINE;
                    while !g.load(Ordering::Acquire) && Instant::now() < deadline {
                        std::thread::yield_now();
                    }
                    Ok(())
                })
            })
            .collect();
        drop(client.request(|s| s.listing_len()));
        assert_eq!(client.busy(), WORKERS + 1);
        gate.store(true, Ordering::Release);
        drop(blockers);
        wait_until("busy count not given back", || client.busy() == 0);
    }

    #[test]
    fn apply_bumps_the_revision() {
        let client = client();
        let entry = client.info().entry;
        let mut p = client.apply(Command::RenameSymbol {
            address: entry,
            name: "entry_point".into(),
        });
        assert!(wait(&mut p).is_ok());
        assert_eq!(client.revision(), 1);
    }

    #[test]
    fn jobs_report_progress_and_cancel() {
        let client = client();
        let (job, mut p) = client.job("spin", |_, progress| {
            let deadline = Instant::now() + DEADLINE;
            while !progress.is_cancelled() && Instant::now() < deadline {
                progress.set(0.5);
                std::thread::yield_now();
            }
            Ok(progress.is_cancelled())
        });
        assert_eq!(client.jobs().len(), 1);
        job.progress.cancel();
        assert_eq!(wait(&mut p), &Ok(true));
        assert!(job.progress.is_finished());
        assert!(client.jobs().is_empty());
    }

    #[test]
    fn a_panicking_job_leaves_the_status_bar() {
        let client = client();
        let (job, mut p) = client.job("doomed", |_, _| -> SourceResult<()> {
            panic!("deliberate test panic")
        });
        assert!(matches!(wait(&mut p), Err(SourceError::TaskPanicked(_))));
        assert!(job.progress.is_finished());
        assert!(client.jobs().is_empty());
    }
}
