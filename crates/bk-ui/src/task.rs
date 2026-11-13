//! Background work: every call into the data interface runs here.
//!
//! [`DataClient`] owns the [`ProgramSource`] and a few worker threads. A
//! view asks for something with [`DataClient::request`] and gets a
//! [`Pending`] handle at once; it polls the handle each frame and draws a
//! placeholder until the value arrives, so no frame ever waits on the
//! source (ADR-012). When a result lands the client calls the waker the
//! shell installed, which asks egui for a repaint.
//!
//! Dropping a [`Pending`] cancels the request if it has not started: a
//! listing page scrolled past before a worker reached it costs nothing.
//! Newer requests are served first, because the newest request is what the
//! user is looking at.
//!
//! Long work that the user should see and be able to stop (searches) is a
//! [`Job`]: it has a name and progress and is listed in the status bar.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use parking_lot::{Condvar, Mutex};

use crate::model::{Command, ProgramSource, SourceResult};

/// Called when a result is ready (the shell repaints).
pub type Waker = Arc<dyn Fn() + Send + Sync>;

type Work = Box<dyn FnOnce(&dyn ProgramSource) + Send>;

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

    /// Installs the function called whenever a result arrives.
    pub fn set_waker(&self, waker: Waker) {
        *self.waker.lock() = Some(waker);
    }

    /// Program facts (cheap: implementations keep them in memory).
    pub fn info(&self) -> crate::model::ProgramInfo {
        self.source.info()
    }

    /// Number of requests queued or running (for the status bar and tests).
    pub fn busy(&self) -> usize {
        self.running.load(Ordering::Relaxed)
    }

    /// Edit counter: bumped after every applied [`Command`]. Views compare
    /// it with the revision their cached data was fetched at.
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }

    /// Runs `f` against the source on a worker thread.
    pub fn request<T: Send + 'static>(
        &self,
        f: impl FnOnce(&dyn ProgramSource) -> T + Send + 'static,
    ) -> Pending<T> {
        let slot = Arc::new(Mutex::new(None));
        let weak: Weak<Mutex<Option<T>>> = Arc::downgrade(&slot);
        let waker = Arc::clone(&self.waker);
        let running = Arc::clone(&self.running);
        running.fetch_add(1, Ordering::Relaxed);
        self.push(Box::new(move |src| {
            // Nobody is waiting any more: skip the work.
            if let Some(slot) = weak.upgrade() {
                let v = f(src);
                *slot.lock() = Some(v);
                drop(slot);
                if let Some(w) = waker.lock().as_ref() {
                    w();
                }
            }
            running.fetch_sub(1, Ordering::Relaxed);
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
    pub fn job<T: Send + 'static>(
        &self,
        name: impl Into<Arc<str>>,
        f: impl FnOnce(&dyn ProgramSource, &Progress) -> T + Send + 'static,
    ) -> (Job, Pending<T>) {
        let job = Job {
            name: name.into(),
            progress: Arc::new(Progress::default()),
        };
        self.jobs.lock().push(job.clone());
        let progress = Arc::clone(&job.progress);
        let jobs = Arc::clone(&self.jobs);
        let pending = self.request(move |src| {
            let v = f(src, &progress);
            progress.finished.store(true, Ordering::Relaxed);
            jobs.lock().retain(|j| !Arc::ptr_eq(&j.progress, &progress));
            v
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

    fn wait<T>(p: &mut Pending<T>) -> &T {
        let deadline = Instant::now() + Duration::from_secs(10);
        while p.poll().is_none() {
            assert!(Instant::now() < deadline, "request did not finish");
            std::thread::yield_now();
        }
        p.poll().unwrap()
    }

    #[test]
    fn requests_complete_off_thread_and_wake() {
        let client = DataClient::new(Arc::new(DemoProgram::licd().unwrap()));
        let woken = Arc::new(AtomicUsize::new(0));
        let w = Arc::clone(&woken);
        client.set_waker(Arc::new(move || {
            w.fetch_add(1, Ordering::Relaxed);
        }));
        let main = std::thread::current().id();
        let mut p = client.request(move |s| {
            assert_ne!(std::thread::current().id(), main);
            s.listing_len()
        });
        assert!(*wait(&mut p).as_ref().unwrap() > 1000);
        assert!(woken.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn apply_bumps_the_revision() {
        let client = DataClient::new(Arc::new(DemoProgram::licd().unwrap()));
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
        let client = DataClient::new(Arc::new(DemoProgram::licd().unwrap()));
        let (job, mut p) = client.job("spin", |_, progress| {
            let deadline = Instant::now() + Duration::from_secs(10);
            while !progress.is_cancelled() && Instant::now() < deadline {
                progress.set(0.5);
                std::thread::yield_now();
            }
            progress.is_cancelled()
        });
        assert_eq!(client.jobs().len(), 1);
        job.progress.cancel();
        assert!(*wait(&mut p));
        assert!(job.progress.is_finished());
        assert!(client.jobs().is_empty());
    }
}
