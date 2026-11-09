use std::{future::Future, sync::OnceLock};

use tokio::{
    runtime::{Builder, Runtime},
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task::AbortHandle,
};

/// None when the OS refuses the threads; a job then never starts and its
/// receiver reports a closed channel.
fn shared() -> Option<&'static Runtime> {
    static RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            Builder::new_multi_thread().worker_threads(2).enable_all().thread_name("zombo-checks").build().ok()
        })
        .as_ref()
}

/// Stops a job. Aborting drops the job's future at its next await, which closes its sockets and
/// its sender, so the receiver ends. Aborting a finished or never-started job does nothing.
#[derive(Debug)]
pub struct Cancel(Option<AbortHandle>);

impl Cancel {
    pub fn abort(&self) {
        if let Some(h) = &self.0 {
            h.abort();
        }
    }
}

pub fn stream<T, F, Fut>(job: F) -> (UnboundedReceiver<T>, Cancel)
where
    T: Send + 'static,
    F: FnOnce(UnboundedSender<T>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = unbounded_channel();
    let handle = shared().map(|runtime| runtime.spawn(job(tx)).abort_handle());
    (rx, Cancel(handle))
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering::SeqCst},
        },
        time::{Duration, Instant},
    };

    use super::*;

    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, SeqCst);
        }
    }

    fn wait_for(flag: &AtomicBool) -> bool {
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until {
            if flag.load(SeqCst) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn aborting_a_slow_job_drops_its_future_and_ends_its_stream() {
        let (dropped, finished) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let (d, f) = (Arc::clone(&dropped), Arc::clone(&finished));
        let (mut rx, cancel) = stream(move |tx: UnboundedSender<u8>| {
            let guard = Dropped(d);
            async move {
                let _guard = guard;
                tokio::time::sleep(Duration::from_secs(3600)).await;
                f.store(true, SeqCst);
                let _ = tx.send(1);
            }
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(!dropped.load(SeqCst), "the job is still running before the abort");
        cancel.abort();
        assert!(wait_for(&dropped), "the future was not dropped, so the work did not stop");
        assert_eq!(rx.blocking_recv(), None, "the stream must end, not wait for a result");
        assert!(!finished.load(SeqCst));
    }

    #[test]
    fn a_job_that_is_not_aborted_delivers_its_result() {
        let (mut rx, _cancel) = stream(|tx: UnboundedSender<u8>| async move {
            let _ = tx.send(7);
        });
        assert_eq!(rx.blocking_recv(), Some(7));
    }
}
