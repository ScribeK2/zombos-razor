use std::{future::Future, sync::OnceLock};

use tokio::{
    runtime::{Builder, Runtime},
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
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

pub fn stream<T, F, Fut>(job: F) -> UnboundedReceiver<T>
where
    T: Send + 'static,
    F: FnOnce(UnboundedSender<T>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = unbounded_channel();
    if let Some(runtime) = shared() {
        runtime.spawn(job(tx));
    }
    rx
}
