use std::{future::Future, sync::OnceLock};

use tokio::{
    runtime::{Builder, Runtime},
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};

fn shared() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("zombo-checks")
            .build()
            .expect("tokio runtime")
    })
}

pub fn stream<T, F, Fut>(job: F) -> UnboundedReceiver<T>
where
    T: Send + 'static,
    F: FnOnce(UnboundedSender<T>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (tx, rx) = unbounded_channel();
    shared().spawn(job(tx));
    rx
}
