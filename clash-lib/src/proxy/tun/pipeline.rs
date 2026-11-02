//! Packet stages with a dedicated writer and one cancellation/exit owner.
use std::future::{Future, pending};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::error;
use crate::Error;
mod writer_thread;
use writer_thread::WriterThread;

#[derive(Default)]
pub(super) struct PacketPipeline {
    tasks: JoinSet<(&'static str, Result<(), Error>)>,
    writer: Option<WriterThread>,
}

impl PacketPipeline {
    pub fn spawn_writer<F>(&mut self, future: F)
    where F: Future<Output = Result<(), Error>> + Send + 'static {
        assert!(self.writer.is_none(), "one writer thread per TUN pipeline");
        match WriterThread::spawn(future) {
            Ok(writer) => {
                self.writer = Some(writer);
            }
            // Report startup failure through the same supervisor, so siblings
            // are joined and the runner still reaches its route cleanup path.
            Err(error) => { self.tasks.spawn(async move { ("writer", Err(Error::Io(error))) }); }
        }
    }

    pub fn spawn<F>(&mut self, name: &'static str, future: F)
    where
        F: Future<Output = Result<(), Error>> + Send + 'static,
    {
        self.tasks.spawn(async move { (name, future.await) });
    }

    pub async fn run(mut self, token: CancellationToken) -> Result<(), Error> {
        // An empty task set is an exit only if there is no dedicated writer.
        let poll_tasks = !self.tasks.is_empty() || self.writer.is_none();
        let writer = &mut self.writer;
        let result = tokio::select! {
            biased;
            _ = token.cancelled() => Ok(()),
            result = async {
                match writer {
                    Some(writer) => writer.finished().await,
                    None => pending().await,
                }
            } => stage_exit("writer", result),
            task = self.tasks.join_next(), if poll_tasks => match task {
                Some(Ok((name, result))) => stage_exit(name, result),
                Some(Err(error)) => Err(Error::Operation(format!(
                    "TUN pipeline task failed: {error}"
                ))),
                None => Err(Error::Operation("TUN packet pipeline is empty".to_owned())),
            },
        };
        // Stop producers and join the writer before releasing device/routes.
        // Owner abort also cancels and joins the thread through its guard.
        if let Some(writer) = &self.writer { writer.cancel(); }
        self.tasks.shutdown().await;
        let joined = match &mut self.writer {
            Some(writer) => writer.shutdown().await,
            None => Ok(()),
        };
        result.and(joined)
    }
}

fn stage_exit(name: &'static str, result: Result<(), Error>) -> Result<(), Error> {
    match result {
        Err(error) => {
            error!(stage = name, "TUN packet stage failed: {error}");
            Err(error)
        }
        Ok(()) => Err(Error::Operation(format!("TUN {name} task exited unexpectedly"))),
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod writer_tests;
