//! Independently scheduled packet stages with one cancellation/exit owner.
use std::future::Future;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use crate::Error;

#[derive(Default)]
pub(super) struct PacketPipeline {
    tasks: JoinSet<(&'static str, Result<(), Error>)>,
}

impl PacketPipeline {
    pub fn spawn<F>(&mut self, name: &'static str, future: F)
    where
        F: Future<Output = Result<(), Error>> + Send + 'static,
    {
        self.tasks.spawn(async move { (name, future.await) });
    }

    pub async fn run(mut self, token: CancellationToken) -> Result<(), Error> {
        let result = tokio::select! {
            biased;
            _ = token.cancelled() => Ok(()),
            task = self.tasks.join_next() => match task {
                Some(Ok((name, Err(error)))) => Err(Error::Operation(format!(
                    "TUN {name} task failed: {error}"
                ))),
                Some(Ok((name, Ok(())))) => Err(Error::Operation(format!(
                    "TUN {name} task exited unexpectedly"
                ))),
                Some(Err(error)) => Err(Error::Operation(format!(
                    "TUN pipeline task failed: {error}"
                ))),
                None => Err(Error::Operation("TUN packet pipeline is empty".to_owned())),
            },
        };
        // Abort and join before the supervisor releases device/route guards.
        // Dropping this owner also aborts children through JoinSet's Drop.
        self.tasks.shutdown().await;
        result
    }
}

#[cfg(test)]
mod tests;
