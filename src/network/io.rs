use std::{
    future::Future as _,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};

pub(super) const IO_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub(super) type SendStream = ProgressIo<iroh::endpoint::SendStream>;
pub(super) type RecvStream = ProgressIo<iroh::endpoint::RecvStream>;

pub(super) struct ProgressIo<T> {
    inner: T,
    timeout: Duration,
    deadline: Option<Pin<Box<Sleep>>>,
    blocked: bool,
}

impl<T> ProgressIo<T> {
    pub(super) const fn new(inner: T, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            deadline: None,
            blocked: false,
        }
    }

    pub(super) const fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    fn stalled<R>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<R>> {
        let deadline = self
            .deadline
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(self.timeout)));
        if !self.blocked {
            deadline.as_mut().reset(Instant::now() + self.timeout);
            self.blocked = true;
        }
        if deadline.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "sync stream made no I/O progress",
            )))
        } else {
            Poll::Pending
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ProgressIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_read(cx, buffer) {
            Poll::Ready(result) => {
                this.blocked = false;
                Poll::Ready(result)
            }
            Poll::Pending => this.stalled(cx),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ProgressIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, bytes) {
            Poll::Ready(result) => {
                this.blocked = false;
                Poll::Ready(result)
            }
            Poll::Pending => this.stalled(cx),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(result) => {
                this.blocked = false;
                Poll::Ready(result)
            }
            Poll::Pending => this.stalled(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(result) => {
                this.blocked = false;
                Poll::Ready(result)
            }
            Poll::Pending => this.stalled(cx),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    #[tokio::test]
    async fn stalled_reads_time_out() {
        let (_sender, receiver) = tokio::io::duplex(1);
        let mut receiver = ProgressIo::new(receiver, Duration::from_millis(20));
        let error = receiver.read_exact(&mut [0]).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn stalled_writes_time_out() {
        let (sender, _receiver) = tokio::io::duplex(1);
        let mut sender = ProgressIo::new(sender, Duration::from_millis(20));
        let error = sender.write_all(b"ab").await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn progress_allows_transfers_longer_than_the_idle_deadline() {
        let (mut sender, receiver) = tokio::io::duplex(1);
        let mut receiver = ProgressIo::new(receiver, Duration::from_millis(80));
        let send = async {
            for byte in b"hello" {
                tokio::time::sleep(Duration::from_millis(30)).await;
                sender.write_all(&[*byte]).await.unwrap();
            }
        };
        let receive = async {
            let mut bytes = [0; 5];
            receiver.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"hello");
        };
        tokio::join!(send, receive);
    }
}
