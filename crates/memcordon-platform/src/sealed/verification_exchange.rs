use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

// Discovery and planning include the provider's bounded 30-second registry
// acquisition plus fresh installed-artifact verification. They are not probes.
// Keep a finite additional verification/transport allowance, without retries
// or cached authority, and share it across every partial frame operation.
pub(crate) const VERIFIED_EXCHANGE_BUDGET: Duration = Duration::from_secs(60);

pub(crate) fn remaining_budget(deadline: Instant, now: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "verified exchange deadline elapsed",
            )
        })
}

pub(crate) struct DeadlineStream<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl<'a> DeadlineStream<'a> {
    pub(crate) fn new(stream: &'a mut UnixStream, budget: Duration) -> io::Result<Self> {
        let deadline = Instant::now().checked_add(budget).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "verified exchange deadline overflow",
            )
        })?;
        Ok(Self { stream, deadline })
    }

    fn read_at(&mut self, bytes: &mut [u8], now: Instant) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining_budget(self.deadline, now)?))?;
        self.stream.read(bytes)
    }

    fn write_at(&mut self, bytes: &[u8], now: Instant) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining_budget(self.deadline, now)?))?;
        self.stream.write(bytes)
    }

    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "used by the separately path-imported deadline integration test, not the library-test target"
    )]
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }

    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "used by the separately path-imported deadline integration test, not the library-test target"
    )]
    pub(crate) fn test_read_at(&mut self, bytes: &mut [u8], now: Instant) -> io::Result<usize> {
        self.read_at(bytes, now)
    }

    #[cfg(test)]
    #[allow(
        dead_code,
        reason = "used by the separately path-imported deadline integration test, not the library-test target"
    )]
    pub(crate) fn test_write_at(&mut self, bytes: &[u8], now: Instant) -> io::Result<usize> {
        self.write_at(bytes, now)
    }
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.read_at(bytes, Instant::now())
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.write_at(bytes, Instant::now())
    }

    fn flush(&mut self) -> io::Result<()> {
        remaining_budget(self.deadline, Instant::now())?;
        self.stream.flush()
    }
}
