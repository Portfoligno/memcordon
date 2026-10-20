/// Fixed-size observations from calls the existing connection loop already makes.
/// These describe API results, not server identity or listener readiness.
#[derive(Default)]
pub struct ConnectObservation {
    create_failures: u32,
    file_not_found: u32,
    pipe_busy: u32,
    last_create_error: Option<u32>,
    wait_successes: u32,
    wait_failures: u32,
    last_wait_error: Option<u32>,
}

impl ConnectObservation {
    pub fn record_create_failure(&mut self, code: Option<u32>) {
        self.create_failures += 1;
        self.file_not_found += u32::from(code == Some(2));
        self.pipe_busy += u32::from(code == Some(231));
        self.last_create_error = code;
    }

    pub fn record_wait(&mut self, result: Result<(), Option<u32>>) {
        match result {
            Ok(()) => self.wait_successes += 1,
            Err(code) => {
                self.wait_failures += 1;
                self.last_wait_error = code;
            }
        }
    }

    pub fn timeout_error(&self) -> String {
        format!(
            "timed out waiting for the sealed provider pipe; observed_create_failures={} file_not_found={} pipe_busy={} last_create_error={:?} wait_successes={} wait_failures={} last_wait_error={:?}",
            self.create_failures,
            self.file_not_found,
            self.pipe_busy,
            self.last_create_error,
            self.wait_successes,
            self.wait_failures,
            self.last_wait_error,
        )
    }
}
