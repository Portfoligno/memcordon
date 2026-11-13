//! Retain the terminal state after the original capture supervisor's sole join.
use crate::{
    CiError, Result,
    work_outcome::{CompilationFacts, WriterSettlement},
};

enum State<T> {
    Pending,
    Complete(T),
    Failed,
    Panicked,
}

pub struct TerminalCapture<T> {
    state: State<T>,
}

impl<T> Default for TerminalCapture<T> {
    fn default() -> Self {
        Self {
            state: State::Pending,
        }
    }
}

fn unresolved(message: &str) -> CiError {
    CiError::OwnedWork {
        source: Box::new(CiError::Message(message.into())),
        writers: WriterSettlement::Unknown,
        facts: CompilationFacts::default(),
    }
}

impl<T> TerminalCapture<T> {
    pub fn complete(&mut self, result: Result<T>) -> Result<()> {
        if !matches!(self.state, State::Pending) {
            let duplicate = unresolved(
                "original capture already has a terminal state; duplicate completion refused",
            );
            return Err(match result {
                Ok(_) => duplicate,
                Err(error) => CiError::LaneFailures {
                    primary: Box::new(duplicate),
                    secondary: Box::new(error),
                },
            });
        }
        match result {
            Ok(output) => {
                self.state = State::Complete(output);
                Ok(())
            }
            Err(error) => {
                self.state = State::Failed;
                Err(error)
            }
        }
    }

    pub fn panicked(&mut self) -> CiError {
        if !matches!(self.state, State::Pending) {
            return unresolved(
                "original capture already has a terminal state; duplicate panic refused",
            );
        }
        self.state = State::Panicked;
        unresolved(
            "original frontend supervisor panicked; original native cleanup remains unresolved",
        )
    }

    pub fn output(&self) -> Result<&T> {
        match &self.state {
            State::Complete(output) => Ok(output),
            State::Pending => Err(unresolved(
                "original frontend capture is pending; sole supervisor settlement remains due",
            )),
            State::Failed => Err(unresolved(
                "original frontend capture completed with failure; original typed error already delivered; native cleanup remains unresolved",
            )),
            State::Panicked => Err(unresolved(
                "original frontend capture supervisor panicked; original native cleanup remains unresolved",
            )),
        }
    }

    pub fn has_output(&self) -> bool {
        matches!(self.state, State::Complete(_))
    }
}
