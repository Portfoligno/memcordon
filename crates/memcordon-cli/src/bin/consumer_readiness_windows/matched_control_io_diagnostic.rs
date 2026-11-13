//! Bounded scalar context for the existing original-stream security queries.
use std::{error::Error, fmt, io};
#[path = "matched_control_sd_diagnostic.rs"]
pub mod descriptor;

#[derive(Clone, Copy, Debug)]
pub enum StreamRole {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug)]
pub enum QueryStage {
    Sizing,
    Copy,
    ReturnedExtent,
}

#[derive(Clone, Copy, Debug)]
pub struct QueryFacts {
    pub role: StreamRole,
    pub first_result: i32,
    pub first_required: u32,
    pub first_native_error: Option<i32>,
    pub supplied_capacity: Option<u32>,
    pub physical_capacity: Option<usize>,
    pub second_result: Option<i32>,
    // Observed output-variable value; a failed query need not have written it.
    pub second_required_observed: Option<u32>,
    pub second_native_error: Option<i32>,
    pub descriptor: Option<descriptor::DescriptorFacts>,
}

impl QueryFacts {
    pub fn error(self, stage: QueryStage, source: Option<io::Error>) -> io::Error {
        let kind = source
            .as_ref()
            .map_or(io::ErrorKind::Other, io::Error::kind);
        io::Error::new(
            kind,
            QueryError {
                stage,
                facts: self,
                source,
            },
        )
    }
}

#[derive(Debug)]
struct QueryError {
    stage: QueryStage,
    facts: QueryFacts,
    source: Option<io::Error>,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self.stage {
            QueryStage::Sizing => "matched original stream security extent differs",
            QueryStage::Copy => "matched original stream security query failed",
            QueryStage::ReturnedExtent => "matched original stream security changed",
        };
        let facts = self.facts;
        write!(
            f,
            "{label}: role={:?} stage={:?} first_result={} first_required={} first_native_error={:?} supplied_capacity={:?} physical_capacity={:?} second_result={:?} second_required_observed={:?} second_native_error={:?} descriptor={:?}",
            facts.role,
            self.stage,
            facts.first_result,
            facts.first_required,
            facts.first_native_error,
            facts.supplied_capacity,
            facts.physical_capacity,
            facts.second_result,
            facts.second_required_observed,
            facts.second_native_error,
            facts.descriptor
        )
    }
}

impl Error for QueryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|error| error as &(dyn Error + 'static))
    }
}
