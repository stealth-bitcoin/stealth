use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AnalysisError {
    #[error("descriptor input cannot be empty")]
    EmptyDescriptor,
    #[error("descriptor `{descriptor}` failed normalization: {message}")]
    DescriptorNormalization { descriptor: String, message: String },
    #[error("environment unavailable: {0}")]
    EnvironmentUnavailable(String),
    #[error("analysis found no history for the supplied descriptors")]
    AnalysisEmpty,
}
