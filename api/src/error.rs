use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

use crate::preflight::ValidationError;
use stealth_engine::error::AnalysisError;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("validation failed: {0}")]
    Validation(#[from] ValidationError),
    #[error("analysis failed: {0}")]
    Analysis(#[from] AnalysisError),
    #[error("scanner not configured – set STEALTH_RPC_URL")]
    ScannerNotConfigured,
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) | Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Analysis(AnalysisError::EmptyDescriptor)
            | Self::Analysis(AnalysisError::DescriptorNormalization { .. }) => {
                StatusCode::BAD_REQUEST
            }
            Self::Analysis(AnalysisError::EnvironmentUnavailable(_)) => StatusCode::BAD_GATEWAY,
            Self::Analysis(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ScannerNotConfigured => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Validation(_) => "invalid_scan_input",
            Self::Analysis(_) => "scan_failed",
            Self::ScannerNotConfigured => "scanner_not_configured",
            Self::Internal(_) => "internal_error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let message = self.to_string();
        let code = self.error_code();
        let body = Json(ErrorResponse {
            error: ErrorDetails { code, message },
        });
        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: ErrorDetails,
}

#[derive(Debug, Serialize)]
struct ErrorDetails {
    code: &'static str,
    message: String,
}
