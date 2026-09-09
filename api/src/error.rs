use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

use stealth_engine::error::AnalysisError;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    NotFound(String),
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

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
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
            Self::NotFound(_) => "not_found",
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
