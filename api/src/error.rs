use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

use crate::preflight::ValidationError;
use stealth_core::scanner::ScanError;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("validation failed: {0}")]
    Validation(#[from] ValidationError),
    #[error("scan failed: {0}")]
    Scanner(#[from] ScanError),
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
            Self::Scanner(ScanError::RpcConnection(_)) => StatusCode::BAD_GATEWAY,
            Self::Scanner(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ScannerNotConfigured => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::Validation(_) => "invalid_scan_input",
            Self::Scanner(_) => "scan_failed",
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
