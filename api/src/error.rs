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
            Self::Analysis(AnalysisError::HistoryTooLarge { .. }) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::Analysis(AnalysisError::EnvironmentUnavailable(_))
            | Self::Analysis(AnalysisError::TransactionNotFound(_))
            | Self::Analysis(AnalysisError::HistoryUnavailable(_))
            | Self::Analysis(AnalysisError::RpcForbidden { .. }) => StatusCode::BAD_GATEWAY,
            Self::Analysis(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ScannerNotConfigured => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "bad_request",
            Self::NotFound(_) => "not_found",
            Self::Analysis(AnalysisError::HistoryTooLarge { .. }) => "history_too_large",
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
        let (tx_count, limit) = match self {
            Self::Analysis(AnalysisError::HistoryTooLarge {
                tx_count, limit, ..
            }) => (Some(tx_count), Some(limit)),
            _ => (None, None),
        };
        let body = Json(ErrorResponse {
            error: ErrorDetails {
                code,
                message,
                tx_count,
                limit,
            },
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
    /// Set for `history_too_large`.
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_side_failures_are_bad_gateway() {
        for error in [
            AnalysisError::EnvironmentUnavailable("down".into()),
            AnalysisError::TransactionNotFound("gone".into()),
            AnalysisError::HistoryUnavailable("pruned".into()),
            AnalysisError::RpcForbidden {
                method: "listunspent".into(),
                detail: String::new(),
            },
        ] {
            assert_eq!(ApiError::from(error).status_code(), StatusCode::BAD_GATEWAY);
        }
    }
}
