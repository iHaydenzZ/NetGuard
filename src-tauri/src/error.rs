//! Unified error type for all Tauri IPC command handlers.
//!
//! `AppError` is the single error type returned by every `#[tauri::command]` function.
//! It serializes as `{ "kind": "...", "message": "..." }` so the frontend can
//! programmatically distinguish error categories.

use serde::ser::SerializeStruct;

/// Application-level error returned by all Tauri commands.
///
/// Each variant maps to a distinct failure domain. The frontend receives a JSON
/// object with `kind` (variant name) and `message` (human-readable description).
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Errors originating from SQLite / database operations.
    #[error("{0}")]
    Database(String),

    /// Errors from the packet capture engine (WinDivert).
    #[error("{0}")]
    Capture(String),

    /// Errors from the rate limiter subsystem.
    #[error("{0}")]
    RateLimiter(String),

    /// I/O and OS-level errors (registry, filesystem, process spawning).
    #[error("{0}")]
    Io(String),

    /// Invalid or missing user input.
    #[error("{0}")]
    InvalidInput(String),
}

impl AppError {
    /// Returns the error kind as a string matching the variant name.
    pub fn kind(&self) -> &'static str {
        match self {
            AppError::Database(_) => "Database",
            AppError::Capture(_) => "Capture",
            AppError::RateLimiter(_) => "RateLimiter",
            AppError::Io(_) => "Io",
            AppError::InvalidInput(_) => "InvalidInput",
        }
    }
}

/// Custom Serialize: produces `{ "kind": "Variant", "message": "..." }` for the frontend.
impl serde::Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_struct("AppError", 2)?;
        s.serialize_field("kind", self.kind())?;
        s.serialize_field("message", &self.to_string())?;
        s.end()
    }
}

// ---- From implementations for ergonomic error conversion ----

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Database(err.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Io(err.to_string())
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        AppError::Database(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_kind_returns_correct_variant_name() {
        assert_eq!(AppError::Database("db fail".into()).kind(), "Database");
        assert_eq!(AppError::Capture("cap fail".into()).kind(), "Capture");
        assert_eq!(
            AppError::RateLimiter("rate fail".into()).kind(),
            "RateLimiter"
        );
        assert_eq!(AppError::Io("io fail".into()).kind(), "Io");
        assert_eq!(
            AppError::InvalidInput("bad input".into()).kind(),
            "InvalidInput"
        );
    }

    #[test]
    fn test_error_display_shows_message() {
        let err = AppError::Database("connection lost".into());
        assert_eq!(err.to_string(), "connection lost");
    }

    #[test]
    fn test_error_serializes_as_kind_and_message() {
        let err = AppError::Capture("WinDivert not found".into());
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["kind"], "Capture");
        assert_eq!(json["message"], "WinDivert not found");
    }

    #[test]
    fn test_from_anyhow_produces_database_variant() {
        let anyhow_err = anyhow::anyhow!("sqlite busy");
        let app_err: AppError = anyhow_err.into();
        assert_eq!(app_err.kind(), "Database");
        assert!(app_err.to_string().contains("sqlite busy"));
    }

    #[test]
    fn test_from_io_error_produces_io_variant() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let app_err: AppError = io_err.into();
        assert_eq!(app_err.kind(), "Io");
        assert!(app_err.to_string().contains("file missing"));
    }

    #[test]
    fn test_all_variants_serialize_with_two_fields() {
        let variants: Vec<AppError> = vec![
            AppError::Database("a".into()),
            AppError::Capture("b".into()),
            AppError::RateLimiter("c".into()),
            AppError::Io("d".into()),
            AppError::InvalidInput("e".into()),
        ];
        for err in variants {
            let json = serde_json::to_value(&err).unwrap();
            let obj = json.as_object().unwrap();
            assert_eq!(obj.len(), 2, "Expected exactly 2 fields for {err:?}");
            assert!(obj.contains_key("kind"));
            assert!(obj.contains_key("message"));
        }
    }
}
