//! `GET /api/v1/about` (`specs/api.md`, About). The handler takes `AuthUser`, so a missing or
//! invalid session is `401`.

use axum::{Json, extract::State};

use crate::api::state::AppState;
use crate::error::AppError;
use crate::services::about::{AboutView, view};
use crate::services::sessions::AuthUser;

/// The dockward version and the bundled Trivy and Grype versions, read at startup (a version
/// that could not be read is `null`), and the live state of each scanner: the binary in use, a
/// broken downloaded version, and the last daily upstream check (#390).
pub async fn get(
    State(state): State<AppState>,
    _user: AuthUser,
) -> Result<Json<AboutView>, AppError> {
    view(&state.about, &state.scanner_programs, &state.pool)
        .await
        .map(Json)
}
