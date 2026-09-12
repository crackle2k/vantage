use crate::{
    db::supabase::AuthUserRecord,
    errors::{AppError, Result},
    middleware::auth::{self, AuthUser},
    models::user::{GoogleAuthRequest, UserCreate, UserLogin, UserRole},
    security,
    services::recaptcha,
    state::AppState,
};
use axum::{
    extract::State,
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use validator::Validate;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route("/google", post(google_auth))
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UserCreate>,
) -> Result<impl IntoResponse> {
    payload
        .validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    security::validate_password_strength(&payload.password)?;

    if state.config.recaptcha_enabled() {
        let token = payload
            .recaptcha_token
            .as_deref()
            .map(str::trim)
            .filter(|token| !token.is_empty() && *token != "recaptcha-not-configured")
            .ok_or_else(|| AppError::BadRequest("reCAPTCHA token required".into()))?;

        recaptcha::verify_recaptcha_token(
            &state.recaptcha_http,
            &state.config,
            token,
            &state.config.recaptcha_signup_action,
        )
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    }

    let email = payload.email.trim().to_lowercase();
    let role = registration_role(payload.role.as_ref())?;

    let full_name = security::sanitize_optional_text(payload.full_name.as_deref(), 120);
    let user_metadata = registration_user_metadata(full_name.as_deref());
    let app_metadata = registration_app_metadata(role);
    let created_user = state
        .db
        .supabase
        .auth_create_user(&email, &payload.password, user_metadata, app_metadata)
        .await
        .map_err(map_supabase_auth_error)?;

    // Force metadata into Supabase Auth before login so the newly minted JWT
    // carries the selected registration role immediately.
    let user = match update_registration_metadata(
        &state,
        created_user.clone(),
        role,
        full_name.as_deref(),
    )
    .await
    {
        Ok(user) => user,
        Err(err) => {
            if let Err(delete_err) = state.db.supabase.auth_delete_user(&created_user.id).await {
                tracing::warn!(
                    error = %delete_err,
                    user_id = %created_user.id,
                    "Failed to roll back Supabase user after registration metadata failure"
                );
            }
            return Err(err);
        }
    };

    let session = state
        .db
        .supabase
        .auth_login_password(&email, &payload.password)
        .await
        .map_err(map_supabase_auth_error)?;

    Ok((
        StatusCode::CREATED,
        session_headers(&session, &state.config),
        Json(auth_response_json(&user)),
    ))
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UserLogin>,
) -> Result<impl IntoResponse> {
    payload
        .validate()
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let email = payload.email.trim().to_lowercase();
    let session = state
        .db
        .supabase
        .auth_login_password(&email, &payload.password)
        .await
        .map_err(map_supabase_auth_error)?;
    let user = ensure_auth_defaults(&state, session.user.clone(), None, Some("email")).await?;

    Ok((
        session_headers(&session, &state.config),
        Json(auth_response_json(&user)),
    ))
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(access_token) = auth::access_token_from_headers(&headers) {
        if let Err(err) = state.db.supabase.auth_logout(&access_token).await {
            tracing::warn!(error = %err, "Supabase logout token revocation failed");
        }
    }

    (
        clear_session_headers(&state.config),
        Json(json!({ "message": "Logged out successfully" })),
    )
        .into_response()
}

async fn me(State(state): State<Arc<AppState>>, auth_user: AuthUser) -> Result<impl IntoResponse> {
    let user = state
        .db
        .supabase
        .auth_get_user(&auth_user.id)
        .await
        .map_err(map_supabase_auth_error)?;

    Ok(Json(public_user_json(&user)))
}

async fn google_auth(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<GoogleAuthRequest>,
) -> Result<impl IntoResponse> {
    let credential = payload.credential.trim();
    if credential.is_empty() {
        return Err(AppError::BadRequest("Google credential required".into()));
    }

    let session = state
        .db
        .supabase
        .auth_login_id_token("google", credential)
        .await
        .map_err(map_supabase_auth_error)?;
    let user = ensure_auth_defaults(
        &state,
        session.user.clone(),
        Some("customer"),
        Some("google"),
    )
    .await?;

    Ok((
        session_headers(&session, &state.config),
        Json(auth_response_json(&user)),
    ))
}

fn session_headers(
    session: &crate::db::supabase::AuthSession,
    config: &crate::config::Config,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for cookie in auth::session_cookies(session, config) {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            headers.append(SET_COOKIE, value);
        }
    }
    headers
}

fn clear_session_headers(config: &crate::config::Config) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for cookie in auth::clear_session_cookies(config) {
        if let Ok(value) = HeaderValue::from_str(&cookie) {
            headers.append(SET_COOKIE, value);
        }
    }
    headers
}

async fn ensure_auth_defaults(
    state: &AppState,
    user: AuthUserRecord,
    default_role: Option<&str>,
    auth_provider: Option<&str>,
) -> Result<AuthUserRecord> {
    let mut app_metadata = user.app_metadata.clone();
    let mut user_metadata = user.user_metadata.clone();
    let mut changed = false;

    if metadata_str(&app_metadata, "role").is_none() {
        merge_metadata(
            &mut app_metadata,
            json!({ "role": default_role.unwrap_or("customer") }),
        );
        changed = true;
    }
    if metadata_str(&app_metadata, "subscription_tier").is_none() {
        merge_metadata(&mut app_metadata, json!({ "subscription_tier": "FREE" }));
        changed = true;
    }
    if let Some(provider) = auth_provider {
        if metadata_str(&user_metadata, "auth_provider") != Some(provider) {
            merge_metadata(&mut user_metadata, json!({ "auth_provider": provider }));
            changed = true;
        }
    }

    if !changed {
        return Ok(user);
    }

    state
        .db
        .supabase
        .auth_update_user(
            &user.id,
            json!({
                "app_metadata": app_metadata,
                "user_metadata": user_metadata,
            }),
        )
        .await
        .map_err(map_supabase_auth_error)
}

fn registration_role(role: Option<&UserRole>) -> Result<&'static str> {
    match role.unwrap_or(&UserRole::Customer) {
        UserRole::Customer => Ok("customer"),
        // Business-owner and admin roles cannot be self-assigned at registration;
        // owner status is granted through the verified claim flow.
        UserRole::BusinessOwner | UserRole::Admin => Err(AppError::Forbidden(
            "This role cannot be self-registered".into(),
        )),
    }
}

async fn update_registration_metadata(
    state: &AppState,
    user: AuthUserRecord,
    role: &str,
    full_name: Option<&str>,
) -> Result<AuthUserRecord> {
    let (app_metadata, user_metadata) = registration_metadata(&user, role, full_name);
    state
        .db
        .supabase
        .auth_update_user(
            &user.id,
            json!({
                "app_metadata": app_metadata,
                "user_metadata": user_metadata,
            }),
        )
        .await
        .map_err(map_supabase_auth_error)
}

fn registration_metadata(
    user: &AuthUserRecord,
    role: &str,
    full_name: Option<&str>,
) -> (Value, Value) {
    let mut app_metadata = user.app_metadata.clone();
    let mut user_metadata = user.user_metadata.clone();

    merge_metadata(&mut app_metadata, registration_app_metadata(role));
    merge_metadata(&mut user_metadata, registration_user_metadata(full_name));

    (app_metadata, user_metadata)
}

fn registration_app_metadata(role: &str) -> Value {
    json!({
        "role": role,
        "subscription_tier": "FREE",
    })
}

fn registration_user_metadata(full_name: Option<&str>) -> Value {
    json!({
        "full_name": full_name,
        "name": full_name,
        "profile_picture": Value::Null,
        "auth_provider": "email",
    })
}

fn public_user_json(user: &AuthUserRecord) -> Value {
    let email = user.email.as_deref().unwrap_or_default();
    let full_name = metadata_str(&user.user_metadata, "full_name")
        .or_else(|| metadata_str(&user.user_metadata, "name"));
    let name = full_name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(email);
    let role = metadata_str(&user.app_metadata, "role").unwrap_or("customer");
    let subscription_tier = metadata_str(&user.app_metadata, "subscription_tier").unwrap_or("FREE");
    let profile_picture = metadata_str(&user.user_metadata, "profile_picture");
    let preferences = user
        .user_metadata
        .get("preferences")
        .unwrap_or(&Value::Null);

    json!({
        "id": user.id,
        "_id": user.id,
        "email": email,
        "name": name,
        "full_name": full_name,
        "role": role,
        "profile_picture": profile_picture,
        "subscription_tier": subscription_tier,
        "created_at": user.created_at,
        "auth_provider": metadata_str(&user.user_metadata, "auth_provider"),
        "preferences": preferences,
        "preferred_categories": preferences.get("preferred_categories").cloned().unwrap_or(Value::Null),
        "preferred_vibes": preferences.get("preferred_vibes").cloned().unwrap_or(Value::Null),
        "prefer_independent": preferences.get("prefer_independent").cloned().unwrap_or(Value::Null),
        "price_pref": preferences.get("price_pref").cloned().unwrap_or(Value::Null),
        "discovery_mode": preferences.get("discovery_mode").cloned().unwrap_or(Value::Null),
        "preferences_completed": preferences.get("preferences_completed").cloned().unwrap_or(Value::Null),
    })
}

fn auth_response_json(user: &AuthUserRecord) -> Value {
    json!({ "user": public_user_json(user) })
}

fn metadata_str<'a>(metadata: &'a Value, key: &str) -> Option<&'a str> {
    metadata.get(key).and_then(Value::as_str)
}

fn merge_metadata(target: &mut Value, patch: Value) {
    let Some(target) = target.as_object_mut() else {
        *target = json!({});
        return merge_metadata(target, patch);
    };
    if let Some(patch) = patch.as_object() {
        for (key, value) in patch {
            if !value.is_null() {
                target.insert(key.clone(), value.clone());
            }
        }
    }
}

fn map_supabase_auth_error(error: anyhow::Error) -> AppError {
    let message = error.to_string();
    let lowered = message.to_ascii_lowercase();
    if lowered.contains("already") || lowered.contains("registered") || lowered.contains("exists") {
        AppError::Conflict("Email already registered".into())
    } else if lowered.contains("not configured") {
        AppError::Internal("Supabase is not configured".into())
    } else if lowered.contains("invalid login") || lowered.contains("invalid credentials") {
        AppError::Unauthorized("Invalid credentials".into())
    } else {
        AppError::Internal("Authentication service unavailable".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_record() -> AuthUserRecord {
        AuthUserRecord {
            id: "11111111-1111-1111-1111-111111111111".into(),
            email: Some("owner@example.com".into()),
            user_metadata: json!({
                "full_name": "Vantage Owner",
                "auth_provider": "email"
            }),
            app_metadata: json!({
                "role": "business_owner",
                "subscription_tier": "FREE"
            }),
            created_at: Some("2026-05-19T00:00:00Z".into()),
        }
    }

    #[test]
    fn auth_response_does_not_expose_bearer_tokens() {
        let response = auth_response_json(&auth_record());

        assert!(response.get("access_token").is_none());
        assert!(response.get("refresh_token").is_none());
        assert!(response.get("token_type").is_none());
        assert_eq!(response["user"]["email"], "owner@example.com");
    }

    #[test]
    fn registration_metadata_forces_selected_role_before_login() {
        let mut record = auth_record();
        record.app_metadata = json!({
            "role": "customer",
            "legacy": "kept"
        });
        record.user_metadata = json!({
            "preferences": { "preferences_completed": true }
        });

        let (app_metadata, user_metadata) =
            registration_metadata(&record, "business_owner", Some("Fresh Owner"));

        assert_eq!(app_metadata["role"], "business_owner");
        assert_eq!(app_metadata["subscription_tier"], "FREE");
        assert_eq!(app_metadata["legacy"], "kept");
        assert_eq!(user_metadata["full_name"], "Fresh Owner");
        assert_eq!(user_metadata["name"], "Fresh Owner");
        assert_eq!(user_metadata["auth_provider"], "email");
        assert_eq!(user_metadata["preferences"]["preferences_completed"], true);
    }
}
