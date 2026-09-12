use crate::{
    db::supabase::AuthUserRecord,
    errors::{AppError, Result},
    middleware::auth::AuthUser,
    security,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, put},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/me", get(get_me).put(update_me))
        .route("/me/preferences", put(update_preferences))
        .route("/me/password", put(change_password))
        .route("/:id", get(get_user_profile))
}

async fn get_me(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
) -> Result<impl IntoResponse> {
    let user = state.db.supabase.auth_get_user(&auth_user.id).await?;
    Ok(Json(user_json(&user, true)))
}

async fn update_me(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<impl IntoResponse> {
    let current = state.db.supabase.auth_get_user(&auth_user.id).await?;
    let mut user_metadata = current.user_metadata.clone();

    if let Some(name) = payload["name"]
        .as_str()
        .or_else(|| payload["full_name"].as_str())
    {
        let cleaned = security::sanitize_text(name, 120);
        set_metadata(&mut user_metadata, "full_name", json!(cleaned));
        set_metadata(&mut user_metadata, "name", json!(cleaned));
    }
    if let Some(profile_picture) = payload["profile_picture"].as_str() {
        if let Some(url) = security::normalize_url(Some(profile_picture), 500, false)? {
            set_metadata(&mut user_metadata, "profile_picture", json!(url));
        }
    }
    if let Some(about_me) = payload["about_me"].as_str() {
        if let Some(cleaned) = security::sanitize_optional_text(Some(about_me), 500) {
            set_metadata(&mut user_metadata, "about_me", json!(cleaned));
        }
    }

    let updated = state
        .db
        .supabase
        .auth_update_user(&auth_user.id, json!({ "user_metadata": user_metadata }))
        .await?;
    Ok(Json(user_json(&updated, true)))
}

async fn update_preferences(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Json(payload): Json<crate::models::user::UserPreferencesUpdate>,
) -> Result<impl IntoResponse> {
    let current = state.db.supabase.auth_get_user(&auth_user.id).await?;
    let mut user_metadata = current.user_metadata.clone();
    set_metadata(
        &mut user_metadata,
        "preferences",
        security::sanitize_preferences(payload),
    );

    let updated = state
        .db
        .supabase
        .auth_update_user(&auth_user.id, json!({ "user_metadata": user_metadata }))
        .await?;

    Ok(Json(user_json(&updated, true)))
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Json(payload): Json<serde_json::Value>,
) -> Result<impl IntoResponse> {
    let current = payload["current_password"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("current_password required".into()))?;
    let new_pw = payload["new_password"]
        .as_str()
        .ok_or_else(|| AppError::BadRequest("new_password required".into()))?;

    security::validate_password_strength(new_pw)?;

    state
        .db
        .supabase
        .auth_login_password(&auth_user.email, current)
        .await
        .map_err(|_| AppError::Unauthorized("Invalid current password".into()))?;
    state
        .db
        .supabase
        .auth_update_user(&auth_user.id, json!({ "password": new_pw }))
        .await?;

    Ok(Json(json!({ "message": "Password changed successfully" })))
}

async fn get_user_profile(
    State(state): State<Arc<AppState>>,
    Path(user_id): Path<String>,
) -> Result<impl IntoResponse> {
    let user_id = security::validate_uuid_id(&user_id, "user ID")?;
    let user = state.db.supabase.auth_get_user(&user_id).await?;
    Ok(Json(user_json(&user, false)))
}

fn user_json(user: &AuthUserRecord, include_private: bool) -> Value {
    let email = user.email.as_deref().unwrap_or_default();
    let full_name = metadata_str(&user.user_metadata, "full_name")
        .or_else(|| metadata_str(&user.user_metadata, "name"));
    let name = full_name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(if include_private {
            email
        } else {
            "Vantage user"
        });
    let preferences = user
        .user_metadata
        .get("preferences")
        .unwrap_or(&Value::Null);
    let role = metadata_str(&user.app_metadata, "role").unwrap_or("customer");
    // Never expose admin status on public profiles — show as customer instead.
    let public_role = if role == "admin" { "customer" } else { role };

    let mut value = json!({
        "id": user.id,
        "_id": user.id,
        "name": name,
        "full_name": full_name,
        "role": if include_private { role } else { public_role },
        "profile_picture": metadata_str(&user.user_metadata, "profile_picture"),
        "about_me": metadata_str(&user.user_metadata, "about_me"),
        "created_at": user.created_at,
        "preferences": preferences,
        "preferred_categories": preferences.get("preferred_categories").cloned().unwrap_or(Value::Null),
        "preferred_vibes": preferences.get("preferred_vibes").cloned().unwrap_or(Value::Null),
        "prefer_independent": preferences.get("prefer_independent").cloned().unwrap_or(Value::Null),
        "price_pref": preferences.get("price_pref").cloned().unwrap_or(Value::Null),
        "discovery_mode": preferences.get("discovery_mode").cloned().unwrap_or(Value::Null),
        "preferences_completed": preferences.get("preferences_completed").cloned().unwrap_or(Value::Null),
    });

    if include_private {
        value["email"] = json!(email);
        value["subscription_tier"] =
            json!(metadata_str(&user.app_metadata, "subscription_tier").unwrap_or("FREE"));
    }

    value
}

fn metadata_str<'a>(metadata: &'a Value, key: &str) -> Option<&'a str> {
    metadata.get(key).and_then(Value::as_str)
}

fn set_metadata(metadata: &mut Value, key: &str, value: Value) {
    if !metadata.is_object() {
        *metadata = json!({});
    }
    if let Some(object) = metadata.as_object_mut() {
        object.insert(key.to_string(), value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_user() -> AuthUserRecord {
        AuthUserRecord {
            id: "550e8400-e29b-41d4-a716-446655440000".into(),
            email: Some("private@example.com".into()),
            user_metadata: json!({
                "full_name": "Private User",
                "about_me": "Public bio"
            }),
            app_metadata: json!({
                "role": "customer",
                "subscription_tier": "FREE"
            }),
            created_at: Some("2026-05-19T00:00:00Z".into()),
        }
    }

    fn nameless_user() -> AuthUserRecord {
        AuthUserRecord {
            id: "550e8400-e29b-41d4-a716-446655440001".into(),
            email: Some("hidden@example.com".into()),
            user_metadata: json!({}),
            app_metadata: json!({ "role": "customer" }),
            created_at: None,
        }
    }

    #[test]
    fn public_profile_json_excludes_email() {
        let value = user_json(&sample_user(), false);
        assert!(value.get("email").is_none());
        assert_eq!(value["name"], "Private User");
        assert_eq!(value["about_me"], "Public bio");
    }

    #[test]
    fn private_profile_json_includes_email() {
        let value = user_json(&sample_user(), true);
        assert_eq!(value["email"], "private@example.com");
    }

    #[test]
    fn public_profile_without_name_does_not_fallback_to_email() {
        let value = user_json(&nameless_user(), false);
        assert!(value.get("email").is_none());
        assert_eq!(value["name"], "Vantage user");
    }
}
