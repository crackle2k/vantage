use crate::{
    errors::{AppError, Result},
    middleware::auth::AuthUser,
    routes::support::{
        eq, limit, normalize_review, offset, order, pagination_headers, pagination_meta,
        pagination_window, q, select_all, unwrap_rpc_items, value_str, QueryParams,
    },
    security,
    state::AppState,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::Arc;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/reviews", post(create_review))
        .route(
            "/reviews/:id",
            get(get_review).put(update_review).delete(delete_review),
        )
        .route("/businesses/:id/reviews", get(list_business_reviews))
        .route("/reviews/business/:id", get(list_business_reviews))
}

#[derive(Deserialize)]
struct PaginationParams {
    limit: Option<i64>,
    offset: Option<i64>,
    cursor: Option<String>,
    include_pagination: Option<bool>,
}

async fn list_business_reviews(
    State(state): State<Arc<AppState>>,
    Path(business_id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<impl IntoResponse> {
    let business_id = security::validate_uuid_id(&business_id, "business ID")?;
    let window = pagination_window(
        params.limit,
        params.offset,
        params.cursor.as_deref(),
        20,
        100,
    )?;
    let query: QueryParams = vec![
        select_all(),
        eq("business_id", business_id),
        order("created_at.desc"),
        limit(window.limit + 1),
        offset(window.offset),
    ];

    let mut reviews = state
        .db
        .supabase
        .select_json("reviews", &query)
        .await?
        .into_iter()
        .map(normalize_review)
        .collect::<Vec<_>>();
    let meta = pagination_meta(window.limit, window.offset, reviews.len());
    reviews.truncate(window.limit as usize);

    let body = if params.include_pagination.unwrap_or(false) {
        json!({
            "items": reviews,
            "pagination": &meta,
            "has_more": meta.has_more,
            "next_cursor": meta.next_cursor.clone(),
        })
    } else {
        json!(reviews)
    };

    Ok((pagination_headers(&meta), Json(body)))
}

async fn get_review(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let row = find_review(&state, &id).await?;
    Ok(Json(normalize_review(row)))
}

#[derive(serde::Deserialize)]
struct ReviewCreate {
    business_id: String,
    rating: f64,
    comment: Option<String>,
}

async fn create_review(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Json(payload): Json<ReviewCreate>,
) -> Result<impl IntoResponse> {
    validate_rating(payload.rating)?;
    let business_id = security::validate_uuid_id(&payload.business_id, "business ID")?;

    let business = state
        .db
        .supabase
        .select_one_json("businesses", &[select_all(), eq("id", &business_id)])
        .await?;
    let business = business.ok_or_else(|| AppError::NotFound("Business not found".into()))?;
    ensure_not_owned_business_review(&business, &auth_user)?;

    let existing = state
        .db
        .supabase
        .select_one_json(
            "reviews",
            &[
                select_all(),
                eq("business_id", &business_id),
                eq("user_id", &auth_user.id),
            ],
        )
        .await?;
    if existing.is_some() {
        return Err(AppError::Conflict(
            "You have already reviewed this business".into(),
        ));
    }
    ensure_review_rate_allowed(&state, &auth_user.id).await?;

    let now = Utc::now().to_rfc3339();
    let mut body = Map::new();
    body.insert("business_id".into(), json!(business_id));
    body.insert("user_id".into(), json!(auth_user.id));
    body.insert("user_name".into(), json!(auth_user.display_name()));
    body.insert("rating".into(), json!(payload.rating));
    body.insert(
        "comment".into(),
        json!(
            security::sanitize_optional_text(payload.comment.as_deref(), 2000).unwrap_or_default()
        ),
    );
    body.insert("is_verified".into(), json!(false));
    body.insert("credibility_weight".into(), json!(1.0));
    body.insert("helpful_count".into(), json!(0));
    body.insert("created_at".into(), json!(now));
    body.insert("updated_at".into(), json!(now));

    let created = state
        .db
        .supabase
        .insert_json("reviews", Value::Object(body))
        .await
        .map_err(map_review_insert_error)?;

    update_business_rating(&state, &business_id).await?;

    Ok((StatusCode::CREATED, Json(normalize_review(created))))
}

#[derive(serde::Deserialize)]
struct ReviewUpdate {
    rating: Option<f64>,
    comment: Option<String>,
}

async fn update_review(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<ReviewUpdate>,
) -> Result<impl IntoResponse> {
    let existing = find_review(&state, &id).await?;
    if value_str(&existing, "user_id") != auth_user.id {
        return Err(AppError::Forbidden("Not your review".into()));
    }
    let business = state
        .db
        .supabase
        .select_one_json(
            "businesses",
            &[select_all(), eq("id", value_str(&existing, "business_id"))],
        )
        .await?
        .ok_or_else(|| AppError::NotFound("Business not found".into()))?;
    ensure_not_owned_business_review(&business, &auth_user)?;
    ensure_review_update_rate_allowed(&state, &auth_user.id, &id).await?;

    let mut body = Map::new();
    body.insert("updated_at".into(), json!(Utc::now().to_rfc3339()));
    if let Some(rating) = payload.rating {
        validate_rating(rating)?;
        body.insert("rating".into(), json!(rating));
    }
    if let Some(comment) = payload.comment {
        body.insert(
            "comment".into(),
            json!(security::sanitize_text(&comment, 2000)),
        );
    }

    let updated = state
        .db
        .supabase
        .update_json(
            "reviews",
            &[eq("id", &id), eq("user_id", &auth_user.id)],
            Value::Object(body),
        )
        .await?;
    let row = updated
        .into_iter()
        .next()
        .ok_or_else(|| AppError::NotFound("Review not found".into()))?;

    update_business_rating(&state, value_str(&existing, "business_id")).await?;

    Ok(Json(normalize_review(row)))
}

async fn delete_review(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse> {
    let existing = find_review(&state, &id).await?;
    if value_str(&existing, "user_id") != auth_user.id && auth_user.role != "admin" {
        return Err(AppError::Forbidden("Not your review".into()));
    }

    state
        .db
        .supabase
        .delete_json("reviews", &[eq("id", &id)])
        .await?;
    update_business_rating(&state, value_str(&existing, "business_id")).await?;

    Ok(Json(json!({ "message": "Review deleted" })))
}

async fn find_review(state: &AppState, id: &str) -> Result<Value> {
    let id = security::validate_uuid_id(id, "review ID")?;
    state
        .db
        .supabase
        .select_one_json("reviews", &[select_all(), eq("id", id)])
        .await?
        .ok_or_else(|| AppError::NotFound("Review not found".into()))
}

async fn update_business_rating(state: &AppState, business_id: &str) -> Result<()> {
    let business_id = security::validate_uuid_id(business_id, "business ID")?;
    match refresh_business_review_summary(state, &business_id).await {
        Ok(()) => return Ok(()),
        Err(err) if review_summary_rpc_unavailable(&err.to_string()) => {
            tracing::warn!(
                error = %err,
                "Review summary RPC unavailable; falling back to API-side aggregate refresh"
            );
        }
        Err(err) => return Err(err.into()),
    }

    update_business_rating_fallback(state, &business_id).await
}

async fn refresh_business_review_summary(
    state: &AppState,
    business_id: &str,
) -> anyhow::Result<()> {
    let rows = state
        .db
        .supabase
        .rpc_json(
            "refresh_business_review_summary",
            json!({ "p_business_id": business_id }),
        )
        .await?;
    let updated = unwrap_rpc_items(rows);
    if updated.is_empty() {
        anyhow::bail!("Business not found");
    }
    Ok(())
}

async fn update_business_rating_fallback(state: &AppState, business_id: &str) -> Result<()> {
    let reviews = state
        .db
        .supabase
        .select_json(
            "reviews",
            &[q("select", "rating"), eq("business_id", business_id)],
        )
        .await?;

    let count = reviews.len() as i64;
    let avg = if count == 0 {
        Value::Null
    } else {
        let total = reviews
            .iter()
            .filter_map(|row| row.get("rating").and_then(Value::as_f64))
            .sum::<f64>();
        json!(total / count as f64)
    };

    state
        .db
        .supabase
        .update_json(
            "businesses",
            &[eq("id", business_id)],
            json!({
                "rating": avg,
                "review_count": count,
                "updated_at": Utc::now().to_rfc3339(),
            }),
        )
        .await?;

    Ok(())
}

fn review_summary_rpc_unavailable(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    (lowered.contains("refresh_business_review_summary") && lowered.contains("does not exist"))
        || lowered.contains("could not find the function")
        || lowered.contains("schema cache")
}

fn validate_rating(rating: f64) -> Result<()> {
    if !(1.0..=5.0).contains(&rating) || !rating.is_finite() {
        return Err(AppError::BadRequest(
            "Rating must be between 1 and 5".into(),
        ));
    }
    Ok(())
}

fn ensure_not_owned_business_review(business: &Value, auth_user: &AuthUser) -> Result<()> {
    if value_str(business, "owner_id") == auth_user.id {
        return Err(AppError::Forbidden(
            "Business owners cannot review their own listing".into(),
        ));
    }
    Ok(())
}

async fn ensure_review_rate_allowed(state: &AppState, user_id: &str) -> Result<()> {
    let since = (Utc::now() - Duration::hours(1)).to_rfc3339();
    let recent = state
        .db
        .supabase
        .count(
            "reviews",
            &[
                eq("user_id", user_id),
                crate::routes::support::gte("created_at", since),
            ],
        )
        .await?;
    if recent >= 8 {
        return Err(AppError::RateLimited);
    }
    Ok(())
}

async fn ensure_review_update_rate_allowed(
    state: &AppState,
    user_id: &str,
    review_id: &str,
) -> Result<()> {
    let allowed = state
        .rate_limiter
        .check(
            &format!("review-update:{}:{}", user_id, review_id),
            8,
            std::time::Duration::from_secs(3600),
        )
        .await;
    if !allowed {
        return Err(AppError::RateLimited);
    }
    Ok(())
}

fn map_review_insert_error(err: anyhow::Error) -> AppError {
    let message = err.to_string().to_ascii_lowercase();
    if message.contains("duplicate") || message.contains("unique") {
        AppError::Conflict("You have already reviewed this business".into())
    } else {
        err.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth_user(id: &str) -> AuthUser {
        AuthUser {
            id: id.into(),
            email: "owner@example.com".into(),
            name: "Owner".into(),
            role: "business_owner".into(),
        }
    }

    #[test]
    fn review_summary_rpc_unavailable_detects_missing_migration_only() {
        assert!(review_summary_rpc_unavailable(
            "Could not find the function public.refresh_business_review_summary in the schema cache"
        ));
        assert!(review_summary_rpc_unavailable(
            "function refresh_business_review_summary(uuid) does not exist"
        ));
        assert!(!review_summary_rpc_unavailable(
            "permission denied for function refresh_business_review_summary"
        ));
    }

    #[test]
    fn business_owners_cannot_review_their_own_listing() {
        let business = json!({
            "owner_id": "550e8400-e29b-41d4-a716-446655440000"
        });

        assert!(ensure_not_owned_business_review(
            &business,
            &auth_user("550e8400-e29b-41d4-a716-446655440000")
        )
        .is_err());
        assert!(ensure_not_owned_business_review(
            &business,
            &auth_user("660e8400-e29b-41d4-a716-446655440000")
        )
        .is_ok());
    }
}
