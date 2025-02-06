use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::{headers, TypedHeader};

use async_session::MemoryStore;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use liboauth2::oauth2::{
    authorized, csrf_checks, delete_session_from_store, encode_state, generate_store_token,
    header_set_cookie, validate_origin, AppError, AppState, AuthResponse, OAuth2Params,
    SessionParams, User,
};
// use liboauth2::oauth2::*;

#[derive(Template)]
#[template(path = "index_user.j2")]
struct IndexTemplateUser<'a> {
    message: &'a str,
}

#[derive(Template)]
#[template(path = "index_anon.j2")]
struct IndexTemplateAnon<'a> {
    message: &'a str,
}

pub(crate) async fn index(user: Option<User>) -> Result<impl IntoResponse, AppError> {
    match user {
        Some(u) => {
            let message = format!("Hey {}!", u.name);
            let template = IndexTemplateUser { message: &message };
            Ok(Html(template.render().unwrap()).into_response())
        }
        None => {
            let message = "Click the Login button below.".to_string();
            let template = IndexTemplateAnon { message: &message };
            Ok(Html(template.render().unwrap()).into_response())
        }
    }
}

pub(crate) async fn popup_close() -> impl IntoResponse {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Self-closing Page</title>
    <script>
        window.onload = function() {
            // Send message to parent window
            if (window.opener) {
                window.opener.postMessage('auth_complete', window.location.origin);
            }
            // Close the window after a short delay
            setTimeout(function() {
                window.close();
            }, 500); // 500 milliseconds = 0.5 seconds
        }
    </script>
</head>
<body>
    <h2>Login Successful</h2>
    <h2>This window will close automatically with in a few seconds...</h2>
</body>
</html>
"#
    .to_string();

    Response::builder()
        .header("Content-Type", "text/html")
        .body(html)
        .unwrap()
}

pub(crate) async fn google_auth(
    State(oauth2_params): State<OAuth2Params>,
    State(session_params): State<SessionParams>,
    State(store): State<MemoryStore>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let expires_at = Utc::now() + Duration::seconds(session_params.csrf_cookie_max_age);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let (csrf_token, csrf_id) =
        generate_store_token("csrf_session", expires_at, Some(user_agent), &store).await?;
    let (nonce_token, nonce_id) =
        generate_store_token("nonce_session", expires_at, None, &store).await?;
    let (pkce_token, pkce_id) =
        generate_store_token("pkce_session", expires_at, None, &store).await?;

    println!("PKCE ID: {:?}, PKCE verifier: {:?}", pkce_id, pkce_token);

    let pkce_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_token.as_bytes()));
    println!("PKCE Challenge: {:#?}", pkce_challenge);

    let encoded_state = encode_state(csrf_token, nonce_id, pkce_id);

    let auth_url = format!(
        "{}?{}&client_id={}&redirect_uri={}&state={}&nonce={}\
        &code_challenge={}&code_challenge_method={}",
        oauth2_params.auth_url,
        oauth2_params.query_string,
        oauth2_params.client_id,
        oauth2_params.redirect_uri,
        encoded_state,
        nonce_token,
        pkce_challenge,
        "S256"
    );

    println!("Auth URL: {:#?}", auth_url);

    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        session_params.csrf_cookie_name.to_string(),
        csrf_id,
        expires_at,
        session_params.csrf_cookie_max_age,
    )?;

    Ok((headers, Redirect::to(&auth_url)))
}

pub async fn protected(user: User) -> impl IntoResponse {
    format!("Welcome to the protected area :)\nHere's your info:\n{user:?}")
}

pub async fn logout(
    State(store): State<MemoryStore>,
    State(session_params): State<SessionParams>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoResponse, AppError> {
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        session_params.session_cookie_name.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )?;

    delete_session_from_store(
        cookies,
        session_params.session_cookie_name.to_string(),
        &store,
    )
    .await?;

    Ok((headers, Redirect::to("/")))
}

pub async fn post_authorized(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
    Form(form): Form<AuthResponse>,
) -> Result<impl IntoResponse, AppError> {
    println!(
        "Cookies: {:#?}",
        cookies.get(&state.session_params.csrf_cookie_name)
    );

    validate_origin(&headers, &state.oauth2_params.auth_url).await?;
    if form.state.is_empty() {
        return Err(anyhow::anyhow!("Missing state parameter").into());
    }

    authorized(&form, state).await
}

pub async fn get_authorized(
    Query(query): Query<AuthResponse>,
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    validate_origin(&headers, &state.oauth2_params.auth_url).await?;
    csrf_checks(cookies.clone(), &state.store, &query, headers).await?;
    delete_session_from_store(
        cookies,
        state.session_params.session_cookie_name.to_string(),
        &state.store,
    )
    .await?;

    authorized(&query, state).await
}
