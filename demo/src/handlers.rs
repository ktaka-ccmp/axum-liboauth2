use askama::Template;
use axum::{
    extract::{Form, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Redirect},
};
use axum_extra::{headers, TypedHeader};

use async_session::MemoryStore;
use chrono::{Duration, Utc};
use sha2::{Digest, Sha256};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

// Helper trait for converting errors to a standard response error format
trait IntoResponseError<T> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)>;
}

impl<T, E: std::fmt::Display> IntoResponseError<T> for Result<T, E> {
    fn into_response_error(self) -> Result<T, (StatusCode, String)> {
        self.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
    }
}

use liboauth2::oauth2::{
    authorized, csrf_checks, delete_session_from_store, encode_state, generate_store_token,
    header_set_cookie, validate_origin, AppState, AuthResponse, OAuth2Params, SessionParams, User,
};

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

#[derive(Template)]
#[template(path = "popup_close.j2")]
struct PopupCloseTemplate;

#[derive(Template)]
#[template(path = "protected.j2")]
struct ProtectedTemplate {
    user: User,
}

pub(crate) async fn index(user: Option<User>) -> Result<Html<String>, (StatusCode, String)> {
    match user {
        Some(u) => {
            let message = format!("Hey {}!", u.name);
            let template = IndexTemplateUser { message: &message };
            let html = Html(template.render().into_response_error()?);
            Ok(html)
        }
        None => {
            let message = "Click the Login button below.".to_string();
            let template = IndexTemplateAnon { message: &message };
            let html = Html(template.render().into_response_error()?);
            Ok(html)
        }
    }
}

pub(crate) async fn popup_close() -> Result<Html<String>, (StatusCode, String)> {
    let template = PopupCloseTemplate;
    let html = Html(template.render().into_response_error()?);
    Ok(html)
}

pub(crate) async fn google_auth(
    State(oauth2_params): State<OAuth2Params>,
    State(session_params): State<SessionParams>,
    State(store): State<MemoryStore>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let expires_at =
        Utc::now() + Duration::seconds(session_params.csrf_cookie_max_age.try_into().unwrap());
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();

    let (csrf_token, csrf_id) =
        generate_store_token("csrf_session", expires_at, Some(user_agent), &store)
            .await
            .into_response_error()?;
    let (nonce_token, nonce_id) = generate_store_token("nonce_session", expires_at, None, &store)
        .await
        .into_response_error()?;
    let (pkce_token, pkce_id) = generate_store_token("pkce_session", expires_at, None, &store)
        .await
        .into_response_error()?;

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
        session_params.csrf_cookie_max_age.try_into().unwrap(),
    )
    .into_response_error()?;

    Ok((headers, Redirect::to(&auth_url)))
}

pub async fn protected(user: User) -> Result<Html<String>, (StatusCode, String)> {
    let template = ProtectedTemplate { user };
    let html = Html(template.render().into_response_error()?);
    Ok(html)
}

pub async fn logout(
    State(store): State<MemoryStore>,
    State(session_params): State<SessionParams>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    let mut headers = HeaderMap::new();
    header_set_cookie(
        &mut headers,
        session_params.session_cookie_name.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )
    .into_response_error()?;

    delete_session_from_store(
        cookies,
        session_params.session_cookie_name.to_string(),
        &store,
    )
    .await
    .into_response_error()?;

    Ok((headers, Redirect::to("/")))
}

pub async fn post_authorized(
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
    Form(form): Form<AuthResponse>,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    println!(
        "Cookies: {:#?}",
        cookies.get(&state.session_params.csrf_cookie_name)
    );

    validate_origin(&headers, &state.oauth2_params.auth_url)
        .await
        .into_response_error()?;

    if form.state.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Missing state parameter".to_string(),
        ));
    }

    authorized(&form, state).await.into_response_error()
}

pub async fn get_authorized(
    Query(query): Query<AuthResponse>,
    State(state): State<AppState>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Redirect), (StatusCode, String)> {
    validate_origin(&headers, &state.oauth2_params.auth_url)
        .await
        .into_response_error()?;
    csrf_checks(cookies.clone(), &state.store, &query, headers)
        .await
        .into_response_error()?;

    delete_session_from_store(
        cookies,
        state.session_params.session_cookie_name.to_string(),
        &state.store,
    )
    .await
    .into_response_error()?;

    authorized(&query, state).await.into_response_error()
}
