# axum google oauth2 example

- [axum google oauth2 example](#axum-google-oauth2-example)
  - [What is in this Repository](#what-is-in-this-repository)
  - [How to use App](#how-to-use-app)
  - [Todo](#todo)

## What is in this Repository

An example implementation of Google OAuth2/OIDC authentication for Axum.
This was inspired by [example implimentation for discord](https://github.com/tokio-rs/axum/blob/main/examples/oauth/src/main.rs).

I wrote [a blog post](https://ktaka.blog.ccmp.jp/2024/12/axum-google-oauth2oidc-implementation.html) about this repository.

https://github.com/user-attachments/assets/64d5265d-13fe-4aba-a82c-91234ab2f9b8

## How to use App

- Obtain Client ID and Client Secret from Google <https://console.cloud.google.com/apis/credentials>
- Add "https://localhost:3443/auth/authorized" to "Authorized redirect URIs"
  - You can replace `localhost:3443` with your host's FQDN
  - You can also use ngrok hostname
- Edit .env file

```text
CLIENT_ID=$client_id
CLIENT_SECRET=$client_secret
ORIGIN='https://localhost:3443'

#(Optional: Run ngrok by `ngrok http 3000`)
#ORIGIN="https://xxxxx.ngrok-free.app"
```

- Start the application

```text
cargo run
```

## Todo

- Expiration check for session and token
- Clean up expired sessions and tokens from SQL store
- Implement PostgreSQL and SQLite storage
- Error handling by thiserr
- ~~Separate libsession and liboauth2~~
- Design and create user Database table
- ~~Remove csrf token etc after their use from token store~~
- Use STATIC parameters to simplify state management [see](https://github.com/ktaka-ccmp/axum-htmx-google-oauth/blob/master/src/settings.rs)
- Use middleware to distinguish authenticated users [see](https://github.com/ktaka-ccmp/axum-htmx-google-oauth/blob/master/src/main.rs#L90)
- Write unit tests
- Write integration tests
- Write documentation
- Publish on crates.io
- CI/CD

