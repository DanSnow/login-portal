use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use auth::Credentials;
use axum::{
    http::{header, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::{get, post, Router},
    Json,
};
use axum_login::{
    tower_sessions::{MemoryStore, SessionManagerLayer},
    AuthManagerLayerBuilder,
};
use clap::{Parser, Subcommand};
use config::UserDatabase;
use rpassword::prompt_password;
use rust_embed::RustEmbed;
use serde_json::json;
use std::net::SocketAddr;

use crate::config::get_user_database;

mod auth;
mod config;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Clone, Copy, Debug)]
enum Commands {
    Hash,
    Server,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cmd = Cli::parse();
    let command = cmd.command.unwrap_or(Commands::Server);
    match command {
        Commands::Hash => hash_password(),
        Commands::Server => start_server().await,
    }
}

fn hash_password() -> anyhow::Result<()> {
    let password = prompt_password("Password: ")?;
    let confirm_password = prompt_password("Comfirn password: ")?;
    if password != confirm_password {
        println!("Passwords do not match");
        return Ok(());
    }
    let salt = SaltString::generate(&mut OsRng);

    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default();

    // Hash password to PHC string ($argon2id$v=19$...)
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();

    // Verify password against PHC string.
    //
    // NOTE: hash params from `parsed_hash` are used instead of what is configured in the
    // `Argon2` instance.
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();
    assert!(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok());
    println!("{}", password_hash);
    Ok(())
}

async fn start_server() -> anyhow::Result<()> {
    let session_store = MemoryStore::default();
    let session_layer = SessionManagerLayer::new(session_store);

    // Auth service.
    let backend = get_user_database();
    let auth_layer = AuthManagerLayerBuilder::new(backend, session_layer).build();

    // Define our app routes, including a fallback option for anything not matched.
    let app = Router::new()
        .route("/_auth/api/v1/login", post(login))
        .route("/", get(index_handler))
        .route("/index.html", get(index_handler))
        .route("/_auth/assets/*file", get(static_handler))
        .layer(auth_layer)
        .fallback_service(get(not_found));

    // Start listening on the given address.
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

// We use static route matchers ("/" and "/index.html") to serve our home
// page.
async fn index_handler(auth_session: AuthSession) -> impl IntoResponse {
    let mut response = static_handler("/index.html".parse::<Uri>().unwrap())
        .await
        .into_response();

    if auth_session.user.is_some() {
        return response;
    }

    *response.status_mut() = StatusCode::UNAUTHORIZED;

    response
}

// We use a wildcard matcher ("/dist/*file") to match against everything
// within our defined assets directory. This is the directory on our Asset
// struct below, where folder = "examples/public/".
async fn static_handler(uri: Uri) -> impl IntoResponse {
    let mut path = uri.path().trim_start_matches('/').to_string();

    if path.starts_with("dist/") {
        path = path.replace("dist/", "");
    }

    StaticFile(path)
}

// Finally, we use a fallback route for anything that didn't match.
async fn not_found() -> Html<&'static str> {
    Html("<h1>404</h1><p>Not Found</p>")
}

#[derive(RustEmbed)]
#[folder = "packages/web/dist"]
struct Asset;

pub struct StaticFile<T>(pub T);

impl<T> IntoResponse for StaticFile<T>
where
    T: Into<String>,
{
    fn into_response(self) -> Response {
        let path = self.0.into();

        match Asset::get(path.as_str()) {
            Some(content) => {
                let mime = mime_guess::from_path(path).first_or_octet_stream();
                ([(header::CONTENT_TYPE, mime.as_ref())], content.data).into_response()
            }
            None => (StatusCode::NOT_FOUND, "404 Not Found").into_response(),
        }
    }
}

type AuthSession = axum_login::AuthSession<UserDatabase>;

#[derive(Debug, serde::Deserialize, Clone)]
struct LoginForm {
    email: String,
    password: String,
}

async fn login(mut auth_session: AuthSession, Json(login): Json<LoginForm>) -> impl IntoResponse {
    let user = auth_session
        .backend
        .users
        .values()
        .find(|user| user.email == login.email);
    let user = match user {
        Some(user) => user,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let parsed_hash = PasswordHash::new(&user.password_hash).unwrap();
    let res = match Argon2::default().verify_password(login.password.as_bytes(), &parsed_hash) {
        Ok(_) => user,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let cred = Credentials {
        username: res.username.clone(),
    };

    let user = match auth_session.authenticate(cred.clone()).await {
        Ok(Some(user)) => user,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    if auth_session.login(&user).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    return Json(json!({"ok": true})).into_response();
}
