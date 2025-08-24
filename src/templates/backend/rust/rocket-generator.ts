import { RustBackendGenerator } from './rust-base-generator';

export class RocketGenerator extends RustBackendGenerator {
  constructor() {
    super('Rocket');
  }
  
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'rocket': '{ version = "0.5", features = ["secrets", "json", "uuid"] }',
      'rocket_db_pools': '{ version = "0.1", features = ["sqlx_postgres"] }',
      'rocket_sync_db_pools': '"0.1"',
      'rocket_cors': '"0.6"',
      'rocket_dyn_templates': '{ version = "0.1", features = ["handlebars", "tera"] }',
      'utoipa': '{ version = "4", features = ["rocket"] }',
      'utoipa-swagger-ui': '{ version = "5", features = ["rocket"] }',
      'serde_json': '"1.0"'
    };
  }
  
  protected generateMainFile(): string {
    return `#[macro_use] extern crate rocket;

use dotenv::dotenv;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Request, Response, State};
use rocket::http::Header;
use rocket_cors::{AllowedOrigins, CorsOptions};
use sqlx::postgres::PgPoolOptions;

mod config;
mod db;
mod error;
mod guards;
mod handlers;
mod models;
mod routes;
mod services;
mod utils;

use crate::config::Config;
use crate::db::{run_migrations, DbPool};
use crate::error::AppError;
use crate::routes::*;

// Custom CORS fairing
pub struct CORS;

#[rocket::async_trait]
impl Fairing for CORS {
    fn info(&self) -> Info {
        Info {
            name: "Add CORS headers to responses",
            kind: Kind::Response
        }
    }

    async fn on_response<'r>(&self, _request: &'r Request<'_>, response: &mut Response<'r>) {
        response.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        response.set_header(Header::new("Access-Control-Allow-Methods", "POST, GET, PATCH, OPTIONS"));
        response.set_header(Header::new("Access-Control-Allow-Headers", "*"));
        response.set_header(Header::new("Access-Control-Allow-Credentials", "true"));
    }
}

#[launch]
async fn rocket() -> _ {
    dotenv().ok();
    
    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");
    
    // Create database pool
    let database_url = config.database_url.clone();
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");
    
    // Run migrations
    run_migrations(&db_pool).await
        .expect("Failed to run migrations");
    
    // Create Redis client
    let redis_client = redis::Client::open(config.redis_url.clone())
        .expect("Failed to create Redis client");
    
    println!("🚀 Starting {} on port {}", config.app_name, config.app_port);
    
    // Configure CORS
    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::some_exact(&[
            "http://localhost:3000",
            "http://localhost:5173"
        ]))
        .allowed_methods(
            vec![
                rocket::http::Method::Get,
                rocket::http::Method::Post,
                rocket::http::Method::Put,
                rocket::http::Method::Patch,
                rocket::http::Method::Delete,
                rocket::http::Method::Options,
            ]
            .into_iter()
            .map(From::from)
            .collect(),
        )
        .allow_credentials(true);
    
    rocket::build()
        .manage(DbPool(db_pool))
        .manage(redis_client)
        .manage(config)
        .attach(cors.to_cors().expect("Failed to create CORS fairing"))
        .attach(CORS)
        .mount("/api/v1", health_routes())
        .mount("/api/v1/auth", auth_routes())
        .mount("/api/v1/users", user_routes())
        .mount("/api/v1/admin", admin_routes())
        .mount("/ws", websocket_routes())
        .mount("/", swagger_routes())
}`;
  }
  
  protected generateServerFile(): string {
    // Rocket doesn't need a separate server file - everything is in main.rs
    return '';
  }
  
  protected generateRouterFile(): string {
    return `use rocket::{Route, routes};

use crate::handlers;

pub fn health_routes() -> Vec<Route> {
    routes![handlers::health::health_check]
}

pub fn auth_routes() -> Vec<Route> {
    routes![
        handlers::auth::register,
        handlers::auth::login,
        handlers::auth::refresh,
        handlers::auth::logout
    ]
}

pub fn user_routes() -> Vec<Route> {
    routes![
        handlers::user::get_profile,
        handlers::user::update_profile,
        handlers::user::delete_account,
        handlers::user::change_password
    ]
}

pub fn admin_routes() -> Vec<Route> {
    routes![
        handlers::user::list_users,
        handlers::user::get_user,
        handlers::user::update_user,
        handlers::user::delete_user
    ]
}

pub fn websocket_routes() -> Vec<Route> {
    routes![handlers::websocket::websocket_handler]
}

pub fn swagger_routes() -> Vec<Route> {
    routes![
        handlers::docs::openapi_spec,
        handlers::docs::swagger_ui
    ]
}`;
  }
  
  protected generateHandlerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/handlers/mod.rs',
        content: `pub mod auth;
pub mod docs;
pub mod health;
pub mod user;
pub mod websocket;`
      },
      {
        path: 'src/handlers/health.rs',
        content: `use rocket::serde::{Deserialize, Serialize};
use rocket::{get, State};
use utoipa::ToSchema;

use crate::db::DbPool;

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub database: String,
    pub uptime: String,
}

#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 503, description = "Service is unhealthy", body = HealthResponse),
    )
)]
#[get("/health")]
pub async fn health_check(db: &State<DbPool>) -> rocket::serde::json::Json<HealthResponse> {
    let mut health = HealthResponse {
        status: "healthy".to_string(),
        database: "healthy".to_string(),
        uptime: format!("{:?}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()),
    };
    
    // Check database connection
    match sqlx::query("SELECT 1").fetch_one(&db.0).await {
        Ok(_) => {},
        Err(_) => {
            health.status = "degraded".to_string();
            health.database = "unhealthy".to_string();
        }
    }
    
    rocket::serde::json::Json(health)
}`
      },
      {
        path: 'src/handlers/auth.rs',
        content: `use rocket::serde::json::Json;
use rocket::{post, State};
use validator::Validate;

use crate::config::Config;
use crate::db::DbPool;
use crate::error::AppResult;
use crate::models::user::{RegisterRequest, LoginRequest};
use crate::models::token::TokenResponse;
use crate::services::auth_service::AuthService;
use crate::services::user_service::UserService;

#[utoipa::path(
    post,
    path = "/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = TokenResponse),
        (status = 400, description = "Invalid request data"),
        (status = 409, description = "User already exists"),
    )
)]
#[post("/register", data = "<body>")]
pub async fn register(
    body: Json<RegisterRequest>,
    db: &State<DbPool>,
    config: &State<Config>,
) -> AppResult<Json<TokenResponse>> {
    body.validate()?;
    
    let user_service = UserService::new(db.0.clone());
    let auth_service = AuthService::new(user_service, config.inner().clone());
    
    let token_response = auth_service.register(&body).await?;
    Ok(Json(token_response))
}

#[utoipa::path(
    post,
    path = "/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = TokenResponse),
        (status = 401, description = "Invalid credentials"),
    )
)]
#[post("/login", data = "<body>")]
pub async fn login(
    body: Json<LoginRequest>,
    db: &State<DbPool>,
    config: &State<Config>,
) -> AppResult<Json<TokenResponse>> {
    body.validate()?;
    
    let user_service = UserService::new(db.0.clone());
    let auth_service = AuthService::new(user_service, config.inner().clone());
    
    let token_response = auth_service.login(&body).await?;
    Ok(Json(token_response))
}

#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "auth",
    responses(
        (status = 200, description = "Token refreshed successfully", body = TokenResponse),
        (status = 401, description = "Invalid refresh token"),
    )
)]
#[post("/refresh", data = "<refresh_token>")]
pub async fn refresh(
    refresh_token: Json<String>,
    db: &State<DbPool>,
    config: &State<Config>,
) -> AppResult<Json<TokenResponse>> {
    let user_service = UserService::new(db.0.clone());
    let auth_service = AuthService::new(user_service, config.inner().clone());
    
    let token_response = auth_service.refresh_token(&refresh_token).await?;
    Ok(Json(token_response))
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "auth",
    responses(
        (status = 200, description = "Logout successful"),
    )
)]
#[post("/logout")]
pub async fn logout() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Logged out successfully"
    }))
}`
      },
      {
        path: 'src/handlers/user.rs',
        content: `use rocket::serde::json::Json;
use rocket::{get, post, put, delete, State};
use uuid::Uuid;
use validator::Validate;

use crate::db::DbPool;
use crate::error::AppResult;
use crate::guards::AuthGuard;
use crate::models::user::{UserResponse, UpdateUserRequest, ChangePasswordRequest};
use crate::services::user_service::UserService;

#[derive(Debug, rocket::serde::Deserialize)]
pub struct PaginationQuery {
    pub page: Option<i32>,
    pub limit: Option<i32>,
}

#[utoipa::path(
    get,
    path = "/users/profile",
    tag = "users",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User profile retrieved", body = UserResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
#[get("/profile")]
pub async fn get_profile(
    auth: AuthGuard,
    db: &State<DbPool>,
) -> AppResult<Json<UserResponse>> {
    let user_service = UserService::new(db.0.clone());
    
    let user = user_service.get_user_by_id(auth.user_id).await?;
    let response: UserResponse = user.into();
    
    Ok(Json(response))
}

#[utoipa::path(
    put,
    path = "/users/profile",
    tag = "users",
    request_body = UpdateUserRequest,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Profile updated", body = UserResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
#[put("/profile", data = "<body>")]
pub async fn update_profile(
    auth: AuthGuard,
    body: Json<UpdateUserRequest>,
    db: &State<DbPool>,
) -> AppResult<Json<UserResponse>> {
    let user_service = UserService::new(db.0.clone());
    
    let user = user_service.update_user(auth.user_id, &body).await?;
    let response: UserResponse = user.into();
    
    Ok(Json(response))
}

#[utoipa::path(
    post,
    path = "/users/change-password",
    tag = "users",
    request_body = ChangePasswordRequest,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Password changed successfully"),
        (status = 400, description = "Invalid old password"),
        (status = 401, description = "Unauthorized"),
    )
)]
#[post("/change-password", data = "<body>")]
pub async fn change_password(
    auth: AuthGuard,
    body: Json<ChangePasswordRequest>,
    db: &State<DbPool>,
) -> AppResult<Json<serde_json::Value>> {
    body.validate()?;
    
    let user_service = UserService::new(db.0.clone());
    
    user_service.change_password(auth.user_id, &body.old_password, &body.new_password).await?;
    
    Ok(Json(serde_json::json!({
        "message": "Password changed successfully"
    })))
}

#[utoipa::path(
    delete,
    path = "/users/profile",
    tag = "users",
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Account deleted successfully"),
        (status = 401, description = "Unauthorized"),
    )
)]
#[delete("/profile")]
pub async fn delete_account(
    auth: AuthGuard,
    db: &State<DbPool>,
) -> AppResult<Json<serde_json::Value>> {
    let user_service = UserService::new(db.0.clone());
    
    user_service.delete_user(auth.user_id).await?;
    
    Ok(Json(serde_json::json!({
        "message": "Account deleted successfully"
    })))
}

// Admin endpoints
#[utoipa::path(
    get,
    path = "/admin/users",
    tag = "users",
    params(
        ("page" = Option<i32>, Query, description = "Page number"),
        ("limit" = Option<i32>, Query, description = "Items per page"),
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "Users list retrieved"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
    )
)]
#[get("/users?<page>&<limit>")]
pub async fn list_users(
    _auth: AuthGuard, // TODO: Add role check for admin
    page: Option<i32>,
    limit: Option<i32>,
    db: &State<DbPool>,
) -> AppResult<Json<serde_json::Value>> {
    let page = page.unwrap_or(1);
    let limit = limit.unwrap_or(10);
    
    let user_service = UserService::new(db.0.clone());
    let (users, total) = user_service.list_users(page, limit).await?;
    
    Ok(Json(serde_json::json!({
        "users": users,
        "total": total,
        "page": page,
        "limit": limit,
    })))
}

#[utoipa::path(
    get,
    path = "/admin/users/{id}",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID"),
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User retrieved", body = UserResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "User not found"),
    )
)]
#[get("/users/<id>")]
pub async fn get_user(
    _auth: AuthGuard, // TODO: Add role check for admin
    id: String,
    db: &State<DbPool>,
) -> AppResult<Json<UserResponse>> {
    let user_id = Uuid::parse_str(&id)?;
    
    let user_service = UserService::new(db.0.clone());
    let user = user_service.get_user_by_id(user_id).await?;
    let response: UserResponse = user.into();
    
    Ok(Json(response))
}

#[utoipa::path(
    put,
    path = "/admin/users/{id}",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID"),
    ),
    request_body = UpdateUserRequest,
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User updated", body = UserResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "User not found"),
    )
)]
#[put("/users/<id>", data = "<body>")]
pub async fn update_user(
    _auth: AuthGuard, // TODO: Add role check for admin
    id: String,
    body: Json<UpdateUserRequest>,
    db: &State<DbPool>,
) -> AppResult<Json<UserResponse>> {
    let user_id = Uuid::parse_str(&id)?;
    
    let user_service = UserService::new(db.0.clone());
    let user = user_service.update_user(user_id, &body).await?;
    let response: UserResponse = user.into();
    
    Ok(Json(response))
}

#[utoipa::path(
    delete,
    path = "/admin/users/{id}",
    tag = "users",
    params(
        ("id" = String, Path, description = "User ID"),
    ),
    security(
        ("bearer_auth" = [])
    ),
    responses(
        (status = 200, description = "User deleted successfully"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "User not found"),
    )
)]
#[delete("/users/<id>")]
pub async fn delete_user(
    _auth: AuthGuard, // TODO: Add role check for admin
    id: String,
    db: &State<DbPool>,
) -> AppResult<Json<serde_json::Value>> {
    let user_id = Uuid::parse_str(&id)?;
    
    let user_service = UserService::new(db.0.clone());
    user_service.delete_user(user_id).await?;
    
    Ok(Json(serde_json::json!({
        "message": "User deleted successfully"
    })))
}`
      },
      {
        path: 'src/handlers/websocket.rs',
        content: `use rocket::{get, State};
use rocket::response::status;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;
use crate::db::DbPool;
use crate::guards::AuthGuard;

#[derive(Debug, Serialize, Deserialize)]
struct WsMessage {
    r#type: String,
    payload: serde_json::Value,
}

// Note: Rocket doesn't have built-in WebSocket support like some other frameworks
// This is a placeholder that would need to be implemented with additional crates
// like tokio-tungstenite or similar
#[get("/connect")]
pub async fn websocket_handler(
    auth: AuthGuard,
    _db: &State<DbPool>,
    _config: &State<Config>,
) -> status::Accepted<String> {
    // In a real implementation, you would:
    // 1. Upgrade the HTTP connection to WebSocket
    // 2. Handle WebSocket messages
    // 3. Implement connection management
    
    let message = format!("WebSocket connection would be established for user {}", auth.user_id);
    status::Accepted(Some(message))
}`
      },
      {
        path: 'src/handlers/docs.rs',
        content: `use rocket::{get, response::content};
use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::handlers::health::health_check,
        crate::handlers::auth::register,
        crate::handlers::auth::login,
        crate::handlers::auth::refresh,
        crate::handlers::auth::logout,
        crate::handlers::user::get_profile,
        crate::handlers::user::update_profile,
        crate::handlers::user::change_password,
        crate::handlers::user::delete_account,
        crate::handlers::user::list_users,
        crate::handlers::user::get_user,
        crate::handlers::user::update_user,
        crate::handlers::user::delete_user,
    ),
    components(
        schemas(
            crate::models::user::User,
            crate::models::user::RegisterRequest,
            crate::models::user::LoginRequest,
            crate::models::user::UserResponse,
            crate::models::user::UpdateUserRequest,
            crate::models::user::ChangePasswordRequest,
            crate::models::token::TokenResponse,
            crate::handlers::health::HealthResponse,
        )
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "auth", description = "Authentication endpoints"),
        (name = "users", description = "User management endpoints"),
    ),
    info(
        title = "${this.options.name}",
        version = "1.0.0",
        description = "Rocket backend service API",
        contact(
            name = "API Support",
            email = "support@example.com",
        ),
        license(
            name = "MIT",
        ),
    ),
    servers(
        (url = "http://localhost:8080", description = "Local development server"),
    ),
)]
struct ApiDoc;

#[get("/api-doc.json")]
pub fn openapi_spec() -> content::RawJson<String> {
    content::RawJson(ApiDoc::openapi().to_pretty_json().unwrap())
}

#[get("/swagger-ui")]
pub fn swagger_ui() -> content::RawHtml<&'static str> {
    content::RawHtml(r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Swagger UI</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/api-doc.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>
    "#)
}`
      }
    ];
  }
  
  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/guards/mod.rs',
        content: `use rocket::request::{FromRequest, Outcome, Request};
use rocket::{http::Status, State};
use uuid::Uuid;

use crate::config::Config;
use crate::error::AppError;
use crate::models::token::decode_jwt;

pub struct AuthGuard {
    pub user_id: Uuid,
    pub email: String,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthGuard {
    type Error = AppError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let config = match request.guard::<&State<Config>>().await {
            Outcome::Success(config) => config,
            _ => return Outcome::Error((Status::InternalServerError, AppError::InternalServerError)),
        };

        match request.headers().get_one("Authorization") {
            Some(header) if header.starts_with("Bearer ") => {
                let token = &header[7..];
                match decode_jwt(token, &config.jwt_secret) {
                    Ok(claims) => Outcome::Success(AuthGuard {
                        user_id: claims.sub,
                        email: claims.email,
                    }),
                    Err(_) => Outcome::Error((Status::Unauthorized, AppError::InvalidToken)),
                }
            }
            _ => Outcome::Error((Status::Unauthorized, AppError::Unauthorized)),
        }
    }
}`
      }
    ];
  }
  
  protected generateConfigFile(): string {
    return `use serde::Deserialize;
use std::env;

use crate::error::AppError;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub app_name: String,
    pub app_env: String,
    pub app_port: String,
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub jwt_expiration: i64,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_pass: String,
    pub smtp_from: String,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        Ok(Config {
            app_name: env::var("APP_NAME").unwrap_or_else(|_| "${this.options.name}".to_string()),
            app_env: env::var("APP_ENV").unwrap_or_else(|_| "development".to_string()),
            app_port: env::var("APP_PORT").unwrap_or_else(|_| "8080".to_string()),
            database_url: env::var("DATABASE_URL")
                .map_err(|_| AppError::Configuration("DATABASE_URL not set".to_string()))?,
            redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string()),
            jwt_secret: env::var("JWT_SECRET")
                .map_err(|_| AppError::Configuration("JWT_SECRET not set".to_string()))?,
            jwt_expiration: env::var("JWT_EXPIRATION")
                .unwrap_or_else(|_| "86400".to_string())
                .parse()
                .unwrap_or(86400),
            smtp_host: env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.gmail.com".to_string()),
            smtp_port: env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse()
                .unwrap_or(587),
            smtp_user: env::var("SMTP_USER").unwrap_or_default(),
            smtp_pass: env::var("SMTP_PASS").unwrap_or_default(),
            smtp_from: env::var("SMTP_FROM").unwrap_or_else(|_| "noreply@example.com".to_string()),
        })
    }
}`;
  }
  
  protected generateErrorFile(): string {
    return `use rocket::response::{Responder, Response};
use rocket::{Request, http::Status, serde::json::Json};
use serde::Serialize;
use std::io::Cursor;

#[derive(Debug)]
pub enum AppError {
    // Database errors
    DatabaseError(sqlx::Error),
    
    // Authentication errors
    Unauthorized,
    InvalidToken,
    TokenCreation,
    
    // User errors
    UserNotFound,
    UserAlreadyExists,
    InvalidCredentials,
    UserNotActive,
    
    // Validation errors
    ValidationError(String),
    
    // Configuration errors
    Configuration(String),
    
    // Redis errors
    RedisError(redis::RedisError),
    
    // UUID parsing errors
    UuidError(uuid::Error),
    
    // Other errors
    InternalServerError,
    BadRequest(String),
    NotFound(String),
}

pub type AppResult<T> = Result<T, AppError>;

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::DatabaseError(e) => write!(f, "Database error: {}", e),
            AppError::Unauthorized => write!(f, "Unauthorized"),
            AppError::InvalidToken => write!(f, "Invalid token"),
            AppError::TokenCreation => write!(f, "Failed to create token"),
            AppError::UserNotFound => write!(f, "User not found"),
            AppError::UserAlreadyExists => write!(f, "User already exists"),
            AppError::InvalidCredentials => write!(f, "Invalid credentials"),
            AppError::UserNotActive => write!(f, "User account is not active"),
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            AppError::Configuration(msg) => write!(f, "Configuration error: {}", msg),
            AppError::RedisError(e) => write!(f, "Redis error: {}", e),
            AppError::UuidError(e) => write!(f, "UUID error: {}", e),
            AppError::InternalServerError => write!(f, "Internal server error"),
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl<'r> Responder<'r, 'static> for AppError {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'static> {
        let status = match &self {
            AppError::Unauthorized | AppError::InvalidToken => Status::Unauthorized,
            AppError::UserNotFound | AppError::NotFound(_) => Status::NotFound,
            AppError::UserAlreadyExists => Status::Conflict,
            AppError::InvalidCredentials | AppError::UserNotActive => Status::Unauthorized,
            AppError::ValidationError(_) | AppError::BadRequest(_) | AppError::UuidError(_) => Status::BadRequest,
            _ => Status::InternalServerError,
        };
        
        let error_response = ErrorResponse {
            error: self.to_string(),
        };
        
        let json = serde_json::to_string(&error_response)
            .unwrap_or_else(|_| r#"{"error":"Internal server error"}"#.to_string());
        
        Response::build()
            .status(status)
            .header(rocket::http::ContentType::JSON)
            .sized_body(json.len(), Cursor::new(json))
            .ok()
    }
}

// Implement conversions
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        AppError::DatabaseError(err)
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        AppError::RedisError(err)
    }
}

impl From<validator::ValidationErrors> for AppError {
    fn from(err: validator::ValidationErrors) -> Self {
        AppError::ValidationError(err.to_string())
    }
}

impl From<uuid::Error> for AppError {
    fn from(err: uuid::Error) -> Self {
        AppError::UuidError(err)
    }
}`;
  }
  
  // Additional database wrapper for Rocket
  protected generateUtilFiles(): { path: string; content: string }[] {
    const baseUtils = super.generateUtilFiles();
    
    // Add Rocket-specific database wrapper
    const dbWrapper = {
      path: 'src/db.rs',
      content: `use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

use crate::config::Config;
use crate::error::AppError;

// Wrapper for database pool to work with Rocket's State management
pub struct DbPool(pub PgPool);

pub async fn create_pool(config: &Config) -> Result<PgPool, AppError> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&config.database_url)
        .await?;
    
    Ok(pool)
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), AppError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await?;
    Ok(())
}`
    };
    
    // Replace the existing db.rs from base utils with Rocket-specific version
    return baseUtils.map((util) => {
      if (util.path === 'src/db.rs') {
        return dbWrapper;
      }
      return util;
    });
  }
  
  // Override to create guards directory instead of middleware
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Set options before calling parent
    this.options = options;
    
    // Generate main file
    await this.writeFile(projectPath + '/src/main.rs', this.generateMainFile());
    
    // Generate config module
    await this.writeFile(projectPath + '/src/config.rs', this.generateConfigFile());
    
    // Generate error handling
    await this.writeFile(projectPath + '/src/error.rs', this.generateErrorFile());
    
    // Generate router (routes.rs)
    await this.writeFile(projectPath + '/src/routes.rs', this.generateRouterFile());
    
    // Generate handlers
    const handlerFiles = this.generateHandlerFiles();
    for (const file of handlerFiles) {
      await this.writeFile(projectPath + '/' + file.path, file.content);
    }
    
    // Generate guards (Rocket's request guards system)
    const guardFiles = this.generateMiddlewareFiles();
    for (const file of guardFiles) {
      await this.writeFile(projectPath + '/' + file.path, file.content);
    }
    
    // Generate models
    const modelFiles = this.generateModelFiles();
    for (const file of modelFiles) {
      await this.writeFile(projectPath + '/' + file.path, file.content);
    }
    
    // Generate services
    const serviceFiles = this.generateServiceFiles();
    for (const file of serviceFiles) {
      await this.writeFile(projectPath + '/' + file.path, file.content);
    }
    
    // Generate utils
    const utilFiles = this.generateUtilFiles();
    for (const file of utilFiles) {
      await this.writeFile(projectPath + '/' + file.path, file.content);
    }
  }
}