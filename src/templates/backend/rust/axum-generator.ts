import { RustBackendGenerator } from './rust-base-generator';

export class AxumGenerator extends RustBackendGenerator {
  constructor() {
    super('Axum');
  }
  
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'axum': '{ version = "0.7", features = ["headers", "json", "query", "form", "ws", "macros"] }',
      'axum-extra': '{ version = "0.9", features = ["typed-header"] }',
      'tower': '{ version = "0.4", features = ["util", "timeout", "load-shed", "limit"] }',
      'tower-http': '{ version = "0.5", features = ["add-extension", "auth", "compression-full", "cors", "fs", "set-header", "trace"] }',
      'hyper': '{ version = "1.0", features = ["full"] }',
      'tower-sessions': '0.12',
      'tower-sessions-redis-store': '0.12',
      'utoipa': '{ version = "4", features = ["axum_extras", "chrono", "uuid"] }',
      'utoipa-swagger-ui': '{ version = "6", features = ["axum"] }',
      'axum-typed-multipart': '0.11'
    };
  }
  
  protected generateMainFile(): string {
    return `use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
    timeout::TimeoutLayer,
    trace::TraceLayer,
    compression::CompressionLayer,
};
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

mod config;
mod db;
mod error;
mod extractors;
mod handlers;
mod models;
mod services;
mod utils;

use crate::config::Config;
use crate::db::{run_migrations, AppState};
use crate::error::AppError;
use crate::handlers::*;

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::health::health_check,
        handlers::auth::register,
        handlers::auth::login,
        handlers::auth::refresh,
        handlers::auth::logout,
        handlers::user::get_profile,
        handlers::user::update_profile,
        handlers::user::change_password,
        handlers::user::delete_account,
        handlers::user::list_users,
        handlers::user::get_user,
        handlers::user::update_user,
        handlers::user::delete_user,
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
            crate::error::ErrorResponse,
        )
    ),
    tags(
        (name = "health", description = "Health check endpoints"),
        (name = "auth", description = "Authentication endpoints"),
        (name = "users", description = "User management endpoints"),
    ),
    info(
        title = "\${this.options.name}",
        version = "1.0.0",
        description = "Axum backend service API",
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

// Custom middleware for logging requests
async fn log_requests(
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    
    println!("🌐 {} {}", method, uri);
    
    let response = next.run(req).await;
    response
}

// Custom middleware for CORS (additional to tower-http)
async fn cors_middleware(
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let response = next.run(req).await;
    
    let mut response = response;
    let headers = response.headers_mut();
    
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, PUT, PATCH, DELETE, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    
    response
}

fn create_router(state: Arc<AppState>) -> Router {
    // API routes
    let api_routes = Router::new()
        .route("/health", get(handlers::health::health_check))
        .nest("/auth", auth_routes())
        .nest("/users", user_routes())
        .nest("/admin", admin_routes())
        .nest("/ws", websocket_routes())
        .with_state(state);

    // Documentation routes
    let docs_routes = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/api-docs/openapi.json", get(openapi_spec));

    // Main router
    Router::new()
        .nest("/api/v1", api_routes)
        .merge(docs_routes)
        .route("/", get(|| async { "🚀 Axum Backend Service" }))
        .nest_service("/static", ServeDir::new("static"))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB
                .layer(TimeoutLayer::new(Duration::from_secs(30)))
                .layer(CorsLayer::new()
                    .allow_origin("http://localhost:3000".parse::<HeaderValue>().unwrap())
                    .allow_origin("http://localhost:5173".parse::<HeaderValue>().unwrap())
                    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS])
                    .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
                    .allow_credentials(true))
                .layer(SessionManagerLayer::new(MemoryStore::default())
                    .with_expiry(Expiry::OnInactivity(Duration::from_secs(3600))))
                .layer(middleware::from_fn(log_requests))
                .layer(middleware::from_fn(cors_middleware)),
        )
}

fn auth_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/register", post(handlers::auth::register))
        .route("/login", post(handlers::auth::login))
        .route("/refresh", post(handlers::auth::refresh))
        .route("/logout", post(handlers::auth::logout))
}

fn user_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/profile", get(handlers::user::get_profile))
        .route("/profile", axum::routing::put(handlers::user::update_profile))
        .route("/profile", axum::routing::delete(handlers::user::delete_account))
        .route("/change-password", post(handlers::user::change_password))
}

fn admin_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/users", get(handlers::user::list_users))
        .route("/users/:id", get(handlers::user::get_user))
        .route("/users/:id", axum::routing::put(handlers::user::update_user))
        .route("/users/:id", axum::routing::delete(handlers::user::delete_user))
}

fn websocket_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/connect", get(handlers::websocket::websocket_handler))
}

async fn openapi_spec() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    // Load environment variables
    dotenv().ok();
    
    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");
    
    // Create database pool
    let database_url = config.database_url.clone();
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&database_url)
        .await
        .expect("Failed to connect to database");
    
    // Run migrations
    run_migrations(&db_pool).await
        .expect("Failed to run migrations");
    
    // Create Redis client
    let redis_client = redis::Client::open(config.redis_url.clone())
        .expect("Failed to create Redis client");
    
    // Create application state
    let state = Arc::new(AppState {
        db: db_pool,
        redis: redis_client,
        config: config.clone(),
    });
    
    // Create router
    let app = create_router(state);
    
    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], config.app_port.parse::<u16>().unwrap_or(8080)));
    println!("🚀 Starting {} on http://{}", config.app_name, addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}`;
  }
  
  protected generateServerFile(): string {
    // Axum doesn't need a separate server file - everything is in main.rs
    return '';
  }
  
  protected generateRouterFile(): string {
    // Axum handles routing in main.rs with the Router builder pattern
    return '';
  }
  
  protected generateHandlerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/handlers/mod.rs',
        content: `pub mod auth;
pub mod health;
pub mod user;
pub mod websocket;`
      },
      {
        path: 'src/handlers/health.rs',
        content: `use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

use crate::{db::AppState, error::AppResult};

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
pub async fn health_check(State(state): State<Arc<AppState>>) -> AppResult<Json<HealthResponse>> {
    let mut health = HealthResponse {
        status: "healthy".to_string(),
        database: "healthy".to_string(),
        uptime: format!("{:?}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()),
    };
    
    // Check database connection
    match sqlx::query("SELECT 1").fetch_one(&state.db).await {
        Ok(_) => {},
        Err(_) => {
            health.status = "degraded".to_string();
            health.database = "unhealthy".to_string();
        }
    }
    
    Ok(Json(health))
}`
      },
      {
        path: 'src/handlers/auth.rs',
        content: `use axum::{extract::State, Json};
use std::sync::Arc;
use validator::Validate;

use crate::{
    db::AppState,
    error::AppResult,
    models::{
        token::TokenResponse,
        user::{LoginRequest, RegisterRequest},
    },
    services::{auth_service::AuthService, user_service::UserService},
};

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
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterRequest>,
) -> AppResult<Json<TokenResponse>> {
    body.validate()?;
    
    let user_service = UserService::new(state.db.clone());
    let auth_service = AuthService::new(user_service, state.config.clone());
    
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
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginRequest>,
) -> AppResult<Json<TokenResponse>> {
    body.validate()?;
    
    let user_service = UserService::new(state.db.clone());
    let auth_service = AuthService::new(user_service, state.config.clone());
    
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
pub async fn refresh(
    State(state): State<Arc<AppState>>,
    Json(refresh_token): Json<String>,
) -> AppResult<Json<TokenResponse>> {
    let user_service = UserService::new(state.db.clone());
    let auth_service = AuthService::new(user_service, state.config.clone());
    
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
pub async fn logout() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "message": "Logged out successfully"
    }))
}`
      },
      {
        path: 'src/handlers/user.rs',
        content: `use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use crate::{
    db::AppState,
    error::AppResult,
    extractors::AuthUser,
    models::user::{ChangePasswordRequest, UpdateUserRequest, UserResponse},
    services::user_service::UserService,
};

#[derive(Debug, Deserialize)]
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
pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
) -> AppResult<Json<UserResponse>> {
    let user_service = UserService::new(state.db.clone());
    
    let user = user_service.get_user_by_id(auth_user.user_id).await?;
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
pub async fn update_profile(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Json(body): Json<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    let user_service = UserService::new(state.db.clone());
    
    let user = user_service.update_user(auth_user.user_id, &body).await?;
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
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
    Json(body): Json<ChangePasswordRequest>,
) -> AppResult<Json<serde_json::Value>> {
    body.validate()?;
    
    let user_service = UserService::new(state.db.clone());
    
    user_service.change_password(auth_user.user_id, &body.old_password, &body.new_password).await?;
    
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
pub async fn delete_account(
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let user_service = UserService::new(state.db.clone());
    
    user_service.delete_user(auth_user.user_id).await?;
    
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
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    _auth_user: AuthUser, // TODO: Add role check for admin
    Query(params): Query<PaginationQuery>,
) -> AppResult<Json<serde_json::Value>> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(10);
    
    let user_service = UserService::new(state.db.clone());
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
pub async fn get_user(
    State(state): State<Arc<AppState>>,
    _auth_user: AuthUser, // TODO: Add role check for admin
    Path(id): Path<String>,
) -> AppResult<Json<UserResponse>> {
    let user_id = Uuid::parse_str(&id)?;
    
    let user_service = UserService::new(state.db.clone());
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
pub async fn update_user(
    State(state): State<Arc<AppState>>,
    _auth_user: AuthUser, // TODO: Add role check for admin
    Path(id): Path<String>,
    Json(body): Json<UpdateUserRequest>,
) -> AppResult<Json<UserResponse>> {
    let user_id = Uuid::parse_str(&id)?;
    
    let user_service = UserService::new(state.db.clone());
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
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    _auth_user: AuthUser, // TODO: Add role check for admin
    Path(id): Path<String>,
) -> AppResult<Json<serde_json::Value>> {
    let user_id = Uuid::parse_str(&id)?;
    
    let user_service = UserService::new(state.db.clone());
    user_service.delete_user(user_id).await?;
    
    Ok(Json(serde_json::json!({
        "message": "User deleted successfully"
    })))
}`
      },
      {
        path: 'src/handlers/websocket.rs',
        content: `use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use futures::{sink::SinkExt, stream::StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::{db::AppState, extractors::AuthUser};

#[derive(Debug, Serialize, Deserialize)]
struct WsMessage {
    r#type: String,
    payload: serde_json::Value,
}

pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    auth_user: AuthUser,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state, auth_user))
}

async fn handle_socket(socket: WebSocket, _state: Arc<AppState>, auth_user: AuthUser) {
    let (mut sender, mut receiver) = socket.split();
    
    // Send welcome message
    let welcome_msg = WsMessage {
        r#type: "welcome".to_string(),
        payload: serde_json::json!({
            "message": format!("Welcome user {}!", auth_user.user_id),
            "user_id": auth_user.user_id,
            "email": auth_user.email
        }),
    };
    
    if let Ok(msg) = serde_json::to_string(&welcome_msg) {
        let _ = sender.send(Message::Text(msg)).await;
    }
    
    // Handle incoming messages
    while let Some(msg) = receiver.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                // Echo back the message
                let response = WsMessage {
                    r#type: "echo".to_string(),
                    payload: serde_json::json!({
                        "original": text,
                        "timestamp": chrono::Utc::now(),
                        "user_id": auth_user.user_id
                    }),
                };
                
                if let Ok(response_text) = serde_json::to_string(&response) {
                    let _ = sender.send(Message::Text(response_text)).await;
                }
            }
            Ok(Message::Binary(data)) => {
                // Echo back binary data
                let _ = sender.send(Message::Binary(data)).await;
            }
            Ok(Message::Ping(data)) => {
                let _ = sender.send(Message::Pong(data)).await;
            }
            Ok(Message::Close(_)) => {
                println!("WebSocket connection closed for user {}", auth_user.user_id);
                break;
            }
            Err(e) => {
                println!("WebSocket error for user {}: {}", auth_user.user_id, e);
                break;
            }
            _ => {}
        }
    }
}`
      }
    ];
  }
  
  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/extractors/mod.rs',
        content: `use axum::{
    async_trait,
    extract::{FromRequestParts, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::{request::Parts, StatusCode},
};
use uuid::Uuid;

use crate::{error::AppError, models::token::decode_jwt};

pub struct AuthUser {
    pub user_id: Uuid,
    pub email: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, _state)
            .await
            .map_err(|_| AppError::Unauthorized)?;

        // Get JWT secret from environment (in a real app, you'd get this from state)
        let jwt_secret = std::env::var("JWT_SECRET")
            .map_err(|_| AppError::Configuration("JWT_SECRET not set".to_string()))?;

        // Decode the token
        let claims = decode_jwt(bearer.token(), &jwt_secret)
            .map_err(|_| AppError::InvalidToken)?;

        Ok(AuthUser {
            user_id: claims.sub,
            email: claims.email,
        })
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
            app_name: env::var("APP_NAME").unwrap_or_else(|_| "\${this.options.name}".to_string()),
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
    return `use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

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
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::Unauthorized | AppError::InvalidToken => StatusCode::UNAUTHORIZED,
            AppError::UserNotFound | AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::UserAlreadyExists => StatusCode::CONFLICT,
            AppError::InvalidCredentials | AppError::UserNotActive => StatusCode::UNAUTHORIZED,
            AppError::ValidationError(_) | AppError::BadRequest(_) | AppError::UuidError(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        
        let error_response = ErrorResponse {
            error: self.to_string(),
        };
        
        (status, Json(error_response)).into_response()
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
  
  // Additional database setup for Axum state management
  protected generateUtilFiles(): { path: string; content: string }[] {
    const baseUtils = super.generateUtilFiles();
    
    // Add Axum-specific state management
    const stateWrapper = {
      path: 'src/db.rs',
      content: `use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

use crate::config::Config;
use crate::error::AppError;

// Application state that will be shared across handlers
pub struct AppState {
    pub db: PgPool,
    pub redis: redis::Client,
    pub config: Config,
}

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
    
    // Replace the existing db.rs from base utils with Axum-specific version
    return baseUtils.map((util) => {
      if (util.path === 'src/db.rs') {
        return stateWrapper;
      }
      return util;
    });
  }
  
  // Override to create extractors directory instead of middleware
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Set options before calling parent
    this.options = options;
    
    // Generate main file
    await this.writeFile(projectPath + '/src/main.rs', this.generateMainFile());
    
    // Generate config module
    await this.writeFile(projectPath + '/src/config.rs', this.generateConfigFile());
    
    // Generate error handling
    await this.writeFile(projectPath + '/src/error.rs', this.generateErrorFile());
    
    // Generate handlers
    const handlerFiles = this.generateHandlerFiles();
    for (const file of handlerFiles) {
      await this.writeFile(projectPath + '/' + file.path, file.content);
    }
    
    // Generate extractors (Axum's request extractors system)
    const extractorFiles = this.generateMiddlewareFiles();
    for (const file of extractorFiles) {
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