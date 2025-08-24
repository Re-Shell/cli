import { RustBackendGenerator } from './rust-base-generator';

export class WarpGenerator extends RustBackendGenerator {
  constructor() {
    super('Warp');
  }
  
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'warp': '{ version = "0.3", features = ["tls"] }',
      'hyper': '"1"',
      'tower': '{ version = "0.4", features = ["full"] }',
      'tower-http': '{ version = "0.5", features = ["cors", "compression", "trace"] }',
      'futures-util': '"0.3"',
      'bytes': '"1"',
      'headers': '"0.3"',
      'utoipa': '{ version = "4", features = ["warp"] }',
      'utoipa-swagger-ui': '{ version = "5", features = ["warp"] }'
    };
  }
  
  protected generateMainFile(): string {
    return `use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use warp::Filter;

mod config;
mod db;
mod error;
mod handlers;
mod middleware;
mod models;
mod routes;
mod services;
mod utils;

use crate::config::Config;
use crate::db::run_migrations;
use crate::error::{AppError, handle_rejection};

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db_pool: sqlx::PgPool,
    pub redis_client: redis::Client,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenv().ok();
    
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("setting default subscriber failed");
    
    // Load configuration
    let config = Config::from_env()?;
    let port = config.app_port.parse::<u16>()
        .map_err(|_| AppError::Configuration("Invalid port number".to_string()))?;
    
    info!("Starting {} on port {}", config.app_name, port);
    
    // Create database pool
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    
    // Run migrations
    run_migrations(&db_pool).await?;
    
    // Create Redis client
    let redis_client = redis::Client::open(config.redis_url.clone())?;
    
    // Create app state
    let state = Arc::new(AppState {
        config: config.clone(),
        db_pool,
        redis_client,
    });
    
    // Build routes
    let routes = routes::routes(state)
        .recover(handle_rejection);
    
    // Create server address
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    
    info!("Server listening on http://{}", addr);
    
    // Start server
    warp::serve(routes)
        .run(addr)
        .await;
    
    Ok(())
}`;
  }
  
  protected generateServerFile(): string {
    // Warp doesn't need a separate server file - everything is in main.rs and routes.rs
    return '';
  }
  
  protected generateRouterFile(): string {
    return `use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

use crate::handlers;
use crate::middleware::{with_auth, with_state};
use crate::AppState;

pub fn routes(
    state: Arc<AppState>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    health_routes(state.clone())
        .or(auth_routes(state.clone()))
        .or(user_routes(state.clone()))
        .or(admin_routes(state.clone()))
        .or(websocket_routes(state.clone()))
        .or(swagger_routes())
        .with(warp::trace::request())
}

fn health_routes(
    state: Arc<AppState>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("api" / "v1" / "health")
        .and(warp::get())
        .and(with_state(state))
        .and_then(handlers::health::health_check)
}

fn auth_routes(
    state: Arc<AppState>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let register = warp::path!("api" / "v1" / "auth" / "register")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_state(state.clone()))
        .and_then(handlers::auth::register);
    
    let login = warp::path!("api" / "v1" / "auth" / "login")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_state(state.clone()))
        .and_then(handlers::auth::login);
    
    let refresh = warp::path!("api" / "v1" / "auth" / "refresh")
        .and(warp::post())
        .and(warp::cookie("refresh_token"))
        .and(with_state(state.clone()))
        .and_then(handlers::auth::refresh);
    
    let logout = warp::path!("api" / "v1" / "auth" / "logout")
        .and(warp::post())
        .and_then(handlers::auth::logout);
    
    register.or(login).or(refresh).or(logout)
}

fn user_routes(
    state: Arc<AppState>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let profile = warp::path!("api" / "v1" / "users" / "profile")
        .and(warp::get())
        .and(with_auth())
        .and(with_state(state.clone()))
        .and_then(handlers::user::get_profile);
    
    let update_profile = warp::path!("api" / "v1" / "users" / "profile")
        .and(warp::put())
        .and(with_auth())
        .and(warp::body::json())
        .and(with_state(state.clone()))
        .and_then(handlers::user::update_profile);
    
    let delete_account = warp::path!("api" / "v1" / "users" / "profile")
        .and(warp::delete())
        .and(with_auth())
        .and(with_state(state.clone()))
        .and_then(handlers::user::delete_account);
    
    let change_password = warp::path!("api" / "v1" / "users" / "change-password")
        .and(warp::post())
        .and(with_auth())
        .and(warp::body::json())
        .and(with_state(state.clone()))
        .and_then(handlers::user::change_password);
    
    profile.or(update_profile).or(delete_account).or(change_password)
}

fn admin_routes(
    state: Arc<AppState>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let list_users = warp::path!("api" / "v1" / "admin" / "users")
        .and(warp::get())
        .and(warp::query())
        .and(with_auth())
        .and(with_state(state.clone()))
        .and_then(handlers::user::list_users);
    
    let get_user = warp::path!("api" / "v1" / "admin" / "users" / String)
        .and(warp::get())
        .and(with_auth())
        .and(with_state(state.clone()))
        .and_then(handlers::user::get_user);
    
    let update_user = warp::path!("api" / "v1" / "admin" / "users" / String)
        .and(warp::put())
        .and(with_auth())
        .and(warp::body::json())
        .and(with_state(state.clone()))
        .and_then(handlers::user::update_user);
    
    let delete_user = warp::path!("api" / "v1" / "admin" / "users" / String)
        .and(warp::delete())
        .and(with_auth())
        .and(with_state(state.clone()))
        .and_then(handlers::user::delete_user);
    
    list_users.or(get_user).or(update_user).or(delete_user)
}

fn websocket_routes(
    state: Arc<AppState>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    warp::path!("ws" / "connect")
        .and(warp::ws())
        .and(with_auth())
        .and(with_state(state))
        .map(|ws: warp::ws::Ws, user_id, state| {
            ws.on_upgrade(move |websocket| handlers::websocket::handle_websocket(websocket, user_id, state))
        })
}

fn swagger_routes() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    use utoipa::OpenApi;
    use utoipa_swagger_ui::Config;
    
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
            description = "Warp backend service API",
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
    
    let config = Arc::new(Config::from("/api-doc.json"));
    let api_doc = warp::path("api-doc.json")
        .and(warp::get())
        .map(|| warp::reply::json(&ApiDoc::openapi()));
    
    let swagger_ui = warp::path("swagger-ui")
        .and(warp::get())
        .and(warp::path::full())
        .and(warp::path::tail())
        .and(warp::any().map(move || config.clone()))
        .and_then(utoipa_swagger_ui::serve);
    
    api_doc.or(swagger_ui)
}`;
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
        content: `use serde::Serialize;
use std::sync::Arc;
use warp::{Reply, Rejection};

use crate::AppState;

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub database: String,
    pub uptime: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 503, description = "Service is unhealthy", body = HealthResponse),
    )
)]
pub async fn health_check(
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    let mut health = HealthResponse {
        status: "healthy".to_string(),
        database: "healthy".to_string(),
        uptime: format!("{:?}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()),
    };
    
    // Check database connection
    match sqlx::query("SELECT 1").fetch_one(&state.db_pool).await {
        Ok(_) => {},
        Err(_) => {
            health.status = "degraded".to_string();
            health.database = "unhealthy".to_string();
        }
    }
    
    Ok(warp::reply::json(&health))
}`
      },
      {
        path: 'src/handlers/auth.rs',
        content: `use std::sync::Arc;
use validator::Validate;
use warp::{Reply, Rejection, http::StatusCode};

use crate::models::user::{RegisterRequest, LoginRequest};
use crate::models::token::TokenResponse;
use crate::services::auth_service::AuthService;
use crate::services::user_service::UserService;
use crate::error::AppError;
use crate::AppState;

#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = TokenResponse),
        (status = 400, description = "Invalid request data"),
        (status = 409, description = "User already exists"),
    )
)]
pub async fn register(
    body: RegisterRequest,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    body.validate()
        .map_err(|e| warp::reject::custom(AppError::ValidationError(e.to_string())))?;
    
    let user_service = UserService::new(state.db_pool.clone());
    let auth_service = AuthService::new(user_service, state.config.clone());
    
    let token_response = auth_service.register(&body).await
        .map_err(warp::reject::custom)?;
    
    Ok(warp::reply::with_status(
        warp::reply::json(&token_response),
        StatusCode::CREATED,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = TokenResponse),
        (status = 401, description = "Invalid credentials"),
    )
)]
pub async fn login(
    body: LoginRequest,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    body.validate()
        .map_err(|e| warp::reject::custom(AppError::ValidationError(e.to_string())))?;
    
    let user_service = UserService::new(state.db_pool.clone());
    let auth_service = AuthService::new(user_service, state.config.clone());
    
    let token_response = auth_service.login(&body).await
        .map_err(warp::reject::custom)?;
    
    // Create response with cookie
    let response = warp::reply::json(&token_response);
    let cookie = format!(
        "refresh_token={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        token_response.refresh_token,
        7 * 24 * 60 * 60 // 7 days
    );
    
    Ok(warp::reply::with_header(
        response,
        "Set-Cookie",
        cookie,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "auth",
    responses(
        (status = 200, description = "Token refreshed successfully", body = TokenResponse),
        (status = 401, description = "Invalid refresh token"),
    )
)]
pub async fn refresh(
    refresh_token: String,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    let user_service = UserService::new(state.db_pool.clone());
    let auth_service = AuthService::new(user_service, state.config.clone());
    
    let token_response = auth_service.refresh_token(&refresh_token).await
        .map_err(warp::reject::custom)?;
    
    Ok(warp::reply::json(&token_response))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    responses(
        (status = 200, description = "Logout successful"),
    )
)]
pub async fn logout() -> Result<impl Reply, Rejection> {
    let cookie = "refresh_token=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
    
    Ok(warp::reply::with_header(
        warp::reply::json(&serde_json::json!({
            "message": "Logged out successfully"
        })),
        "Set-Cookie",
        cookie,
    ))
}`
      },
      {
        path: 'src/handlers/user.rs',
        content: `use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;
use warp::{Reply, Rejection};

use crate::models::user::{UserResponse, UpdateUserRequest, ChangePasswordRequest};
use crate::services::user_service::UserService;
use crate::error::AppError;
use crate::AppState;

#[derive(Debug, serde::Deserialize)]
pub struct PaginationQuery {
    pub page: Option<i32>,
    pub limit: Option<i32>,
}

#[utoipa::path(
    get,
    path = "/api/v1/users/profile",
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
    user_id: Uuid,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    let user_service = UserService::new(state.db_pool.clone());
    
    let user = user_service.get_user_by_id(user_id).await
        .map_err(warp::reject::custom)?;
    let response: UserResponse = user.into();
    
    Ok(warp::reply::json(&response))
}

#[utoipa::path(
    put,
    path = "/api/v1/users/profile",
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
    user_id: Uuid,
    body: UpdateUserRequest,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    let user_service = UserService::new(state.db_pool.clone());
    
    let user = user_service.update_user(user_id, &body).await
        .map_err(warp::reject::custom)?;
    let response: UserResponse = user.into();
    
    Ok(warp::reply::json(&response))
}

#[utoipa::path(
    post,
    path = "/api/v1/users/change-password",
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
    user_id: Uuid,
    body: ChangePasswordRequest,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    body.validate()
        .map_err(|e| warp::reject::custom(AppError::ValidationError(e.to_string())))?;
    
    let user_service = UserService::new(state.db_pool.clone());
    
    user_service.change_password(user_id, &body.old_password, &body.new_password).await
        .map_err(warp::reject::custom)?;
    
    Ok(warp::reply::json(&serde_json::json!({
        "message": "Password changed successfully"
    })))
}

#[utoipa::path(
    delete,
    path = "/api/v1/users/profile",
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
    user_id: Uuid,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    let user_service = UserService::new(state.db_pool.clone());
    
    user_service.delete_user(user_id).await
        .map_err(warp::reject::custom)?;
    
    Ok(warp::reply::json(&serde_json::json!({
        "message": "Account deleted successfully"
    })))
}

// Admin endpoints
#[utoipa::path(
    get,
    path = "/api/v1/admin/users",
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
    query: PaginationQuery,
    user_id: Uuid,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    // TODO: Add role check for admin
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10);
    
    let user_service = UserService::new(state.db_pool.clone());
    let (users, total) = user_service.list_users(page, limit).await
        .map_err(warp::reject::custom)?;
    
    Ok(warp::reply::json(&serde_json::json!({
        "users": users,
        "total": total,
        "page": page,
        "limit": limit,
    })))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/users/{id}",
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
    id: String,
    _user_id: Uuid,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    let user_id = Uuid::parse_str(&id)
        .map_err(|_| warp::reject::custom(AppError::BadRequest("Invalid user ID".to_string())))?;
    
    let user_service = UserService::new(state.db_pool.clone());
    let user = user_service.get_user_by_id(user_id).await
        .map_err(warp::reject::custom)?;
    let response: UserResponse = user.into();
    
    Ok(warp::reply::json(&response))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/users/{id}",
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
    id: String,
    _user_id: Uuid,
    body: UpdateUserRequest,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    let user_id = Uuid::parse_str(&id)
        .map_err(|_| warp::reject::custom(AppError::BadRequest("Invalid user ID".to_string())))?;
    
    let user_service = UserService::new(state.db_pool.clone());
    let user = user_service.update_user(user_id, &body).await
        .map_err(warp::reject::custom)?;
    let response: UserResponse = user.into();
    
    Ok(warp::reply::json(&response))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/users/{id}",
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
    id: String,
    _user_id: Uuid,
    state: Arc<AppState>,
) -> Result<impl Reply, Rejection> {
    let user_id = Uuid::parse_str(&id)
        .map_err(|_| warp::reject::custom(AppError::BadRequest("Invalid user ID".to_string())))?;
    
    let user_service = UserService::new(state.db_pool.clone());
    user_service.delete_user(user_id).await
        .map_err(warp::reject::custom)?;
    
    Ok(warp::reply::json(&serde_json::json!({
        "message": "User deleted successfully"
    })))
}`
      },
      {
        path: 'src/handlers/websocket.rs',
        content: `use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};
use uuid::Uuid;
use warp::ws::{Message, WebSocket};

use crate::AppState;

#[derive(Debug, Serialize, Deserialize)]
struct WsMessage {
    r#type: String,
    payload: serde_json::Value,
}

pub async fn handle_websocket(
    ws: WebSocket,
    user_id: Uuid,
    _state: Arc<AppState>,
) {
    let (mut tx, mut rx) = ws.split();
    
    info!("WebSocket connection established for user {}", user_id);
    
    // Send welcome message
    let welcome = WsMessage {
        r#type: "welcome".to_string(),
        payload: serde_json::json!({
            "message": "Connected to WebSocket",
            "userId": user_id,
        }),
    };
    
    if let Ok(msg) = serde_json::to_string(&welcome) {
        if let Err(e) = tx.send(Message::text(msg)).await {
            error!("Failed to send welcome message: {}", e);
            return;
        }
    }
    
    // Handle incoming messages
    while let Some(result) = rx.next().await {
        match result {
            Ok(msg) => {
                if let Ok(text) = msg.to_str() {
                    match serde_json::from_str::<WsMessage>(text) {
                        Ok(ws_msg) => {
                            match ws_msg.r#type.as_str() {
                                "ping" => {
                                    let pong = WsMessage {
                                        r#type: "pong".to_string(),
                                        payload: ws_msg.payload,
                                    };
                                    if let Ok(json) = serde_json::to_string(&pong) {
                                        if let Err(e) = tx.send(Message::text(json)).await {
                                            error!("Failed to send pong: {}", e);
                                            break;
                                        }
                                    }
                                }
                                "broadcast" => {
                                    info!("Broadcast message from user {}: {:?}", user_id, ws_msg.payload);
                                    // Implement broadcast logic here
                                }
                                _ => {
                                    info!("Unknown message type: {}", ws_msg.r#type);
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse WebSocket message: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
        }
    }
    
    info!("WebSocket connection closed for user {}", user_id);
}`
      }
    ];
  }
  
  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/middleware/mod.rs',
        content: `use std::sync::Arc;
use uuid::Uuid;
use warp::{Filter, Rejection};

use crate::config::Config;
use crate::error::AppError;
use crate::models::token::decode_jwt;
use crate::AppState;

pub fn with_state(
    state: Arc<AppState>,
) -> impl Filter<Extract = (Arc<AppState>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}

pub fn with_auth() -> impl Filter<Extract = (Uuid,), Error = Rejection> + Clone {
    warp::header::optional::<String>("authorization")
        .and(with_state_for_auth())
        .and_then(|auth_header: Option<String>, state: Arc<AppState>| async move {
            match auth_header {
                Some(header) if header.starts_with("Bearer ") => {
                    let token = &header[7..];
                    match decode_jwt(token, &state.config.jwt_secret) {
                        Ok(claims) => Ok(claims.sub),
                        Err(_) => Err(warp::reject::custom(AppError::InvalidToken)),
                    }
                }
                _ => Err(warp::reject::custom(AppError::Unauthorized)),
            }
        })
}

fn with_state_for_auth() -> impl Filter<Extract = (Arc<AppState>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || {
        // This is a workaround - in a real app, you'd pass the state properly
        // For now, we'll create a dummy state just for the JWT secret
        let config = Config::from_env().expect("Failed to load config");
        Arc::new(AppState {
            config: config.clone(),
            db_pool: sqlx::PgPool::new(), // This won't be used
            redis_client: redis::Client::open("redis://127.0.0.1:6379").unwrap(),
        })
    })
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
    return `use serde::Serialize;
use std::convert::Infallible;
use warp::{http::StatusCode, reject::Reject, Rejection, Reply};

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
    
    // Other errors
    InternalServerError,
    BadRequest(String),
    NotFound(String),
}

impl Reject for AppError {}

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
            AppError::InternalServerError => write!(f, "Internal server error"),
            AppError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
        }
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

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "Not Found".to_string();
    } else if let Some(e) = err.find::<AppError>() {
        match e {
            AppError::Unauthorized | AppError::InvalidToken => {
                code = StatusCode::UNAUTHORIZED;
                message = e.to_string();
            }
            AppError::UserNotFound | AppError::NotFound(_) => {
                code = StatusCode::NOT_FOUND;
                message = e.to_string();
            }
            AppError::UserAlreadyExists => {
                code = StatusCode::CONFLICT;
                message = e.to_string();
            }
            AppError::InvalidCredentials | AppError::UserNotActive => {
                code = StatusCode::UNAUTHORIZED;
                message = e.to_string();
            }
            AppError::ValidationError(_) | AppError::BadRequest(_) => {
                code = StatusCode::BAD_REQUEST;
                message = e.to_string();
            }
            _ => {
                code = StatusCode::INTERNAL_SERVER_ERROR;
                message = "Internal Server Error".to_string();
            }
        }
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "Method Not Allowed".to_string();
    } else {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "Internal Server Error".to_string();
    }

    let json = warp::reply::json(&ErrorResponse { error: message });
    Ok(warp::reply::with_status(json, code))
}`;
  }
  
  // Override routes.rs instead of router.rs
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Call parent to generate base files
    await super.generateFrameworkFiles(projectPath, options);
    
    // Rename router.rs to routes.rs for Warp convention
    const fs = await import('fs').then(m => m.promises);
    const path = await import('path');
    
    const routerPath = path.join(projectPath, 'src/router.rs');
    const routesPath = path.join(projectPath, 'src/routes.rs');
    
    if (await fs.access(routerPath).then(() => true).catch(() => false)) {
      await fs.rename(routerPath, routesPath);
    }
  }
}