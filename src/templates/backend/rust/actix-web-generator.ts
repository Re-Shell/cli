import { RustBackendGenerator } from './rust-base-generator';

export class ActixWebGenerator extends RustBackendGenerator {
  constructor() {
    super('Actix-Web');
  }
  
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'actix-web': '{ version = "4", features = ["macros"] }',
      'actix-cors': '"2"',
      'actix-files': '"0.6"',
      'actix-session': '{ version = "0.8", features = ["cookie-session", "redis-rs-tls-session"] }',
      'actix-web-httpauth': '"0.8"',
      'actix-ws': '"0.2"',
      'actix-multipart': '"0.6"',
      'utoipa': '{ version = "4", features = ["actix_extras"] }',
      'utoipa-swagger-ui': '{ version = "5", features = ["actix-web"] }'
    };
  }
  
  protected generateMainFile(): string {
    return `use actix_web::{middleware, web, App, HttpServer};
use actix_cors::Cors;
use actix_session::{SessionMiddleware, storage::RedisSessionStore};
use actix_session::config::PersistentSession;
use actix_web::cookie::{time::Duration, Key};
use dotenv::dotenv;
use sqlx::postgres::PgPoolOptions;
use std::env;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod config;
mod db;
mod error;
mod handlers;
mod middleware as app_middleware;
mod models;
mod router;
mod services;
mod utils;

use crate::config::Config;
use crate::db::run_migrations;
use crate::error::AppError;

#[actix_web::main]
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
    let config_clone = config.clone();
    
    info!("Starting {} on port {}", config.app_name, config.app_port);
    
    // Create database pool
    let db_pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;
    
    // Run migrations
    run_migrations(&db_pool).await?;
    
    // Create Redis client
    let redis_client = redis::Client::open(config.redis_url.clone())?;
    
    // Create session store
    let store = RedisSessionStore::new(config.redis_url.clone()).await?;
    let secret_key = Key::from(config.jwt_secret.as_bytes());
    
    // Start HTTP server
    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_origin("http://localhost:5173")
            .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE"])
            .allowed_headers(vec!["Authorization", "Content-Type"])
            .expose_headers(vec!["Content-Length"])
            .supports_credentials()
            .max_age(3600);
        
        App::new()
            // Add shared state
            .app_data(web::Data::new(db_pool.clone()))
            .app_data(web::Data::new(redis_client.clone()))
            .app_data(web::Data::new(config.clone()))
            // Add middleware
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            .wrap(
                SessionMiddleware::builder(store.clone(), secret_key.clone())
                    .session_lifecycle(
                        PersistentSession::default()
                            .session_ttl(Duration::hours(24))
                    )
                    .build()
            )
            .wrap(app_middleware::request_id::RequestId)
            // Configure routes
            .configure(router::configure)
            // Static files
            .service(actix_files::Files::new("/static", "./static").show_files_listing())
    })
    .bind(format!("0.0.0.0:{}", config_clone.app_port))?
    .run()
    .await?;
    
    Ok(())
}`;
  }
  
  protected generateServerFile(): string {
    // Actix-Web doesn't need a separate server file - everything is in main.rs
    return '';
  }
  
  protected generateRouterFile(): string {
    return `use actix_web::{web, HttpResponse};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::handlers::{auth, health, user, websocket};
use crate::middleware::auth::RequireAuth;

#[derive(OpenApi)]
#[openapi(
    paths(
        health::health_check,
        auth::register,
        auth::login,
        auth::refresh,
        auth::logout,
        user::get_profile,
        user::update_profile,
        user::change_password,
        user::delete_account,
        user::list_users,
        user::get_user,
        user::update_user,
        user::delete_user,
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
        description = "Actix-Web backend service API",
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

pub fn configure(cfg: &mut web::ServiceConfig) {
    // OpenAPI documentation
    cfg.service(
        SwaggerUi::new("/swagger-ui/{_:.*}")
            .url("/api-doc/openapi.json", ApiDoc::openapi()),
    );
    
    // API v1 routes
    cfg.service(
        web::scope("/api/v1")
            // Health check
            .service(
                web::scope("/health")
                    .route("", web::get().to(health::health_check))
            )
            // Auth routes
            .service(
                web::scope("/auth")
                    .route("/register", web::post().to(auth::register))
                    .route("/login", web::post().to(auth::login))
                    .route("/refresh", web::post().to(auth::refresh))
                    .route("/logout", web::post().to(auth::logout))
            )
            // User routes (protected)
            .service(
                web::scope("/users")
                    .wrap(RequireAuth)
                    .route("/profile", web::get().to(user::get_profile))
                    .route("/profile", web::put().to(user::update_profile))
                    .route("/profile", web::delete().to(user::delete_account))
                    .route("/change-password", web::post().to(user::change_password))
            )
            // Admin routes (protected with role check)
            .service(
                web::scope("/admin")
                    .wrap(RequireAuth)
                    .service(
                        web::scope("/users")
                            .route("", web::get().to(user::list_users))
                            .route("/{id}", web::get().to(user::get_user))
                            .route("/{id}", web::put().to(user::update_user))
                            .route("/{id}", web::delete().to(user::delete_user))
                    )
            )
    );
    
    // WebSocket routes
    cfg.service(
        web::scope("/ws")
            .wrap(RequireAuth)
            .route("/connect", web::get().to(websocket::websocket_handler))
    );
    
    // Fallback route
    cfg.default_service(web::to(|| async {
        HttpResponse::NotFound().json(serde_json::json!({
            "error": "Route not found"
        }))
    }));
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
        content: `use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;

#[derive(Debug, Serialize, ToSchema)]
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
    pool: web::Data<PgPool>,
) -> HttpResponse {
    let mut health = HealthResponse {
        status: "healthy".to_string(),
        database: "healthy".to_string(),
        uptime: format!("{:?}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()),
    };
    
    // Check database connection
    match sqlx::query("SELECT 1").fetch_one(pool.as_ref()).await {
        Ok(_) => {},
        Err(_) => {
            health.status = "degraded".to_string();
            health.database = "unhealthy".to_string();
        }
    }
    
    if health.status == "healthy" {
        HttpResponse::Ok().json(health)
    } else {
        HttpResponse::ServiceUnavailable().json(health)
    }
}`
      },
      {
        path: 'src/handlers/auth.rs',
        content: `use actix_web::{web, HttpResponse, HttpRequest};
use actix_session::Session;
use sqlx::PgPool;
use validator::Validate;

use crate::models::user::{RegisterRequest, LoginRequest, UserResponse};
use crate::models::token::TokenResponse;
use crate::services::auth_service::AuthService;
use crate::services::user_service::UserService;
use crate::config::Config;
use crate::error::AppError;

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
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()?;
    
    let user_service = UserService::new(pool.as_ref().clone());
    let auth_service = AuthService::new(user_service, config.as_ref().clone());
    
    let token_response = auth_service.register(&body).await?;
    
    Ok(HttpResponse::Created().json(token_response))
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
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    session: Session,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()?;
    
    let user_service = UserService::new(pool.as_ref().clone());
    let auth_service = AuthService::new(user_service, config.as_ref().clone());
    
    let token_response = auth_service.login(&body).await?;
    
    // Set refresh token in session
    session.insert("refresh_token", &token_response.refresh_token)?;
    
    Ok(HttpResponse::Ok().json(token_response))
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
    pool: web::Data<PgPool>,
    config: web::Data<Config>,
    session: Session,
) -> Result<HttpResponse, AppError> {
    let refresh_token = session
        .get::<String>("refresh_token")?
        .ok_or(AppError::Unauthorized)?;
    
    let user_service = UserService::new(pool.as_ref().clone());
    let auth_service = AuthService::new(user_service, config.as_ref().clone());
    
    let token_response = auth_service.refresh_token(&refresh_token).await?;
    
    Ok(HttpResponse::Ok().json(token_response))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    responses(
        (status = 200, description = "Logout successful"),
    )
)]
pub async fn logout(session: Session) -> Result<HttpResponse, AppError> {
    session.purge();
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Logged out successfully"
    })))
}`
      },
      {
        path: 'src/handlers/user.rs',
        content: `use actix_web::{web, HttpResponse, HttpRequest};
use sqlx::PgPool;
use uuid::Uuid;
use validator::Validate;

use crate::models::user::{UserResponse, UpdateUserRequest, ChangePasswordRequest};
use crate::services::user_service::UserService;
use crate::error::AppError;
use crate::utils::auth::get_user_id_from_request;

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
    req: HttpRequest,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let user_id = get_user_id_from_request(&req)?;
    let user_service = UserService::new(pool.as_ref().clone());
    
    let user = user_service.get_user_by_id(user_id).await?;
    let response: UserResponse = user.into();
    
    Ok(HttpResponse::Ok().json(response))
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
    req: HttpRequest,
    pool: web::Data<PgPool>,
    body: web::Json<UpdateUserRequest>,
) -> Result<HttpResponse, AppError> {
    let user_id = get_user_id_from_request(&req)?;
    let user_service = UserService::new(pool.as_ref().clone());
    
    let user = user_service.update_user(user_id, &body).await?;
    let response: UserResponse = user.into();
    
    Ok(HttpResponse::Ok().json(response))
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
    req: HttpRequest,
    pool: web::Data<PgPool>,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse, AppError> {
    body.validate()?;
    
    let user_id = get_user_id_from_request(&req)?;
    let user_service = UserService::new(pool.as_ref().clone());
    
    user_service.change_password(user_id, &body.old_password, &body.new_password).await?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
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
    req: HttpRequest,
    pool: web::Data<PgPool>,
) -> Result<HttpResponse, AppError> {
    let user_id = get_user_id_from_request(&req)?;
    let user_service = UserService::new(pool.as_ref().clone());
    
    user_service.delete_user(user_id).await?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
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
    pool: web::Data<PgPool>,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, AppError> {
    let page = query.page.unwrap_or(1);
    let limit = query.limit.unwrap_or(10);
    
    let user_service = UserService::new(pool.as_ref().clone());
    let (users, total) = user_service.list_users(page, limit).await?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
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
        ("id" = Uuid, Path, description = "User ID"),
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
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let user_service = UserService::new(pool.as_ref().clone());
    let user = user_service.get_user_by_id(id.into_inner()).await?;
    let response: UserResponse = user.into();
    
    Ok(HttpResponse::Ok().json(response))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/users/{id}",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
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
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
    body: web::Json<UpdateUserRequest>,
) -> Result<HttpResponse, AppError> {
    let user_service = UserService::new(pool.as_ref().clone());
    let user = user_service.update_user(id.into_inner(), &body).await?;
    let response: UserResponse = user.into();
    
    Ok(HttpResponse::Ok().json(response))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/users/{id}",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
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
    pool: web::Data<PgPool>,
    id: web::Path<Uuid>,
) -> Result<HttpResponse, AppError> {
    let user_service = UserService::new(pool.as_ref().clone());
    user_service.delete_user(id.into_inner()).await?;
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "User deleted successfully"
    })))
}

#[derive(Debug, serde::Deserialize)]
pub struct PaginationQuery {
    pub page: Option<i32>,
    pub limit: Option<i32>,
}`
      },
      {
        path: 'src/handlers/websocket.rs',
        content: `use actix_web::{web, HttpRequest, HttpResponse};
use actix_ws::Message;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::{info, error};

use crate::error::AppError;
use crate::utils::auth::get_user_id_from_request;

#[derive(Debug, Serialize, Deserialize)]
struct WsMessage {
    r#type: String,
    payload: serde_json::Value,
}

pub async fn websocket_handler(
    req: HttpRequest,
    stream: web::Payload,
) -> Result<HttpResponse, AppError> {
    let user_id = get_user_id_from_request(&req)?;
    
    let (response, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;
    
    info!("WebSocket connection established for user {}", user_id);
    
    // Send welcome message
    let welcome = WsMessage {
        r#type: "welcome".to_string(),
        payload: serde_json::json!({
            "message": "Connected to WebSocket",
            "userId": user_id,
        }),
    };
    
    session.text(serde_json::to_string(&welcome)?).await?;
    
    // Handle incoming messages
    actix_web::rt::spawn(async move {
        while let Some(Ok(msg)) = msg_stream.next().await {
            match msg {
                Message::Text(text) => {
                    match serde_json::from_str::<WsMessage>(&text) {
                        Ok(ws_msg) => {
                            match ws_msg.r#type.as_str() {
                                "ping" => {
                                    let pong = WsMessage {
                                        r#type: "pong".to_string(),
                                        payload: ws_msg.payload,
                                    };
                                    if let Ok(json) = serde_json::to_string(&pong) {
                                        let _ = session.text(json).await;
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
                Message::Binary(_) => {
                    info!("Received binary message");
                }
                Message::Close(reason) => {
                    info!("WebSocket closed: {:?}", reason);
                    break;
                }
                Message::Ping(bytes) => {
                    let _ = session.pong(&bytes).await;
                }
                Message::Pong(_) => {}
                _ => {}
            }
        }
        
        info!("WebSocket connection closed for user {}", user_id);
    });
    
    Ok(response)
}`
      }
    ];
  }
  
  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/middleware/mod.rs',
        content: `pub mod auth;
pub mod request_id;
pub mod rate_limit;`
      },
      {
        path: 'src/middleware/auth.rs',
        content: `use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};

use crate::config::Config;
use crate::models::token::decode_jwt;
use crate::error::AppError;

pub struct RequireAuth;

impl<S, B> Transform<S, ServiceRequest> for RequireAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequireAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequireAuthMiddleware { service }))
    }
}

pub struct RequireAuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequireAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let auth_header = req.headers().get("Authorization");
        
        if let Some(auth_value) = auth_header {
            if let Ok(auth_str) = auth_value.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    
                    // Get config from app data
                    if let Some(config) = req.app_data::<actix_web::web::Data<Config>>() {
                        match decode_jwt(token, &config.jwt_secret) {
                            Ok(claims) => {
                                // Insert user ID into request extensions
                                req.extensions_mut().insert(claims.sub);
                                req.extensions_mut().insert(claims.email);
                                
                                let fut = self.service.call(req);
                                return Box::pin(async move {
                                    let res = fut.await?;
                                    Ok(res)
                                });
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
        }
        
        Box::pin(async move {
            Ok(req.into_response(
                HttpResponse::Unauthorized()
                    .json(serde_json::json!({
                        "error": "Invalid or missing authentication"
                    }))
                    .into_body()
            ))
        })
    }
}

pub struct RequireRole {
    role: String,
}

impl RequireRole {
    pub fn new(role: &str) -> Self {
        Self {
            role: role.to_string(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequireRole
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequireRoleMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequireRoleMiddleware {
            service,
            role: self.role.clone(),
        }))
    }
}

pub struct RequireRoleMiddleware<S> {
    service: S,
    role: String,
}

impl<S, B> Service<ServiceRequest> for RequireRoleMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // TODO: Implement role checking logic
        // For now, just pass through
        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}`
      },
      {
        path: 'src/middleware/request_id.rs',
        content: `use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use uuid::Uuid;

pub struct RequestId;

impl<S, B> Transform<S, ServiceRequest> for RequestId
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RequestIdMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestIdMiddleware { service }))
    }
}

pub struct RequestIdMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequestIdMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let request_id = Uuid::new_v4().to_string();
        req.extensions_mut().insert(request_id.clone());
        
        let fut = self.service.call(req);
        Box::pin(async move {
            let mut res = fut.await?;
            res.headers_mut()
                .insert(
                    actix_web::http::header::HeaderName::from_static("x-request-id"),
                    actix_web::http::header::HeaderValue::from_str(&request_id).unwrap(),
                );
            Ok(res)
        })
    }
}`
      },
      {
        path: 'src/middleware/rate_limit.rs',
        content: `use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse, HttpMessage,
};
use futures_util::future::LocalBoxFuture;
use std::future::{ready, Ready};
use std::time::Duration;
use redis::AsyncCommands;

pub struct RateLimit {
    limit: i32,
    window: Duration,
}

impl RateLimit {
    pub fn new(limit: i32, window: Duration) -> Self {
        Self { limit, window }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimit
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RateLimitMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddleware {
            service,
            limit: self.limit,
            window: self.window,
        }))
    }
}

pub struct RateLimitMiddleware<S> {
    service: S,
    limit: i32,
    window: Duration,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let limit = self.limit;
        let window = self.window;
        
        let ip = req.peer_addr()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        
        let key = format!("rate_limit:{}", ip);
        
        // Get Redis client from app data
        let redis_client = req.app_data::<actix_web::web::Data<redis::Client>>().cloned();
        
        let fut = self.service.call(req);
        
        Box::pin(async move {
            if let Some(client) = redis_client {
                match client.get_async_connection().await {
                    Ok(mut conn) => {
                        let count: Result<i32, _> = conn.incr(&key, 1).await;
                        
                        if let Ok(count) = count {
                            if count == 1 {
                                let _: Result<(), _> = conn.expire(&key, window.as_secs() as usize).await;
                            }
                            
                            if count > limit {
                                return Ok(ServiceRequest::from_parts(req.into_parts().0, ())
                                    .into_response(
                                        HttpResponse::TooManyRequests()
                                            .json(serde_json::json!({
                                                "error": "Rate limit exceeded"
                                            }))
                                            .into_body()
                                    ));
                            }
                        }
                    }
                    Err(_) => {
                        // Redis connection failed, allow request
                    }
                }
            }
            
            let res = fut.await?;
            Ok(res)
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
    return `use actix_web::{error::ResponseError, http::StatusCode, HttpResponse};
use std::fmt;

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

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let message = self.to_string();
        
        HttpResponse::build(status).json(serde_json::json!({
            "error": message
        }))
    }
    
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::Unauthorized | AppError::InvalidToken => StatusCode::UNAUTHORIZED,
            AppError::UserNotFound | AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::UserAlreadyExists => StatusCode::CONFLICT,
            AppError::InvalidCredentials | AppError::UserNotActive => StatusCode::UNAUTHORIZED,
            AppError::ValidationError(_) | AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Configuration(_) | AppError::TokenCreation => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::DatabaseError(_) | AppError::RedisError(_) | AppError::InternalServerError => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
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

impl From<validator::ValidationErrors> for AppError {
    fn from(err: validator::ValidationErrors) -> Self {
        AppError::ValidationError(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::BadRequest(err.to_string())
    }
}

impl From<actix_session::SessionInsertError> for AppError {
    fn from(_: actix_session::SessionInsertError) -> Self {
        AppError::InternalServerError
    }
}

impl From<actix_session::SessionGetError> for AppError {
    fn from(_: actix_session::SessionGetError) -> Self {
        AppError::InternalServerError
    }
}`;
  }
  
  // Additional utility files
  protected generateUtilFiles(): { path: string; content: string }[] {
    const baseUtils = super.generateUtilFiles();
    
    // Add Actix-specific auth utility
    const authUtil = {
      path: 'src/utils/auth.rs',
      content: `use actix_web::HttpRequest;
use uuid::Uuid;

use crate::error::AppError;

pub fn get_user_id_from_request(req: &HttpRequest) -> Result<Uuid, AppError> {
    req.extensions()
        .get::<Uuid>()
        .copied()
        .ok_or(AppError::Unauthorized)
}

pub fn get_user_email_from_request(req: &HttpRequest) -> Result<String, AppError> {
    req.extensions()
        .get::<String>()
        .cloned()
        .ok_or(AppError::Unauthorized)
}`
    };
    
    return [...baseUtils, authUtil];
  }
  
  // Override to include migrations
  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    await super.generateFrameworkFiles(projectPath, options);
    
    // Create migrations directory
    const fs = await import('fs').then(m => m.promises);
    const path = await import('path');
    
    await fs.mkdir(path.join(projectPath, 'migrations'), { recursive: true });
    
    // Create initial migration
    const timestamp = new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14);
    await this.writeFile(
      path.join(projectPath, 'migrations', `${timestamp}_create_users_table.sql`),
      `-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create updated_at trigger
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE
    ON users FOR EACH ROW EXECUTE PROCEDURE update_updated_at_column();

-- Create indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_is_active ON users(is_active);`
    );
    
    // Create static directory for static files
    await fs.mkdir(path.join(projectPath, 'static'), { recursive: true });
    await this.writeFile(
      path.join(projectPath, 'static', '.gitkeep'),
      ''
    );
  }
}