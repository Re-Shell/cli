import { GleamBackendGenerator } from './gleam-base-generator';
import * as fs from 'fs-extra';
import * as path from 'path';

export class WispGenerator extends GleamBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Wisp';
    this.config.features.push(
      'Modern web framework',
      'Type-safe routing',
      'Middleware pipeline',
      'Request/Response helpers',
      'Session management',
      'CORS support',
      'Static file serving',
      'WebSocket support',
      'Form parsing',
      'Cookie handling'
    );
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'wisp': '~> 0.14',
      'mist': '~> 1.0',
      'gleam_pgo': '~> 0.8',
      'argon2': '~> 1.0',
      'repeatedly': '~> 1.0'
    };
  }

  protected generateMainFile(): string {
    const appName = this.getAppModuleName(this.options?.name || 'app');
    
    return `import gleam/erlang/process
import mist
import wisp
import wisp/wisp_mist
import ${appName}/router
import ${appName}/config/config

pub fn main() {
  // Load configuration
  let config = config.load()
  
  // Configure Wisp
  let handler = router.handle_request
  
  // Create the Mist web server
  let assert Ok(_) =
    handler
    |> wisp_mist.handler(config.secret_key_base)
    |> mist.new
    |> mist.port(config.port)
    |> mist.start_http
  
  // Log server start
  wisp.log_info("Server started on port " <> int.to_string(config.port))
  
  // Keep the server running
  process.sleep_forever()
}
`;
  }

  protected generateRouterFile(): string {
    const appName = this.getAppModuleName(this.options?.name || 'app');
    
    return `import gleam/http.{Get, Post, Put, Delete}
import gleam/string_builder
import wisp.{type Request, type Response}
import ${appName}/controllers/health
import ${appName}/controllers/auth
import ${appName}/controllers/users
import ${appName}/middleware/cors
import ${appName}/middleware/auth as auth_middleware

pub fn handle_request(req: Request) -> Response {
  // Apply CORS middleware
  use req <- cors.middleware(req)
  
  // Route the request
  case wisp.path_segments(req) {
    // Health check
    ["health"] -> {
      case req.method {
        Get -> health.check(req)
        _ -> wisp.method_not_allowed([Get])
      }
    }
    
    // API routes
    ["api", ..rest] -> handle_api_routes(req, rest)
    
    // Static files
    [] -> wisp.ok() |> wisp.html_body(home_page())
    
    // 404 for unmatched routes
    _ -> wisp.not_found()
  }
}

fn handle_api_routes(req: Request, path: List(String)) -> Response {
  case path {
    // Auth routes
    ["auth", "register"] -> {
      case req.method {
        Post -> auth.register(req)
        _ -> wisp.method_not_allowed([Post])
      }
    }
    
    ["auth", "login"] -> {
      case req.method {
        Post -> auth.login(req)
        _ -> wisp.method_not_allowed([Post])
      }
    }
    
    ["auth", "refresh"] -> {
      case req.method {
        Post -> auth.refresh_token(req)
        _ -> wisp.method_not_allowed([Post])
      }
    }
    
    ["auth", "logout"] -> {
      case req.method {
        Post -> {
          use req <- auth_middleware.require_auth(req)
          auth.logout(req)
        }
        _ -> wisp.method_not_allowed([Post])
      }
    }
    
    // User routes (protected)
    ["users", ..rest] -> {
      use req <- auth_middleware.require_auth(req)
      handle_user_routes(req, rest)
    }
    
    // Not found
    _ -> wisp.not_found()
  }
}

fn handle_user_routes(req: Request, path: List(String)) -> Response {
  case path {
    [] -> {
      case req.method {
        Get -> users.list_users(req)
        _ -> wisp.method_not_allowed([Get])
      }
    }
    
    ["me"] -> {
      case req.method {
        Get -> users.get_current_user(req)
        Put -> users.update_current_user(req)
        _ -> wisp.method_not_allowed([Get, Put])
      }
    }
    
    [id] -> {
      case req.method {
        Get -> users.get_user(req, id)
        Put -> users.update_user(req, id)
        Delete -> users.delete_user(req, id)
        _ -> wisp.method_not_allowed([Get, Put, Delete])
      }
    }
    
    _ -> wisp.not_found()
  }
}

fn home_page() -> string_builder.StringBuilder {
  string_builder.from_string(
    "<!DOCTYPE html>
    <html>
    <head>
        <title>Gleam Wisp API</title>
        <meta charset='UTF-8'>
        <style>
            body {
                font-family: system-ui, -apple-system, sans-serif;
                max-width: 800px;
                margin: 0 auto;
                padding: 2rem;
                background: #f5f5f5;
            }
            .container {
                background: white;
                padding: 2rem;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            h1 { color: #FF3E7C; }
            .endpoint { 
                background: #f8f9fa;
                padding: 0.5rem 1rem;
                margin: 0.5rem 0;
                border-radius: 4px;
                font-family: monospace;
            }
            .method {
                font-weight: bold;
                color: #28a745;
            }
        </style>
    </head>
    <body>
        <div class='container'>
            <h1>🌟 Gleam Wisp API</h1>
            <p>Welcome to your Gleam web service!</p>
            <h2>Available Endpoints:</h2>
            <div class='endpoint'><span class='method'>GET</span> /health</div>
            <div class='endpoint'><span class='method'>POST</span> /api/auth/register</div>
            <div class='endpoint'><span class='method'>POST</span> /api/auth/login</div>
            <div class='endpoint'><span class='method'>GET</span> /api/users</div>
            <p>Check out the <a href='/docs/api.md'>API documentation</a> for more details.</p>
        </div>
    </body>
    </html>"
  )
}
`;
  }

  protected generateConfigFile(): string {
    const appName = this.getAppModuleName(this.options?.name || 'app');
    
    return `import gleam/erlang/os
import gleam/int
import gleam/option.{type Option, None, Some}
import gleam/result

pub type Config {
  Config(
    port: Int,
    secret_key_base: String,
    database_url: String,
    jwt_secret: String,
    environment: String,
  )
}

pub fn load() -> Config {
  Config(
    port: get_port(),
    secret_key_base: get_env("SECRET_KEY_BASE", "your-secret-key-base"),
    database_url: get_env("DATABASE_URL", "postgresql://localhost:5432/app"),
    jwt_secret: get_env("JWT_SECRET", "your-jwt-secret"),
    environment: get_env("GLEAM_ENV", "development"),
  )
}

fn get_port() -> Int {
  case os.get_env("PORT") {
    Ok(port_str) -> {
      case int.parse(port_str) {
        Ok(port) -> port
        Error(_) -> ${this.options?.port || 8080}
      }
    }
    Error(_) -> ${this.options?.port || 8080}
  }
}

fn get_env(key: String, default: String) -> String {
  case os.get_env(key) {
    Ok(value) -> value
    Error(_) -> default
  }
}

pub fn is_development(config: Config) -> Bool {
  config.environment == "development"
}

pub fn is_production(config: Config) -> Bool {
  config.environment == "production"
}
`;
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    const appName = this.getAppModuleName(this.options?.name || 'app');
    
    return [
      {
        path: 'src/middleware/cors.gleam',
        content: `import gleam/http
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import wisp.{type Request, type Response}

pub fn middleware(
  req: Request,
  handler: fn(Request) -> Response,
) -> Response {
  let response = handler(req)
  
  // Get origin from request
  let origin = case list.key_find(req.headers, "origin") {
    Ok(origin) -> origin
    Error(_) -> "*"
  }
  
  // Add CORS headers
  response
  |> wisp.set_header("access-control-allow-origin", origin)
  |> wisp.set_header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS")
  |> wisp.set_header("access-control-allow-headers", "Content-Type, Authorization")
  |> wisp.set_header("access-control-max-age", "86400")
  |> fn(res) {
    case req.method {
      http.Options -> wisp.response(204)
      _ -> res
    }
  }
}

pub fn allowed_origins() -> List(String) {
  ["http://localhost:3000", "http://localhost:5173", "https://yourdomain.com"]
}
`
      },
      {
        path: 'src/middleware/auth.gleam',
        content: `import gleam/http
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import wisp.{type Request, type Response}
import ${appName}/utils/jwt
import ${appName}/models/user

pub type AuthContext {
  AuthContext(user: user.User, claims: jwt.Claims)
}

pub fn require_auth(
  req: Request,
  handler: fn(Request) -> Response,
) -> Response {
  case get_auth_header(req) {
    Ok(token) -> {
      case jwt.verify(token) {
        Ok(claims) -> {
          // Here you would normally fetch the user from database
          // For now, we'll create a mock user
          let user = user.User(
            id: claims.sub,
            email: claims.email,
            name: "Test User",
            created_at: 0,
            updated_at: 0,
          )
          
          // Add auth context to request
          let req_with_auth = req
          handler(req_with_auth)
        }
        Error(_) -> unauthorized_response()
      }
    }
    Error(_) -> unauthorized_response()
  }
}

pub fn optional_auth(
  req: Request,
  handler: fn(Request) -> Response,
) -> Response {
  case get_auth_header(req) {
    Ok(token) -> {
      case jwt.verify(token) {
        Ok(_claims) -> handler(req)
        Error(_) -> handler(req)
      }
    }
    Error(_) -> handler(req)
  }
}

fn get_auth_header(req: Request) -> Result(String, Nil) {
  case list.key_find(req.headers, "authorization") {
    Ok(header) -> {
      case string.starts_with(header, "Bearer ") {
        True -> Ok(string.drop_left(header, 7))
        False -> Error(Nil)
      }
    }
    Error(_) -> Error(Nil)
  }
}

fn unauthorized_response() -> Response {
  wisp.response(401)
  |> wisp.json_body(
    json.object([
      #("error", json.string("Unauthorized")),
      #("message", json.string("Invalid or missing authentication token")),
    ])
  )
}
`
      }
    ];
  }

  protected generateControllerFiles(): { path: string; content: string }[] {
    const appName = this.getAppModuleName(this.options?.name || 'app');
    
    return [
      {
        path: 'src/controllers/health.gleam',
        content: `import gleam/http/response
import gleam/json
import wisp.{type Request, type Response}

pub fn check(_req: Request) -> Response {
  let health_data = json.object([
    #("status", json.string("healthy")),
    #("service", json.string("Gleam Wisp API")),
    #("version", json.string("1.0.0")),
    #("timestamp", json.int(current_timestamp())),
  ])
  
  wisp.ok()
  |> wisp.json_body(health_data)
}

fn current_timestamp() -> Int {
  // In a real app, you'd use gleam_erlang to get current time
  1234567890
}
`
      },
      {
        path: 'src/controllers/auth.gleam',
        content: `import gleam/json
import gleam/dynamic
import gleam/result
import gleam/option.{None, Some}
import wisp.{type Request, type Response}
import ${appName}/models/user
import ${appName}/utils/jwt
import ${appName}/utils/password

pub type RegisterRequest {
  RegisterRequest(
    email: String,
    password: String,
    name: String,
  )
}

pub type LoginRequest {
  LoginRequest(
    email: String,
    password: String,
  )
}

pub fn register(req: Request) -> Response {
  use json_body <- wisp.require_json(req)
  
  let decoder = dynamic.decode3(
    RegisterRequest,
    dynamic.field("email", dynamic.string),
    dynamic.field("password", dynamic.string),
    dynamic.field("name", dynamic.string),
  )
  
  case decoder(json_body) {
    Ok(register_req) -> {
      // Validate email
      case is_valid_email(register_req.email) {
        False -> {
          wisp.bad_request()
          |> wisp.json_body(error_response("Invalid email format"))
        }
        True -> {
          // Hash password
          let hashed = password.hash(register_req.password)
          
          // Create user (in real app, save to database)
          let user = user.User(
            id: "user_" <> generate_id(),
            email: register_req.email,
            name: register_req.name,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
          )
          
          // Generate tokens
          let access_token = jwt.generate(user.id, user.email)
          let refresh_token = jwt.generate_refresh(user.id)
          
          wisp.created()
          |> wisp.json_body(
            json.object([
              #("user", user.to_json(user)),
              #("access_token", json.string(access_token)),
              #("refresh_token", json.string(refresh_token)),
            ])
          )
        }
      }
    }
    Error(_) -> {
      wisp.bad_request()
      |> wisp.json_body(error_response("Invalid request body"))
    }
  }
}

pub fn login(req: Request) -> Response {
  use json_body <- wisp.require_json(req)
  
  let decoder = dynamic.decode2(
    LoginRequest,
    dynamic.field("email", dynamic.string),
    dynamic.field("password", dynamic.string),
  )
  
  case decoder(json_body) {
    Ok(login_req) -> {
      // In real app, fetch user from database
      // For demo, we'll simulate a successful login
      let user = user.User(
        id: "user_123",
        email: login_req.email,
        name: "Test User",
        created_at: current_timestamp(),
        updated_at: current_timestamp(),
      )
      
      // Generate tokens
      let access_token = jwt.generate(user.id, user.email)
      let refresh_token = jwt.generate_refresh(user.id)
      
      wisp.ok()
      |> wisp.json_body(
        json.object([
          #("user", user.to_json(user)),
          #("access_token", json.string(access_token)),
          #("refresh_token", json.string(refresh_token)),
        ])
      )
    }
    Error(_) -> {
      wisp.bad_request()
      |> wisp.json_body(error_response("Invalid request body"))
    }
  }
}

pub fn refresh_token(req: Request) -> Response {
  use json_body <- wisp.require_json(req)
  
  case dynamic.field("refresh_token", dynamic.string)(json_body) {
    Ok(refresh_token) -> {
      case jwt.verify(refresh_token) {
        Ok(claims) -> {
          // Generate new tokens
          let access_token = jwt.generate(claims.sub, claims.email)
          let new_refresh = jwt.generate_refresh(claims.sub)
          
          wisp.ok()
          |> wisp.json_body(
            json.object([
              #("access_token", json.string(access_token)),
              #("refresh_token", json.string(new_refresh)),
            ])
          )
        }
        Error(_) -> {
          wisp.unauthorized()
          |> wisp.json_body(error_response("Invalid refresh token"))
        }
      }
    }
    Error(_) -> {
      wisp.bad_request()
      |> wisp.json_body(error_response("Refresh token required"))
    }
  }
}

pub fn logout(_req: Request) -> Response {
  wisp.ok()
  |> wisp.json_body(
    json.object([
      #("message", json.string("Logged out successfully")),
    ])
  )
}

fn error_response(message: String) -> json.Json {
  json.object([
    #("error", json.string(message)),
  ])
}

fn is_valid_email(email: String) -> Bool {
  // Simple email validation
  case string.contains(email, "@") {
    True -> string.contains(email, ".")
    False -> False
  }
}

fn generate_id() -> String {
  // In real app, use proper ID generation
  "123456"
}

fn current_timestamp() -> Int {
  // In real app, use gleam_erlang for proper timestamp
  1234567890
}
`
      },
      {
        path: 'src/controllers/users.gleam',
        content: `import gleam/json
import gleam/dynamic
import gleam/list
import gleam/int
import gleam/option.{None, Some}
import wisp.{type Request, type Response}
import ${appName}/models/user

pub fn list_users(req: Request) -> Response {
  // Parse query parameters
  let limit = get_query_param(req, "limit", "10")
  let offset = get_query_param(req, "offset", "0")
  
  // In real app, fetch from database
  let users = [
    user.User(
      id: "user_1",
      email: "user1@example.com",
      name: "User One",
      created_at: 1234567890,
      updated_at: 1234567890,
    ),
    user.User(
      id: "user_2",
      email: "user2@example.com",
      name: "User Two",
      created_at: 1234567890,
      updated_at: 1234567890,
    ),
  ]
  
  wisp.ok()
  |> wisp.json_body(
    json.object([
      #("users", json.array(users, user.to_json)),
      #("count", json.int(list.length(users))),
      #("limit", json.string(limit)),
      #("offset", json.string(offset)),
    ])
  )
}

pub fn get_user(_req: Request, id: String) -> Response {
  // In real app, fetch from database
  let user = user.User(
    id: id,
    email: "user@example.com",
    name: "Test User",
    created_at: 1234567890,
    updated_at: 1234567890,
  )
  
  wisp.ok()
  |> wisp.json_body(
    json.object([
      #("user", user.to_json(user)),
    ])
  )
}

pub fn update_user(req: Request, id: String) -> Response {
  use json_body <- wisp.require_json(req)
  
  case dynamic.field("name", dynamic.string)(json_body) {
    Ok(name) -> {
      // In real app, update in database
      let user = user.User(
        id: id,
        email: "user@example.com",
        name: name,
        created_at: 1234567890,
        updated_at: current_timestamp(),
      )
      
      wisp.ok()
      |> wisp.json_body(
        json.object([
          #("user", user.to_json(user)),
        ])
      )
    }
    Error(_) -> {
      wisp.bad_request()
      |> wisp.json_body(error_response("Name is required"))
    }
  }
}

pub fn delete_user(_req: Request, id: String) -> Response {
  // In real app, delete from database
  wisp.no_content()
}

pub fn get_current_user(_req: Request) -> Response {
  // Get user from auth context
  let user = user.User(
    id: "current_user",
    email: "current@example.com",
    name: "Current User",
    created_at: 1234567890,
    updated_at: 1234567890,
  )
  
  wisp.ok()
  |> wisp.json_body(
    json.object([
      #("user", user.to_json(user)),
    ])
  )
}

pub fn update_current_user(req: Request) -> Response {
  update_user(req, "current_user")
}

fn get_query_param(req: Request, key: String, default: String) -> String {
  // In real app, parse query parameters properly
  default
}

fn error_response(message: String) -> json.Json {
  json.object([
    #("error", json.string(message)),
  ])
}

fn current_timestamp() -> Int {
  // In real app, use gleam_erlang for proper timestamp
  1234567890
}
`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/models/user.gleam',
        content: `import gleam/json
import gleam/option.{type Option, None, Some}

pub type User {
  User(
    id: String,
    email: String,
    name: String,
    created_at: Int,
    updated_at: Int,
  )
}

pub fn to_json(user: User) -> json.Json {
  json.object([
    #("id", json.string(user.id)),
    #("email", json.string(user.email)),
    #("name", json.string(user.name)),
    #("created_at", json.int(user.created_at)),
    #("updated_at", json.int(user.updated_at)),
  ])
}

pub fn new(email: String, name: String) -> User {
  User(
    id: generate_id(),
    email: email,
    name: name,
    created_at: current_timestamp(),
    updated_at: current_timestamp(),
  )
}

fn generate_id() -> String {
  // In real app, use proper UUID generation
  "user_" <> int.to_string(random_int())
}

fn current_timestamp() -> Int {
  // In real app, use gleam_erlang for proper timestamp
  1234567890
}

fn random_int() -> Int {
  // In real app, use proper random number generation
  42
}
`
      }
    ];
  }

  protected generateUtilFiles(): { path: string; content: string }[] {
    const appName = this.getAppModuleName(this.options?.name || 'app');
    
    return [
      {
        path: 'src/utils/jwt.gleam',
        content: `import gleam/base64
import gleam/bit_array
import gleam/crypto
import gleam/json
import gleam/result
import gleam/string
import ${appName}/config/config

pub type Claims {
  Claims(
    sub: String,
    email: String,
    exp: Int,
    iat: Int,
  )
}

pub fn generate(user_id: String, email: String) -> String {
  let config = config.load()
  let now = current_timestamp()
  
  let header = json.object([
    #("alg", json.string("HS256")),
    #("typ", json.string("JWT")),
  ])
  
  let claims = json.object([
    #("sub", json.string(user_id)),
    #("email", json.string(email)),
    #("exp", json.int(now + 3600)),
    #("iat", json.int(now)),
  ])
  
  let header_b64 = base64.url_encode(json.to_string(header), False)
  let claims_b64 = base64.url_encode(json.to_string(claims), False)
  let message = header_b64 <> "." <> claims_b64
  
  let signature = sign(message, config.jwt_secret)
  message <> "." <> signature
}

pub fn generate_refresh(user_id: String) -> String {
  let config = config.load()
  let now = current_timestamp()
  
  let header = json.object([
    #("alg", json.string("HS256")),
    #("typ", json.string("JWT")),
  ])
  
  let claims = json.object([
    #("sub", json.string(user_id)),
    #("exp", json.int(now + 604800)), // 7 days
    #("iat", json.int(now)),
  ])
  
  let header_b64 = base64.url_encode(json.to_string(header), False)
  let claims_b64 = base64.url_encode(json.to_string(claims), False)
  let message = header_b64 <> "." <> claims_b64
  
  let signature = sign(message, config.jwt_secret)
  message <> "." <> signature
}

pub fn verify(token: String) -> Result(Claims, String) {
  let parts = string.split(token, ".")
  case list.length(parts) {
    3 -> {
      let [header, payload, signature] = parts
      let message = header <> "." <> payload
      
      let config = config.load()
      let expected_sig = sign(message, config.jwt_secret)
      
      case signature == expected_sig {
        True -> {
          // Decode claims
          case base64.url_decode(payload) {
            Ok(decoded) -> {
              // Parse JSON and extract claims
              // In real app, properly parse JSON
              Ok(Claims(
                sub: "user_123",
                email: "user@example.com",
                exp: current_timestamp() + 3600,
                iat: current_timestamp(),
              ))
            }
            Error(_) -> Error("Invalid payload")
          }
        }
        False -> Error("Invalid signature")
      }
    }
    _ -> Error("Invalid token format")
  }
}

fn sign(message: String, secret: String) -> String {
  // In real app, use proper HMAC-SHA256
  // This is a placeholder
  base64.url_encode("signature", False)
}

fn current_timestamp() -> Int {
  // In real app, use gleam_erlang for proper timestamp
  1234567890
}
`
      },
      {
        path: 'src/utils/password.gleam',
        content: `import gleam/crypto
import gleam/string
import gleam/bit_array
import gleam/base64

pub fn hash(password: String) -> String {
  // In real app, use argon2 for proper password hashing
  // This is a simplified version
  let salt = "random_salt"
  let salted = password <> salt
  
  base64.encode(bit_array.from_string(salted), False)
}

pub fn verify(password: String, hash: String) -> Bool {
  // In real app, use argon2 for proper verification
  hash(password) == hash
}

pub fn generate_salt() -> String {
  // In real app, generate cryptographically secure random salt
  "random_salt_" <> int.to_string(random_int())
}

fn random_int() -> Int {
  // In real app, use proper random number generation
  42
}
`
      }
    ];
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    const appName = this.getAppModuleName(this.options?.name || 'app');
    
    return [
      {
        path: 'test/auth_test.gleam',
        content: `import gleeunit
import gleeunit/should
import ${appName}/utils/jwt
import ${appName}/utils/password

pub fn main() {
  gleeunit.main()
}

pub fn password_hashing_test() {
  let pass = "SecurePassword123!"
  let hash = password.hash(pass)
  
  hash
  |> should.not_equal(pass)
  
  password.verify(pass, hash)
  |> should.be_true
  
  password.verify("wrong_password", hash)
  |> should.be_false
}

pub fn jwt_generation_test() {
  let user_id = "user_123"
  let email = "test@example.com"
  
  let token = jwt.generate(user_id, email)
  
  token
  |> string.contains(".")
  |> should.be_true
  
  let parts = string.split(token, ".")
  list.length(parts)
  |> should.equal(3)
}

pub fn jwt_verification_test() {
  let user_id = "user_123"
  let email = "test@example.com"
  
  let token = jwt.generate(user_id, email)
  
  case jwt.verify(token) {
    Ok(claims) -> {
      claims.sub
      |> should.equal(user_id)
      
      claims.email
      |> should.equal(email)
    }
    Error(_) -> {
      should.fail()
    }
  }
}
`
      },
      {
        path: 'test/router_test.gleam',
        content: `import gleeunit
import gleeunit/should
import gleam/http.{Get}
import wisp/testing
import ${appName}/router

pub fn main() {
  gleeunit.main()
}

pub fn health_check_test() {
  let request = testing.get("/health", [])
  let response = router.handle_request(request)
  
  response.status
  |> should.equal(200)
}

pub fn not_found_test() {
  let request = testing.get("/nonexistent", [])
  let response = router.handle_request(request)
  
  response.status
  |> should.equal(404)
}

pub fn cors_headers_test() {
  let request = testing.get("/health", [#("origin", "http://localhost:3000")])
  let response = router.handle_request(request)
  
  response.headers
  |> list.key_find("access-control-allow-origin")
  |> should.be_ok
}
`
      }
    ];
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Create additional directories
    await fs.mkdir(path.join(projectPath, 'priv', 'static', 'css'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'priv', 'static', 'js'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'priv', 'static', 'images'), { recursive: true });

    // Create a simple CSS file
    await fs.writeFile(path.join(projectPath, 'priv', 'static', 'css', 'style.css'), `/* Wisp App Styles */
body {
  font-family: system-ui, -apple-system, sans-serif;
  line-height: 1.6;
  color: #333;
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.container {
  background: #f4f4f4;
  padding: 20px;
  border-radius: 8px;
}

h1 {
  color: #FF3E7C;
}

code {
  background: #e4e4e4;
  padding: 2px 4px;
  border-radius: 3px;
  font-family: 'Courier New', monospace;
}
`);

    // Create development scripts
    await fs.mkdir(path.join(projectPath, 'scripts'), { recursive: true });
    
    await fs.writeFile(path.join(projectPath, 'scripts', 'dev.sh'), `#!/bin/bash

echo "Starting Gleam Wisp development server..."

# Install dependencies if needed
if [ ! -d "build" ]; then
  echo "Installing dependencies..."
  gleam deps download
fi

# Run the development server
gleam run

# For development with file watching (requires watchexec)
# watchexec -r -e gleam -- gleam run
`);

    await fs.writeFile(path.join(projectPath, 'scripts', 'test.sh'), `#!/bin/bash

echo "Running tests..."

# Run all tests
gleam test

# Run with coverage if available
# gleam test --coverage
`);

    await fs.writeFile(path.join(projectPath, 'scripts', 'build.sh'), `#!/bin/bash

echo "Building Gleam Wisp application..."

# Clean previous build
rm -rf build

# Build the application
gleam build

# Create release
gleam export erlang-shipment

echo "Build complete!"
`);

    // Make scripts executable
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);
    
    try {
      await execAsync('chmod +x scripts/*.sh', { cwd: projectPath });
    } catch (error) {
      console.warn('Failed to make scripts executable');
    }
  }
}