import { GleamBackendGenerator } from './gleam-base-generator';
import * as fs from 'fs-extra';
import * as path from 'path';

export class MistGenerator extends GleamBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Mist';
    this.config.features.push(
      'Low-level HTTP server',
      'WebSocket support',
      'HTTP/2 support',
      'TLS/SSL support',
      'Custom request handling',
      'Streaming responses',
      'Binary protocol support',
      'High performance',
      'Connection pooling',
      'Graceful shutdown'
    );
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'mist': '~> 1.0',
      'gleam_pgo': '~> 0.8',
      'argon2': '~> 1.0',
      'repeatedly': '~> 1.0',
      'simplifile': '~> 1.0'
    };
  }

  protected generateMainFile(): string {
    const appName = this.getAppModuleName(this.options?.name || 'app');
    
    return `import gleam/bytes_builder
import gleam/erlang/process
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import mist
import ${appName}/router
import ${appName}/config/config

pub fn main() {
  // Load configuration
  let config = config.load()
  
  // Create the HTTP handler
  let handler = fn(request: Request(mist.Connection)) -> Response(mist.ResponseData) {
    // Log request
    log_request(request)
    
    // Route the request
    router.handle_request(request)
  }
  
  // Start the server
  let assert Ok(_) =
    handler
    |> mist.new
    |> mist.port(config.port)
    |> mist.start_http
  
  // Log server start
  io.println("🚀 Mist server started on port " <> int.to_string(config.port))
  
  // Keep the server running
  process.sleep_forever()
}

fn log_request(request: Request(mist.Connection)) -> Nil {
  io.println(
    request.method
    |> http.method_to_string
    |> string.uppercase
    <> " "
    <> request.path
  )
}
`;
  }

  protected generateRouterFile(): string {
    const appName = this.getAppModuleName(this.options?.name || 'app');
    
    return `import gleam/bit_array
import gleam/bytes_builder
import gleam/http.{Get, Post, Put, Delete, Options}
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import mist.{type Connection, type ResponseData}
import ${appName}/controllers/health
import ${appName}/controllers/auth
import ${appName}/controllers/users
import ${appName}/middleware/cors
import ${appName}/middleware/auth as auth_middleware
import ${appName}/middleware/logger

pub fn handle_request(req: Request(Connection)) -> Response(ResponseData) {
  // Apply logging middleware
  logger.log(req)
  
  // Apply CORS middleware
  let req = cors.apply_headers(req)
  
  // Handle OPTIONS requests for CORS
  case req.method {
    Options -> cors.handle_preflight(req)
    _ -> route_request(req)
  }
}

fn route_request(req: Request(Connection)) -> Response(ResponseData) {
  let segments = string.split(req.path, "/")
    |> list.filter(fn(s) { !string.is_empty(s) })
  
  case segments {
    // Health check
    ["health"] -> {
      case req.method {
        Get -> health.check(req)
        _ -> method_not_allowed([Get])
      }
    }
    
    // API routes
    ["api", ..rest] -> handle_api_routes(req, rest)
    
    // Static files
    ["static", ..path] -> serve_static_file(path)
    
    // Home page
    [] -> home_page()
    
    // 404 for unmatched routes
    _ -> not_found()
  }
}

fn handle_api_routes(
  req: Request(Connection),
  path: List(String),
) -> Response(ResponseData) {
  case path {
    // Auth routes
    ["auth", "register"] -> {
      case req.method {
        Post -> auth.register(req)
        _ -> method_not_allowed([Post])
      }
    }
    
    ["auth", "login"] -> {
      case req.method {
        Post -> auth.login(req)
        _ -> method_not_allowed([Post])
      }
    }
    
    ["auth", "refresh"] -> {
      case req.method {
        Post -> auth.refresh_token(req)
        _ -> method_not_allowed([Post])
      }
    }
    
    ["auth", "logout"] -> {
      case req.method {
        Post -> {
          use <- auth_middleware.require_auth(req)
          auth.logout(req)
        }
        _ -> method_not_allowed([Post])
      }
    }
    
    // User routes (protected)
    ["users", ..rest] -> {
      use <- auth_middleware.require_auth(req)
      handle_user_routes(req, rest)
    }
    
    // WebSocket endpoint
    ["ws"] -> handle_websocket(req)
    
    // Not found
    _ -> not_found()
  }
}

fn handle_user_routes(
  req: Request(Connection),
  path: List(String),
) -> Response(ResponseData) {
  case path {
    [] -> {
      case req.method {
        Get -> users.list_users(req)
        _ -> method_not_allowed([Get])
      }
    }
    
    ["me"] -> {
      case req.method {
        Get -> users.get_current_user(req)
        Put -> users.update_current_user(req)
        _ -> method_not_allowed([Get, Put])
      }
    }
    
    [id] -> {
      case req.method {
        Get -> users.get_user(req, id)
        Put -> users.update_user(req, id)
        Delete -> users.delete_user(req, id)
        _ -> method_not_allowed([Get, Put, Delete])
      }
    }
    
    _ -> not_found()
  }
}

fn handle_websocket(req: Request(Connection)) -> Response(ResponseData) {
  mist.websocket(
    request: req,
    on_init: fn(_conn) { #(Nil, None) },
    on_close: fn(_state) { Nil },
    handler: websocket_handler,
  )
}

fn websocket_handler(state, conn, message) {
  case message {
    mist.Text(text) -> {
      // Echo the message back
      let assert Ok(_) = mist.send_text_frame(conn, "Echo: " <> text)
      #(state, None)
    }
    mist.Binary(data) -> {
      // Handle binary data
      let assert Ok(_) = mist.send_binary_frame(conn, data)
      #(state, None)
    }
    mist.Close -> {
      #(state, Some(fn() { Nil }))
    }
    _ -> #(state, None)
  }
}

fn serve_static_file(path: List(String)) -> Response(ResponseData) {
  let file_path = string.join(path, "/")
  let full_path = "priv/static/" <> file_path
  
  case simplifile.read(full_path) {
    Ok(content) -> {
      response.new(200)
      |> response.set_header("content-type", get_content_type(file_path))
      |> response.set_body(mist.Bytes(bytes_builder.from_bit_array(content)))
    }
    Error(_) -> not_found()
  }
}

fn get_content_type(path: String) -> String {
  case string.split(path, ".") |> list.last {
    Ok("html") -> "text/html"
    Ok("css") -> "text/css"
    Ok("js") -> "application/javascript"
    Ok("json") -> "application/json"
    Ok("png") -> "image/png"
    Ok("jpg") | Ok("jpeg") -> "image/jpeg"
    Ok("svg") -> "image/svg+xml"
    _ -> "application/octet-stream"
  }
}

fn home_page() -> Response(ResponseData) {
  let html = "<!DOCTYPE html>
<html>
<head>
    <title>Gleam Mist API</title>
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
        .feature {
            background: #f8f9fa;
            padding: 0.5rem 1rem;
            margin: 0.5rem 0;
            border-radius: 4px;
        }
        code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class='container'>
        <h1>⚡ Gleam Mist Server</h1>
        <p>A high-performance HTTP server built with Gleam and Mist.</p>
        
        <h2>Features:</h2>
        <div class='feature'>✅ Low-level HTTP handling</div>
        <div class='feature'>✅ WebSocket support at <code>/api/ws</code></div>
        <div class='feature'>✅ Static file serving</div>
        <div class='feature'>✅ JWT authentication</div>
        <div class='feature'>✅ RESTful API</div>
        
        <h2>API Endpoints:</h2>
        <ul>
            <li><code>GET /health</code> - Health check</li>
            <li><code>POST /api/auth/register</code> - User registration</li>
            <li><code>POST /api/auth/login</code> - User login</li>
            <li><code>GET /api/users</code> - List users (auth required)</li>
            <li><code>WS /api/ws</code> - WebSocket endpoint</li>
        </ul>
        
        <p>Check the <a href='/static/docs/api.html'>API documentation</a> for more details.</p>
    </div>
</body>
</html>"
  
  response.new(200)
  |> response.set_header("content-type", "text/html")
  |> response.set_body(mist.Bytes(bytes_builder.from_string(html)))
}

fn not_found() -> Response(ResponseData) {
  let body = json.object([
    #("error", json.string("Not found")),
    #("status", json.int(404)),
  ])
  
  response.new(404)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    mist.Bytes(
      bytes_builder.from_string(json.to_string(body))
    )
  )
}

fn method_not_allowed(allowed: List(http.Method)) -> Response(ResponseData) {
  let methods = allowed
    |> list.map(http.method_to_string)
    |> list.map(string.uppercase)
    |> string.join(", ")
  
  let body = json.object([
    #("error", json.string("Method not allowed")),
    #("allowed", json.string(methods)),
    #("status", json.int(405)),
  ])
  
  response.new(405)
  |> response.set_header("allow", methods)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    mist.Bytes(
      bytes_builder.from_string(json.to_string(body))
    )
  )
}
`;
  }

  protected generateConfigFile(): string {
    return `import gleam/erlang/os
import gleam/int
import gleam/result

pub type Config {
  Config(
    port: Int,
    secret_key_base: String,
    database_url: String,
    jwt_secret: String,
    environment: String,
    max_connections: Int,
    read_timeout: Int,
    write_timeout: Int,
  )
}

pub fn load() -> Config {
  Config(
    port: get_int_env("PORT", ${this.options?.port || 8080}),
    secret_key_base: get_env("SECRET_KEY_BASE", "your-secret-key-base"),
    database_url: get_env("DATABASE_URL", "postgresql://localhost:5432/app"),
    jwt_secret: get_env("JWT_SECRET", "your-jwt-secret"),
    environment: get_env("GLEAM_ENV", "development"),
    max_connections: get_int_env("MAX_CONNECTIONS", 1000),
    read_timeout: get_int_env("READ_TIMEOUT", 30000),
    write_timeout: get_int_env("WRITE_TIMEOUT", 30000),
  )
}

fn get_env(key: String, default: String) -> String {
  case os.get_env(key) {
    Ok(value) -> value
    Error(_) -> default
  }
}

fn get_int_env(key: String, default: Int) -> Int {
  case os.get_env(key) {
    Ok(value) -> {
      case int.parse(value) {
        Ok(int_value) -> int_value
        Error(_) -> default
      }
    }
    Error(_) -> default
  }
}

pub fn is_development(config: Config) -> Bool {
  config.environment == "development"
}

pub fn is_production(config: Config) -> Bool {
  config.environment == "production"
}

pub fn is_test(config: Config) -> Bool {
  config.environment == "test"
}
`;
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    const appName = this.getAppModuleName(this.options?.name || 'app');
    
    return [
      {
        path: 'src/middleware/cors.gleam',
        content: `import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import mist.{type Connection, type ResponseData}
import gleam/bytes_builder

pub fn apply_headers(req: Request(Connection)) -> Request(Connection) {
  req
}

pub fn handle_preflight(req: Request(Connection)) -> Response(ResponseData) {
  let origin = get_origin(req)
  
  response.new(204)
  |> response.set_header("access-control-allow-origin", origin)
  |> response.set_header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS")
  |> response.set_header("access-control-allow-headers", "Content-Type, Authorization")
  |> response.set_header("access-control-max-age", "86400")
  |> response.set_body(mist.Bytes(bytes_builder.new()))
}

pub fn add_cors_headers(
  res: Response(ResponseData),
  req: Request(Connection),
) -> Response(ResponseData) {
  let origin = get_origin(req)
  
  res
  |> response.set_header("access-control-allow-origin", origin)
  |> response.set_header("access-control-allow-methods", "GET, POST, PUT, DELETE, OPTIONS")
  |> response.set_header("access-control-allow-headers", "Content-Type, Authorization")
}

fn get_origin(req: Request(Connection)) -> String {
  case list.key_find(req.headers, "origin") {
    Ok(origin) -> {
      case is_allowed_origin(origin) {
        True -> origin
        False -> "*"
      }
    }
    Error(_) -> "*"
  }
}

fn is_allowed_origin(origin: String) -> Bool {
  let allowed = [
    "http://localhost:3000",
    "http://localhost:5173",
    "https://yourdomain.com",
  ]
  
  list.contains(allowed, origin)
}
`
      },
      {
        path: 'src/middleware/auth.gleam',
        content: `import gleam/http
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/bytes_builder
import mist.{type Connection, type ResponseData}
import ${appName}/utils/jwt
import ${appName}/models/user

pub type AuthContext {
  AuthContext(user: user.User, claims: jwt.Claims)
}

pub fn require_auth(
  req: Request(Connection),
  handler: fn(Request(Connection)) -> Response(ResponseData),
) -> Response(ResponseData) {
  case get_auth_header(req) {
    Ok(token) -> {
      case jwt.verify(token) {
        Ok(claims) -> {
          // In a real app, fetch user from database
          let user = user.User(
            id: claims.sub,
            email: claims.email,
            name: "Test User",
            password_hash: "",
            created_at: 0,
            updated_at: 0,
          )
          
          // For now, just proceed with the handler
          handler(req)
        }
        Error(_) -> unauthorized_response()
      }
    }
    Error(_) -> unauthorized_response()
  }
}

pub fn optional_auth(
  req: Request(Connection),
  handler: fn(Request(Connection)) -> Response(ResponseData),
) -> Response(ResponseData) {
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

pub fn get_auth_context(req: Request(Connection)) -> Result(AuthContext, Nil) {
  case get_auth_header(req) {
    Ok(token) -> {
      case jwt.verify(token) {
        Ok(claims) -> {
          let user = user.User(
            id: claims.sub,
            email: claims.email,
            name: "Test User",
            password_hash: "",
            created_at: 0,
            updated_at: 0,
          )
          Ok(AuthContext(user: user, claims: claims))
        }
        Error(_) -> Error(Nil)
      }
    }
    Error(_) -> Error(Nil)
  }
}

fn get_auth_header(req: Request(Connection)) -> Result(String, Nil) {
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

fn unauthorized_response() -> Response(ResponseData) {
  let body = json.object([
    #("error", json.string("Unauthorized")),
    #("message", json.string("Invalid or missing authentication token")),
  ])
  
  response.new(401)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    mist.Bytes(
      bytes_builder.from_string(json.to_string(body))
    )
  )
}
`
      },
      {
        path: 'src/middleware/logger.gleam',
        content: `import gleam/http
import gleam/http/request.{type Request}
import gleam/io
import gleam/string
import gleam/int
import mist.{type Connection}

pub fn log(req: Request(Connection)) -> Nil {
  let method = req.method
    |> http.method_to_string
    |> string.uppercase
  
  let timestamp = current_timestamp()
  
  io.println(
    "[" <> int.to_string(timestamp) <> "] "
    <> method
    <> " "
    <> req.path
    <> " - "
    <> get_remote_ip(req)
  )
}

fn get_remote_ip(req: Request(Connection)) -> String {
  // In a real app, extract IP from connection
  "127.0.0.1"
}

fn current_timestamp() -> Int {
  // In a real app, use gleam_erlang for proper timestamp
  1234567890
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
        content: `import gleam/bytes_builder
import gleam/http/response.{type Response}
import gleam/http/request.{type Request}
import gleam/json
import gleam/int
import mist.{type Connection, type ResponseData}

pub fn check(_req: Request(Connection)) -> Response(ResponseData) {
  let health_data = json.object([
    #("status", json.string("healthy")),
    #("service", json.string("Gleam Mist API")),
    #("version", json.string("1.0.0")),
    #("timestamp", json.int(current_timestamp())),
  ])
  
  response.new(200)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    mist.Bytes(
      bytes_builder.from_string(json.to_string(health_data))
    )
  )
}

fn current_timestamp() -> Int {
  // In a real app, use gleam_erlang for proper timestamp
  1234567890
}
`
      },
      {
        path: 'src/controllers/auth.gleam',
        content: `import gleam/bytes_builder
import gleam/http/response.{type Response}
import gleam/http/request.{type Request}
import gleam/json
import gleam/dynamic
import gleam/result
import gleam/bit_array
import gleam/option.{None, Some}
import mist.{type Connection, type ResponseData}
import ${appName}/models/user
import ${appName}/utils/jwt
import ${appName}/utils/password
import ${appName}/middleware/cors

pub type RegisterRequest {
  RegisterRequest(email: String, password: String, name: String)
}

pub type LoginRequest {
  LoginRequest(email: String, password: String)
}

pub fn register(req: Request(Connection)) -> Response(ResponseData) {
  // Read request body
  case mist.read_body(req, 1024 * 1024) {
    Ok(body) -> {
      case bit_array.to_string(body) {
        Ok(body_string) -> {
          case json.decode(body_string, register_decoder) {
            Ok(register_req) -> {
              // Validate email
              case is_valid_email(register_req.email) {
                False -> {
                  bad_request("Invalid email format")
                }
                True -> {
                  // Hash password
                  let hashed = password.hash(register_req.password)
                  
                  // Create user
                  let new_user = user.new(
                    email: register_req.email,
                    name: register_req.name,
                    password_hash: hashed,
                  )
                  
                  // Generate tokens
                  let access_token = jwt.generate(new_user.id, new_user.email)
                  let refresh_token = jwt.generate_refresh(new_user.id)
                  
                  let response_body = json.object([
                    #("user", user.to_json(new_user)),
                    #("access_token", json.string(access_token)),
                    #("refresh_token", json.string(refresh_token)),
                  ])
                  
                  response.new(201)
                  |> response.set_header("content-type", "application/json")
                  |> response.set_body(
                    mist.Bytes(
                      bytes_builder.from_string(json.to_string(response_body))
                    )
                  )
                  |> cors.add_cors_headers(req)
                }
              }
            }
            Error(_) -> bad_request("Invalid request body")
          }
        }
        Error(_) -> bad_request("Invalid request encoding")
      }
    }
    Error(_) -> bad_request("Failed to read request body")
  }
}

pub fn login(req: Request(Connection)) -> Response(ResponseData) {
  case mist.read_body(req, 1024 * 1024) {
    Ok(body) -> {
      case bit_array.to_string(body) {
        Ok(body_string) -> {
          case json.decode(body_string, login_decoder) {
            Ok(login_req) -> {
              // In real app, fetch from database and verify password
              let user_data = user.User(
                id: "user_123",
                email: login_req.email,
                name: "Test User",
                password_hash: password.hash(login_req.password),
                created_at: current_timestamp(),
                updated_at: current_timestamp(),
              )
              
              // Generate tokens
              let access_token = jwt.generate(user_data.id, user_data.email)
              let refresh_token = jwt.generate_refresh(user_data.id)
              
              let response_body = json.object([
                #("user", user.to_json(user_data)),
                #("access_token", json.string(access_token)),
                #("refresh_token", json.string(refresh_token)),
              ])
              
              response.new(200)
              |> response.set_header("content-type", "application/json")
              |> response.set_body(
                mist.Bytes(
                  bytes_builder.from_string(json.to_string(response_body))
                )
              )
              |> cors.add_cors_headers(req)
            }
            Error(_) -> bad_request("Invalid request body")
          }
        }
        Error(_) -> bad_request("Invalid request encoding")
      }
    }
    Error(_) -> bad_request("Failed to read request body")
  }
}

pub fn refresh_token(req: Request(Connection)) -> Response(ResponseData) {
  case mist.read_body(req, 1024 * 1024) {
    Ok(body) -> {
      case bit_array.to_string(body) {
        Ok(body_string) -> {
          case json.decode(body_string, refresh_decoder) {
            Ok(refresh_req) -> {
              case jwt.verify(refresh_req) {
                Ok(claims) -> {
                  // Generate new tokens
                  let access_token = jwt.generate(claims.sub, claims.email)
                  let new_refresh = jwt.generate_refresh(claims.sub)
                  
                  let response_body = json.object([
                    #("access_token", json.string(access_token)),
                    #("refresh_token", json.string(new_refresh)),
                  ])
                  
                  response.new(200)
                  |> response.set_header("content-type", "application/json")
                  |> response.set_body(
                    mist.Bytes(
                      bytes_builder.from_string(json.to_string(response_body))
                    )
                  )
                  |> cors.add_cors_headers(req)
                }
                Error(_) -> unauthorized("Invalid refresh token")
              }
            }
            Error(_) -> bad_request("Invalid request body")
          }
        }
        Error(_) -> bad_request("Invalid request encoding")
      }
    }
    Error(_) -> bad_request("Failed to read request body")
  }
}

pub fn logout(_req: Request(Connection)) -> Response(ResponseData) {
  let response_body = json.object([
    #("message", json.string("Logged out successfully")),
  ])
  
  response.new(200)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    mist.Bytes(
      bytes_builder.from_string(json.to_string(response_body))
    )
  )
}

fn register_decoder(json_value: dynamic.Dynamic) -> Result(RegisterRequest, List(dynamic.DecodeError)) {
  dynamic.decode3(
    RegisterRequest,
    dynamic.field("email", dynamic.string),
    dynamic.field("password", dynamic.string),
    dynamic.field("name", dynamic.string),
  )(json_value)
}

fn login_decoder(json_value: dynamic.Dynamic) -> Result(LoginRequest, List(dynamic.DecodeError)) {
  dynamic.decode2(
    LoginRequest,
    dynamic.field("email", dynamic.string),
    dynamic.field("password", dynamic.string),
  )(json_value)
}

fn refresh_decoder(json_value: dynamic.Dynamic) -> Result(String, List(dynamic.DecodeError)) {
  dynamic.field("refresh_token", dynamic.string)(json_value)
}

fn bad_request(message: String) -> Response(ResponseData) {
  error_response(400, message)
}

fn unauthorized(message: String) -> Response(ResponseData) {
  error_response(401, message)
}

fn error_response(status: Int, message: String) -> Response(ResponseData) {
  let body = json.object([
    #("error", json.string(message)),
    #("status", json.int(status)),
  ])
  
  response.new(status)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    mist.Bytes(
      bytes_builder.from_string(json.to_string(body))
    )
  )
}

fn is_valid_email(email: String) -> Bool {
  case string.contains(email, "@") {
    True -> string.contains(email, ".")
    False -> False
  }
}

fn current_timestamp() -> Int {
  // In real app, use gleam_erlang for proper timestamp
  1234567890
}
`
      },
      {
        path: 'src/controllers/users.gleam',
        content: `import gleam/bytes_builder
import gleam/http/response.{type Response}
import gleam/http/request.{type Request}
import gleam/json
import gleam/dynamic
import gleam/list
import gleam/int
import gleam/option.{None, Some}
import gleam/result
import gleam/bit_array
import mist.{type Connection, type ResponseData}
import ${appName}/models/user
import ${appName}/middleware/auth
import ${appName}/middleware/cors

pub fn list_users(req: Request(Connection)) -> Response(ResponseData) {
  // In real app, parse query params and fetch from database
  let users = [
    user.User(
      id: "user_1",
      email: "user1@example.com",
      name: "User One",
      password_hash: "",
      created_at: 1234567890,
      updated_at: 1234567890,
    ),
    user.User(
      id: "user_2",
      email: "user2@example.com",
      name: "User Two",
      password_hash: "",
      created_at: 1234567890,
      updated_at: 1234567890,
    ),
  ]
  
  let response_body = json.object([
    #("users", json.array(users, user.to_json_public)),
    #("count", json.int(list.length(users))),
    #("limit", json.int(10)),
    #("offset", json.int(0)),
  ])
  
  response.new(200)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    mist.Bytes(
      bytes_builder.from_string(json.to_string(response_body))
    )
  )
  |> cors.add_cors_headers(req)
}

pub fn get_user(req: Request(Connection), id: String) -> Response(ResponseData) {
  // In real app, fetch from database
  let user_data = user.User(
    id: id,
    email: "user@example.com",
    name: "Test User",
    password_hash: "",
    created_at: 1234567890,
    updated_at: 1234567890,
  )
  
  let response_body = json.object([
    #("user", user.to_json_public(user_data)),
  ])
  
  response.new(200)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    mist.Bytes(
      bytes_builder.from_string(json.to_string(response_body))
    )
  )
  |> cors.add_cors_headers(req)
}

pub fn update_user(req: Request(Connection), id: String) -> Response(ResponseData) {
  case mist.read_body(req, 1024 * 1024) {
    Ok(body) -> {
      case bit_array.to_string(body) {
        Ok(body_string) -> {
          case json.decode(body_string, update_decoder) {
            Ok(name) -> {
              // In real app, update in database
              let user_data = user.User(
                id: id,
                email: "user@example.com",
                name: name,
                password_hash: "",
                created_at: 1234567890,
                updated_at: current_timestamp(),
              )
              
              let response_body = json.object([
                #("user", user.to_json_public(user_data)),
              ])
              
              response.new(200)
              |> response.set_header("content-type", "application/json")
              |> response.set_body(
                mist.Bytes(
                  bytes_builder.from_string(json.to_string(response_body))
                )
              )
              |> cors.add_cors_headers(req)
            }
            Error(_) -> bad_request("Invalid request body")
          }
        }
        Error(_) -> bad_request("Invalid request encoding")
      }
    }
    Error(_) -> bad_request("Failed to read request body")
  }
}

pub fn delete_user(req: Request(Connection), _id: String) -> Response(ResponseData) {
  // In real app, delete from database
  response.new(204)
  |> response.set_body(mist.Bytes(bytes_builder.new()))
  |> cors.add_cors_headers(req)
}

pub fn get_current_user(req: Request(Connection)) -> Response(ResponseData) {
  case auth.get_auth_context(req) {
    Ok(auth_context) -> {
      let response_body = json.object([
        #("user", user.to_json_public(auth_context.user)),
      ])
      
      response.new(200)
      |> response.set_header("content-type", "application/json")
      |> response.set_body(
        mist.Bytes(
          bytes_builder.from_string(json.to_string(response_body))
        )
      )
      |> cors.add_cors_headers(req)
    }
    Error(_) -> unauthorized("Authentication required")
  }
}

pub fn update_current_user(req: Request(Connection)) -> Response(ResponseData) {
  case auth.get_auth_context(req) {
    Ok(auth_context) -> update_user(req, auth_context.user.id)
    Error(_) -> unauthorized("Authentication required")
  }
}

fn update_decoder(json_value: dynamic.Dynamic) -> Result(String, List(dynamic.DecodeError)) {
  dynamic.field("name", dynamic.string)(json_value)
}

fn bad_request(message: String) -> Response(ResponseData) {
  error_response(400, message)
}

fn unauthorized(message: String) -> Response(ResponseData) {
  error_response(401, message)
}

fn error_response(status: Int, message: String) -> Response(ResponseData) {
  let body = json.object([
    #("error", json.string(message)),
    #("status", json.int(status)),
  ])
  
  response.new(status)
  |> response.set_header("content-type", "application/json")
  |> response.set_body(
    mist.Bytes(
      bytes_builder.from_string(json.to_string(body))
    )
  )
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
import gleam/int
import gleam/option.{type Option, None, Some}

pub type User {
  User(
    id: String,
    email: String,
    name: String,
    password_hash: String,
    created_at: Int,
    updated_at: Int,
  )
}

pub fn to_json(user: User) -> json.Json {
  json.object([
    #("id", json.string(user.id)),
    #("email", json.string(user.email)),
    #("name", json.string(user.name)),
    #("password_hash", json.string(user.password_hash)),
    #("created_at", json.int(user.created_at)),
    #("updated_at", json.int(user.updated_at)),
  ])
}

pub fn to_json_public(user: User) -> json.Json {
  // Exclude password_hash from public JSON
  json.object([
    #("id", json.string(user.id)),
    #("email", json.string(user.email)),
    #("name", json.string(user.name)),
    #("created_at", json.int(user.created_at)),
    #("updated_at", json.int(user.updated_at)),
  ])
}

pub fn new(email: String, name: String, password_hash: String) -> User {
  User(
    id: generate_id(),
    email: email,
    name: name,
    password_hash: password_hash,
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
import gleam/dynamic
import ${appName}/config/config

pub type Claims {
  Claims(sub: String, email: String, exp: Int, iat: Int)
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
  
  let header_b64 = base64.url_encode(bit_array.from_string(json.to_string(header)), False)
  let claims_b64 = base64.url_encode(bit_array.from_string(json.to_string(claims)), False)
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
  
  let header_b64 = base64.url_encode(bit_array.from_string(json.to_string(header)), False)
  let claims_b64 = base64.url_encode(bit_array.from_string(json.to_string(claims)), False)
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
          // Decode and parse claims
          case base64.url_decode(payload) {
            Ok(decoded) -> {
              case bit_array.to_string(decoded) {
                Ok(json_string) -> {
                  case json.decode(json_string, claims_decoder) {
                    Ok(claims) -> {
                      // Check expiration
                      case claims.exp > current_timestamp() {
                        True -> Ok(claims)
                        False -> Error("Token expired")
                      }
                    }
                    Error(_) -> Error("Invalid claims")
                  }
                }
                Error(_) -> Error("Invalid payload encoding")
              }
            }
            Error(_) -> Error("Invalid base64 payload")
          }
        }
        False -> Error("Invalid signature")
      }
    }
    _ -> Error("Invalid token format")
  }
}

fn claims_decoder(json_value: dynamic.Dynamic) -> Result(Claims, List(dynamic.DecodeError)) {
  dynamic.decode4(
    Claims,
    dynamic.field("sub", dynamic.string),
    dynamic.field("email", dynamic.string),
    dynamic.field("exp", dynamic.int),
    dynamic.field("iat", dynamic.int),
  )(json_value)
}

fn sign(message: String, secret: String) -> String {
  // In real app, use proper HMAC-SHA256
  // This is a simplified placeholder
  base64.url_encode(bit_array.from_string("signature_" <> message <> "_" <> secret), False)
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
import gleam/int

pub fn hash(password: String) -> String {
  // In real app, use argon2 for proper password hashing
  // This is a simplified version
  let salt = generate_salt()
  let salted = password <> salt
  
  base64.encode(bit_array.from_string(salted), False) <> ":" <> salt
}

pub fn verify(password: String, hash: String) -> Bool {
  case string.split(hash, ":") {
    [hashed_part, salt] -> {
      let salted = password <> salt
      let computed = base64.encode(bit_array.from_string(salted), False)
      computed == hashed_part
    }
    _ -> False
  }
}

pub fn generate_salt() -> String {
  // In real app, generate cryptographically secure random salt
  "salt_" <> int.to_string(random_int())
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
import gleam/string
import gleam/list
import ${appName}/utils/jwt
import ${appName}/utils/password

pub fn main() {
  gleeunit.main()
}

pub fn password_hashing_test() {
  let pass = "SecurePassword123!"
  let hash = password.hash(pass)
  
  // Hash should not equal password
  hash
  |> should.not_equal(pass)
  
  // Should contain salt separator
  string.contains(hash, ":")
  |> should.be_true
  
  // Should verify correctly
  password.verify(pass, hash)
  |> should.be_true
  
  // Wrong password should not verify
  password.verify("wrong_password", hash)
  |> should.be_false
}

pub fn jwt_generation_test() {
  let user_id = "user_123"
  let email = "test@example.com"
  
  let token = jwt.generate(user_id, email)
  
  // Should contain two dots
  string.split(token, ".")
  |> list.length
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
      
      // Should have future expiration
      claims.exp
      |> should.be_ok
    }
    Error(_) -> {
      should.fail()
    }
  }
}
`
      },
      {
        path: 'test/user_test.gleam',
        content: `import gleeunit
import gleeunit/should
import gleam/string
import ${appName}/models/user

pub fn main() {
  gleeunit.main()
}

pub fn user_creation_test() {
  let email = "test@example.com"
  let name = "Test User"
  let password_hash = "hashed_password"
  
  let new_user = user.new(email, name, password_hash)
  
  new_user.email
  |> should.equal(email)
  
  new_user.name
  |> should.equal(name)
  
  new_user.password_hash
  |> should.equal(password_hash)
  
  // Should have generated ID
  string.starts_with(new_user.id, "user_")
  |> should.be_true
  
  // Should have timestamps
  new_user.created_at
  |> should.not_equal(0)
  
  new_user.updated_at
  |> should.equal(new_user.created_at)
}

pub fn user_json_test() {
  let test_user = user.User(
    id: "user_123",
    email: "test@example.com",
    name: "Test User",
    password_hash: "secret_hash",
    created_at: 1234567890,
    updated_at: 1234567890,
  )
  
  // Public JSON should not include password hash
  let public_json = user.to_json_public(test_user)
  
  // Convert to string and check
  let json_string = json.to_string(public_json)
  
  string.contains(json_string, "test@example.com")
  |> should.be_true
  
  string.contains(json_string, "secret_hash")
  |> should.be_false
}
`
      }
    ];
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Create static file directories
    await fs.mkdir(path.join(projectPath, 'priv', 'static', 'css'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'priv', 'static', 'js'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'priv', 'static', 'images'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'priv', 'static', 'docs'), { recursive: true });

    // Create a simple static HTML file
    await fs.writeFile(path.join(projectPath, 'priv', 'static', 'docs', 'api.html'), `<!DOCTYPE html>
<html>
<head>
    <title>Gleam Mist API Documentation</title>
    <style>
        body { font-family: system-ui; max-width: 800px; margin: 0 auto; padding: 20px; }
        h1 { color: #FF3E7C; }
        .endpoint { background: #f5f5f5; padding: 10px; margin: 10px 0; border-radius: 4px; }
        code { background: #e0e0e0; padding: 2px 4px; border-radius: 2px; }
    </style>
</head>
<body>
    <h1>Gleam Mist API Documentation</h1>
    <h2>Authentication</h2>
    <div class="endpoint">
        <h3>POST /api/auth/register</h3>
        <p>Register a new user account.</p>
        <pre>
{
  "email": "user@example.com",
  "password": "securepassword",
  "name": "User Name"
}
        </pre>
    </div>
    <div class="endpoint">
        <h3>POST /api/auth/login</h3>
        <p>Login with email and password.</p>
        <pre>
{
  "email": "user@example.com",
  "password": "securepassword"
}
        </pre>
    </div>
    <h2>WebSocket</h2>
    <div class="endpoint">
        <h3>WS /api/ws</h3>
        <p>WebSocket endpoint for real-time communication.</p>
    </div>
</body>
</html>`);

    // Create development and build scripts
    await fs.mkdir(path.join(projectPath, 'scripts'), { recursive: true });
    
    await fs.writeFile(path.join(projectPath, 'scripts', 'dev.sh'), `#!/bin/bash

echo "Starting Gleam Mist development server..."

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

echo "Building Gleam Mist application..."

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