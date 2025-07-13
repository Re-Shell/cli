/**
 * Zap Framework Template Generator
 * Blazingly fast web framework for Zig
 */

import { ZigBackendGenerator } from './zig-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class ZapGenerator extends ZigBackendGenerator {
  constructor() {
    super('Zap');
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Update build.zig.zon with Zap dependency
    await this.updateBuildZon(projectPath);

    // Generate main application
    await this.generateMainApp(projectPath, options);

    // Generate server setup
    await this.generateServer(projectPath);

    // Generate routes
    await this.generateRoutes(projectPath);

    // Generate handlers
    await this.generateHandlers(projectPath);

    // Generate middleware
    await this.generateMiddleware(projectPath);

    // Generate models
    await this.generateModels(projectPath);

    // Generate utilities
    await this.generateUtilities(projectPath);

    // Generate configuration
    await this.generateConfig(projectPath, options);

    // Generate authentication
    await this.generateAuth(projectPath);

    // Generate WebSocket support
    await this.generateWebSocket(projectPath);
  }

  private async updateBuildZon(projectPath: string): Promise<void> {
    const buildZonPath = path.join(projectPath, 'build.zig.zon');
    const buildZonContent = await fs.readFile(buildZonPath, 'utf-8');
    
    // Update with Zap dependency
    const updatedContent = buildZonContent.replace(
      '.dependencies = .{',
      `.dependencies = .{
        .zap = .{
            .url = "https://github.com/zigzap/zap/archive/refs/tags/v0.5.0.tar.gz",
            .hash = "1220abc123def456789012345678901234567890abcdef1234567890abcdef12",
        },`
    );

    await fs.writeFile(buildZonPath, updatedContent);

    // Update build.zig to include Zap
    const buildZigPath = path.join(projectPath, 'build.zig');
    const buildZigContent = await fs.readFile(buildZigPath, 'utf-8');
    
    const updatedBuildZig = buildZigContent.replace(
      '// Add dependencies',
      `// Add dependencies
    const zap = b.dependency("zap", .{
        .target = target,
        .optimize = optimize,
    });
    exe.root_module.addImport("zap", zap.module("zap"));`
    );

    await fs.writeFile(buildZigPath, updatedBuildZig);
  }

  private async generateMainApp(projectPath: string, options: any): Promise<void> {
    const mainContent = `const std = @import("std");
const zap = @import("zap");
const server = @import("server.zig");
const config = @import("config/config.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Load configuration
    const app_config = try config.load(allocator);
    defer app_config.deinit();

    // Initialize and start server
    var app_server = try server.Server.init(allocator, app_config);
    defer app_server.deinit();

    std.log.info("⚡ Zap server starting on http://{s}:{d}", .{ app_config.host, app_config.port });
    
    try app_server.listen();
}

test "main tests" {
    const testing = std.testing;
    try testing.expect(true);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'main.zig'),
      mainContent
    );
  }

  private async generateServer(projectPath: string): Promise<void> {
    const serverContent = `const std = @import("std");
const zap = @import("zap");
const routes = @import("routes.zig");
const middleware = @import("middleware/middleware.zig");
const Config = @import("config/config.zig").Config;

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: Config,
    listener: zap.HttpListener,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Server {
        // Initialize Zap listener
        const listener = zap.HttpListener.init(.{
            .port = config.port,
            .on_request = onRequest,
            .log = true,
            .public_folder = "static",
            .max_clients = 100000,
            .max_body_size = 100 * 1024 * 1024, // 100MB
        });

        return Server{
            .allocator = allocator,
            .config = config,
            .listener = listener,
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit();
    }

    pub fn listen(self: *Server) !void {
        // Set up routes
        try routes.setupRoutes(&self.listener);

        // Start listening
        try self.listener.listen();

        std.log.info("Zap server listening on port {d}", .{self.config.port});

        // Keep the server running
        zap.start(.{
            .threads = 4,
            .workers = 2,
        });
    }

    fn onRequest(r: zap.Request) void {
        // Global request handler
        if (r.path) |path| {
            std.log.info("{s} {s}", .{ @tagName(r.method), path });
        }
    }
};

test "server initialization" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const config = Config{
        .host = "127.0.0.1",
        .port = 8080,
        .allocator = allocator,
    };

    var server = try Server.init(allocator, config);
    defer server.deinit();

    try testing.expect(server.config.port == 8080);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'server.zig'),
      serverContent
    );
  }

  private async generateRoutes(projectPath: string): Promise<void> {
    const routesContent = `const std = @import("std");
const zap = @import("zap");
const handlers = @import("handlers/handlers.zig");
const middleware = @import("middleware/middleware.zig");

pub fn setupRoutes(listener: *zap.HttpListener) !void {
    // Health check routes
    listener.get("/health", handlers.health.handleHealth);
    listener.get("/ready", handlers.health.handleReady);

    // Auth routes
    listener.post("/api/v1/auth/register", handlers.auth.handleRegister);
    listener.post("/api/v1/auth/login", handlers.auth.handleLogin);
    listener.post("/api/v1/auth/refresh", handlers.auth.handleRefresh);
    listener.post("/api/v1/auth/logout", handlers.auth.handleLogout);

    // User routes with authentication middleware
    const authenticated = zap.Router.init(listener.allocator);
    authenticated.use(middleware.authenticate);
    
    authenticated.get("/api/v1/users", handlers.users.handleList);
    authenticated.get("/api/v1/users/me", handlers.users.handleGetCurrent);
    authenticated.get("/api/v1/users/:id", handlers.users.handleGetById);
    authenticated.put("/api/v1/users/:id", handlers.users.handleUpdate);
    authenticated.delete("/api/v1/users/:id", handlers.users.handleDelete);

    listener.use(authenticated);

    // WebSocket route
    listener.websocket("/ws", handlers.websocket.handleWebSocket);

    // Static files (handled by Zap automatically from public_folder)

    // 404 handler
    listener.notFound(handle404);
}

fn handle404(r: zap.Request) void {
    r.setStatus(.not_found);
    r.sendJson(.{
        .error = "Not Found",
        .message = "The requested resource was not found",
        .path = r.path,
    }) catch |err| {
        std.log.err("Failed to send 404 response: {}", .{err});
    };
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'routes.zig'),
      routesContent
    );
  }

  private async generateHandlers(projectPath: string): Promise<void> {
    const handlersDir = path.join(projectPath, 'src', 'handlers');

    // Handlers index
    const handlersIndexContent = `pub const health = @import("health.zig");
pub const auth = @import("auth.zig");
pub const users = @import("users.zig");
pub const websocket = @import("websocket.zig");
`;

    await fs.writeFile(
      path.join(handlersDir, 'handlers.zig'),
      handlersIndexContent
    );

    // Health handlers
    const healthHandlersContent = `const std = @import("std");
const zap = @import("zap");

pub fn handleHealth(r: zap.Request) void {
    r.sendJson(.{
        .status = "healthy",
        .timestamp = std.time.timestamp(),
        .version = "1.0.0",
        .service = "zap-service",
        .uptime = getUptime(),
    }) catch |err| {
        std.log.err("Failed to send health response: {}", .{err});
    };
}

pub fn handleReady(r: zap.Request) void {
    // Check dependencies
    const db_ready = checkDatabase();
    const cache_ready = checkCache();
    
    const all_ready = db_ready and cache_ready;
    
    r.setStatus(if (all_ready) .ok else .service_unavailable);
    r.sendJson(.{
        .status = if (all_ready) "ready" else "not ready",
        .checks = .{
            .database = if (db_ready) "ok" else "error",
            .cache = if (cache_ready) "ok" else "error",
        },
    }) catch |err| {
        std.log.err("Failed to send ready response: {}", .{err});
    };
}

fn getUptime() f64 {
    // Mock uptime calculation
    return 3600.0; // 1 hour
}

fn checkDatabase() bool {
    // TODO: Implement actual database check
    return true;
}

fn checkCache() bool {
    // TODO: Implement actual cache check
    return true;
}
`;

    await fs.writeFile(
      path.join(handlersDir, 'health.zig'),
      healthHandlersContent
    );

    // Auth handlers
    const authHandlersContent = `const std = @import("std");
const zap = @import("zap");
const auth_service = @import("../utils/auth.zig");
const models = @import("../models/models.zig");
const validation = @import("../utils/validation.zig");

pub fn handleRegister(r: zap.Request) void {
    const body = r.body orelse {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Bad Request",
            .message = "Request body is required",
        }) catch {};
        return;
    };

    // Parse request
    const parsed = std.json.parseFromSlice(
        models.RegisterRequest,
        r.allocator,
        body,
        .{}
    ) catch {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Bad Request",
            .message = "Invalid JSON",
        }) catch {};
        return;
    };
    defer parsed.deinit();

    const req = parsed.value;

    // Validate
    if (!validation.isValidEmail(req.email)) {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Validation Error",
            .message = "Invalid email format",
        }) catch {};
        return;
    }

    if (!validation.isValidPassword(req.password)) {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Validation Error",
            .message = "Password must be at least 6 characters",
        }) catch {};
        return;
    }

    // Hash password
    const hashed_password = auth_service.hashPassword(r.allocator, req.password) catch {
        r.setStatus(.internal_server_error);
        r.sendJson(.{
            .error = "Internal Server Error",
            .message = "Failed to process request",
        }) catch {};
        return;
    };
    defer r.allocator.free(hashed_password);

    // Create user (mock)
    const user = models.User{
        .id = "user123",
        .email = req.email,
        .name = req.name,
        .role = "user",
    };

    // Generate token
    const token = auth_service.generateToken(
        r.allocator,
        user.id,
        user.email,
        user.role
    ) catch {
        r.setStatus(.internal_server_error);
        r.sendJson(.{
            .error = "Internal Server Error",
            .message = "Failed to generate token",
        }) catch {};
        return;
    };
    defer r.allocator.free(token);

    r.setStatus(.created);
    r.sendJson(.{
        .user = user,
        .token = token,
    }) catch {};
}

pub fn handleLogin(r: zap.Request) void {
    const body = r.body orelse {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Bad Request",
            .message = "Request body is required",
        }) catch {};
        return;
    };

    // Parse request
    const parsed = std.json.parseFromSlice(
        models.LoginRequest,
        r.allocator,
        body,
        .{}
    ) catch {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Bad Request",
            .message = "Invalid JSON",
        }) catch {};
        return;
    };
    defer parsed.deinit();

    const req = parsed.value;

    // Mock authentication
    const user = models.User{
        .id = "user123",
        .email = req.email,
        .name = "Test User",
        .role = "user",
    };

    // Generate token
    const token = auth_service.generateToken(
        r.allocator,
        user.id,
        user.email,
        user.role
    ) catch {
        r.setStatus(.internal_server_error);
        r.sendJson(.{
            .error = "Internal Server Error",
            .message = "Failed to generate token",
        }) catch {};
        return;
    };
    defer r.allocator.free(token);

    r.sendJson(.{
        .user = user,
        .token = token,
    }) catch {};
}

pub fn handleRefresh(r: zap.Request) void {
    const auth_header = r.getHeader("authorization") orelse {
        r.setStatus(.unauthorized);
        r.sendJson(.{
            .error = "Unauthorized",
            .message = "Missing authorization header",
        }) catch {};
        return;
    };

    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
        r.setStatus(.unauthorized);
        r.sendJson(.{
            .error = "Unauthorized",
            .message = "Invalid authorization header",
        }) catch {};
        return;
    }

    const token = auth_header[7..];
    
    // Verify token
    const payload = auth_service.verifyToken(r.allocator, token) catch {
        r.setStatus(.unauthorized);
        r.sendJson(.{
            .error = "Unauthorized",
            .message = "Invalid token",
        }) catch {};
        return;
    };

    // Generate new token
    const new_token = auth_service.generateToken(
        r.allocator,
        payload.sub,
        payload.email,
        payload.role
    ) catch {
        r.setStatus(.internal_server_error);
        r.sendJson(.{
            .error = "Internal Server Error",
            .message = "Failed to generate token",
        }) catch {};
        return;
    };
    defer r.allocator.free(new_token);

    r.sendJson(.{ .token = new_token }) catch {};
}

pub fn handleLogout(r: zap.Request) void {
    // In production, blacklist token
    r.sendJson(.{
        .message = "Logged out successfully",
    }) catch {};
}
`;

    await fs.writeFile(
      path.join(handlersDir, 'auth.zig'),
      authHandlersContent
    );

    // Users handlers
    const usersHandlersContent = `const std = @import("std");
const zap = @import("zap");
const models = @import("../models/models.zig");
const auth = @import("../utils/auth.zig");

pub fn handleList(r: zap.Request) void {
    // Check authorization
    if (!auth.hasRole(r, "admin")) {
        r.setStatus(.forbidden);
        r.sendJson(.{
            .error = "Forbidden",
            .message = "Insufficient permissions",
        }) catch {};
        return;
    }

    // Parse query parameters
    const page_str = r.getQuery("page") orelse "1";
    const limit_str = r.getQuery("limit") orelse "10";
    
    const page = std.fmt.parseInt(u32, page_str, 10) catch 1;
    const limit = std.fmt.parseInt(u32, limit_str, 10) catch 10;

    // Mock user list
    const users = [_]models.User{
        .{ .id = "1", .email = "user1@example.com", .name = "User One", .role = "user" },
        .{ .id = "2", .email = "user2@example.com", .name = "User Two", .role = "admin" },
    };

    r.sendJson(.{
        .data = users,
        .meta = .{
            .page = page,
            .limit = limit,
            .total = users.len,
            .total_pages = (users.len + limit - 1) / limit,
        },
    }) catch {};
}

pub fn handleGetCurrent(r: zap.Request) void {
    const user = auth.getCurrentUser(r) orelse {
        r.setStatus(.unauthorized);
        r.sendJson(.{
            .error = "Unauthorized",
            .message = "Not authenticated",
        }) catch {};
        return;
    };

    r.sendJson(user) catch {};
}

pub fn handleGetById(r: zap.Request) void {
    const id = r.getParam("id") orelse {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Bad Request",
            .message = "User ID is required",
        }) catch {};
        return;
    };

    const current_user = auth.getCurrentUser(r) orelse {
        r.setStatus(.unauthorized);
        r.sendJson(.{
            .error = "Unauthorized",
            .message = "Not authenticated",
        }) catch {};
        return;
    };

    // Check permissions
    if (!std.mem.eql(u8, current_user.id, id) and !std.mem.eql(u8, current_user.role, "admin")) {
        r.setStatus(.forbidden);
        r.sendJson(.{
            .error = "Forbidden",
            .message = "Access denied",
        }) catch {};
        return;
    }

    // Mock user lookup
    const user = models.User{
        .id = id,
        .email = "user@example.com",
        .name = "Test User",
        .role = "user",
    };

    r.sendJson(user) catch {};
}

pub fn handleUpdate(r: zap.Request) void {
    const id = r.getParam("id") orelse {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Bad Request",
            .message = "User ID is required",
        }) catch {};
        return;
    };

    const body = r.body orelse {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Bad Request",
            .message = "Request body is required",
        }) catch {};
        return;
    };

    // Parse update request
    const parsed = std.json.parseFromSlice(
        models.UpdateUserRequest,
        r.allocator,
        body,
        .{}
    ) catch {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Bad Request",
            .message = "Invalid JSON",
        }) catch {};
        return;
    };
    defer parsed.deinit();

    const req = parsed.value;

    // Mock user update
    const updated_user = models.User{
        .id = id,
        .email = req.email orelse "user@example.com",
        .name = req.name orelse "Updated User",
        .role = "user",
    };

    r.sendJson(updated_user) catch {};
}

pub fn handleDelete(r: zap.Request) void {
    const id = r.getParam("id") orelse {
        r.setStatus(.bad_request);
        r.sendJson(.{
            .error = "Bad Request",
            .message = "User ID is required",
        }) catch {};
        return;
    };

    // Check authorization
    if (!auth.hasRole(r, "admin")) {
        r.setStatus(.forbidden);
        r.sendJson(.{
            .error = "Forbidden",
            .message = "Insufficient permissions",
        }) catch {};
        return;
    }

    // Mock deletion
    _ = id;

    r.setStatus(.no_content);
    r.send("") catch {};
}
`;

    await fs.writeFile(
      path.join(handlersDir, 'users.zig'),
      usersHandlersContent
    );

    // WebSocket handler
    const websocketHandlerContent = `const std = @import("std");
const zap = @import("zap");

pub fn handleWebSocket(r: zap.Request) void {
    r.upgradeToWebsocket(&Context{
        .allocator = r.allocator,
    }, &callbacks) catch |err| {
        std.log.err("Failed to upgrade to WebSocket: {}", .{err});
        r.setStatus(.bad_request);
        r.send("WebSocket upgrade failed") catch {};
    };
}

const Context = struct {
    allocator: std.mem.Allocator,
};

const callbacks = zap.WebSocketCallbacks{
    .on_open = onOpen,
    .on_close = onClose,
    .on_message = onMessage,
};

fn onOpen(ctx: *Context, ws: *zap.WebSocket) void {
    std.log.info("WebSocket connection opened", .{});
    
    ws.send(.{
        .type = "connected",
        .message = "Welcome to Zap WebSocket!",
        .timestamp = std.time.timestamp(),
    }, .text) catch |err| {
        std.log.err("Failed to send welcome message: {}", .{err});
    };
}

fn onClose(ctx: *Context, ws: *zap.WebSocket) void {
    _ = ctx;
    _ = ws;
    std.log.info("WebSocket connection closed", .{});
}

fn onMessage(ctx: *Context, ws: *zap.WebSocket, message: []const u8, is_text: bool) void {
    if (is_text) {
        std.log.info("Received text message: {s}", .{message});
        
        // Echo the message back
        const response = std.fmt.allocPrint(ctx.allocator, 
            \\{{"type":"echo","message":"{s}","timestamp":{}}}
        , .{ message, std.time.timestamp() }) catch {
            std.log.err("Failed to allocate response", .{});
            return;
        };
        defer ctx.allocator.free(response);
        
        ws.send(response, .text) catch |err| {
            std.log.err("Failed to send echo: {}", .{err});
        };
    } else {
        std.log.info("Received binary message of {} bytes", .{message.len});
    }
}
`;

    await fs.writeFile(
      path.join(handlersDir, 'websocket.zig'),
      websocketHandlerContent
    );
  }

  private async generateMiddleware(projectPath: string): Promise<void> {
    const middlewareDir = path.join(projectPath, 'src', 'middleware');

    // Middleware module
    const middlewareContent = `const std = @import("std");
const zap = @import("zap");
const auth = @import("../utils/auth.zig");

pub fn cors(r: *zap.Request) void {
    r.setHeader("Access-Control-Allow-Origin", "*") catch {};
    r.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS") catch {};
    r.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization") catch {};
    
    if (r.method == .OPTIONS) {
        r.setStatus(.no_content);
        r.send("") catch {};
    }
}

pub fn logger(r: *zap.Request) void {
    const timestamp = std.time.timestamp();
    const method = @tagName(r.method);
    const path = r.path orelse "unknown";
    
    std.log.info("[{d}] {s} {s}", .{ timestamp, method, path });
}

pub fn authenticate(r: *zap.Request) bool {
    const auth_header = r.getHeader("authorization") orelse {
        r.setStatus(.unauthorized);
        r.sendJson(.{
            .error = "Unauthorized",
            .message = "Missing authorization header",
        }) catch {};
        return false;
    };

    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
        r.setStatus(.unauthorized);
        r.sendJson(.{
            .error = "Unauthorized",
            .message = "Invalid authorization format",
        }) catch {};
        return false;
    }

    const token = auth_header[7..];
    
    // Verify token
    _ = auth.verifyToken(r.allocator, token) catch {
        r.setStatus(.unauthorized);
        r.sendJson(.{
            .error = "Unauthorized",
            .message = "Invalid token",
        }) catch {};
        return false;
    };

    return true;
}

pub fn rateLimiter(r: *zap.Request) bool {
    // Simple rate limiting
    const ip = r.getHeader("x-forwarded-for") orelse 
               r.getHeader("x-real-ip") orelse 
               "unknown";
    
    // In production, implement proper rate limiting with storage
    _ = ip;
    
    const rate_limit = 100;
    const requests_made = 50; // Mock
    
    if (requests_made >= rate_limit) {
        r.setStatus(.too_many_requests);
        r.setHeader("X-RateLimit-Limit", "100") catch {};
        r.setHeader("X-RateLimit-Remaining", "0") catch {};
        r.sendJson(.{
            .error = "Too Many Requests",
            .message = "Rate limit exceeded",
        }) catch {};
        return false;
    }
    
    r.setHeader("X-RateLimit-Limit", "100") catch {};
    r.setHeader("X-RateLimit-Remaining", 
        try std.fmt.allocPrint(r.allocator, "{d}", .{rate_limit - requests_made})
    ) catch {};
    
    return true;
}

// Middleware chain
pub fn chain(middlewares: []const fn(*zap.Request) bool) fn(*zap.Request) void {
    return struct {
        fn handle(r: *zap.Request) void {
            for (middlewares) |mw| {
                if (!mw(r)) {
                    return;
                }
            }
        }
    }.handle;
}
`;

    await fs.writeFile(
      path.join(middlewareDir, 'middleware.zig'),
      middlewareContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    const modelsDir = path.join(projectPath, 'src', 'models');

    // Models
    const modelsContent = `const std = @import("std");

// User model
pub const User = struct {
    id: []const u8,
    email: []const u8,
    name: []const u8,
    role: []const u8,
    created_at: ?i64 = null,
    updated_at: ?i64 = null,
};

// Auth request models
pub const RegisterRequest = struct {
    email: []const u8,
    password: []const u8,
    name: []const u8,
};

pub const LoginRequest = struct {
    email: []const u8,
    password: []const u8,
};

// User request models
pub const UpdateUserRequest = struct {
    email: ?[]const u8 = null,
    name: ?[]const u8 = null,
};

// Response models
pub const ErrorResponse = struct {
    error: []const u8,
    message: []const u8,
    details: ?[]const u8 = null,
};

pub const PaginatedResponse = struct {
    data: []const User,
    meta: struct {
        page: u32,
        limit: u32,
        total: u32,
        total_pages: u32,
    },
};

// Token payload
pub const TokenPayload = struct {
    sub: []const u8, // user id
    email: []const u8,
    role: []const u8,
    exp: i64, // expiration timestamp
    iat: i64, // issued at timestamp
};

// Session model
pub const Session = struct {
    id: []const u8,
    user_id: []const u8,
    token: []const u8,
    expires_at: i64,
    created_at: i64,
};

// WebSocket message
pub const WebSocketMessage = struct {
    type: []const u8,
    payload: std.json.Value,
    timestamp: i64,
};
`;

    await fs.writeFile(
      path.join(modelsDir, 'models.zig'),
      modelsContent
    );
  }

  private async generateUtilities(projectPath: string): Promise<void> {
    const utilsDir = path.join(projectPath, 'src', 'utils');

    // Enhanced validation utilities
    const validationContent = `const std = @import("std");

pub fn isValidEmail(email: []const u8) bool {
    if (email.len < 3 or email.len > 320) return false;
    
    const at_index = std.mem.indexOf(u8, email, "@") orelse return false;
    const dot_index = std.mem.lastIndexOf(u8, email, ".") orelse return false;
    
    // Basic validation rules
    if (at_index == 0 or at_index == email.len - 1) return false;
    if (dot_index <= at_index + 1 or dot_index == email.len - 1) return false;
    
    // Check for multiple @ symbols
    const at_count = std.mem.count(u8, email, "@");
    if (at_count != 1) return false;
    
    return true;
}

pub fn isValidPassword(password: []const u8) bool {
    return password.len >= 6 and password.len <= 128;
}

pub fn isValidUsername(username: []const u8) bool {
    if (username.len < 3 or username.len > 30) return false;
    
    for (username) |char| {
        if (!std.ascii.isAlphanumeric(char) and char != '_' and char != '-') {
            return false;
        }
    }
    
    return true;
}

pub fn sanitizeInput(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();
    
    for (input) |char| {
        switch (char) {
            '<' => try result.appendSlice("&lt;"),
            '>' => try result.appendSlice("&gt;"),
            '"' => try result.appendSlice("&quot;"),
            '\'' => try result.appendSlice("&#x27;"),
            '&' => try result.appendSlice("&amp;"),
            else => try result.append(char),
        }
    }
    
    return result.toOwnedSlice();
}

pub fn validatePhoneNumber(phone: []const u8) bool {
    if (phone.len < 10 or phone.len > 15) return false;
    
    for (phone) |char| {
        if (!std.ascii.isDigit(char) and char != '+' and char != '-' and char != ' ') {
            return false;
        }
    }
    
    return true;
}

test "email validation" {
    const testing = std.testing;
    
    try testing.expect(isValidEmail("user@example.com"));
    try testing.expect(isValidEmail("test.user+tag@sub.example.co.uk"));
    try testing.expect(!isValidEmail("invalid.email"));
    try testing.expect(!isValidEmail("@example.com"));
    try testing.expect(!isValidEmail("user@"));
    try testing.expect(!isValidEmail("user@@example.com"));
}

test "password validation" {
    const testing = std.testing;
    
    try testing.expect(isValidPassword("secure123"));
    try testing.expect(!isValidPassword("12345"));
    try testing.expect(!isValidPassword("a" ** 129));
}

test "username validation" {
    const testing = std.testing;
    
    try testing.expect(isValidUsername("john_doe"));
    try testing.expect(isValidUsername("user-123"));
    try testing.expect(!isValidUsername("jo"));
    try testing.expect(!isValidUsername("user@name"));
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'validation.zig'),
      validationContent
    );

    // Response utilities
    const responseUtilsContent = `const std = @import("std");
const zap = @import("zap");

pub fn sendError(r: *zap.Request, status: zap.StatusCode, code: []const u8, message: []const u8) void {
    r.setStatus(status);
    r.sendJson(.{
        .error = .{
            .code = code,
            .message = message,
            .timestamp = std.time.timestamp(),
        },
    }) catch |err| {
        std.log.err("Failed to send error response: {}", .{err});
    };
}

pub fn sendSuccess(r: *zap.Request, data: anytype) void {
    r.sendJson(.{
        .success = true,
        .data = data,
        .timestamp = std.time.timestamp(),
    }) catch |err| {
        std.log.err("Failed to send success response: {}", .{err});
    };
}

pub fn sendPaginated(
    r: *zap.Request,
    data: anytype,
    page: u32,
    limit: u32,
    total: u32,
) void {
    r.sendJson(.{
        .data = data,
        .meta = .{
            .page = page,
            .limit = limit,
            .total = total,
            .total_pages = (total + limit - 1) / limit,
            .has_next = page * limit < total,
            .has_prev = page > 1,
        },
    }) catch |err| {
        std.log.err("Failed to send paginated response: {}", .{err});
    };
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'response.zig'),
      responseUtilsContent
    );
  }

  private async generateConfig(projectPath: string, options: any): Promise<void> {
    const configDir = path.join(projectPath, 'src', 'config');

    // Enhanced configuration
    const configContent = `const std = @import("std");

pub const Config = struct {
    allocator: std.mem.Allocator,
    
    // Server
    host: []const u8,
    port: u16,
    workers: u32,
    max_connections: u32,
    
    // Security
    jwt_secret: []const u8,
    bcrypt_rounds: u32,
    cors_origin: []const u8,
    
    // Database
    database_url: []const u8,
    db_pool_size: u32,
    
    // Redis
    redis_url: ?[]const u8,
    
    // Logging
    log_level: []const u8,
    log_format: []const u8,
    
    // Rate limiting
    rate_limit_window: u64, // milliseconds
    rate_limit_max: u32,
    
    pub fn deinit(self: Config) void {
        _ = self;
    }
};

pub fn load(allocator: std.mem.Allocator) !Config {
    const env = std.process.getEnvMap(allocator) catch std.process.EnvMap.init(allocator);
    defer env.deinit();
    
    return Config{
        .allocator = allocator,
        
        // Server
        .host = env.get("HOST") orelse "0.0.0.0",
        .port = try parsePort(env.get("PORT") orelse "${options.port || 8080}"),
        .workers = try parseU32(env.get("WORKERS") orelse "4"),
        .max_connections = try parseU32(env.get("MAX_CONNECTIONS") orelse "100000"),
        
        // Security
        .jwt_secret = env.get("JWT_SECRET") orelse "your-secret-key-change-in-production",
        .bcrypt_rounds = try parseU32(env.get("BCRYPT_ROUNDS") orelse "10"),
        .cors_origin = env.get("CORS_ORIGIN") orelse "*",
        
        // Database
        .database_url = env.get("DATABASE_URL") orelse "sqlite://./data/app.db",
        .db_pool_size = try parseU32(env.get("DB_POOL_SIZE") orelse "10"),
        
        // Redis
        .redis_url = env.get("REDIS_URL"),
        
        // Logging
        .log_level = env.get("LOG_LEVEL") orelse "info",
        .log_format = env.get("LOG_FORMAT") orelse "json",
        
        // Rate limiting
        .rate_limit_window = try parseU64(env.get("RATE_LIMIT_WINDOW") orelse "60000"),
        .rate_limit_max = try parseU32(env.get("RATE_LIMIT_MAX") orelse "100"),
    };
}

fn parsePort(port_str: []const u8) !u16 {
    return std.fmt.parseInt(u16, port_str, 10);
}

fn parseU32(str: []const u8) !u32 {
    return std.fmt.parseInt(u32, str, 10);
}

fn parseU64(str: []const u8) !u64 {
    return std.fmt.parseInt(u64, str, 10);
}

pub fn validate(config: Config) !void {
    if (config.port == 0) {
        return error.InvalidPort;
    }
    
    if (config.jwt_secret.len < 32) {
        std.log.warn("JWT secret is too short. Use at least 32 characters in production.", .{});
    }
    
    if (std.mem.eql(u8, config.jwt_secret, "your-secret-key-change-in-production")) {
        std.log.warn("Using default JWT secret. Change this in production!", .{});
    }
}

test "config loading and validation" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const config = try load(allocator);
    defer config.deinit();
    
    try testing.expect(config.port > 0);
    try testing.expect(config.workers > 0);
    try validate(config);
}
`;

    await fs.writeFile(
      path.join(configDir, 'config.zig'),
      configContent
    );
  }

  private async generateAuth(projectPath: string): Promise<void> {
    const authContent = `const std = @import("std");
const zap = @import("zap");
const models = @import("../models/models.zig");

// Constants
const SALT_ROUNDS = 10;
const TOKEN_EXPIRY = 7 * 24 * 60 * 60; // 7 days in seconds

// Bcrypt-like password hashing (simplified for demo)
pub fn hashPassword(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    // In production, use proper bcrypt implementation
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    
    // Add salt
    const salt = "static-salt-change-in-production";
    hasher.update(salt);
    hasher.update(password);
    
    var hash: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher.final(&hash);
    
    return std.fmt.allocPrint(allocator, "$2b$10$\\{s}", .{
        std.fmt.fmtSliceHexLower(&hash)
    });
}

pub fn verifyPassword(password: []const u8, hash: []const u8) !bool {
    const allocator = std.heap.page_allocator;
    const computed_hash = try hashPassword(allocator, password);
    defer allocator.free(computed_hash);
    
    return std.crypto.utils.timingSafeEql(u8, computed_hash, hash);
}

// JWT implementation
pub fn generateToken(
    allocator: std.mem.Allocator,
    user_id: []const u8,
    email: []const u8,
    role: []const u8,
) ![]u8 {
    const header = .{
        .alg = "HS256",
        .typ = "JWT",
    };
    
    const payload = models.TokenPayload{
        .sub = user_id,
        .email = email,
        .role = role,
        .exp = std.time.timestamp() + TOKEN_EXPIRY,
        .iat = std.time.timestamp(),
    };
    
    // Encode header
    var header_json = std.ArrayList(u8).init(allocator);
    defer header_json.deinit();
    try std.json.stringify(header, .{}, header_json.writer());
    const header_b64 = try base64UrlEncode(allocator, header_json.items);
    defer allocator.free(header_b64);
    
    // Encode payload
    var payload_json = std.ArrayList(u8).init(allocator);
    defer payload_json.deinit();
    try std.json.stringify(payload, .{}, payload_json.writer());
    const payload_b64 = try base64UrlEncode(allocator, payload_json.items);
    defer allocator.free(payload_b64);
    
    // Create signature
    const secret = std.os.getenv("JWT_SECRET") orelse "your-secret-key";
    const message = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    defer allocator.free(message);
    
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
    hmac.update(message);
    var signature: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    hmac.final(&signature);
    
    const signature_b64 = try base64UrlEncode(allocator, &signature);
    defer allocator.free(signature_b64);
    
    return std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{
        header_b64,
        payload_b64,
        signature_b64,
    });
}

pub fn verifyToken(allocator: std.mem.Allocator, token: []const u8) !models.TokenPayload {
    var parts = std.mem.tokenize(u8, token, ".");
    const header_b64 = parts.next() orelse return error.InvalidToken;
    const payload_b64 = parts.next() orelse return error.InvalidToken;
    const signature_b64 = parts.next() orelse return error.InvalidToken;
    
    // Verify signature
    const secret = std.os.getenv("JWT_SECRET") orelse "your-secret-key";
    const message = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    defer allocator.free(message);
    
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(secret);
    hmac.update(message);
    var computed_signature: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
    hmac.final(&computed_signature);
    
    const computed_signature_b64 = try base64UrlEncode(allocator, &computed_signature);
    defer allocator.free(computed_signature_b64);
    
    if (!std.mem.eql(u8, computed_signature_b64, signature_b64)) {
        return error.InvalidSignature;
    }
    
    // Decode payload
    const payload_json = try base64UrlDecode(allocator, payload_b64);
    defer allocator.free(payload_json);
    
    const parsed = try std.json.parseFromSlice(models.TokenPayload, allocator, payload_json, .{});
    defer parsed.deinit();
    
    // Check expiration
    if (parsed.value.exp < std.time.timestamp()) {
        return error.TokenExpired;
    }
    
    return parsed.value;
}

// Helper functions for Zap
pub fn getCurrentUser(r: zap.Request) ?models.User {
    const auth_header = r.getHeader("authorization") orelse return null;
    
    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
        return null;
    }
    
    const token = auth_header[7..];
    const allocator = r.allocator;
    
    const payload = verifyToken(allocator, token) catch return null;
    
    return models.User{
        .id = payload.sub,
        .email = payload.email,
        .name = "Test User", // In production, fetch from database
        .role = payload.role,
    };
}

pub fn hasRole(r: zap.Request, required_role: []const u8) bool {
    const user = getCurrentUser(r) orelse return false;
    return std.mem.eql(u8, user.role, required_role);
}

// Base64 URL encoding/decoding
fn base64UrlEncode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(encoded, data);
    return encoded;
}

fn base64UrlDecode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(data);
    const decoded = try allocator.alloc(u8, decoded_len);
    try decoder.decode(decoded, data);
    return decoded;
}

test "password hashing and verification" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const password = "test123";
    const hash = try hashPassword(allocator, password);
    defer allocator.free(hash);
    
    try testing.expect(try verifyPassword(password, hash));
    try testing.expect(!try verifyPassword("wrong", hash));
}

test "token generation and verification" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const token = try generateToken(allocator, "user123", "test@example.com", "user");
    defer allocator.free(token);
    
    const payload = try verifyToken(allocator, token);
    try testing.expectEqualStrings("user123", payload.sub);
    try testing.expectEqualStrings("test@example.com", payload.email);
    try testing.expectEqualStrings("user", payload.role);
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'utils', 'auth.zig'),
      authContent
    );
  }

  private async generateWebSocket(projectPath: string): Promise<void> {
    const wsContent = `const std = @import("std");
const zap = @import("zap");

// WebSocket connection manager
pub const ConnectionManager = struct {
    allocator: std.mem.Allocator,
    connections: std.AutoHashMap(*zap.WebSocket, ConnectionInfo),
    mutex: std.Thread.Mutex,

    const ConnectionInfo = struct {
        id: []const u8,
        user_id: ?[]const u8,
        connected_at: i64,
    };

    pub fn init(allocator: std.mem.Allocator) ConnectionManager {
        return .{
            .allocator = allocator,
            .connections = std.AutoHashMap(*zap.WebSocket, ConnectionInfo).init(allocator),
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        self.connections.deinit();
    }

    pub fn addConnection(self: *ConnectionManager, ws: *zap.WebSocket, info: ConnectionInfo) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        try self.connections.put(ws, info);
        std.log.info("WebSocket connected: {s}", .{info.id});
    }

    pub fn removeConnection(self: *ConnectionManager, ws: *zap.WebSocket) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        if (self.connections.fetchRemove(ws)) |entry| {
            std.log.info("WebSocket disconnected: {s}", .{entry.value.id});
        }
    }

    pub fn broadcast(self: *ConnectionManager, message: []const u8, exclude: ?*zap.WebSocket) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            if (exclude != null and entry.key_ptr.* == exclude.?) {
                continue;
            }
            
            entry.key_ptr.*.send(message, .text) catch |err| {
                std.log.err("Failed to send to WebSocket: {}", .{err});
            };
        }
    }

    pub fn sendToUser(self: *ConnectionManager, user_id: []const u8, message: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        var iter = self.connections.iterator();
        while (iter.next()) |entry| {
            if (entry.value.user_id) |uid| {
                if (std.mem.eql(u8, uid, user_id)) {
                    entry.key_ptr.*.send(message, .text) catch |err| {
                        std.log.err("Failed to send to user {s}: {}", .{ user_id, err });
                    };
                }
            }
        }
    }

    pub fn getConnectionCount(self: *ConnectionManager) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        
        return self.connections.count();
    }
};

// Global connection manager
var connection_manager: ?ConnectionManager = null;

pub fn initConnectionManager(allocator: std.mem.Allocator) void {
    connection_manager = ConnectionManager.init(allocator);
}

pub fn deinitConnectionManager() void {
    if (connection_manager) |*cm| {
        cm.deinit();
        connection_manager = null;
    }
}

pub fn getConnectionManager() *ConnectionManager {
    return &connection_manager.?;
}

// WebSocket message handlers
pub fn handleMessage(ws: *zap.WebSocket, message: []const u8) void {
    const allocator = std.heap.page_allocator;
    
    // Parse message
    const parsed = std.json.parseFromSlice(
        struct {
            type: []const u8,
            data: std.json.Value,
        },
        allocator,
        message,
        .{}
    ) catch {
        ws.send(
            \\{"type":"error","message":"Invalid message format"}
        , .text) catch {};
        return;
    };
    defer parsed.deinit();
    
    const msg = parsed.value;
    
    // Handle different message types
    if (std.mem.eql(u8, msg.type, "ping")) {
        ws.send(
            \\{"type":"pong","timestamp":
        ++ std.fmt.allocPrint(allocator, "{d}", .{std.time.timestamp()}) catch "0" ++
            \\}
        , .text) catch {};
    } else if (std.mem.eql(u8, msg.type, "broadcast")) {
        // Broadcast to all connections
        const cm = getConnectionManager();
        cm.broadcast(message, ws);
    } else {
        ws.send(
            \\{"type":"error","message":"Unknown message type"}
        , .text) catch {};
    }
}

// Room-based messaging
pub const Room = struct {
    name: []const u8,
    members: std.AutoHashMap(*zap.WebSocket, void),
    
    pub fn init(allocator: std.mem.Allocator, name: []const u8) Room {
        return .{
            .name = name,
            .members = std.AutoHashMap(*zap.WebSocket, void).init(allocator),
        };
    }
    
    pub fn deinit(self: *Room) void {
        self.members.deinit();
    }
    
    pub fn join(self: *Room, ws: *zap.WebSocket) !void {
        try self.members.put(ws, {});
    }
    
    pub fn leave(self: *Room, ws: *zap.WebSocket) void {
        _ = self.members.remove(ws);
    }
    
    pub fn broadcast(self: *Room, message: []const u8, exclude: ?*zap.WebSocket) void {
        var iter = self.members.iterator();
        while (iter.next()) |entry| {
            if (exclude != null and entry.key_ptr.* == exclude.?) {
                continue;
            }
            
            entry.key_ptr.*.send(message, .text) catch {};
        }
    }
};
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'utils', 'websocket.zig'),
      wsContent
    );
  }
}