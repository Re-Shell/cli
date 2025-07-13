/**
 * Zig HTTP Server Template Generator
 * Using Zig's standard library HTTP server
 */

import { ZigBackendGenerator } from './zig-base-generator';
import { promises as fs } from 'fs';
import * as path from 'path';

export class HttpServerGenerator extends ZigBackendGenerator {
  constructor() {
    super('HTTP Server');
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Generate main application
    await this.generateMainApp(projectPath, options);

    // Generate server module
    await this.generateServer(projectPath);

    // Generate router
    await this.generateRouter(projectPath);

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

    // Generate database module
    await this.generateDatabase(projectPath);

    // Generate authentication
    await this.generateAuth(projectPath);
  }

  private async generateMainApp(projectPath: string, options: any): Promise<void> {
    const mainContent = `const std = @import("std");
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
    var http_server = try server.Server.init(allocator, app_config);
    defer http_server.deinit();

    std.log.info("🚀 Server starting on http://{s}:{d}", .{ app_config.host, app_config.port });
    
    try http_server.listen();
}

test "main tests" {
    const testing = std.testing;
    // Add main tests here
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'main.zig'),
      mainContent
    );
  }

  private async generateServer(projectPath: string): Promise<void> {
    const serverContent = `const std = @import("std");
const http = std.http;
const router = @import("router.zig");
const middleware = @import("middleware/middleware.zig");
const Config = @import("config/config.zig").Config;

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: Config,
    server: http.Server,
    router: router.Router,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Server {
        const address = try std.net.Address.parseIp(config.host, config.port);
        const server_instance = http.Server.init(allocator, .{
            .reuse_address = true,
            .reuse_port = true,
        });

        return Server{
            .allocator = allocator,
            .config = config,
            .server = server_instance,
            .router = try router.Router.init(allocator),
        };
    }

    pub fn deinit(self: *Server) void {
        self.server.deinit();
        self.router.deinit();
    }

    pub fn listen(self: *Server) !void {
        const address = try std.net.Address.parseIp(self.config.host, self.config.port);
        
        try self.server.listen(address);

        while (true) {
            var response = try self.server.accept(.{
                .allocator = self.allocator,
            });
            defer response.deinit();

            // Handle the request in a separate thread
            const thread = try std.Thread.spawn(.{}, handleRequest, .{ self, &response });
            thread.detach();
        }
    }

    fn handleRequest(self: *Server, response: *http.Server.Response) void {
        self.processRequest(response) catch |err| {
            std.log.err("Error handling request: {}", .{err});
            response.status = .internal_server_error;
            response.do() catch {};
        };
    }

    fn processRequest(self: *Server, response: *http.Server.Response) !void {
        // Read request body
        const body = try response.reader().readAllAlloc(self.allocator, 1024 * 1024); // 1MB limit
        defer self.allocator.free(body);

        // Apply middleware
        try middleware.cors(response);
        try middleware.logger(response);

        // Route the request
        try self.router.route(response, body);

        // Send response
        try response.do();
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

  private async generateRouter(projectPath: string): Promise<void> {
    const routerContent = `const std = @import("std");
const http = std.http;
const handlers = @import("handlers/handlers.zig");

pub const Route = struct {
    method: http.Method,
    path: []const u8,
    handler: *const fn (*http.Server.Response, []const u8) anyerror!void,
};

pub const Router = struct {
    allocator: std.mem.Allocator,
    routes: std.ArrayList(Route),

    pub fn init(allocator: std.mem.Allocator) !Router {
        var r = Router{
            .allocator = allocator,
            .routes = std.ArrayList(Route).init(allocator),
        };

        // Register routes
        try r.registerRoutes();

        return r;
    }

    pub fn deinit(self: *Router) void {
        self.routes.deinit();
    }

    fn registerRoutes(self: *Router) !void {
        // Health routes
        try self.addRoute(.GET, "/health", handlers.health.handleHealth);
        try self.addRoute(.GET, "/ready", handlers.health.handleReady);

        // Auth routes
        try self.addRoute(.POST, "/api/v1/auth/register", handlers.auth.handleRegister);
        try self.addRoute(.POST, "/api/v1/auth/login", handlers.auth.handleLogin);
        try self.addRoute(.POST, "/api/v1/auth/refresh", handlers.auth.handleRefresh);
        try self.addRoute(.POST, "/api/v1/auth/logout", handlers.auth.handleLogout);

        // User routes
        try self.addRoute(.GET, "/api/v1/users", handlers.users.handleList);
        try self.addRoute(.GET, "/api/v1/users/me", handlers.users.handleGetCurrent);
        try self.addRoute(.GET, "/api/v1/users/:id", handlers.users.handleGetById);
        try self.addRoute(.PUT, "/api/v1/users/:id", handlers.users.handleUpdate);
        try self.addRoute(.DELETE, "/api/v1/users/:id", handlers.users.handleDelete);
    }

    fn addRoute(self: *Router, method: http.Method, path: []const u8, handler: anytype) !void {
        try self.routes.append(Route{
            .method = method,
            .path = path,
            .handler = handler,
        });
    }

    pub fn route(self: *Router, response: *http.Server.Response, body: []const u8) !void {
        const request = response.request;
        const method = request.method;
        const target = request.target;

        // Find matching route
        for (self.routes.items) |r| {
            if (r.method == method and self.matchPath(r.path, target)) {
                try r.handler(response, body);
                return;
            }
        }

        // 404 Not Found
        response.status = .not_found;
        try response.headers.append("content-type", "application/json");
        try response.writeAll(
            \\{"error": "Not Found", "message": "The requested resource was not found"}
        );
    }

    fn matchPath(self: *Router, pattern: []const u8, path: []const u8) bool {
        // Simple path matching (extend for parameter support)
        if (std.mem.indexOf(u8, pattern, ":") != null) {
            // TODO: Implement parameter matching
            return self.matchPathWithParams(pattern, path);
        }
        return std.mem.eql(u8, pattern, path);
    }

    fn matchPathWithParams(self: *Router, pattern: []const u8, path: []const u8) bool {
        var pattern_parts = std.mem.tokenize(u8, pattern, "/");
        var path_parts = std.mem.tokenize(u8, path, "/");

        while (pattern_parts.next()) |pattern_part| {
            const path_part = path_parts.next() orelse return false;
            
            if (pattern_part[0] == ':') {
                // Parameter - matches any value
                continue;
            }
            
            if (!std.mem.eql(u8, pattern_part, path_part)) {
                return false;
            }
        }

        return path_parts.next() == null;
    }
};

test "router path matching" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var r = try Router.init(allocator);
    defer r.deinit();

    try testing.expect(r.matchPath("/api/users", "/api/users"));
    try testing.expect(!r.matchPath("/api/users", "/api/posts"));
    try testing.expect(r.matchPath("/api/users/:id", "/api/users/123"));
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'router.zig'),
      routerContent
    );
  }

  private async generateHandlers(projectPath: string): Promise<void> {
    const handlersDir = path.join(projectPath, 'src', 'handlers');

    // Handlers index
    const handlersIndexContent = `pub const health = @import("health.zig");
pub const auth = @import("auth.zig");
pub const users = @import("users.zig");
`;

    await fs.writeFile(
      path.join(handlersDir, 'handlers.zig'),
      handlersIndexContent
    );

    // Auth handlers
    const authHandlersContent = `const std = @import("std");
const http = std.http;
const json = std.json;
const auth_service = @import("../utils/auth.zig");
const models = @import("../models/models.zig");

pub fn handleRegister(response: *http.Server.Response, body: []const u8) !void {
    const allocator = response.allocator;

    // Parse request body
    const parsed = try json.parseFromSlice(models.RegisterRequest, allocator, body, .{});
    defer parsed.deinit();
    const req = parsed.value;

    // Validate input
    if (req.email.len == 0 or req.password.len < 6 or req.name.len == 0) {
        response.status = .bad_request;
        try response.headers.append("content-type", "application/json");
        try response.writeAll(
            \\{"error": "Validation Error", "message": "Invalid input data"}
        );
        return;
    }

    // Check if user exists (mock)
    // In production, check database

    // Hash password
    const hashed_password = try auth_service.hashPassword(allocator, req.password);
    defer allocator.free(hashed_password);

    // Create user (mock)
    const user = models.User{
        .id = "user123",
        .email = req.email,
        .name = req.name,
        .role = "user",
    };

    // Generate token
    const token = try auth_service.generateToken(allocator, user.id, user.email, user.role);
    defer allocator.free(token);

    // Send response
    response.status = .created;
    try response.headers.append("content-type", "application/json");
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try json.stringify(.{
        .user = user,
        .token = token,
    }, .{}, buffer.writer());
    
    try response.writeAll(buffer.items);
}

pub fn handleLogin(response: *http.Server.Response, body: []const u8) !void {
    const allocator = response.allocator;

    // Parse request body
    const parsed = try json.parseFromSlice(models.LoginRequest, allocator, body, .{});
    defer parsed.deinit();
    const req = parsed.value;

    // Validate input
    if (req.email.len == 0 or req.password.len == 0) {
        response.status = .bad_request;
        try response.headers.append("content-type", "application/json");
        try response.writeAll(
            \\{"error": "Validation Error", "message": "Email and password required"}
        );
        return;
    }

    // Find user and verify password (mock)
    // In production, query database and verify password

    const user = models.User{
        .id = "user123",
        .email = req.email,
        .name = "Test User",
        .role = "user",
    };

    // Generate token
    const token = try auth_service.generateToken(allocator, user.id, user.email, user.role);
    defer allocator.free(token);

    // Send response
    response.status = .ok;
    try response.headers.append("content-type", "application/json");
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try json.stringify(.{
        .user = user,
        .token = token,
    }, .{}, buffer.writer());
    
    try response.writeAll(buffer.items);
}

pub fn handleRefresh(response: *http.Server.Response, body: []const u8) !void {
    _ = body;
    const allocator = response.allocator;

    // Get token from header
    const auth_header = response.request.headers.getFirstValue("authorization") orelse {
        response.status = .unauthorized;
        try response.headers.append("content-type", "application/json");
        try response.writeAll(
            \\{"error": "Unauthorized", "message": "Missing authorization header"}
        );
        return;
    };

    // Verify token and refresh
    // In production, implement proper token refresh logic

    const new_token = try auth_service.generateToken(allocator, "user123", "user@example.com", "user");
    defer allocator.free(new_token);

    response.status = .ok;
    try response.headers.append("content-type", "application/json");
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try json.stringify(.{ .token = new_token }, .{}, buffer.writer());
    try response.writeAll(buffer.items);
}

pub fn handleLogout(response: *http.Server.Response, body: []const u8) !void {
    _ = body;
    
    // In production, blacklist token or clear session

    response.status = .ok;
    try response.headers.append("content-type", "application/json");
    try response.writeAll(
        \\{"message": "Logged out successfully"}
    );
}
`;

    await fs.writeFile(
      path.join(handlersDir, 'auth.zig'),
      authHandlersContent
    );

    // Users handlers
    const usersHandlersContent = `const std = @import("std");
const http = std.http;
const json = std.json;
const models = @import("../models/models.zig");
const auth = @import("../utils/auth.zig");

pub fn handleList(response: *http.Server.Response, body: []const u8) !void {
    _ = body;
    const allocator = response.allocator;

    // Check authorization
    if (!try auth.isAuthorized(response.request, "admin")) {
        response.status = .forbidden;
        try response.headers.append("content-type", "application/json");
        try response.writeAll(
            \\{"error": "Forbidden", "message": "Insufficient permissions"}
        );
        return;
    }

    // Mock user list
    const users = [_]models.User{
        .{ .id = "1", .email = "user1@example.com", .name = "User One", .role = "user" },
        .{ .id = "2", .email = "user2@example.com", .name = "User Two", .role = "admin" },
    };

    response.status = .ok;
    try response.headers.append("content-type", "application/json");
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try json.stringify(.{
        .data = users,
        .meta = .{
            .page = 1,
            .limit = 10,
            .total = users.len,
        },
    }, .{}, buffer.writer());
    
    try response.writeAll(buffer.items);
}

pub fn handleGetCurrent(response: *http.Server.Response, body: []const u8) !void {
    _ = body;
    const allocator = response.allocator;

    // Get current user from token
    const current_user = try auth.getCurrentUser(response.request) orelse {
        response.status = .unauthorized;
        try response.headers.append("content-type", "application/json");
        try response.writeAll(
            \\{"error": "Unauthorized", "message": "Not authenticated"}
        );
        return;
    };

    response.status = .ok;
    try response.headers.append("content-type", "application/json");
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try json.stringify(current_user, .{}, buffer.writer());
    try response.writeAll(buffer.items);
}

pub fn handleGetById(response: *http.Server.Response, body: []const u8) !void {
    _ = body;
    const allocator = response.allocator;

    // Extract ID from path
    const path = response.request.target;
    const id = extractIdFromPath(path) orelse {
        response.status = .bad_request;
        try response.headers.append("content-type", "application/json");
        try response.writeAll(
            \\{"error": "Bad Request", "message": "Invalid user ID"}
        );
        return;
    };

    // Mock user lookup
    const user = models.User{
        .id = id,
        .email = "user@example.com",
        .name = "Test User",
        .role = "user",
    };

    response.status = .ok;
    try response.headers.append("content-type", "application/json");
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try json.stringify(user, .{}, buffer.writer());
    try response.writeAll(buffer.items);
}

pub fn handleUpdate(response: *http.Server.Response, body: []const u8) !void {
    const allocator = response.allocator;

    // Extract ID from path
    const path = response.request.target;
    const id = extractIdFromPath(path) orelse {
        response.status = .bad_request;
        try response.headers.append("content-type", "application/json");
        try response.writeAll(
            \\{"error": "Bad Request", "message": "Invalid user ID"}
        );
        return;
    };

    // Parse update request
    const parsed = try json.parseFromSlice(models.UpdateUserRequest, allocator, body, .{});
    defer parsed.deinit();
    const req = parsed.value;

    // Mock user update
    const updated_user = models.User{
        .id = id,
        .email = req.email orelse "user@example.com",
        .name = req.name orelse "Updated User",
        .role = "user",
    };

    response.status = .ok;
    try response.headers.append("content-type", "application/json");
    
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try json.stringify(updated_user, .{}, buffer.writer());
    try response.writeAll(buffer.items);
}

pub fn handleDelete(response: *http.Server.Response, body: []const u8) !void {
    _ = body;

    // Extract ID from path
    const path = response.request.target;
    const id = extractIdFromPath(path) orelse {
        response.status = .bad_request;
        try response.headers.append("content-type", "application/json");
        try response.writeAll(
            \\{"error": "Bad Request", "message": "Invalid user ID"}
        );
        return;
    };

    // Check authorization
    if (!try auth.isAuthorized(response.request, "admin")) {
        response.status = .forbidden;
        try response.headers.append("content-type", "application/json");
        try response.writeAll(
            \\{"error": "Forbidden", "message": "Insufficient permissions"}
        );
        return;
    }

    // Mock user deletion
    _ = id;

    response.status = .no_content;
}

fn extractIdFromPath(path: []const u8) ?[]const u8 {
    // Simple ID extraction from path like /api/v1/users/123
    const prefix = "/api/v1/users/";
    if (std.mem.startsWith(u8, path, prefix)) {
        return path[prefix.len..];
    }
    return null;
}
`;

    await fs.writeFile(
      path.join(handlersDir, 'users.zig'),
      usersHandlersContent
    );
  }

  private async generateMiddleware(projectPath: string): Promise<void> {
    const middlewareDir = path.join(projectPath, 'src', 'middleware');

    // Middleware index
    const middlewareIndexContent = `const std = @import("std");
const http = std.http;

pub fn cors(response: *http.Server.Response) !void {
    try response.headers.append("Access-Control-Allow-Origin", "*");
    try response.headers.append("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    try response.headers.append("Access-Control-Allow-Headers", "Content-Type, Authorization");
    
    if (response.request.method == .OPTIONS) {
        response.status = .no_content;
    }
}

pub fn logger(response: *http.Server.Response) !void {
    const method = @tagName(response.request.method);
    const path = response.request.target;
    const timestamp = std.time.timestamp();
    
    std.log.info("[{d}] {s} {s}", .{ timestamp, method, path });
}

pub fn rateLimiter(allocator: std.mem.Allocator, response: *http.Server.Response) !void {
    // Simple rate limiting implementation
    const RateLimitData = struct {
        requests: u32,
        reset_time: i64,
    };
    
    // In production, use proper storage
    _ = allocator;
    
    const current_time = std.time.timestamp();
    const rate_limit = 100; // requests per minute
    
    // Mock rate limit check
    const requests_made = 50;
    
    if (requests_made >= rate_limit) {
        response.status = .too_many_requests;
        try response.headers.append("content-type", "application/json");
        try response.headers.append("X-RateLimit-Limit", "100");
        try response.headers.append("X-RateLimit-Remaining", "0");
        try response.headers.append("X-RateLimit-Reset", try std.fmt.allocPrint(
            response.allocator,
            "{d}",
            .{current_time + 60}
        ));
        try response.writeAll(
            \\{"error": "Too Many Requests", "message": "Rate limit exceeded"}
        );
        return;
    }
    
    try response.headers.append("X-RateLimit-Limit", "100");
    try response.headers.append("X-RateLimit-Remaining", try std.fmt.allocPrint(
        response.allocator,
        "{d}",
        .{rate_limit - requests_made}
    ));
}
`;

    await fs.writeFile(
      path.join(middlewareDir, 'middleware.zig'),
      middlewareIndexContent
    );
  }

  private async generateModels(projectPath: string): Promise<void> {
    const modelsDir = path.join(projectPath, 'src', 'models');

    // Models index
    const modelsIndexContent = `// User model
pub const User = struct {
    id: []const u8,
    email: []const u8,
    name: []const u8,
    role: []const u8,
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
`;

    await fs.writeFile(
      path.join(modelsDir, 'models.zig'),
      modelsIndexContent
    );
  }

  private async generateUtilities(projectPath: string): Promise<void> {
    const utilsDir = path.join(projectPath, 'src', 'utils');

    // Validation utilities
    const validationContent = `const std = @import("std");

pub fn isValidEmail(email: []const u8) bool {
    // Simple email validation
    const at_index = std.mem.indexOf(u8, email, "@") orelse return false;
    const dot_index = std.mem.lastIndexOf(u8, email, ".") orelse return false;
    
    return at_index > 0 and dot_index > at_index + 1 and dot_index < email.len - 1;
}

pub fn isValidPassword(password: []const u8) bool {
    return password.len >= 6;
}

pub fn sanitizeInput(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var result = std.ArrayList(u8).init(allocator);
    defer result.deinit();
    
    for (input) |char| {
        switch (char) {
            '<', '>', '"', '\'', '&' => {
                // Skip potentially dangerous characters
                continue;
            },
            else => try result.append(char),
        }
    }
    
    return result.toOwnedSlice();
}

test "email validation" {
    const testing = std.testing;
    
    try testing.expect(isValidEmail("user@example.com"));
    try testing.expect(!isValidEmail("invalid.email"));
    try testing.expect(!isValidEmail("@example.com"));
    try testing.expect(!isValidEmail("user@"));
}

test "password validation" {
    const testing = std.testing;
    
    try testing.expect(isValidPassword("secure123"));
    try testing.expect(!isValidPassword("12345"));
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'validation.zig'),
      validationContent
    );

    // JSON utilities
    const jsonUtilsContent = `const std = @import("std");
const json = std.json;

pub fn stringify(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    
    try json.stringify(value, .{}, buffer.writer());
    return buffer.toOwnedSlice();
}

pub fn parse(comptime T: type, allocator: std.mem.Allocator, data: []const u8) !json.Parsed(T) {
    return json.parseFromSlice(T, allocator, data, .{});
}

pub fn sendJsonResponse(
    response: *std.http.Server.Response,
    status: std.http.Status,
    data: anytype,
) !void {
    response.status = status;
    try response.headers.append("content-type", "application/json");
    
    const json_data = try stringify(response.allocator, data);
    defer response.allocator.free(json_data);
    
    try response.writeAll(json_data);
}
`;

    await fs.writeFile(
      path.join(utilsDir, 'json.zig'),
      jsonUtilsContent
    );
  }

  private async generateConfig(projectPath: string, options: any): Promise<void> {
    const configDir = path.join(projectPath, 'src', 'config');

    // Configuration module
    const configContent = `const std = @import("std");

pub const Config = struct {
    allocator: std.mem.Allocator,
    host: []const u8,
    port: u16,
    log_level: []const u8,
    database_url: []const u8,
    jwt_secret: []const u8,
    cors_origin: []const u8,

    pub fn deinit(self: Config) void {
        // Free allocated strings if needed
        _ = self;
    }
};

pub fn load(allocator: std.mem.Allocator) !Config {
    return Config{
        .allocator = allocator,
        .host = std.os.getenv("HOST") orelse "0.0.0.0",
        .port = try parsePort(std.os.getenv("PORT") orelse "${options.port || 8080}"),
        .log_level = std.os.getenv("LOG_LEVEL") orelse "info",
        .database_url = std.os.getenv("DATABASE_URL") orelse "sqlite://./data/app.db",
        .jwt_secret = std.os.getenv("JWT_SECRET") orelse "your-secret-key",
        .cors_origin = std.os.getenv("CORS_ORIGIN") orelse "*",
    };
}

fn parsePort(port_str: []const u8) !u16 {
    return std.fmt.parseInt(u16, port_str, 10) catch |err| {
        std.log.err("Invalid port number: {s}", .{port_str});
        return err;
    };
}

test "config loading" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const config = try load(allocator);
    defer config.deinit();
    
    try testing.expect(config.port > 0);
    try testing.expect(config.host.len > 0);
}
`;

    await fs.writeFile(
      path.join(configDir, 'config.zig'),
      configContent
    );
  }

  private async generateDatabase(projectPath: string): Promise<void> {
    const dbContent = `const std = @import("std");
const sqlite = @cImport({
    @cInclude("sqlite3.h");
});

pub const Database = struct {
    allocator: std.mem.Allocator,
    db: ?*sqlite.sqlite3,

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !Database {
        var db: ?*sqlite.sqlite3 = null;
        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const result = sqlite.sqlite3_open(c_path, &db);
        if (result != sqlite.SQLITE_OK) {
            std.log.err("Failed to open database: {}", .{result});
            return error.DatabaseOpenFailed;
        }

        // Create tables
        try createTables(db.?);

        return Database{
            .allocator = allocator,
            .db = db,
        };
    }

    pub fn deinit(self: *Database) void {
        if (self.db) |db| {
            _ = sqlite.sqlite3_close(db);
        }
    }

    fn createTables(db: *sqlite.sqlite3) !void {
        const create_users_sql =
            \\CREATE TABLE IF NOT EXISTS users (
            \\    id TEXT PRIMARY KEY,
            \\    email TEXT UNIQUE NOT NULL,
            \\    password TEXT NOT NULL,
            \\    name TEXT NOT NULL,
            \\    role TEXT NOT NULL DEFAULT 'user',
            \\    created_at INTEGER NOT NULL,
            \\    updated_at INTEGER NOT NULL
            \\);
        ;

        var err_msg: ?[*:0]u8 = null;
        const result = sqlite.sqlite3_exec(db, create_users_sql, null, null, &err_msg);
        if (result != sqlite.SQLITE_OK) {
            std.log.err("Failed to create tables: {s}", .{err_msg orelse "unknown error"});
            if (err_msg) |msg| {
                sqlite.sqlite3_free(msg);
            }
            return error.TableCreationFailed;
        }
    }

    pub fn findUserByEmail(self: *Database, email: []const u8) !?User {
        _ = self;
        _ = email;
        // TODO: Implement database query
        return null;
    }

    pub fn createUser(self: *Database, user: User) !void {
        _ = self;
        _ = user;
        // TODO: Implement database insert
    }
};

const User = struct {
    id: []const u8,
    email: []const u8,
    password: []const u8,
    name: []const u8,
    role: []const u8,
    created_at: i64,
    updated_at: i64,
};
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'utils', 'database.zig'),
      dbContent
    );
  }

  private async generateAuth(projectPath: string): Promise<void> {
    const authContent = `const std = @import("std");
const crypto = std.crypto;
const http = std.http;
const models = @import("../models/models.zig");

// Simple password hashing using SHA256 (use bcrypt in production)
pub fn hashPassword(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    var hash: [crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(password, &hash, .{});
    
    return std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&hash)});
}

pub fn verifyPassword(password: []const u8, hash: []const u8) !bool {
    const allocator = std.heap.page_allocator;
    const computed_hash = try hashPassword(allocator, password);
    defer allocator.free(computed_hash);
    
    return std.mem.eql(u8, computed_hash, hash);
}

// Simple JWT implementation (use proper JWT library in production)
pub fn generateToken(
    allocator: std.mem.Allocator,
    user_id: []const u8,
    email: []const u8,
    role: []const u8,
) ![]u8 {
    const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}
    
    const payload = models.TokenPayload{
        .sub = user_id,
        .email = email,
        .role = role,
        .exp = std.time.timestamp() + 7 * 24 * 60 * 60, // 7 days
        .iat = std.time.timestamp(),
    };
    
    var payload_json = std.ArrayList(u8).init(allocator);
    defer payload_json.deinit();
    try std.json.stringify(payload, .{}, payload_json.writer());
    
    const payload_base64 = try base64Encode(allocator, payload_json.items);
    defer allocator.free(payload_base64);
    
    const token = try std.fmt.allocPrint(allocator, "{s}.{s}.mock-signature", .{ header, payload_base64 });
    return token;
}

pub fn verifyToken(allocator: std.mem.Allocator, token: []const u8) !models.TokenPayload {
    // Simple token parsing (implement proper verification in production)
    var parts = std.mem.tokenize(u8, token, ".");
    _ = parts.next() orelse return error.InvalidToken; // header
    const payload_part = parts.next() orelse return error.InvalidToken;
    
    const payload_json = try base64Decode(allocator, payload_part);
    defer allocator.free(payload_json);
    
    const parsed = try std.json.parseFromSlice(models.TokenPayload, allocator, payload_json, .{});
    defer parsed.deinit();
    
    // Check expiration
    if (parsed.value.exp < std.time.timestamp()) {
        return error.TokenExpired;
    }
    
    return parsed.value;
}

pub fn isAuthorized(request: http.Server.Request, required_role: []const u8) !bool {
    const auth_header = request.headers.getFirstValue("authorization") orelse return false;
    
    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
        return false;
    }
    
    const token = auth_header[7..];
    const allocator = std.heap.page_allocator;
    
    const payload = verifyToken(allocator, token) catch return false;
    
    if (required_role.len > 0 and !std.mem.eql(u8, payload.role, required_role)) {
        return false;
    }
    
    return true;
}

pub fn getCurrentUser(request: http.Server.Request) !?models.User {
    const auth_header = request.headers.getFirstValue("authorization") orelse return null;
    
    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
        return null;
    }
    
    const token = auth_header[7..];
    const allocator = std.heap.page_allocator;
    
    const payload = verifyToken(allocator, token) catch return null;
    
    return models.User{
        .id = payload.sub,
        .email = payload.email,
        .name = "Test User", // In production, fetch from database
        .role = payload.role,
    };
}

fn base64Encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(encoded, data);
    return encoded;
}

fn base64Decode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(data);
    const decoded = try allocator.alloc(u8, decoded_len);
    try decoder.decode(decoded, data);
    return decoded;
}

test "password hashing" {
    const testing = std.testing;
    const allocator = testing.allocator;
    
    const password = "test123";
    const hash = try hashPassword(allocator, password);
    defer allocator.free(hash);
    
    try testing.expect(hash.len > 0);
    try testing.expect(try verifyPassword(password, hash));
}
`;

    await fs.writeFile(
      path.join(projectPath, 'src', 'utils', 'auth.zig'),
      authContent
    );
  }
}