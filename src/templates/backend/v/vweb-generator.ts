import { VBackendGenerator } from './v-base-generator';
import * as fs from 'fs/promises';
import * as path from 'path';

export class VwebGenerator extends VBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Vweb';
    this.config.features.push(
      'Built-in V framework',
      'Template engine',
      'ORM integration',
      'Session management',
      'CSRF protection',
      'Static file serving',
      'WebSocket support',
      'Middleware system',
      'Form validation',
      'File uploads'
    );
  }

  protected getFrameworkDependencies(): string[] {
    // Vweb is built-in, but we might need external packages
    return [
      'nedpals.vargs',
      'vlang.vjwt',
      'spytheman.vini'
    ];
  }

  protected generateMainFile(): string {
    return `module main

import src.server
import src.config

fn main() {
    // Load configuration
    cfg := config.load()
    
    // Start the server
    server.start(cfg)
}
`;
  }

  protected generateServerFile(): string {
    return `module server

import vweb
import src.config
import src.router
import src.middleware
import os
import log

pub struct App {
    vweb.Context
pub mut:
    config config.Config
    logger log.Logger
}

pub fn start(cfg config.Config) {
    mut logger := log.Logger{}
    logger.set_level(log.level_from_tag(cfg.log_level) or { log.Level.info })
    
    println('Starting Vweb server on \${cfg.host}:\${cfg.port}...')
    
    // Create app instance
    mut app := &App{
        config: cfg
        logger: logger
    }
    
    // Setup routes
    router.setup(mut app)
    
    // Setup static file serving
    app.handle_static('public', true)
    
    // Start the server
    vweb.run(app, cfg.port)
}

// Middleware to log requests
pub fn (mut app App) before_request() {
    app.logger.info('\${app.req.method} \${app.req.url}')
    
    // Apply global middleware
    middleware.cors(mut app)
    middleware.logger(mut app)
}
`;
  }

  protected generateRouterFile(): string {
    return `module router

import vweb
import src.controllers.auth_controller
import src.controllers.user_controller
import src.controllers.health_controller
import src.middleware

pub fn setup(mut app server.App) {
    // Health check route
    app.route_get('/health', health_controller.health)
    
    // API routes
    app.route_get('/api', api_info)
    
    // Auth routes
    app.route_post('/api/auth/register', auth_controller.register)
    app.route_post('/api/auth/login', auth_controller.login)
    app.route_post('/api/auth/refresh', auth_controller.refresh_token)
    app.route_post('/api/auth/logout', middleware.auth_required(auth_controller.logout))
    
    // User routes (protected)
    app.route_get('/api/users', middleware.auth_required(user_controller.list_users))
    app.route_get('/api/users/:id', middleware.auth_required(user_controller.get_user))
    app.route_post('/api/users', middleware.auth_required(user_controller.create_user))
    app.route_put('/api/users/:id', middleware.auth_required(user_controller.update_user))
    app.route_delete('/api/users/:id', middleware.auth_required(middleware.admin_required(user_controller.delete_user)))
    
    // Serve index page
    app.route_get('/', index)
}

fn api_info(mut app server.App) vweb.Result {
    return app.json({
        'name': 'Vweb API'
        'version': '1.0.0'
        'framework': 'Vweb'
    })
}

fn index(mut app server.App) vweb.Result {
    return app.html('<!DOCTYPE html>
<html>
<head>
    <title>Vweb Service</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: #2196F3;
            color: white;
            padding: 20px;
            border-radius: 5px;
        }
        .content {
            margin-top: 20px;
        }
        code {
            background: #f4f4f4;
            padding: 2px 5px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Welcome to Vweb!</h1>
        <p>A fast, simple web framework built into V</p>
    </div>
    <div class="content">
        <h2>API Endpoints</h2>
        <ul>
            <li><code>GET /health</code> - Health check</li>
            <li><code>GET /api</code> - API information</li>
            <li><code>POST /api/auth/register</code> - User registration</li>
            <li><code>POST /api/auth/login</code> - User login</li>
            <li><code>GET /api/users</code> - List users (requires auth)</li>
        </ul>
        <h2>Getting Started</h2>
        <p>Check out the <a href="/docs/api.md">API documentation</a> for more details.</p>
    </div>
</body>
</html>')
}
`;
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/middleware/auth.v',
        content: `module middleware

import vweb
import src.server
import src.utils.jwt
import src.models.user
import json

pub fn auth_required(handler fn(mut app server.App) vweb.Result) fn(mut app server.App) vweb.Result {
    return fn [handler] (mut app server.App) vweb.Result {
        // Get authorization header
        auth_header := app.get_header('Authorization')
        if auth_header == '' {
            app.set_status(401, 'Unauthorized')
            return app.json({
                'error': 'Missing authorization header'
            })
        }
        
        // Extract token
        if !auth_header.starts_with('Bearer ') {
            app.set_status(401, 'Unauthorized')
            return app.json({
                'error': 'Invalid authorization header format'
            })
        }
        
        token := auth_header[7..]
        
        // Verify token
        payload := jwt.verify_token(token) or {
            app.set_status(401, 'Unauthorized')
            return app.json({
                'error': 'Invalid or expired token'
            })
        }
        
        // Get user from database
        user_id := payload['sub'].str()
        user := user.get_by_id(user_id) or {
            app.set_status(401, 'Unauthorized')
            return app.json({
                'error': 'User not found'
            })
        }
        
        // Store user in context
        app.user = user
        
        // Call the actual handler
        return handler(mut app)
    }
}

pub fn admin_required(handler fn(mut app server.App) vweb.Result) fn(mut app server.App) vweb.Result {
    return fn [handler] (mut app server.App) vweb.Result {
        if app.user.role != 'admin' {
            app.set_status(403, 'Forbidden')
            return app.json({
                'error': 'Admin access required'
            })
        }
        
        return handler(mut app)
    }
}

pub fn rate_limit(max_requests int, window_seconds int) fn(mut app server.App) {
    // Simple in-memory rate limiting
    mut request_counts := map[string][]i64{}
    
    return fn [max_requests, window_seconds, mut request_counts] (mut app server.App) {
        client_ip := app.get_header('X-Forwarded-For') or { app.ip() }
        current_time := time.now().unix
        window_start := current_time - window_seconds
        
        // Clean old entries
        if client_ip in request_counts {
            request_counts[client_ip] = request_counts[client_ip].filter(it > window_start)
        } else {
            request_counts[client_ip] = []
        }
        
        // Check rate limit
        if request_counts[client_ip].len >= max_requests {
            app.set_status(429, 'Too Many Requests')
            app.json({
                'error': 'Rate limit exceeded'
                'retry_after': window_seconds
            })
            return
        }
        
        // Add current request
        request_counts[client_ip] << current_time
    }
}
`
      },
      {
        path: 'src/middleware/cors.v',
        content: `module middleware

import vweb
import src.server

pub fn cors(mut app server.App) {
    origin := app.get_header('Origin') or { '*' }
    
    // Set CORS headers
    app.add_header('Access-Control-Allow-Origin', origin)
    app.add_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
    app.add_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    app.add_header('Access-Control-Allow-Credentials', 'true')
    
    // Handle preflight requests
    if app.req.method == .options {
        app.set_status(204, 'No Content')
        return
    }
}

pub fn logger(mut app server.App) {
    start_time := time.now()
    
    // Log request details
    app.logger.info('\${app.req.method} \${app.req.url} from \${app.ip()}')
    
    // TODO: Add response time logging after request completes
}

pub fn error_handler(mut app server.App) {
    // Global error handling
    // This would be called on panics/errors
}
`
      },
      {
        path: 'src/middleware/validation.v',
        content: `module middleware

import src.server
import regex

pub struct ValidationError {
pub:
    field string
    message string
}

pub fn validate_email(email string) ?ValidationError {
    if email.len == 0 {
        return ValidationError{
            field: 'email'
            message: 'Email is required'
        }
    }
    
    email_regex := regex.regex_opt(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$') or {
        return ValidationError{
            field: 'email'
            message: 'Invalid email regex'
        }
    }
    
    if !email_regex.matches_string(email) {
        return ValidationError{
            field: 'email'
            message: 'Invalid email format'
        }
    }
    
    return none
}

pub fn validate_password(password string) ?ValidationError {
    if password.len < 8 {
        return ValidationError{
            field: 'password'
            message: 'Password must be at least 8 characters'
        }
    }
    
    has_upper := password.bytes().any(it >= \`A\` && it <= \`Z\`)
    has_lower := password.bytes().any(it >= \`a\` && it <= \`z\`)
    has_digit := password.bytes().any(it >= \`0\` && it <= \`9\`)
    
    if !has_upper || !has_lower || !has_digit {
        return ValidationError{
            field: 'password'
            message: 'Password must contain uppercase, lowercase, and digit'
        }
    }
    
    return none
}

pub fn validate_username(username string) ?ValidationError {
    if username.len < 3 {
        return ValidationError{
            field: 'username'
            message: 'Username must be at least 3 characters'
        }
    }
    
    if username.len > 20 {
        return ValidationError{
            field: 'username'
            message: 'Username must not exceed 20 characters'
        }
    }
    
    // Check if username contains only alphanumeric and underscore
    for c in username {
        if !((c >= \`a\` && c <= \`z\`) || (c >= \`A\` && c <= \`Z\`) || (c >= \`0\` && c <= \`9\`) || c == \`_\`) {
            return ValidationError{
                field: 'username'
                message: 'Username can only contain letters, numbers, and underscores'
            }
        }
    }
    
    return none
}
`
      }
    ];
  }

  protected generateControllerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/controllers/health_controller.v',
        content: `module health_controller

import vweb
import src.server
import time
import runtime
import os

pub fn health(mut app server.App) vweb.Result {
    uptime := time.now().unix - app.start_time
    
    return app.json({
        'status': 'healthy'
        'service': 'vweb-service'
        'version': '1.0.0'
        'uptime': uptime
        'timestamp': time.now().unix
        'memory': {
            'used': runtime.nr_heap_bytes()
            'free': runtime.nr_free_heap_bytes()
        }
        'environment': os.getenv('APP_ENV')
    })
}
`
      },
      {
        path: 'src/controllers/auth_controller.v',
        content: `module auth_controller

import vweb
import src.server
import src.models.user
import src.utils.jwt
import src.utils.hash
import src.middleware
import json
import time

pub fn register(mut app server.App) vweb.Result {
    // Parse request body
    data := json.decode(RegisterRequest, app.req.data) or {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': 'Invalid request body'
        })
    }
    
    // Validate input
    if err := middleware.validate_email(data.email) {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': err.message
            'field': err.field
        })
    }
    
    if err := middleware.validate_password(data.password) {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': err.message
            'field': err.field
        })
    }
    
    if err := middleware.validate_username(data.username) {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': err.message
            'field': err.field
        })
    }
    
    // Check if user exists
    existing := user.get_by_email(data.email) or { user.User{} }
    if existing.id != 0 {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': 'Email already registered'
        })
    }
    
    // Create user
    mut new_user := user.User{
        email: data.email
        username: data.username
        password_hash: hash.hash_password(data.password)
        role: 'user'
        created_at: time.now().unix
        updated_at: time.now().unix
    }
    
    new_user = user.create(new_user) or {
        app.set_status(500, 'Internal Server Error')
        return app.json({
            'error': 'Failed to create user'
        })
    }
    
    // Generate tokens
    access_token := jwt.generate_access_token(new_user)
    refresh_token := jwt.generate_refresh_token(new_user)
    
    // Save refresh token
    user.save_refresh_token(new_user.id, refresh_token)
    
    return app.json({
        'user': new_user.to_public()
        'access_token': access_token
        'refresh_token': refresh_token
    })
}

pub fn login(mut app server.App) vweb.Result {
    // Parse request body
    data := json.decode(LoginRequest, app.req.data) or {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': 'Invalid request body'
        })
    }
    
    // Find user
    user_obj := user.get_by_email(data.email) or {
        app.set_status(401, 'Unauthorized')
        return app.json({
            'error': 'Invalid credentials'
        })
    }
    
    // Verify password
    if !hash.verify_password(data.password, user_obj.password_hash) {
        app.set_status(401, 'Unauthorized')
        return app.json({
            'error': 'Invalid credentials'
        })
    }
    
    // Generate tokens
    access_token := jwt.generate_access_token(user_obj)
    refresh_token := jwt.generate_refresh_token(user_obj)
    
    // Save refresh token
    user.save_refresh_token(user_obj.id, refresh_token)
    
    return app.json({
        'user': user_obj.to_public()
        'access_token': access_token
        'refresh_token': refresh_token
    })
}

pub fn refresh_token(mut app server.App) vweb.Result {
    // Parse request body
    data := json.decode(RefreshRequest, app.req.data) or {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': 'Invalid request body'
        })
    }
    
    // Verify refresh token
    payload := jwt.verify_refresh_token(data.refresh_token) or {
        app.set_status(401, 'Unauthorized')
        return app.json({
            'error': 'Invalid refresh token'
        })
    }
    
    user_id := payload['sub'].int()
    
    // Check if token is valid for user
    if !user.is_refresh_token_valid(user_id, data.refresh_token) {
        app.set_status(401, 'Unauthorized')
        return app.json({
            'error': 'Invalid refresh token'
        })
    }
    
    // Get user
    user_obj := user.get_by_id(user_id) or {
        app.set_status(401, 'Unauthorized')
        return app.json({
            'error': 'User not found'
        })
    }
    
    // Generate new access token
    access_token := jwt.generate_access_token(user_obj)
    
    return app.json({
        'access_token': access_token
    })
}

pub fn logout(mut app server.App) vweb.Result {
    // Invalidate refresh tokens
    user.invalidate_refresh_tokens(app.user.id)
    
    return app.json({
        'message': 'Logged out successfully'
    })
}

struct RegisterRequest {
    email string
    username string
    password string
}

struct LoginRequest {
    email string
    password string
}

struct RefreshRequest {
    refresh_token string
}
`
      },
      {
        path: 'src/controllers/user_controller.v',
        content: `module user_controller

import vweb
import src.server
import src.models.user
import json
import strconv

pub fn list_users(mut app server.App) vweb.Result {
    page := strconv.atoi(app.query['page'] or { '1' }) or { 1 }
    limit := strconv.atoi(app.query['limit'] or { '10' }) or { 10 }
    search := app.query['search'] or { '' }
    
    users, total := user.get_paginated(page, limit, search)
    
    return app.json({
        'data': users.map(it.to_public())
        'pagination': {
            'page': page
            'limit': limit
            'total': total
            'pages': (total + limit - 1) / limit
        }
    })
}

pub fn get_user(mut app server.App) vweb.Result {
    id := strconv.atoi(app.params['id'] or { '0' }) or { 0 }
    
    user_obj := user.get_by_id(id) or {
        app.set_status(404, 'Not Found')
        return app.json({
            'error': 'User not found'
        })
    }
    
    return app.json({
        'data': user_obj.to_public()
    })
}

pub fn create_user(mut app server.App) vweb.Result {
    // Only admins can create users directly
    if app.user.role != 'admin' {
        app.set_status(403, 'Forbidden')
        return app.json({
            'error': 'Admin access required'
        })
    }
    
    // Parse request body
    data := json.decode(CreateUserRequest, app.req.data) or {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': 'Invalid request body'
        })
    }
    
    // Validate input
    if err := middleware.validate_email(data.email) {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': err.message
            'field': err.field
        })
    }
    
    if err := middleware.validate_username(data.username) {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': err.message
            'field': err.field
        })
    }
    
    // Check if user exists
    existing := user.get_by_email(data.email) or { user.User{} }
    if existing.id != 0 {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': 'Email already registered'
        })
    }
    
    // Create user
    mut new_user := user.User{
        email: data.email
        username: data.username
        password_hash: hash.hash_password(data.password)
        role: data.role or { 'user' }
        created_at: time.now().unix
        updated_at: time.now().unix
    }
    
    new_user = user.create(new_user) or {
        app.set_status(500, 'Internal Server Error')
        return app.json({
            'error': 'Failed to create user'
        })
    }
    
    return app.json({
        'data': new_user.to_public()
        'message': 'User created successfully'
    })
}

pub fn update_user(mut app server.App) vweb.Result {
    id := strconv.atoi(app.params['id'] or { '0' }) or { 0 }
    
    // Users can only update their own profile, admins can update anyone
    if app.user.id != id && app.user.role != 'admin' {
        app.set_status(403, 'Forbidden')
        return app.json({
            'error': 'Cannot update other users'
        })
    }
    
    // Get existing user
    mut user_obj := user.get_by_id(id) or {
        app.set_status(404, 'Not Found')
        return app.json({
            'error': 'User not found'
        })
    }
    
    // Parse request body
    data := json.decode(UpdateUserRequest, app.req.data) or {
        app.set_status(400, 'Bad Request')
        return app.json({
            'error': 'Invalid request body'
        })
    }
    
    // Update fields
    if data.username != '' {
        if err := middleware.validate_username(data.username) {
            app.set_status(400, 'Bad Request')
            return app.json({
                'error': err.message
                'field': err.field
            })
        }
        user_obj.username = data.username
    }
    
    if data.email != '' && data.email != user_obj.email {
        if err := middleware.validate_email(data.email) {
            app.set_status(400, 'Bad Request')
            return app.json({
                'error': err.message
                'field': err.field
            })
        }
        
        // Check if email is taken
        existing := user.get_by_email(data.email) or { user.User{} }
        if existing.id != 0 {
            app.set_status(400, 'Bad Request')
            return app.json({
                'error': 'Email already in use'
            })
        }
        
        user_obj.email = data.email
    }
    
    // Only admins can change roles
    if data.role != '' && app.user.role == 'admin' {
        user_obj.role = data.role
    }
    
    user_obj.updated_at = time.now().unix
    
    // Update user
    user_obj = user.update(user_obj) or {
        app.set_status(500, 'Internal Server Error')
        return app.json({
            'error': 'Failed to update user'
        })
    }
    
    return app.json({
        'data': user_obj.to_public()
        'message': 'User updated successfully'
    })
}

pub fn delete_user(mut app server.App) vweb.Result {
    id := strconv.atoi(app.params['id'] or { '0' }) or { 0 }
    
    // Check if user exists
    user_obj := user.get_by_id(id) or {
        app.set_status(404, 'Not Found')
        return app.json({
            'error': 'User not found'
        })
    }
    
    // Delete user
    user.delete(id) or {
        app.set_status(500, 'Internal Server Error')
        return app.json({
            'error': 'Failed to delete user'
        })
    }
    
    return app.json({
        'message': 'User deleted successfully'
    })
}

struct CreateUserRequest {
    email string
    username string
    password string
    role ?string
}

struct UpdateUserRequest {
    email ?string
    username ?string
    role ?string
}
`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/models/user.v',
        content: `module user

import orm
import sqlite
import time

[table: 'users']
pub struct User {
pub mut:
    id int [primary; sql: serial]
    email string [unique]
    username string
    password_hash string
    role string
    created_at i64
    updated_at i64
}

pub fn (u User) to_public() map[string]json2.Any {
    return {
        'id': u.id
        'email': u.email
        'username': u.username
        'role': u.role
        'created_at': u.created_at
        'updated_at': u.updated_at
    }
}

// Database connection
__global db sqlite.DB

pub fn init_db() {
    db = sqlite.connect('./data/app.db') or {
        panic('Failed to connect to database: $err')
    }
    
    // Create tables
    sql db {
        create table User
    }
}

pub fn get_by_id(id int) ?User {
    users := sql db {
        select from User where id == id limit 1
    }
    if users.len == 0 {
        return none
    }
    return users[0]
}

pub fn get_by_email(email string) ?User {
    users := sql db {
        select from User where email == email limit 1
    }
    if users.len == 0 {
        return none
    }
    return users[0]
}

pub fn get_paginated(page int, limit int, search string) ([]User, int) {
    offset := (page - 1) * limit
    
    mut users := []User{}
    mut total := 0
    
    if search != '' {
        users = sql db {
            select from User where username like '%$search%' or email like '%$search%' limit limit offset offset
        }
        total = sql db {
            select count from User where username like '%$search%' or email like '%$search%'
        }
    } else {
        users = sql db {
            select from User limit limit offset offset
        }
        total = sql db {
            select count from User
        }
    }
    
    return users, total
}

pub fn create(user User) ?User {
    sql db {
        insert user into User
    }
    
    // Get the created user
    return get_by_email(user.email)
}

pub fn update(user User) ?User {
    sql db {
        update User set email = user.email, username = user.username, role = user.role, updated_at = user.updated_at where id == user.id
    }
    
    return get_by_id(user.id)
}

pub fn delete(id int) ? {
    sql db {
        delete from User where id == id
    }
}

// Refresh token management
__global refresh_tokens map[int][]string

pub fn save_refresh_token(user_id int, token string) {
    if user_id !in refresh_tokens {
        refresh_tokens[user_id] = []
    }
    refresh_tokens[user_id] << token
}

pub fn is_refresh_token_valid(user_id int, token string) bool {
    if user_id !in refresh_tokens {
        return false
    }
    return token in refresh_tokens[user_id]
}

pub fn invalidate_refresh_tokens(user_id int) {
    if user_id in refresh_tokens {
        delete(refresh_tokens, user_id)
    }
}
`
      },
      {
        path: 'src/models/base.v',
        content: `module models

import time

pub interface Model {
    id int
    created_at i64
    updated_at i64
}

pub fn (m Model) before_create() {
    m.created_at = time.now().unix
    m.updated_at = m.created_at
}

pub fn (m Model) before_update() {
    m.updated_at = time.now().unix
}
`
      }
    ];
  }

  protected generateUtilFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/utils/jwt.v',
        content: `module jwt

import crypto.hmac
import crypto.sha256
import encoding.base64
import json
import time
import src.config

struct JWTHeader {
    alg string = 'HS256'
    typ string = 'JWT'
}

struct JWTPayload {
pub mut:
    sub string
    exp i64
    iat i64
    role string
}

fn encode_part(data string) string {
    return base64.url_encode(data.bytes()).replace('=', '')
}

fn decode_part(data string) string {
    mut padded := data
    padding := (4 - data.len % 4) % 4
    padded += '='.repeat(padding)
    return base64.url_decode(padded)
}

pub fn generate_token(user_id int, role string, expires_in int) string {
    header := JWTHeader{}
    mut payload := JWTPayload{
        sub: user_id.str()
        iat: time.now().unix
        exp: time.now().unix + expires_in
        role: role
    }
    
    header_json := json.encode(header)
    payload_json := json.encode(payload)
    
    header_encoded := encode_part(header_json)
    payload_encoded := encode_part(payload_json)
    
    message := '$header_encoded.$payload_encoded'
    
    cfg := config.load()
    signature := hmac.new(cfg.jwt_secret.bytes(), message.bytes(), sha256.sum, sha256.block_size).hex()
    signature_encoded := encode_part(signature)
    
    return '$message.$signature_encoded'
}

pub fn verify_token(token string) ?map[string]json2.Any {
    parts := token.split('.')
    if parts.len != 3 {
        return error('Invalid token format')
    }
    
    message := '\${parts[0]}.\${parts[1]}'
    
    cfg := config.load()
    expected_signature := hmac.new(cfg.jwt_secret.bytes(), message.bytes(), sha256.sum, sha256.block_size).hex()
    expected_signature_encoded := encode_part(expected_signature)
    
    if parts[2] != expected_signature_encoded {
        return error('Invalid signature')
    }
    
    payload_json := decode_part(parts[1])
    payload := json.decode(map[string]json2.Any, payload_json) or {
        return error('Invalid payload')
    }
    
    // Check expiration
    exp := payload['exp'].i64()
    if exp < time.now().unix {
        return error('Token expired')
    }
    
    return payload
}

pub fn generate_access_token(user models.User) string {
    cfg := config.load()
    return generate_token(user.id, user.role, cfg.jwt_expires_in)
}

pub fn generate_refresh_token(user models.User) string {
    cfg := config.load()
    return generate_token(user.id, 'refresh', cfg.refresh_token_expires_in)
}

pub fn verify_refresh_token(token string) ?map[string]json2.Any {
    payload := verify_token(token)?
    
    if payload['role'].str() != 'refresh' {
        return error('Not a refresh token')
    }
    
    return payload
}
`
      },
      {
        path: 'src/utils/hash.v',
        content: `module hash

import crypto.bcrypt

pub fn hash_password(password string) string {
    return bcrypt.generate_from_password(password.bytes(), 10) or {
        panic('Failed to hash password: $err')
    }
}

pub fn verify_password(password string, hash string) bool {
    return bcrypt.compare_hash_and_password(password.bytes(), hash.bytes()) or {
        return false
    }
}
`
      },
      {
        path: 'src/utils/helpers.v',
        content: `module utils

import rand
import time
import json

pub fn generate_uuid() string {
    mut uuid := ''
    
    // Generate UUID v4
    for i in 0 .. 16 {
        if i == 6 {
            // Version 4
            uuid += rand.hex_string(1)[0..1]
            uuid += '4'
        } else if i == 8 {
            // Variant
            choices := ['8', '9', 'a', 'b']
            uuid += choices[rand.int_u64(4)]
            uuid += rand.hex_string(1)[0..1]
        } else {
            uuid += rand.hex_string(2)
        }
        
        if i in [3, 5, 7, 9] {
            uuid += '-'
        }
    }
    
    return uuid
}

pub fn sanitize_input(input string) string {
    return input
        .replace('<', '&lt;')
        .replace('>', '&gt;')
        .replace('"', '&quot;')
        .replace("'", '&#x27;')
        .replace('/', '&#x2F;')
}

pub fn paginate<T>(items []T, page int, page_size int) ([]T, int) {
    total := items.len
    start := (page - 1) * page_size
    end := start + page_size
    
    if start >= total {
        return []T{}, total
    }
    
    if end > total {
        end = total
    }
    
    return items[start..end], total
}

pub fn format_timestamp(ts i64) string {
    t := time.unix(ts)
    return t.format()
}

pub fn parse_int_param(value string, default_value int) int {
    return value.int() or { default_value }
}

pub fn respond_json(data map[string]json2.Any) string {
    return json.encode(data)
}

pub fn respond_error(message string, code string) map[string]json2.Any {
    return {
        'success': false
        'error': message
        'code': code
    }
}

pub fn respond_success(data json2.Any, message string) map[string]json2.Any {
    return {
        'success': true
        'data': data
        'message': message
    }
}
`
      }
    ];
  }

  protected generateConfigFile(): string {
    return `module config

import os
import strconv

pub struct Config {
pub:
    // Server
    host string
    port int
    app_env string
    
    // Database
    database_url string
    
    // Security
    jwt_secret string
    jwt_expires_in int
    refresh_token_expires_in int
    
    // CORS
    cors_origins []string
    
    // Rate limiting
    rate_limit_max int
    rate_limit_window int
    
    // Logging
    log_level string
    log_file string
    
    // Redis (optional)
    redis_url string
}

pub fn load() Config {
    return Config{
        host: os.getenv_opt('HOST') or { '0.0.0.0' }
        port: strconv.atoi(os.getenv_opt('PORT') or { '8080' }) or { 8080 }
        app_env: os.getenv_opt('APP_ENV') or { 'development' }
        
        database_url: os.getenv_opt('DATABASE_URL') or { 'sqlite://./data/app.db' }
        
        jwt_secret: os.getenv_opt('JWT_SECRET') or { 'your-secret-key-change-in-production' }
        jwt_expires_in: strconv.atoi(os.getenv_opt('JWT_EXPIRES_IN') or { '3600' }) or { 3600 }
        refresh_token_expires_in: strconv.atoi(os.getenv_opt('REFRESH_TOKEN_EXPIRES_IN') or { '604800' }) or { 604800 }
        
        cors_origins: (os.getenv_opt('CORS_ORIGINS') or { '*' }).split(',')
        
        rate_limit_max: strconv.atoi(os.getenv_opt('RATE_LIMIT_MAX') or { '100' }) or { 100 }
        rate_limit_window: strconv.atoi(os.getenv_opt('RATE_LIMIT_WINDOW') or { '60' }) or { 60 }
        
        log_level: os.getenv_opt('LOG_LEVEL') or { 'info' }
        log_file: os.getenv_opt('LOG_FILE') or { './logs/app.log' }
        
        redis_url: os.getenv_opt('REDIS_URL') or { '' }
    }
}

pub fn (c Config) is_development() bool {
    return c.app_env == 'development'
}

pub fn (c Config) is_production() bool {
    return c.app_env == 'production'
}

pub fn (c Config) is_test() bool {
    return c.app_env == 'test'
}
`;
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'tests/health_test.v',
        content: `module tests

import net.http
import json

fn test_health_endpoint() {
    // Make request to health endpoint
    resp := http.get('http://localhost:8080/health') or {
        assert false, 'Failed to connect to server'
        return
    }
    
    assert resp.status_code == 200
    
    // Parse response
    data := json.decode(map[string]json2.Any, resp.body) or {
        assert false, 'Failed to parse JSON response'
        return
    }
    
    assert data['status'].str() == 'healthy'
    assert data['service'].str() == 'vweb-service'
    assert 'version' in data
    assert 'timestamp' in data
}
`
      },
      {
        path: 'tests/auth_test.v',
        content: `module tests

import net.http
import json

fn test_register() {
    // Test user registration
    body := json.encode({
        'email': 'test@example.com'
        'username': 'testuser'
        'password': 'TestPassword123!'
    })
    
    mut req := http.new_request(.post, 'http://localhost:8080/api/auth/register', body)
    req.add_header(.content_type, 'application/json')
    
    resp := req.do() or {
        assert false, 'Failed to make request'
        return
    }
    
    assert resp.status_code == 200
    
    data := json.decode(map[string]json2.Any, resp.body) or {
        assert false, 'Failed to parse response'
        return
    }
    
    assert 'user' in data
    assert 'access_token' in data
    assert 'refresh_token' in data
}

fn test_login() {
    // Test user login
    body := json.encode({
        'email': 'test@example.com'
        'password': 'TestPassword123!'
    })
    
    mut req := http.new_request(.post, 'http://localhost:8080/api/auth/login', body)
    req.add_header(.content_type, 'application/json')
    
    resp := req.do() or {
        assert false, 'Failed to make request'
        return
    }
    
    assert resp.status_code == 200
    
    data := json.decode(map[string]json2.Any, resp.body) or {
        assert false, 'Failed to parse response'
        return
    }
    
    assert 'user' in data
    assert 'access_token' in data
    assert 'refresh_token' in data
}

fn test_invalid_login() {
    // Test invalid credentials
    body := json.encode({
        'email': 'test@example.com'
        'password': 'wrongpassword'
    })
    
    mut req := http.new_request(.post, 'http://localhost:8080/api/auth/login', body)
    req.add_header(.content_type, 'application/json')
    
    resp := req.do() or {
        assert false, 'Failed to make request'
        return
    }
    
    assert resp.status_code == 401
    
    data := json.decode(map[string]json2.Any, resp.body) or {
        assert false, 'Failed to parse response'
        return
    }
    
    assert 'error' in data
}
`
      },
      {
        path: 'tests/user_test.v',
        content: `module tests

import net.http
import json

fn test_list_users_requires_auth() {
    // Test that listing users requires authentication
    resp := http.get('http://localhost:8080/api/users') or {
        assert false, 'Failed to make request'
        return
    }
    
    assert resp.status_code == 401
}

fn test_list_users_with_auth() {
    // First, get a token
    token := get_test_token()
    
    // Make authenticated request
    mut req := http.new_request(.get, 'http://localhost:8080/api/users', '')
    req.add_header(.authorization, 'Bearer $token')
    
    resp := req.do() or {
        assert false, 'Failed to make request'
        return
    }
    
    assert resp.status_code == 200
    
    data := json.decode(map[string]json2.Any, resp.body) or {
        assert false, 'Failed to parse response'
        return
    }
    
    assert 'data' in data
    assert 'pagination' in data
}

fn get_test_token() string {
    // Helper function to get auth token
    body := json.encode({
        'email': 'test@example.com'
        'password': 'TestPassword123!'
    })
    
    mut req := http.new_request(.post, 'http://localhost:8080/api/auth/login', body)
    req.add_header(.content_type, 'application/json')
    
    resp := req.do() or {
        panic('Failed to get test token')
    }
    
    data := json.decode(map[string]json2.Any, resp.body) or {
        panic('Failed to parse token response')
    }
    
    return data['access_token'].str()
}
`
      }
    ];
  }

  protected async generateProjectStructure(projectPath: string, options: any): Promise<void> {
    // Create additional directories
    await fs.mkdir(path.join(projectPath, 'data'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'logs'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'scripts'), { recursive: true });

    // Generate development script
    const devScriptContent = `#!/bin/bash
# Development script for Vweb

# Colors for output
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

echo -e "\\\${GREEN}Starting Vweb development environment...\\\${NC}"

# Check if V is installed
if ! command -v v &> /dev/null; then
    echo -e "\\\${YELLOW}V is not installed. Please install V first.\\\${NC}"
    echo "Visit: https://vlang.io"
    exit 1
fi

# Install dependencies
echo -e "\\\${GREEN}Installing dependencies...\\\${NC}"
v install

# Initialize database
echo -e "\\\${GREEN}Initializing database...\\\${NC}"
mkdir -p data
touch data/app.db

# Start development server with hot reload
echo -e "\\\${GREEN}Starting development server with hot reload...\\\${NC}"
v watch run .
`;

    await fs.writeFile(path.join(projectPath, 'scripts', 'dev.sh'), devScriptContent);
    await fs.chmod(path.join(projectPath, 'scripts', 'dev.sh'), '755');

    // Generate production build script
    const buildScriptContent = `#!/bin/bash
# Production build script for Vweb

set -e

echo "Building Vweb application for production..."

# Build with optimizations
echo "Building optimized binary..."
v -prod -cc clang -cflags "-O3 -flto" .

echo "Production build complete!"
echo "Run './server' to start the application"
`;

    await fs.writeFile(path.join(projectPath, 'scripts', 'build.sh'), buildScriptContent);
    await fs.chmod(path.join(projectPath, 'scripts', 'build.sh'), '755');

    // Generate example static files
    const indexHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vweb Service</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <h1>Welcome to Vweb!</h1>
    <p>This is a static HTML file served by Vweb.</p>
    <script src="/js/app.js"></script>
</body>
</html>
`;

    await fs.writeFile(path.join(projectPath, 'public', 'index.html'), indexHtml);

    const styleCss = `/* Basic styles for Vweb application */
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.6;
    margin: 0;
    padding: 20px;
    max-width: 1200px;
    margin: 0 auto;
}

h1 {
    color: #333;
}

.container {
    background: #f4f4f4;
    padding: 20px;
    border-radius: 5px;
}
`;

    await fs.writeFile(path.join(projectPath, 'public', 'css', 'style.css'), styleCss);

    const appJs = `// Client-side JavaScript for Vweb application
console.log('Vweb application loaded');
`;

    await fs.writeFile(path.join(projectPath, 'public', 'js', 'app.js'), appJs);
  }
}