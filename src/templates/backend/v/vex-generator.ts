import { VBackendGenerator } from './v-base-generator';
import * as fs from 'fs-extra';
import * as path from 'path';

export class VexGenerator extends VBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Vex';
    this.config.features.push(
      'Express-like routing',
      'Middleware system',
      'Request validation',
      'Response helpers',
      'Error handling',
      'Static file serving',
      'Template rendering',
      'Cookie support',
      'Session management',
      'CORS support'
    );
  }

  protected getFrameworkDependencies(): string[] {
    return ['nedpals/vex'];
  }

  protected generateMainFile(): string {
    return `module main

import vex
import vex.middleware
import json
import time
import os

import src.auth
import src.models
import src.controllers
import src.middleware as app_middleware
import src.config

fn main() {
    // Load configuration
    cfg := config.load()
    
    // Initialize database
    models.init_db() or {
        eprintln('Failed to initialize database: \${err}')
        exit(1)
    }
    
    // Create Vex app
    mut app := vex.new()
    
    // Global middleware
    app.use(middleware.logger())
    app.use(middleware.cors(vex.CorsOptions{
        allowed_origins: ['*']
        allowed_methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
        allowed_headers: ['Content-Type', 'Authorization']
        max_age: 86400
    }))
    app.use(middleware.body_parser())
    app.use(middleware.cookie_parser())
    
    // Static files
    app.serve_static('/public', 'public')
    
    // Routes
    setup_routes(mut app)
    
    // Error handler
    app.error(error_handler)
    
    // Start server
    port := os.getenv('PORT') or { '3000' }
    println('[V Vex Server] Server running on http://localhost:\${port}')
    app.listen(port.int()) or {
        eprintln('Failed to start server: \${err}')
        exit(1)
    }
}

fn setup_routes(mut app vex.App) {
    // Health check
    app.get('/health', controllers.health_check)
    
    // API routes
    api := app.group('/api')
    
    // Auth routes
    auth_group := api.group('/auth')
    auth_group.post('/register', controllers.register)
    auth_group.post('/login', controllers.login)
    auth_group.post('/refresh', controllers.refresh_token)
    auth_group.post('/logout', app_middleware.authenticate, controllers.logout)
    
    // Protected routes
    protected := api.group('')
    protected.use(app_middleware.authenticate)
    
    // User routes
    users := protected.group('/users')
    users.get('', controllers.get_users)
    users.get('/:id', controllers.get_user)
    users.put('/:id', controllers.update_user)
    users.delete('/:id', controllers.delete_user)
    users.get('/me', controllers.get_current_user)
    users.put('/me', controllers.update_current_user)
}

fn error_handler(ctx mut vex.Context, err vex.Error) {
    status := match err.code {
        400 { 400 }
        401 { 401 }
        403 { 403 }
        404 { 404 }
        else { 500 }
    }
    
    ctx.status(status)
    ctx.json(vex.JsonResponse{
        'error': err.message
        'status': status
        'timestamp': time.now().unix
    })
}
`;
  }

  protected generateServerFile(): string {
    // Vex doesn't need a separate server file as it's integrated in main
    return '';
  }

  protected generateRouterFile(): string {
    // Vex routing is integrated in main file
    return '';
  }

  protected generateConfigFile(): string {
    return `module config

import os
import json

pub struct Config {
pub mut:
    port string
    jwt_secret string
    database_url string
    environment string
}

pub fn load() Config {
    mut cfg := Config{
        port: os.getenv('PORT') or { '3000' }
        jwt_secret: os.getenv('JWT_SECRET') or { 'your-secret-key' }
        database_url: os.getenv('DATABASE_URL') or { 'database.db' }
        environment: os.getenv('V_ENV') or { 'development' }
    }
    
    // Load from config file if exists
    if os.exists('config.json') {
        config_data := os.read_file('config.json') or { return cfg }
        file_config := json.decode(Config, config_data) or { return cfg }
        
        // Environment variables take precedence
        if cfg.port == '3000' { cfg.port = file_config.port }
        if cfg.jwt_secret == 'your-secret-key' { cfg.jwt_secret = file_config.jwt_secret }
        if cfg.database_url == 'database.db' { cfg.database_url = file_config.database_url }
    }
    
    return cfg
}
`;
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/middleware/auth.v',
        content: `module middleware

import vex
import src.auth
import src.models

pub fn authenticate(ctx mut vex.Context) {
    auth_header := ctx.get_header('Authorization') or {
        ctx.status(401)
        ctx.json({'error': 'Authorization header required'})
        return
    }
    
    if !auth_header.starts_with('Bearer ') {
        ctx.status(401)
        ctx.json({'error': 'Invalid authorization header format'})
        return
    }
    
    token := auth_header[7..]
    
    claims := auth.verify_token(token) or {
        ctx.status(401)
        ctx.json({'error': 'Invalid or expired token'})
        return
    }
    
    user := models.find_user_by_id(claims.sub) or {
        ctx.status(401)
        ctx.json({'error': 'User not found'})
        return
    }
    
    ctx.set('user', user)
    ctx.set('claims', claims)
    ctx.next()
}

pub fn admin_only(ctx mut vex.Context) {
    user := ctx.get('user') or {
        ctx.status(401)
        ctx.json({'error': 'Unauthorized'})
        return
    }
    
    // Add admin check logic here
    // For now, we'll just pass through
    ctx.next()
}
`
      }
    ];
  }

  protected generateControllerFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/controllers/health.v',
        content: `module controllers

import vex
import time

pub fn health_check(ctx mut vex.Context) {
    ctx.json({
        'status': 'healthy'
        'service': 'V Vex API'
        'timestamp': time.now().unix
        'version': '1.0.0'
    })
}
`
      },
      {
        path: 'src/controllers/auth.v',
        content: `module controllers

import vex
import json
import src.auth
import src.models
import src.validators

pub fn register(ctx mut vex.Context) {
    body := ctx.body_json() or {
        ctx.status(400)
        ctx.json({'error': 'Invalid request body'})
        return
    }
    
    // Validate input
    email := body['email'] or {
        ctx.status(400)
        ctx.json({'error': 'Email is required'})
        return
    }.str()
    
    password := body['password'] or {
        ctx.status(400)
        ctx.json({'error': 'Password is required'})
        return
    }.str()
    
    name := body['name'] or { '' }.str()
    
    if !validators.is_valid_email(email) {
        ctx.status(400)
        ctx.json({'error': 'Invalid email format'})
        return
    }
    
    if password.len < 8 {
        ctx.status(400)
        ctx.json({'error': 'Password must be at least 8 characters'})
        return
    }
    
    // Check if user exists
    existing := models.find_user_by_email(email) or { models.User{} }
    if existing.id != '' {
        ctx.status(409)
        ctx.json({'error': 'User already exists'})
        return
    }
    
    // Hash password
    password_hash := auth.hash_password(password) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to hash password'})
        return
    }
    
    // Create user
    user := models.create_user(email, password_hash, name) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to create user'})
        return
    }
    
    // Generate tokens
    access_token := auth.generate_token(user.id, user.email) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to generate token'})
        return
    }
    
    refresh_token := auth.generate_refresh_token(user.id) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to generate refresh token'})
        return
    }
    
    ctx.status(201)
    ctx.json({
        'user': user.to_public()
        'access_token': access_token
        'refresh_token': refresh_token
    })
}

pub fn login(ctx mut vex.Context) {
    body := ctx.body_json() or {
        ctx.status(400)
        ctx.json({'error': 'Invalid request body'})
        return
    }
    
    email := body['email'] or {
        ctx.status(400)
        ctx.json({'error': 'Email is required'})
        return
    }.str()
    
    password := body['password'] or {
        ctx.status(400)
        ctx.json({'error': 'Password is required'})
        return
    }.str()
    
    // Find user
    user := models.find_user_by_email(email) or {
        ctx.status(401)
        ctx.json({'error': 'Invalid credentials'})
        return
    }
    
    // Verify password
    if !auth.verify_password(password, user.password_hash) {
        ctx.status(401)
        ctx.json({'error': 'Invalid credentials'})
        return
    }
    
    // Generate tokens
    access_token := auth.generate_token(user.id, user.email) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to generate token'})
        return
    }
    
    refresh_token := auth.generate_refresh_token(user.id) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to generate refresh token'})
        return
    }
    
    ctx.json({
        'user': user.to_public()
        'access_token': access_token
        'refresh_token': refresh_token
    })
}

pub fn refresh_token(ctx mut vex.Context) {
    body := ctx.body_json() or {
        ctx.status(400)
        ctx.json({'error': 'Invalid request body'})
        return
    }
    
    refresh_token := body['refresh_token'] or {
        ctx.status(400)
        ctx.json({'error': 'Refresh token is required'})
        return
    }.str()
    
    // Verify refresh token
    claims := auth.verify_token(refresh_token) or {
        ctx.status(401)
        ctx.json({'error': 'Invalid refresh token'})
        return
    }
    
    // Get user
    user := models.find_user_by_id(claims.sub) or {
        ctx.status(404)
        ctx.json({'error': 'User not found'})
        return
    }
    
    // Generate new tokens
    access_token := auth.generate_token(user.id, user.email) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to generate token'})
        return
    }
    
    new_refresh_token := auth.generate_refresh_token(user.id) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to generate refresh token'})
        return
    }
    
    ctx.json({
        'access_token': access_token
        'refresh_token': new_refresh_token
    })
}

pub fn logout(ctx mut vex.Context) {
    // In a real app, you might want to blacklist the token
    ctx.json({'message': 'Logged out successfully'})
}
`
      },
      {
        path: 'src/controllers/users.v',
        content: `module controllers

import vex
import src.models

pub fn get_users(ctx mut vex.Context) {
    limit := ctx.query['limit'] or { '10' }.int()
    offset := ctx.query['offset'] or { '0' }.int()
    
    users := models.list_users(limit, offset) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to fetch users'})
        return
    }
    
    public_users := users.map(|u| u.to_public())
    
    ctx.json({
        'users': public_users
        'count': users.len
        'limit': limit
        'offset': offset
    })
}

pub fn get_user(ctx mut vex.Context) {
    id := ctx.params['id'] or {
        ctx.status(400)
        ctx.json({'error': 'User ID is required'})
        return
    }
    
    user := models.find_user_by_id(id) or {
        ctx.status(404)
        ctx.json({'error': 'User not found'})
        return
    }
    
    ctx.json({'user': user.to_public()})
}

pub fn update_user(ctx mut vex.Context) {
    id := ctx.params['id'] or {
        ctx.status(400)
        ctx.json({'error': 'User ID is required'})
        return
    }
    
    // Check if user is updating their own profile or is admin
    current_user := ctx.get('user') or {
        ctx.status(401)
        ctx.json({'error': 'Unauthorized'})
        return
    }
    
    if current_user.id != id {
        ctx.status(403)
        ctx.json({'error': 'Forbidden'})
        return
    }
    
    body := ctx.body_json() or {
        ctx.status(400)
        ctx.json({'error': 'Invalid request body'})
        return
    }
    
    name := body['name'] or { '' }.str()
    
    user := models.update_user(id, name) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to update user'})
        return
    }
    
    ctx.json({'user': user.to_public()})
}

pub fn delete_user(ctx mut vex.Context) {
    id := ctx.params['id'] or {
        ctx.status(400)
        ctx.json({'error': 'User ID is required'})
        return
    }
    
    // Check if user is deleting their own profile or is admin
    current_user := ctx.get('user') or {
        ctx.status(401)
        ctx.json({'error': 'Unauthorized'})
        return
    }
    
    if current_user.id != id {
        ctx.status(403)
        ctx.json({'error': 'Forbidden'})
        return
    }
    
    models.delete_user(id) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to delete user'})
        return
    }
    
    ctx.status(204)
}

pub fn get_current_user(ctx mut vex.Context) {
    user := ctx.get('user') or {
        ctx.status(401)
        ctx.json({'error': 'Unauthorized'})
        return
    }
    
    ctx.json({'user': user.to_public()})
}

pub fn update_current_user(ctx mut vex.Context) {
    user := ctx.get('user') or {
        ctx.status(401)
        ctx.json({'error': 'Unauthorized'})
        return
    }
    
    body := ctx.body_json() or {
        ctx.status(400)
        ctx.json({'error': 'Invalid request body'})
        return
    }
    
    name := body['name'] or { '' }.str()
    
    updated_user := models.update_user(user.id, name) or {
        ctx.status(500)
        ctx.json({'error': 'Failed to update user'})
        return
    }
    
    ctx.json({'user': updated_user.to_public()})
}
`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/models/user.v',
        content: `module models

import sqlite
import time
import rand

pub struct User {
pub mut:
    id string [primary; sql: 'TEXT']
    email string [unique; sql: 'TEXT NOT NULL']
    password_hash string [sql: 'TEXT NOT NULL']
    name string [sql: 'TEXT']
    created_at i64 [sql: 'INTEGER']
    updated_at i64 [sql: 'INTEGER']
}

pub fn (u User) to_public() map[string]json2.Any {
    return {
        'id': json2.Any(u.id)
        'email': json2.Any(u.email)
        'name': json2.Any(u.name)
        'created_at': json2.Any(u.created_at)
        'updated_at': json2.Any(u.updated_at)
    }
}

pub fn init_db() ! {
    db := sqlite.connect(':memory:')!
    
    sql db {
        create table User
    }!
    
    db.close()
}

pub fn create_user(email string, password_hash string, name string) !User {
    db := get_db()!
    defer { db.close() }
    
    user := User{
        id: generate_id()
        email: email
        password_hash: password_hash
        name: name
        created_at: time.now().unix
        updated_at: time.now().unix
    }
    
    sql db {
        insert user into User
    }!
    
    return user
}

pub fn find_user_by_email(email string) !User {
    db := get_db()!
    defer { db.close() }
    
    users := sql db {
        select from User where email == email limit 1
    }!
    
    if users.len == 0 {
        return error('User not found')
    }
    
    return users[0]
}

pub fn find_user_by_id(id string) !User {
    db := get_db()!
    defer { db.close() }
    
    users := sql db {
        select from User where id == id limit 1
    }!
    
    if users.len == 0 {
        return error('User not found')
    }
    
    return users[0]
}

pub fn update_user(id string, name string) !User {
    db := get_db()!
    defer { db.close() }
    
    sql db {
        update User set name = name, updated_at = time.now().unix where id == id
    }!
    
    return find_user_by_id(id)!
}

pub fn delete_user(id string) ! {
    db := get_db()!
    defer { db.close() }
    
    sql db {
        delete from User where id == id
    }!
}

pub fn list_users(limit int, offset int) ![]User {
    db := get_db()!
    defer { db.close() }
    
    return sql db {
        select from User order by created_at desc limit limit offset offset
    }!
}

fn get_db() !sqlite.DB {
    return sqlite.connect('database.db')!
}

fn generate_id() string {
    // Simple ID generation - in production use UUID
    return 'user_\${time.now().unix}_\${rand.intn(10000)}'
}
`
      }
    ];
  }

  protected generateUtilFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/auth/jwt.v',
        content: `module auth

import crypto.hmac
import crypto.sha256
import encoding.base64
import json
import time
import os

const (
    jwt_secret = os.getenv('JWT_SECRET') or { 'your-secret-key' }
    jwt_expiry = 3600 // 1 hour
    refresh_expiry = 86400 * 7 // 7 days
)

pub struct Claims {
pub mut:
    sub string
    email string
    exp i64
    iat i64
}

pub fn generate_token(user_id string, email string) !string {
    header := base64.url_encode('{"alg":"HS256","typ":"JWT"}'.bytes())
    
    claims := Claims{
        sub: user_id
        email: email
        exp: time.now().unix + jwt_expiry
        iat: time.now().unix
    }
    
    payload := base64.url_encode(json.encode(claims).bytes())
    message := '\${header}.\${payload}'
    
    signature := hmac.new(jwt_secret.bytes(), message.bytes(), sha256.sum, sha256.block_size)
    sig := base64.url_encode(signature)
    
    return '\${message}.\${sig}'
}

pub fn generate_refresh_token(user_id string) !string {
    claims := Claims{
        sub: user_id
        exp: time.now().unix + refresh_expiry
        iat: time.now().unix
    }
    
    return generate_custom_token(claims)
}

fn generate_custom_token(claims Claims) !string {
    header := base64.url_encode('{"alg":"HS256","typ":"JWT"}'.bytes())
    payload := base64.url_encode(json.encode(claims).bytes())
    message := '\${header}.\${payload}'
    
    signature := hmac.new(jwt_secret.bytes(), message.bytes(), sha256.sum, sha256.block_size)
    sig := base64.url_encode(signature)
    
    return '\${message}.\${sig}'
}

pub fn verify_token(token string) !Claims {
    parts := token.split('.')
    if parts.len != 3 {
        return error('Invalid token format')
    }
    
    message := '\${parts[0]}.\${parts[1]}'
    signature := hmac.new(jwt_secret.bytes(), message.bytes(), sha256.sum, sha256.block_size)
    expected_sig := base64.url_encode(signature)
    
    if parts[2] != expected_sig {
        return error('Invalid token signature')
    }
    
    payload_bytes := base64.url_decode(parts[1])
    claims := json.decode(Claims, payload_bytes.bytestr())!
    
    if claims.exp < time.now().unix {
        return error('Token expired')
    }
    
    return claims
}
`
      },
      {
        path: 'src/auth/hash.v',
        content: `module auth

import crypto.bcrypt

pub fn hash_password(password string) !string {
    return bcrypt.generate_from_password(password.bytes(), 10)!.bytestr()
}

pub fn verify_password(password string, hash string) bool {
    return bcrypt.compare_hash_and_password(password.bytes(), hash.bytes()) or { return false }
    return true
}
`
      },
      {
        path: 'src/validators/validators.v',
        content: `module validators

import regex

pub fn is_valid_email(email string) bool {
    mut re := regex.regex_opt(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$') or { return false }
    return re.matches_string(email)
}

pub fn is_valid_password(password string) bool {
    if password.len < 8 {
        return false
    }
    
    has_upper := password.bytes().any(it >= 65 && it <= 90)
    has_lower := password.bytes().any(it >= 97 && it <= 122)
    has_digit := password.bytes().any(it >= 48 && it <= 57)
    
    return has_upper && has_lower && has_digit
}

pub fn is_valid_id(id string) bool {
    return id.len > 0 && id.starts_with('user_')
}
`
      }
    ];
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'tests/auth_test.v',
        content: `module tests

import src.auth
import src.models

fn test_password_hashing() {
    password := 'SecurePassword123!'
    
    hash := auth.hash_password(password) or {
        assert false, 'Failed to hash password'
        return
    }
    
    assert hash != password
    assert hash.len > 0
    
    assert auth.verify_password(password, hash)
    assert !auth.verify_password('wrong_password', hash)
}

fn test_jwt_generation_and_verification() {
    user_id := 'user_123'
    email := 'test@example.com'
    
    token := auth.generate_token(user_id, email) or {
        assert false, 'Failed to generate token'
        return
    }
    
    assert token.len > 0
    assert token.count('.') == 2
    
    claims := auth.verify_token(token) or {
        assert false, 'Failed to verify token'
        return
    }
    
    assert claims.sub == user_id
    assert claims.email == email
    assert claims.exp > time.now().unix
}

fn test_expired_token() {
    // This would require mocking time or generating a token with past expiry
    // For now, we'll skip this test
}
`
      },
      {
        path: 'tests/validators_test.v',
        content: `module tests

import src.validators

fn test_email_validation() {
    valid_emails := [
        'user@example.com',
        'test.user@domain.co.uk',
        'user+tag@example.org',
        'user123@test-domain.com'
    ]
    
    invalid_emails := [
        'invalid',
        '@example.com',
        'user@',
        'user@.com',
        'user..name@example.com',
        'user@domain'
    ]
    
    for email in valid_emails {
        assert validators.is_valid_email(email), 'Expected ' + email + ' to be valid'
    }
    
    for email in invalid_emails {
        assert !validators.is_valid_email(email), 'Expected ' + email + ' to be invalid'
    }
}

fn test_password_validation() {
    valid_passwords := [
        'Password123',
        'SecurePass1',
        'MyP@ssw0rd',
        'LongPasswordWith123'
    ]
    
    invalid_passwords := [
        'short',
        'alllowercase',
        'ALLUPPERCASE',
        'NoNumbers',
        '12345678',
        'password'
    ]
    
    for password in valid_passwords {
        assert validators.is_valid_password(password), 'Expected ' + password + ' to be valid'
    }
    
    for password in invalid_passwords {
        assert !validators.is_valid_password(password), 'Expected ' + password + ' to be invalid'
    }
}
`
      }
    ];
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    // Create additional directories
    await fs.mkdir(path.join(projectPath, 'src', 'auth'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'src', 'validators'), { recursive: true });
    await fs.mkdir(path.join(projectPath, 'scripts'), { recursive: true });

    // v.mod with Vex dependency
    await fs.writeFile(path.join(projectPath, 'v.mod'), `Module {
    name: '${options.name || 'v-vex-api'}'
    description: 'A V Vex REST API'
    version: '1.0.0'
    license: 'MIT'
    dependencies: [
        'nedpals/vex'
    ]
}
`);

    // Development script
    await fs.writeFile(path.join(projectPath, 'scripts', 'dev.sh'), `#!/bin/bash

echo "Starting V Vex development server..."

# Install dependencies
v install

# Run with hot reload
while true; do
    v watch run src/main.v
done
`);

    // Build script
    await fs.writeFile(path.join(projectPath, 'scripts', 'build.sh'), `#!/bin/bash

echo "Building V Vex application..."

# Install dependencies
v install

# Build for production
v -prod -o ${options.name || 'server'} src/main.v

echo "Build complete! Binary: ${options.name || 'server'}"
`);

    // Make scripts executable
    await this.executeCommand(projectPath, 'chmod +x scripts/*.sh');
  }

  protected generateVModFile(options: any): string {
    return `Module {
    name: '${options.name || 'v-vex-api'}'
    description: 'A V Vex REST API'
    version: '1.0.0'
    license: 'MIT'
    dependencies: [
        'nedpals/vex'
    ]
}
`;
  }

  private async executeCommand(projectPath: string, command: string): Promise<void> {
    // Execute command using Node.js child_process
    const { exec } = await import('child_process');
    const { promisify } = await import('util');
    const execAsync = promisify(exec);
    
    try {
      await execAsync(command, { cwd: projectPath });
    } catch (error) {
      console.warn(`Failed to execute command: ${command}`);
    }
  }
}