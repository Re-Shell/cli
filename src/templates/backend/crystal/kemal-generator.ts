import { CrystalBackendGenerator } from './crystal-base-generator';

export class KemalGenerator extends CrystalBackendGenerator {
  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'kemal': '~> 1.4.0',
      'granite': '~> 0.22.0',
      'pg': '~> 0.26.0',
      'redis': '~> 2.9.0',
      'jwt': '~> 1.5.0',
      'crypto': '~> 0.1.0',
      'json': '~> 0.1.0'
    };
  }

  protected generateMainFile(): string {
    return `require "kemal"
require "json"
require "jwt"
require "pg"
require "redis"
require "granite"
require "./config/*"
require "./models/*"
require "./services/*"
require "./middleware/*"
require "./controllers/*"

# Configure Granite (ORM)
Granite::Connections << Granite::Adapter::Pg.new(name: "pg", url: ENV["DATABASE_URL"])

# Configure Redis
REDIS_CLIENT = Redis.new(url: ENV["REDIS_URL"]? || "redis://localhost:6379")

# Middleware
add_handler AuthMiddleware.new
add_handler CORSMiddleware.new

# Health check
get "/health" do |env|
  env.response.content_type = "application/json"
  {
    status: "OK",
    timestamp: Time.local.to_rfc3339,
    service: ENV["APP_NAME"]? || "Kemal API",
    version: "1.0.0"
  }.to_json
end

# Authentication routes
post "/api/auth/register" do |env|
  AuthController.new.register(env)
end

post "/api/auth/login" do |env|
  AuthController.new.login(env)
end

post "/api/auth/refresh" do |env|
  AuthController.new.refresh(env)
end

# Protected routes
before "/api/users*" do |env|
  AuthMiddleware.authenticate!(env)
end

get "/api/auth/me" do |env|
  AuthController.new.me(env)
end

get "/api/users" do |env|
  UserController.new.index(env)
end

post "/api/users" do |env|
  UserController.new.create(env)
end

get "/api/users/:id" do |env|
  UserController.new.show(env)
end

put "/api/users/:id" do |env|
  UserController.new.update(env)
end

delete "/api/users/:id" do |env|
  UserController.new.delete(env)
end

# Error handlers
error 404 do |env|
  env.response.content_type = "application/json"
  env.response.status_code = 404
  {error: "Not Found", message: "The requested resource was not found"}.to_json
end

error 500 do |env, ex|
  env.response.content_type = "application/json"
  env.response.status_code = 500
  {error: "Internal Server Error", message: "An unexpected error occurred"}.to_json
end

# Start server
Kemal.config.host_binding = ENV["HOST"]? || "0.0.0.0"
Kemal.config.port = (ENV["PORT"]? || "8080").to_i
Kemal.config.env = ENV["CRYSTAL_ENV"]? || "development"

puts "🚀 Kemal server starting on http://#{Kemal.config.host_binding}:#{Kemal.config.port}"
Kemal.run`;
  }

  protected generateRoutingFile(): string {
    return `# Routes are defined in main.cr for Kemal
# This file exists for consistency with other frameworks`;
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/services/user_service.cr',
        content: `require "crypto/bcrypt/password"

class UserService
  def self.create_user(name : String, email : String, password : String, role : String = "user") : User
    # Check if email already exists
    existing_user = User.find_by(email: email)
    raise "Email already exists" if existing_user

    # Hash password
    password_hash = Crypto::Bcrypt::Password.create(password).to_s

    # Create user
    user = User.new
    user.name = name
    user.email = email
    user.password_hash = password_hash
    user.role = role
    user.is_active = true

    unless user.save
      raise "Failed to create user: #{user.errors.join(", ")}"
    end

    user
  end

  def self.update_user(user : User, name : String?, email : String?, password : String?, role : String?) : User
    # Check email uniqueness if changing
    if email && email != user.email
      existing_user = User.find_by(email: email)
      raise "Email already exists" if existing_user
      user.email = email
    end

    user.name = name if name
    user.role = role if role

    if password
      user.password_hash = Crypto::Bcrypt::Password.create(password).to_s
    end

    unless user.save
      raise "Failed to update user: #{user.errors.join(", ")}"
    end

    user
  end

  def self.delete_user(user : User) : Bool
    user.destroy
  end

  def self.find_by_id(id : Int64) : User?
    User.find(id)
  end

  def self.find_by_email(email : String) : User?
    User.find_by(email: email)
  end

  def self.verify_credentials(email : String, password : String) : User?
    user = find_by_email(email)
    return nil unless user && user.is_active

    if Crypto::Bcrypt::Password.new(user.password_hash).verify(password)
      user
    else
      nil
    end
  end

  def self.get_all_users(page : Int32 = 1, per_page : Int32 = 20)
    offset = (page - 1) * per_page
    users = User.all("ORDER BY created_at DESC LIMIT ? OFFSET ?", [per_page, offset])
    total = User.count

    {
      data: users.map(&.to_json_safe),
      meta: {
        total: total,
        page: page,
        per_page: per_page,
        pages: (total / per_page.to_f).ceil.to_i
      }
    }
  end
end`
      },
      {
        path: 'src/services/auth_service.cr',
        content: `require "jwt"
require "json"

class AuthService
  JWT_SECRET = ENV["JWT_SECRET"] || "your-secret-key"
  JWT_EXPIRATION = (ENV["JWT_EXPIRATION"]? || "3600").to_i

  def self.register(name : String, email : String, password : String) : Hash(String, JSON::Any)
    user = UserService.create_user(name, email, password)
    token = generate_token(user)

    {
      "user" => JSON.parse(user.to_json_safe.to_json),
      "token" => JSON.parse(token.to_json),
      "expires_at" => JSON.parse((Time.local.to_unix + JWT_EXPIRATION).to_json)
    }
  end

  def self.login(email : String, password : String) : Hash(String, JSON::Any)
    user = UserService.verify_credentials(email, password)
    raise "Invalid credentials" unless user

    token = generate_token(user)

    {
      "user" => JSON.parse(user.to_json_safe.to_json),
      "token" => JSON.parse(token.to_json),
      "expires_at" => JSON.parse((Time.local.to_unix + JWT_EXPIRATION).to_json)
    }
  end

  def self.validate_token(token : String) : User?
    begin
      payload = JWT.decode(token, JWT_SECRET, JWT::Algorithm::HS256)
      user_id = payload[0]["user_id"].as_i64
      UserService.find_by_id(user_id)
    rescue ex
      nil
    end
  end

  def self.refresh_token(token : String) : Hash(String, JSON::Any)
    user = validate_token(token)
    raise "Invalid token" unless user

    new_token = generate_token(user)

    {
      "user" => JSON.parse(user.to_json_safe.to_json),
      "token" => JSON.parse(new_token.to_json),
      "expires_at" => JSON.parse((Time.local.to_unix + JWT_EXPIRATION).to_json)
    }
  end

  private def self.generate_token(user : User) : String
    payload = {
      "user_id" => user.id,
      "email" => user.email,
      "role" => user.role,
      "iat" => Time.local.to_unix,
      "exp" => Time.local.to_unix + JWT_EXPIRATION
    }

    JWT.encode(payload, JWT_SECRET, JWT::Algorithm::HS256)
  end
end`
      }
    ];
  }

  protected generateRepositoryFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/models/base_model.cr',
        content: `require "granite/adapter/pg"

abstract class BaseModel < Granite::Base
  connection pg
  
  column id : Int64, primary: true
  column created_at : Time?
  column updated_at : Time?

  before_save :set_timestamps

  private def set_timestamps
    now = Time.local
    self.created_at = now if self.created_at.nil?
    self.updated_at = now
  end
end`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/models/user.cr',
        content: `require "./base_model"

class User < BaseModel
  table users

  column name : String
  column email : String
  column password_hash : String
  column role : String = "user"
  column is_active : Bool = true

  validate name, "can't be blank", ->(user : User) { !user.name.to_s.empty? }
  validate email, "can't be blank", ->(user : User) { !user.email.to_s.empty? }
  validate email, "must be valid", ->(user : User) { 
    user.email.to_s.includes?("@") && user.email.to_s.includes?(".")
  }
  validate email, "must be unique", ->(user : User) {
    existing = User.find_by(email: user.email)
    existing.nil? || existing.id == user.id
  }
  validate password_hash, "can't be blank", ->(user : User) { !user.password_hash.to_s.empty? }
  validate role, "must be valid", ->(user : User) { 
    ["user", "admin", "moderator"].includes?(user.role.to_s)
  }

  def has_role?(role : String) : Bool
    self.role == role
  end

  def is_admin? : Bool
    has_role?("admin")
  end

  def to_json_safe
    {
      id: self.id,
      name: self.name,
      email: self.email,
      role: self.role,
      is_active: self.is_active,
      created_at: self.created_at,
      updated_at: self.updated_at
    }
  end
end`
      }
    ];
  }

  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/config/database.cr',
        content: `require "granite/adapter/pg"

# Database configuration is handled in main.cr
# This file exists for future database configuration needs`
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/middleware/auth_middleware.cr',
        content: `require "kemal"

class AuthMiddleware < Kemal::Handler
  def call(env)
    call_next(env)
  end

  def self.authenticate!(env)
    auth_header = env.request.headers["Authorization"]?
    
    unless auth_header && auth_header.starts_with?("Bearer ")
      env.response.status_code = 401
      env.response.content_type = "application/json"
      return env.response.print({
        error: "Unauthorized",
        message: "Authorization header required"
      }.to_json)
    end

    token = auth_header[7..-1]
    user = AuthService.validate_token(token)

    unless user
      env.response.status_code = 401
      env.response.content_type = "application/json"
      return env.response.print({
        error: "Unauthorized", 
        message: "Invalid token"
      }.to_json)
    end

    env.set("current_user", user)
  end

  def self.require_role!(env, required_role : String)
    user = env.get("current_user").as(User)
    
    unless user.has_role?(required_role)
      env.response.status_code = 403
      env.response.content_type = "application/json"
      return env.response.print({
        error: "Forbidden",
        message: "Insufficient permissions"
      }.to_json)
    end
  end
end`
      },
      {
        path: 'src/middleware/cors_middleware.cr',
        content: `require "kemal"

class CORSMiddleware < Kemal::Handler
  def call(env)
    # Handle preflight requests
    if env.request.method == "OPTIONS"
      env.response.headers["Access-Control-Allow-Origin"] = ENV["CORS_ORIGIN"]? || "*"
      env.response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
      env.response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
      env.response.headers["Access-Control-Max-Age"] = "86400"
      env.response.status_code = 200
      return
    end

    call_next(env)

    # Add CORS headers to all responses
    env.response.headers["Access-Control-Allow-Origin"] = ENV["CORS_ORIGIN"]? || "*"
    env.response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    env.response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
  end
end`
      },
      {
        path: 'src/controllers/auth_controller.cr',
        content: `require "json"

class AuthController
  def register(env)
    begin
      data = JSON.parse(env.request.body.not_nil!.gets_to_end)
      
      name = data["name"].as_s
      email = data["email"].as_s
      password = data["password"].as_s

      result = AuthService.register(name, email, password)

      env.response.content_type = "application/json"
      env.response.status_code = 201
      {
        message: "User registered successfully",
        data: result
      }.to_json
    rescue ex
      env.response.content_type = "application/json"
      env.response.status_code = 422
      {
        error: "Registration failed",
        message: ex.message
      }.to_json
    end
  end

  def login(env)
    begin
      data = JSON.parse(env.request.body.not_nil!.gets_to_end)
      
      email = data["email"].as_s
      password = data["password"].as_s

      result = AuthService.login(email, password)

      env.response.content_type = "application/json"
      {
        message: "Login successful",
        data: result
      }.to_json
    rescue ex
      env.response.content_type = "application/json"
      env.response.status_code = 401
      {
        error: "Login failed",
        message: ex.message || "Invalid credentials"
      }.to_json
    end
  end

  def refresh(env)
    begin
      data = JSON.parse(env.request.body.not_nil!.gets_to_end)
      token = data["token"].as_s

      result = AuthService.refresh_token(token)

      env.response.content_type = "application/json"
      {
        message: "Token refreshed successfully",
        data: result
      }.to_json
    rescue ex
      env.response.content_type = "application/json"
      env.response.status_code = 401
      {
        error: "Token refresh failed",
        message: ex.message
      }.to_json
    end
  end

  def me(env)
    user = env.get("current_user").as(User)
    
    env.response.content_type = "application/json"
    {
      data: user.to_json_safe
    }.to_json
  end
end`
      },
      {
        path: 'src/controllers/user_controller.cr',
        content: `require "json"

class UserController
  def index(env)
    AuthMiddleware.authenticate!(env)
    
    page = (env.params.query["page"]? || "1").to_i
    per_page = (env.params.query["per_page"]? || "20").to_i

    result = UserService.get_all_users(page, per_page)

    env.response.content_type = "application/json"
    result.to_json
  end

  def create(env)
    AuthMiddleware.authenticate!(env)
    AuthMiddleware.require_role!(env, "admin")
    
    begin
      data = JSON.parse(env.request.body.not_nil!.gets_to_end)
      
      name = data["name"].as_s
      email = data["email"].as_s
      password = data["password"].as_s
      role = data["role"]?.try(&.as_s) || "user"

      user = UserService.create_user(name, email, password, role)

      env.response.content_type = "application/json"
      env.response.status_code = 201
      {
        message: "User created successfully",
        data: user.to_json_safe
      }.to_json
    rescue ex
      env.response.content_type = "application/json"
      env.response.status_code = 422
      {
        error: "User creation failed",
        message: ex.message
      }.to_json
    end
  end

  def show(env)
    AuthMiddleware.authenticate!(env)
    
    id = env.params.url["id"].to_i64
    user = UserService.find_by_id(id)

    unless user
      env.response.content_type = "application/json"
      env.response.status_code = 404
      return {
        error: "Not Found",
        message: "User not found"
      }.to_json
    end

    env.response.content_type = "application/json"
    {
      data: user.to_json_safe
    }.to_json
  end

  def update(env)
    AuthMiddleware.authenticate!(env)
    
    id = env.params.url["id"].to_i64
    user = UserService.find_by_id(id)

    unless user
      env.response.content_type = "application/json"
      env.response.status_code = 404
      return {
        error: "Not Found",
        message: "User not found"
      }.to_json
    end

    # Users can only update themselves unless admin
    current_user = env.get("current_user").as(User)
    unless current_user.id == user.id || current_user.is_admin?
      env.response.content_type = "application/json"
      env.response.status_code = 403
      return {
        error: "Forbidden",
        message: "Access denied"
      }.to_json
    end

    begin
      data = JSON.parse(env.request.body.not_nil!.gets_to_end)
      
      name = data["name"]?.try(&.as_s)
      email = data["email"]?.try(&.as_s)
      password = data["password"]?.try(&.as_s)
      role = data["role"]?.try(&.as_s)

      # Only admins can change roles
      role = nil unless current_user.is_admin?

      updated_user = UserService.update_user(user, name, email, password, role)

      env.response.content_type = "application/json"
      {
        message: "User updated successfully",
        data: updated_user.to_json_safe
      }.to_json
    rescue ex
      env.response.content_type = "application/json"
      env.response.status_code = 422
      {
        error: "User update failed",
        message: ex.message
      }.to_json
    end
  end

  def delete(env)
    AuthMiddleware.authenticate!(env)
    AuthMiddleware.require_role!(env, "admin")
    
    id = env.params.url["id"].to_i64
    user = UserService.find_by_id(id)

    unless user
      env.response.content_type = "application/json"
      env.response.status_code = 404
      return {
        error: "Not Found",
        message: "User not found"
      }.to_json
    end

    begin
      UserService.delete_user(user)

      env.response.content_type = "application/json"
      {
        message: "User deleted successfully"
      }.to_json
    rescue ex
      env.response.content_type = "application/json"
      env.response.status_code = 422
      {
        error: "User deletion failed",
        message: ex.message
      }.to_json
    end
  end
end`
      }
    ];
  }

  protected generateTestFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'spec/spec_helper.cr',
        content: `require "spec"
require "../src/main"

# Test helpers and setup

def create_test_user(name = "Test User", email = "test@example.com", password = "password123")
  UserService.create_user(name, email, password)
end

def generate_auth_header(user : User)
  token = AuthService.generate_token(user)
  "Bearer #{token}"
end`
      },
      {
        path: 'spec/services/user_service_spec.cr',
        content: `require "../spec_helper"

describe UserService do
  describe ".create_user" do
    it "creates a new user with valid data" do
      user = UserService.create_user("Test User", "test@example.com", "password123")
      
      user.name.should eq("Test User")
      user.email.should eq("test@example.com")
      user.role.should eq("user")
      user.is_active.should be_true
    end

    it "raises error for duplicate email" do
      UserService.create_user("User 1", "test@example.com", "password123")
      
      expect_raises(Exception, "Email already exists") do
        UserService.create_user("User 2", "test@example.com", "password456")
      end
    end
  end

  describe ".verify_credentials" do
    it "returns user for valid credentials" do
      created_user = UserService.create_user("Test User", "test@example.com", "password123")
      user = UserService.verify_credentials("test@example.com", "password123")
      
      user.should_not be_nil
      user.not_nil!.id.should eq(created_user.id)
    end

    it "returns nil for invalid credentials" do
      UserService.create_user("Test User", "test@example.com", "password123")
      user = UserService.verify_credentials("test@example.com", "wrongpassword")
      
      user.should be_nil
    end
  end
end`
      },
      {
        path: 'spec/services/auth_service_spec.cr',
        content: `require "../spec_helper"

describe AuthService do
  describe ".register" do
    it "registers a new user and returns auth data" do
      result = AuthService.register("Test User", "test@example.com", "password123")
      
      result.should have_key("user")
      result.should have_key("token")
      result.should have_key("expires_at")
    end
  end

  describe ".login" do
    it "logs in existing user with valid credentials" do
      UserService.create_user("Test User", "test@example.com", "password123")
      result = AuthService.login("test@example.com", "password123")
      
      result.should have_key("user")
      result.should have_key("token")
      result.should have_key("expires_at")
    end

    it "raises error for invalid credentials" do
      UserService.create_user("Test User", "test@example.com", "password123")
      
      expect_raises(Exception, "Invalid credentials") do
        AuthService.login("test@example.com", "wrongpassword")
      end
    end
  end

  describe ".validate_token" do
    it "returns user for valid token" do
      user = UserService.create_user("Test User", "test@example.com", "password123")
      result = AuthService.login("test@example.com", "password123")
      token = result["token"].as_s
      
      validated_user = AuthService.validate_token(token)
      validated_user.should_not be_nil
      validated_user.not_nil!.id.should eq(user.id)
    end

    it "returns nil for invalid token" do
      user = AuthService.validate_token("invalid-token")
      user.should be_nil
    end
  end
end`
      },
      {
        path: 'spec/models/user_spec.cr',
        content: `require "../spec_helper"

describe User do
  describe "#has_role?" do
    it "returns true for matching role" do
      user = User.new
      user.role = "admin"
      
      user.has_role?("admin").should be_true
      user.has_role?("user").should be_false
    end
  end

  describe "#is_admin?" do
    it "returns true for admin users" do
      admin = User.new
      admin.role = "admin"
      admin.is_admin?.should be_true

      user = User.new  
      user.role = "user"
      user.is_admin?.should be_false
    end
  end

  describe "#to_json_safe" do
    it "excludes password_hash from JSON" do
      user = User.new
      user.name = "Test User"
      user.email = "test@example.com"
      user.password_hash = "hashed_password"
      
      json = user.to_json_safe
      json.should have_key(:name)
      json.should have_key(:email)
      json.should_not have_key(:password_hash)
    end
  end
end`
      },
      {
        path: 'docker/postgres/init.sql',
        content: `-- Initialize database schema for Crystal Kemal application

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(50) DEFAULT 'user' NOT NULL,
  is_active BOOLEAN DEFAULT true NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);

-- Insert sample admin user (password: admin123)
INSERT INTO users (name, email, password_hash, role) 
VALUES (
  'Admin User', 
  'admin@example.com', 
  '$2a$10$8K1p/a0dhrxSMkMM0f0sxOj.8HQ1Wd4d6Q9I.8H7iV5p0.0jQ5j7a', 
  'admin'
) ON CONFLICT (email) DO NOTHING;`
      }
    ];
  }
}