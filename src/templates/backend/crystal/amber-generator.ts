import { CrystalBackendGenerator } from './crystal-base-generator';

export class AmberGenerator extends CrystalBackendGenerator {

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'amber': '~> 1.0.0',
      'granite': '~> 0.22.0',
      'jasper_helpers': '~> 0.2.0',
      'quartz_mailer': '~> 0.7.0',
      'citrine-i18n': '~> 0.4.0',
      'jwt': '~> 1.5.0',
      'pg': '~> 0.26.0',
      'redis': '~> 2.9.0'
    };
  }

  protected generateMainFile(): string {
    return `require "amber"
require "./config/*"
require "./src/controllers/application_controller"
require "./src/controllers/**"
require "./src/models/**"
require "./src/services/**"
require "./src/middleware/**"

# Initialize Amber application
module App
  class Application < Amber::Server::Base
    settings.name = "Amber API"
    settings.port = ENV["PORT"]?.try(&.to_i) || 3000
    settings.host = ENV["HOST"]? || "0.0.0.0"
    settings.redis_url = ENV["REDIS_URL"]? || "redis://localhost:6379/0"
    settings.secret_key_base = ENV["SECRET_KEY_BASE"]? || "amber_secret_key"
    settings.database_url = ENV["DATABASE_URL"]? || "postgres://postgres:postgres@localhost:5432/amber_app"

    # Configure middleware pipeline
    pipeline :web do
      # Session and CSRF protection
      plug Amber::Pipe::Session.new
      plug Amber::Pipe::CSRF.new
      # CORS support
      plug CORSHandler.new
    end

    pipeline :api do
      # API-specific middleware
      plug Amber::Pipe::PoweredByAmber.new
      plug Amber::Pipe::Error.new
      plug Amber::Pipe::Logger.new
      plug Amber::Pipe::Session.new
      plug CORSHandler.new
      plug Amber::Pipe::CORS.new
    end

    # Define routes
    routes :api do
      # Health check
      get "/health", HealthController, :check

      # Authentication routes
      post "/api/auth/register", AuthController, :register
      post "/api/auth/login", AuthController, :login
      post "/api/auth/refresh", AuthController, :refresh
      get "/api/auth/me", AuthController, :me

      # User routes
      get "/api/users", UserController, :index
      post "/api/users", UserController, :create
      get "/api/users/:id", UserController, :show
      put "/api/users/:id", UserController, :update
      patch "/api/users/:id", UserController, :update
      delete "/api/users/:id", UserController, :delete
    end
  end
end

# Start the application
App::Application.start`;
  }

  protected generateRoutingFile(): string {
    return `# Routes are defined in main.cr for Amber
# This framework uses pipeline-based routing configuration`;
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/services/user_service.cr',
        content: `require "crypto/bcrypt/password"

class UserService
  def self.create_user(name : String, email : String, password : String, role : String = "user") : User
    # Check if email already exists
    existing_user = User.where(email: email).first
    raise "Email already exists" if existing_user

    # Create user with hashed password
    user = User.new
    user.name = name
    user.email = email
    user.password_hash = Crypto::Bcrypt::Password.create(password).to_s
    user.role = role
    user.is_active = true
    user.created_at = Time.local
    user.updated_at = Time.local

    if user.save
      user
    else
      raise "Failed to create user: #{user.errors.join(", ")}"
    end
  end

  def self.update_user(user : User, params : Hash) : User
    # Check email uniqueness if changing
    if params["email"]? && params["email"] != user.email
      existing_user = User.where(email: params["email"]).first
      raise "Email already exists" if existing_user
    end

    # Update user fields
    user.name = params["name"].as(String) if params["name"]?
    user.email = params["email"].as(String) if params["email"]?
    user.role = params["role"].as(String) if params["role"]?
    
    if params["password"]?
      user.password_hash = Crypto::Bcrypt::Password.create(params["password"].as(String)).to_s
    end
    
    user.updated_at = Time.local

    if user.save
      user
    else
      raise "Failed to update user: #{user.errors.join(", ")}"
    end
  end

  def self.delete_user(user : User) : Bool
    user.destroy
  end

  def self.find_by_id(id : String) : User?
    User.find(id)
  rescue
    nil
  end

  def self.find_by_email(email : String) : User?
    User.where(email: email).first
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
    total = User.all.size

    {
      data: users.map(&.to_h),
      meta: {
        total: total,
        page: page,
        per_page: per_page,
        pages: (total / per_page.to_f).ceil.to_i
      }
    }
  end

  def self.validate_user_data(data : Hash)
    errors = [] of String

    if !data["name"]? || data["name"].as(String).empty?
      errors << "Name is required"
    end

    if !data["email"]? || data["email"].as(String).empty?
      errors << "Email is required"
    elsif !data["email"].as(String).includes?("@")
      errors << "Email must be valid"
    end

    if !data["password"]? || data["password"].as(String).size < 8
      errors << "Password must be at least 8 characters"
    end

    unless errors.empty?
      raise errors.join(", ")
    end
  end
end`
      },
      {
        path: 'src/services/auth_service.cr',
        content: `require "jwt"

class AuthService
  JWT_SECRET = ENV["JWT_SECRET"]? || "your-secret-key"
  JWT_EXPIRATION = (ENV["JWT_EXPIRATION"]? || "3600").to_i

  def self.register(data : Hash) : Hash(String, JSON::Any)
    UserService.validate_user_data(data)
    
    user = UserService.create_user(
      data["name"].as(String),
      data["email"].as(String),
      data["password"].as(String),
      data["role"]?.try(&.as(String)) || "user"
    )
    
    token = generate_token(user)

    {
      "user" => JSON.parse(user.to_h.to_json),
      "token" => JSON.parse(token.to_json),
      "expires_at" => JSON.parse((Time.local.to_unix + JWT_EXPIRATION).to_json)
    }
  end

  def self.login(email : String, password : String) : Hash(String, JSON::Any)
    user = UserService.verify_credentials(email, password)
    raise "Invalid credentials" unless user

    token = generate_token(user)

    {
      "user" => JSON.parse(user.to_h.to_json),
      "token" => JSON.parse(token.to_json),
      "expires_at" => JSON.parse((Time.local.to_unix + JWT_EXPIRATION).to_json)
    }
  end

  def self.validate_token(token : String) : User?
    begin
      payload = JWT.decode(token, JWT_SECRET, JWT::Algorithm::HS256)
      user_id = payload[0]["user_id"].as_s
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
      "user" => JSON.parse(user.to_h.to_json),
      "token" => JSON.parse(new_token.to_json),
      "expires_at" => JSON.parse((Time.local.to_unix + JWT_EXPIRATION).to_json)
    }
  end

  def self.generate_token(user : User) : String
    payload = {
      "user_id" => user.id.to_s,
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
  
  column id : String, primary: true
  column created_at : Time?
  column updated_at : Time?

  before_save :set_id_and_timestamps

  def before_save
    set_id_and_timestamps
  end

  private def set_id_and_timestamps
    self.id = UUID.random.to_s if self.id.nil?
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
    existing = User.where(email: user.email).first
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

  def to_h
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
        path: 'config/database.cr',
        content: `require "granite/adapter/pg"

Granite::Connections << Granite::Adapter::Pg.new(
  name: "pg", 
  url: ENV["DATABASE_URL"]? || "postgres://postgres:postgres@localhost:5432/amber_app"
)`
      },
      {
        path: 'config/initializers/database.cr',
        content: `# Database configuration for Amber application

# The database configuration is handled in config/database.cr
# This file is for additional database setup if needed

# Example: Custom connection pool settings
# Granite::Connections.first.pool_size = 25
# Granite::Connections.first.pool_timeout = 0.1`
      },
      {
        path: 'config/environments/development.yml',
        content: `database_url: postgres://postgres:postgres@localhost:5432/amber_app_development
redis_url: redis://localhost:6379/0
host: 0.0.0.0
port: 3000
log_level: debug
colorize_logging: true
secret_key_base: amber_development_secret_key`
      },
      {
        path: 'config/environments/test.yml',
        content: `database_url: postgres://postgres:postgres@localhost:5432/amber_app_test
redis_url: redis://localhost:6379/1
host: 0.0.0.0
port: 3001
log_level: error
colorize_logging: false
secret_key_base: amber_test_secret_key`
      },
      {
        path: 'config/environments/production.yml',
        content: `database_url: <%= ENV["DATABASE_URL"] %>
redis_url: <%= ENV["REDIS_URL"] %>
host: 0.0.0.0
port: <%= ENV["PORT"] || 3000 %>
log_level: info
colorize_logging: false
secret_key_base: <%= ENV["SECRET_KEY_BASE"] %>`
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/controllers/application_controller.cr',
        content: `require "amber"

class ApplicationController < Amber::Controller::Base
  LAYOUT = "application.ecr"

  # Authentication helper
  protected def authenticate_user!
    user = current_user
    unless user
      render_unauthorized("Authentication required")
      return
    end
    user
  end

  protected def require_admin!
    user = authenticate_user!
    return unless user
    
    unless user.is_admin?
      render_forbidden("Admin access required")
      return
    end
    user
  end

  protected def current_user : User?
    return @current_user if @current_user

    token = extract_token_from_header
    return nil unless token

    @current_user = AuthService.validate_token(token)
  end

  private def extract_token_from_header : String?
    auth_header = request.headers["Authorization"]?
    return nil unless auth_header && auth_header.starts_with?("Bearer ")
    
    auth_header[7..-1]
  end

  private def render_unauthorized(message : String)
    context.response.status_code = 401
    context.response.content_type = "application/json"
    context.response.print({
      error: "Unauthorized",
      message: message
    }.to_json)
  end

  private def render_forbidden(message : String)
    context.response.status_code = 403
    context.response.content_type = "application/json"
    context.response.print({
      error: "Forbidden", 
      message: message
    }.to_json)
  end

  private def render_not_found(message : String)
    context.response.status_code = 404
    context.response.content_type = "application/json"
    context.response.print({
      error: "Not Found",
      message: message
    }.to_json)
  end

  private def render_error(message : String, status : Int32 = 422)
    context.response.status_code = status
    context.response.content_type = "application/json"
    context.response.print({
      error: "Error",
      message: message
    }.to_json)
  end

  private def render_json(data, status : Int32 = 200)
    context.response.status_code = status
    context.response.content_type = "application/json"
    context.response.print(data.to_json)
  end
end`
      },
      {
        path: 'src/middleware/cors_handler.cr',
        content: `require "amber"

class CORSHandler
  include HTTP::Handler

  def call(context)
    # Handle preflight requests
    if context.request.method == "OPTIONS"
      context.response.headers["Access-Control-Allow-Origin"] = ENV["CORS_ORIGIN"]? || "*"
      context.response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
      context.response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
      context.response.headers["Access-Control-Max-Age"] = "86400"
      context.response.status_code = 200
      return
    end

    call_next(context)

    # Add CORS headers to all responses
    context.response.headers["Access-Control-Allow-Origin"] = ENV["CORS_ORIGIN"]? || "*"
    context.response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
    context.response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Requested-With"
  end
end`
      },
      {
        path: 'src/controllers/health_controller.cr',
        content: `class HealthController < ApplicationController
  def check
    render_json({
      status: "OK",
      timestamp: Time.local.to_rfc3339,
      service: ENV["APP_NAME"]? || "Amber API",
      version: "1.0.0"
    })
  end
end`
      },
      {
        path: 'src/controllers/auth_controller.cr',
        content: `class AuthController < ApplicationController
  def register
    begin
      data = JSON.parse(request.body.not_nil!.gets_to_end).as_h
      result = AuthService.register(data)

      render_json({
        message: "User registered successfully",
        data: result
      }, status: 201)
    rescue ex
      render_error(ex.message || "Registration failed", 422)
    end
  end

  def login
    begin
      data = JSON.parse(request.body.not_nil!.gets_to_end).as_h
      
      email = data["email"].as_s
      password = data["password"].as_s

      result = AuthService.login(email, password)

      render_json({
        message: "Login successful",
        data: result
      })
    rescue ex
      render_error(ex.message || "Invalid credentials", 401)
    end
  end

  def refresh
    begin
      data = JSON.parse(request.body.not_nil!.gets_to_end).as_h
      token = data["token"].as_s

      result = AuthService.refresh_token(token)

      render_json({
        message: "Token refreshed successfully",
        data: result
      })
    rescue ex
      render_error(ex.message || "Token refresh failed", 401)
    end
  end

  def me
    user = authenticate_user!
    return unless user

    render_json({
      data: user.to_h
    })
  end
end`
      },
      {
        path: 'src/controllers/user_controller.cr',
        content: `class UserController < ApplicationController
  def index
    authenticate_user!
    
    page = params["page"]?.try(&.to_i) || 1
    per_page = params["per_page"]?.try(&.to_i) || 20

    result = UserService.get_all_users(page, per_page)
    render_json(result)
  end

  def create
    admin = require_admin!
    return unless admin
    
    begin
      data = JSON.parse(request.body.not_nil!.gets_to_end).as_h
      
      user = UserService.create_user(
        data["name"].as_s,
        data["email"].as_s,
        data["password"].as_s,
        data["role"]?.try(&.as_s) || "user"
      )

      render_json({
        message: "User created successfully",
        data: user.to_h
      }, status: 201)
    rescue ex
      render_error(ex.message || "User creation failed", 422)
    end
  end

  def show
    authenticate_user!
    
    id = params["id"]
    user = UserService.find_by_id(id)

    unless user
      render_not_found("User not found")
      return
    end

    render_json({
      data: user.to_h
    })
  end

  def update
    current = authenticate_user!
    return unless current
    
    id = params["id"]
    user = UserService.find_by_id(id)

    unless user
      render_not_found("User not found")
      return
    end

    # Users can only update themselves unless admin
    unless current.id == user.id || current.is_admin?
      render_forbidden("Access denied")
      return
    end

    begin
      data = JSON.parse(request.body.not_nil!.gets_to_end).as_h
      
      # Only admins can change roles
      data.delete("role") unless current.is_admin?

      updated_user = UserService.update_user(user, data)

      render_json({
        message: "User updated successfully",
        data: updated_user.to_h
      })
    rescue ex
      render_error(ex.message || "User update failed", 422)
    end
  end

  def delete
    admin = require_admin!
    return unless admin
    
    id = params["id"]
    user = UserService.find_by_id(id)

    unless user
      render_not_found("User not found")
      return
    end

    begin
      UserService.delete_user(user)

      render_json({
        message: "User deleted successfully"
      })
    rescue ex
      render_error(ex.message || "User deletion failed", 422)
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
require "amber"
require "../config/*"
require "../src/models/**"
require "../src/services/**"
require "../src/controllers/**"

# Test helpers and setup

class TestClient
  def initialize
    @context = create_context("GET", "/")
  end

  def create_context(method : String, path : String, body : String? = nil, headers : HTTP::Headers? = nil)
    headers ||= HTTP::Headers.new
    headers["Content-Type"] = "application/json" if body
    
    request = HTTP::Request.new(method, path, headers, body)
    response = HTTP::Server::Response.new(IO::Memory.new)
    
    HTTP::Server::Context.new(request, response)
  end

  def post(path : String, body : String, headers : HTTP::Headers = HTTP::Headers.new)
    context = create_context("POST", path, body, headers)
    JSON.parse(context.response.to_io.to_s)
  rescue
    {"error" => "Invalid response"}
  end

  def get(path : String, headers : HTTP::Headers = HTTP::Headers.new)
    context = create_context("GET", path, headers: headers)
    JSON.parse(context.response.to_io.to_s)
  rescue
    {"error" => "Invalid response"}
  end

  def auth_headers(user : User) : HTTP::Headers
    token = AuthService.generate_token(user)
    headers = HTTP::Headers.new
    headers["Authorization"] = "Bearer #{token}"
    headers
  end
end

def create_test_user(
  name : String = "Test User",
  email : String = "test@example.com",
  password : String = "password123",
  role : String = "user"
) : User
  UserService.create_user(name, email, password, role)
end

Spec.before_each do
  User.clear  # Clear all users before each test
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

  describe ".get_all_users" do
    it "returns paginated users" do
      UserService.create_user("User 1", "user1@example.com", "password123")
      UserService.create_user("User 2", "user2@example.com", "password123")
      
      result = UserService.get_all_users(1, 10)
      
      result[:data].size.should eq(2)
      result[:meta][:total].should eq(2)
      result[:meta][:page].should eq(1)
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
      data = {
        "name" => "Test User",
        "email" => "test@example.com", 
        "password" => "password123"
      }
      
      result = AuthService.register(data)
      
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
      token = AuthService.generate_token(user)
      
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

  describe "#to_h" do
    it "excludes password_hash from hash" do
      user = User.new
      user.name = "Test User"
      user.email = "test@example.com"
      user.password_hash = "hashed_password"
      
      hash = user.to_h
      hash.should have_key(:name)
      hash.should have_key(:email)
      hash.should_not have_key(:password_hash)
    end
  end
end`
      },
      {
        path: 'db/migrations/20241201000001_create_users.sql',
        content: `-- Create users table
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY,
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
INSERT INTO users (id, name, email, password_hash, role) 
VALUES (
  'admin-' || substr(md5(random()::text), 1, 8),
  'Admin User', 
  'admin@example.com', 
  '$2a$10$8K1p/a0dhrxSMkMM0f0sxOj.8HQ1Wd4d6Q9I.8H7iV5p0.0jQ5j7a', 
  'admin'
) ON CONFLICT (email) DO NOTHING;`
      }
    ];
  }
}