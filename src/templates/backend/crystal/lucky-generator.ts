import { CrystalBackendGenerator } from './crystal-base-generator';

export class LuckyGenerator extends CrystalBackendGenerator {

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'lucky': '~> 1.0.0',
      'avram': '~> 1.0.0',
      'authentic': '~> 0.8.0',
      'carbon': '~> 0.2.0',
      'jwt': '~> 1.5.0',
      'pg': '~> 0.26.0',
      'redis': '~> 2.9.0'
    };
  }

  protected generateMainFile(): string {
    return `require "./src/app"

# Start the Lucky application
if Lucky::Env.development?
  Avram::Migrator::Runner.new.ensure_migrated!
end

Lucky::AppServer.new.call`;
  }

  protected generateRoutingFile(): string {
    return `# Routes are defined in config/routes.cr for Lucky
# Actions handle individual routes with type safety`;
  }

  protected generateServiceFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/app.cr',
        content: `require "lucky"
require "avram/lucky"
require "authentic"
require "carbon"
require "./app_database"
require "./models/base_model"
require "./models/**"
require "./queries/**"
require "./operations/**"
require "./serializers/**"
require "./actions/**"
require "./pages/**"
require "./emails/**"
require "./handlers/**"

# Load configuration
require "./config/server"
require "./config/database"
require "./config/email"
require "./config/authentic"
require "./config/cookies"

# Setup logging
Lucky::LogHandler.configure do |settings|
  settings.show_timestamps = true
  settings.level = Lucky::Env.production? ? Logger::Severity::INFO : Logger::Severity::DEBUG
end

Lucky::ErrorHandler.configure do |settings|
  settings.show_debug_output = !Lucky::Env.production?
end

Lucky::RouteHelper.configure do |settings|
  if Lucky::Env.production?
    settings.base_uri = ENV.fetch("APP_DOMAIN")
  else
    settings.base_uri = "http://localhost:5000"
  end
end

Lucky::Server.configure do |settings|
  if Lucky::Env.production?
    settings.secret_key_base = secret_key_from_env
    settings.host = "0.0.0.0"
    settings.port = ENV["PORT"].to_i
  else
    settings.secret_key_base = "super_secret_key_for_dev"
    settings.host = Lucky::ServerSettings.host
    settings.port = Lucky::ServerSettings.port
  end
end

private def secret_key_from_env
  ENV["SECRET_KEY_BASE"] || raise_missing_secret_key_in_production
end

private def raise_missing_secret_key_in_production
  raise "Please set the SECRET_KEY_BASE environment variable. You can generate one with 'lucky gen.secret_key'"
end`
      },
      {
        path: 'src/app_database.cr',
        content: `require "avram"

class AppDatabase < Avram::Database
  def self.configure
    settings.credentials = Avram::Credentials.parse?(ENV["DATABASE_URL"]?) || Avram::Credentials.new(
      database: "#{app_name}_#{Lucky::Env.name}",
      hostname: ENV["DB_HOST"]? || "localhost",
      port: ENV["DB_PORT"]?.try(&.to_i) || 5432,
      username: ENV["DB_USERNAME"]? || "postgres",
      password: ENV["DB_PASSWORD"]? || "postgres"
    )
  end

  private def self.app_name
    "lucky_app"
  end
end

AppDatabase.configure`
      },
      {
        path: 'src/services/user_service.cr',
        content: `class UserService
  def self.find_user_by_email(email : String) : User?
    UserQuery.new.email(email).first?
  end

  def self.authenticate(email : String, password : String) : User?
    if user = find_user_by_email(email)
      if Authentic.correct_password?(user, password)
        user
      end
    end
  end

  def self.create_user!(name : String, email : String, password : String, role : String = "user") : User
    SaveUser.create!(
      name: name,
      email: email,
      password: password,
      password_confirmation: password,
      role: role
    )
  end

  def self.update_user!(user : User, params : Hash) : User
    SaveUser.update!(
      user,
      name: params["name"]?.try(&.as_s),
      email: params["email"]?.try(&.as_s),
      role: params["role"]?.try(&.as_s)
    )
  end

  def self.update_password!(user : User, password : String) : User
    SaveUser.update!(
      user,
      password: password,
      password_confirmation: password
    )
  end

  def self.delete_user!(user : User)
    DeleteUser.delete!(user)
  end

  def self.all_users(page : Int32 = 1, per_page : Int32 = 20)
    UserQuery.new
      .order_by(:created_at, :desc)
      .paginate(page: page, per_page: per_page)
  end
end`
      },
      {
        path: 'src/services/auth_service.cr',
        content: `require "jwt"

class AuthService
  JWT_SECRET = ENV["JWT_SECRET"] || "your-secret-key"
  JWT_EXPIRATION = (ENV["JWT_EXPIRATION"]? || "3600").to_i.seconds

  def self.generate_token(user : User) : String
    payload = {
      "user_id" => user.id,
      "email" => user.email,
      "role" => user.role,
      "iat" => Time.local.to_unix,
      "exp" => (Time.local + JWT_EXPIRATION).to_unix
    }

    JWT.encode(payload, JWT_SECRET, JWT::Algorithm::HS256)
  end

  def self.verify_token(token : String) : User?
    begin
      payload = JWT.decode(token, JWT_SECRET, JWT::Algorithm::HS256)
      user_id = payload[0]["user_id"].as_i64
      UserQuery.find(user_id)
    rescue
      nil
    end
  end

  def self.register(name : String, email : String, password : String) : NamedTuple(user: User, token: String)
    user = UserService.create_user!(name, email, password)
    token = generate_token(user)
    
    {user: user, token: token}
  end

  def self.login(email : String, password : String) : NamedTuple(user: User, token: String)?
    if user = UserService.authenticate(email, password)
      token = generate_token(user)
      {user: user, token: token}
    end
  end

  def self.refresh_token(old_token : String) : String?
    if user = verify_token(old_token)
      generate_token(user)
    end
  end
end`
      }
    ];
  }

  protected generateRepositoryFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/models/base_model.cr',
        content: `require "avram/model"

abstract class BaseModel < Avram::Model
  def self.database : Avram::Database.class
    AppDatabase
  end
end`
      },
      {
        path: 'src/queries/base_query.cr',
        content: `require "avram"

abstract class BaseQuery(T) < Avram::Query(T)
end`
      }
    ];
  }

  protected generateModelFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/models/user.cr',
        content: `require "authentic"

class User < BaseModel
  include Authentic::PasswordAuthenticatable

  table do
    column name : String
    column email : String
    column encrypted_password : String
    column role : String = "user"
    column is_active : Bool = true
  end

  def has_role?(role : String) : Bool
    self.role == role
  end

  def is_admin? : Bool
    has_role?("admin")
  end

  def to_json_safe
    {
      id: id,
      name: name,
      email: email,
      role: role,
      is_active: is_active,
      created_at: created_at,
      updated_at: updated_at
    }
  end
end`
      }
    ];
  }

  protected generateConfigFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/config/server.cr',
        content: `Lucky::Server.configure do |settings|
  settings.secret_key_base = Lucky::Env.production? ? ENV.fetch("SECRET_KEY_BASE") : "super_secret_key_for_dev"
  settings.host = ENV["HOST"]? || "0.0.0.0"
  settings.port = ENV["PORT"]?.try(&.to_i) || 5000
  settings.gzip_enabled = true
  settings.gzip_content_types = ["text/html", "application/json", "text/css", "application/javascript"]
end`
      },
      {
        path: 'src/config/database.cr',
        content: `require "../app_database"

database_name = "lucky_app_#{Lucky::Env.name}"

AppDatabase.configure do |settings|
  if Lucky::Env.production?
    settings.credentials = Avram::Credentials.parse(ENV["DATABASE_URL"])
  else
    settings.credentials = Avram::Credentials.new(
      database: database_name,
      hostname: ENV["DB_HOST"]? || "localhost",
      port: ENV["DB_PORT"]?.try(&.to_i) || 5432,
      username: ENV["DB_USERNAME"]? || "postgres",
      password: ENV["DB_PASSWORD"]? || "postgres"
    )
  end
end

Avram.configure do |settings|
  settings.database_to_migrate = AppDatabase
  settings.lazy_load_enabled = Lucky::Env.production?
end`
      },
      {
        path: 'src/config/email.cr',
        content: `require "carbon"

BaseEmail.configure do |settings|
  if Lucky::Env.production?
    # Replace with your email service credentials
    settings.adapter = Carbon::SmtpAdapter.new(
      host: ENV.fetch("SMTP_HOST"),
      port: ENV.fetch("SMTP_PORT").to_i,
      username: ENV.fetch("SMTP_USERNAME"),
      password: ENV.fetch("SMTP_PASSWORD"),
      tls: Carbon::Tls::StartTls
    )
  else
    settings.adapter = Carbon::DevAdapter.new(print_emails: true)
  end
end`
      },
      {
        path: 'src/config/authentic.cr',
        content: `require "authentic"

Authentic.configure do |settings|
  settings.secret_key = Lucky::Server.settings.secret_key_base
  
  # Encryption settings
  settings.encryption_algorithm = Authentic::EncryptionAlgorithm::Bcrypt
  settings.bcrypt_cost = Lucky::Env.production? ? 12 : 4

  # Session settings  
  settings.password_reset_expiration = 15.minutes
  settings.sign_in_required_message = "You must be signed in to access that page"
end`
      },
      {
        path: 'src/config/cookies.cr',
        content: `Lucky::Session.configure do |settings|
  settings.key = "_lucky_session"
  settings.max_age = 1.year
  settings.secure = Lucky::Env.production?
  settings.http_only = true
  settings.same_site = HTTP::Cookie::SameSite::Lax
end

Lucky::CookieJar.configure do |settings|
  settings.on_set = ->(cookie : HTTP::Cookie) {
    cookie.secure = Lucky::Env.production?
    cookie.http_only = true
    cookie.same_site = HTTP::Cookie::SameSite::Lax
  }
end`
      },
      {
        path: 'src/operations/save_user.cr',
        content: `class SaveUser < User::SaveOperation
  permit_columns name, email, role, is_active
  
  before_save do
    validate_required name, email
    validate_uniqueness_of email
    validate_inclusion_of role, in: ["user", "admin", "moderator"]
    validate_format_of email, with: /@/
  end

  before_save encrypt_password
end`
      },
      {
        path: 'src/operations/delete_user.cr',
        content: `class DeleteUser < User::DeleteOperation
end`
      },
      {
        path: 'src/queries/user_query.cr',
        content: `class UserQuery < User::BaseQuery
  def by_email(email : String)
    email(email)
  end

  def active
    is_active(true)
  end

  def with_role(role : String)
    role(role)
  end

  def admins
    with_role("admin")
  end
end`
      }
    ];
  }

  protected generateMiddlewareFiles(): { path: string; content: string }[] {
    return [
      {
        path: 'src/actions/api/api_action.cr',
        content: `require "lucky"

abstract class Api::ApiAction < Lucky::Action
  include Lucky::ProtectFromForgery
  disable_cookies
  accepted_formats [:json]

  # JWT Authentication
  def authenticate_user!
    user_from_token || unauthorized_response
  end

  def require_admin!
    authenticate_user!
    forbidden_response unless current_user.is_admin?
  end

  private def user_from_token : User?
    token = extract_token_from_header
    return unless token
    
    @current_user ||= AuthService.verify_token(token)
  end

  private def extract_token_from_header : String?
    auth_header = request.headers["Authorization"]?
    return unless auth_header && auth_header.starts_with?("Bearer ")
    
    auth_header[7..-1]
  end

  private getter current_user : User do
    @current_user.not_nil!
  end

  private def unauthorized_response
    json({error: "Unauthorized", message: "Authentication required"}, status: 401)
  end

  private def forbidden_response
    json({error: "Forbidden", message: "Insufficient permissions"}, status: 403)
  end

  # CORS handling
  before_action do
    response.headers["Access-Control-Allow-Origin"] = ENV["CORS_ORIGIN"]? || "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    
    if request.method == "OPTIONS"
      response.headers["Access-Control-Max-Age"] = "86400"
      head 200
    else
      continue
    end
  end
end`
      },
      {
        path: 'src/actions/health.cr',
        content: `class Health < Lucky::Action
  get "/health" do
    json({
      status: "OK",
      timestamp: Time.local.to_rfc3339,
      service: ENV["APP_NAME"]? || "Lucky API",
      version: "1.0.0"
    })
  end
end`
      },
      {
        path: 'src/actions/api/auth/register.cr',
        content: `class Api::Auth::Register < Api::ApiAction
  post "/api/auth/register" do
    name = params.get("name")
    email = params.get("email")
    password = params.get("password")

    result = AuthService.register(name, email, password)
    
    json({
      message: "User registered successfully",
      data: {
        user: result[:user].to_json_safe,
        token: result[:token]
      }
    }, status: 201)
  rescue Avram::InvalidOperationError => error
    json({
      error: "Registration failed",
      message: error.message,
      details: error.details
    }, status: 422)
  rescue ex
    json({
      error: "Registration failed",
      message: ex.message
    }, status: 422)
  end
end`
      },
      {
        path: 'src/actions/api/auth/login.cr',
        content: `class Api::Auth::Login < Api::ApiAction
  post "/api/auth/login" do
    email = params.get("email")
    password = params.get("password")

    if result = AuthService.login(email, password)
      json({
        message: "Login successful",
        data: {
          user: result[:user].to_json_safe,
          token: result[:token]
        }
      })
    else
      json({
        error: "Login failed",
        message: "Invalid credentials"
      }, status: 401)
    end
  end
end`
      },
      {
        path: 'src/actions/api/auth/me.cr',
        content: `class Api::Auth::Me < Api::ApiAction
  get "/api/auth/me" do
    authenticate_user!
    
    json({
      data: current_user.to_json_safe
    })
  end
end`
      },
      {
        path: 'src/actions/api/auth/refresh.cr',
        content: `class Api::Auth::Refresh < Api::ApiAction
  post "/api/auth/refresh" do
    token = params.get("token")
    
    if new_token = AuthService.refresh_token(token)
      if user = AuthService.verify_token(new_token)
        json({
          message: "Token refreshed successfully",
          data: {
            user: user.to_json_safe,
            token: new_token
          }
        })
      else
        json({
          error: "Token refresh failed",
          message: "Invalid token"
        }, status: 401)
      end
    else
      json({
        error: "Token refresh failed", 
        message: "Invalid or expired token"
      }, status: 401)
    end
  end
end`
      },
      {
        path: 'src/actions/api/users/index.cr',
        content: `class Api::Users::Index < Api::ApiAction
  get "/api/users" do
    authenticate_user!
    
    page = params.get?("page").try(&.to_i) || 1
    per_page = params.get?("per_page").try(&.to_i) || 20
    
    users = UserService.all_users(page, per_page)
    
    json({
      data: users.results.map(&.to_json_safe),
      meta: {
        total: users.total,
        page: page,
        per_page: per_page,
        pages: users.total_pages
      }
    })
  end
end`
      },
      {
        path: 'src/actions/api/users/create.cr',
        content: `class Api::Users::Create < Api::ApiAction
  post "/api/users" do
    require_admin!
    
    name = params.get("name")
    email = params.get("email") 
    password = params.get("password")
    role = params.get?("role") || "user"

    user = UserService.create_user!(name, email, password, role)
    
    json({
      message: "User created successfully",
      data: user.to_json_safe
    }, status: 201)
  rescue Avram::InvalidOperationError => error
    json({
      error: "User creation failed",
      message: error.message,
      details: error.details
    }, status: 422)
  rescue ex
    json({
      error: "User creation failed",
      message: ex.message
    }, status: 422)
  end
end`
      },
      {
        path: 'src/actions/api/users/show.cr',
        content: `class Api::Users::Show < Api::ApiAction
  get "/api/users/:user_id" do
    authenticate_user!
    
    user = UserQuery.find(user_id)
    
    json({
      data: user.to_json_safe
    })
  rescue Avram::RecordNotFoundError
    json({
      error: "Not Found",
      message: "User not found"
    }, status: 404)
  end
end`
      },
      {
        path: 'src/actions/api/users/update.cr',
        content: `class Api::Users::Update < Api::ApiAction
  put "/api/users/:user_id" do
    authenticate_user!
    
    user = UserQuery.find(user_id)
    
    # Users can only update themselves unless admin
    unless current_user.id == user.id || current_user.is_admin?
      json({
        error: "Forbidden",
        message: "Access denied"
      }, status: 403)
      return
    end

    update_params = params.to_h.select(["name", "email", "role"])
    # Only admins can change roles
    update_params.delete("role") unless current_user.is_admin?

    updated_user = UserService.update_user!(user, update_params)
    
    json({
      message: "User updated successfully",
      data: updated_user.to_json_safe
    })
  rescue Avram::RecordNotFoundError
    json({
      error: "Not Found",
      message: "User not found"
    }, status: 404)
  rescue Avram::InvalidOperationError => error
    json({
      error: "User update failed",
      message: error.message,
      details: error.details
    }, status: 422)
  rescue ex
    json({
      error: "User update failed",
      message: ex.message
    }, status: 422)
  end
end`
      },
      {
        path: 'src/actions/api/users/delete.cr',
        content: `class Api::Users::Delete < Api::ApiAction
  delete "/api/users/:user_id" do
    require_admin!
    
    user = UserQuery.find(user_id)
    UserService.delete_user!(user)
    
    json({
      message: "User deleted successfully"
    })
  rescue Avram::RecordNotFoundError
    json({
      error: "Not Found",
      message: "User not found"
    }, status: 404)
  rescue ex
    json({
      error: "User deletion failed",
      message: ex.message
    }, status: 422)
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
require "lucky_env"

# Configure test environment
Lucky::Env.temp_config(name: "test") do
  require "../src/app"
end

require "avram/spec"

# Test setup and helpers
class ApiClient
  include Lucky::RequestExpectations
  
  def initialize(@io : IO = IO::Memory.new)
  end

  def get(path : String, headers : HTTP::Headers = HTTP::Headers.new)
    response = Lucky::BaseHTTPClient.new.get(path, headers: headers)
    JSON.parse(response.body)
  end

  def post(path : String, body : String, headers : HTTP::Headers = HTTP::Headers.new)
    headers["Content-Type"] = "application/json"
    response = Lucky::BaseHTTPClient.new.post(path, body: body, headers: headers)
    JSON.parse(response.body)
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
  SaveUser.create!(
    name: name,
    email: email,
    password: password,
    password_confirmation: password,
    role: role
  )
end

Spec.before_each do
  AppDatabase.truncate
end`
      },
      {
        path: 'spec/operations/save_user_spec.cr',
        content: `require "../spec_helper"

describe SaveUser do
  it "creates user with valid data" do
    operation = SaveUser.new(
      name: "Test User",
      email: "test@example.com",
      password: "password123",
      password_confirmation: "password123"
    )
    
    user = operation.save!
    user.name.should eq("Test User")
    user.email.should eq("test@example.com")
    user.role.should eq("user")
  end

  it "validates email uniqueness" do
    create_test_user(email: "test@example.com")
    
    operation = SaveUser.new(
      name: "Another User",
      email: "test@example.com",
      password: "password123",
      password_confirmation: "password123"
    )
    
    operation.save.should be_nil
    operation.email.errors.should contain("is already taken")
  end

  it "validates required fields" do
    operation = SaveUser.new
    
    operation.save.should be_nil
    operation.name.errors.should contain("is required")
    operation.email.errors.should contain("is required")
  end

  it "validates email format" do
    operation = SaveUser.new(
      name: "Test User",
      email: "invalid-email",
      password: "password123",
      password_confirmation: "password123"
    )
    
    operation.save.should be_nil
    operation.email.errors.should contain("is invalid")
  end
end`
      },
      {
        path: 'spec/services/auth_service_spec.cr',
        content: `require "../spec_helper"

describe AuthService do
  describe ".register" do
    it "creates user and returns token" do
      result = AuthService.register("Test User", "test@example.com", "password123")
      
      result[:user].should be_a(User)
      result[:token].should be_a(String)
      
      user = result[:user]
      user.name.should eq("Test User")
      user.email.should eq("test@example.com")
    end
  end

  describe ".login" do
    it "returns user and token for valid credentials" do
      user = create_test_user
      
      result = AuthService.login("test@example.com", "password123")
      result.should_not be_nil
      
      if result
        result[:user].id.should eq(user.id)
        result[:token].should be_a(String)
      end
    end

    it "returns nil for invalid credentials" do
      create_test_user
      
      result = AuthService.login("test@example.com", "wrongpassword")
      result.should be_nil
    end
  end

  describe ".verify_token" do
    it "returns user for valid token" do
      user = create_test_user
      token = AuthService.generate_token(user)
      
      verified_user = AuthService.verify_token(token)
      verified_user.should_not be_nil
      verified_user.not_nil!.id.should eq(user.id)
    end

    it "returns nil for invalid token" do
      user = AuthService.verify_token("invalid-token")
      user.should be_nil
    end
  end
end`
      },
      {
        path: 'spec/actions/api/auth/register_spec.cr',
        content: `require "../../../spec_helper"

describe Api::Auth::Register do
  it "registers new user successfully" do
    client = ApiClient.new
    
    response = client.post("/api/auth/register", {
      name: "Test User",
      email: "test@example.com", 
      password: "password123"
    }.to_json)
    
    response["message"].should eq("User registered successfully")
    response["data"]["user"]["email"].should eq("test@example.com")
    response["data"]["token"].should be_a(String)
  end

  it "returns error for duplicate email" do
    create_test_user(email: "test@example.com")
    client = ApiClient.new
    
    response = client.post("/api/auth/register", {
      name: "Another User",
      email: "test@example.com",
      password: "password123"  
    }.to_json)
    
    response["error"].should eq("Registration failed")
  end
end`
      },
      {
        path: 'spec/actions/api/auth/login_spec.cr',
        content: `require "../../../spec_helper"

describe Api::Auth::Login do
  it "logs in user with valid credentials" do
    create_test_user
    client = ApiClient.new
    
    response = client.post("/api/auth/login", {
      email: "test@example.com",
      password: "password123"
    }.to_json)
    
    response["message"].should eq("Login successful")
    response["data"]["user"]["email"].should eq("test@example.com") 
    response["data"]["token"].should be_a(String)
  end

  it "returns error for invalid credentials" do
    create_test_user
    client = ApiClient.new
    
    response = client.post("/api/auth/login", {
      email: "test@example.com",
      password: "wrongpassword"
    }.to_json)
    
    response["error"].should eq("Login failed")
    response["message"].should eq("Invalid credentials")
  end
end`
      },
      {
        path: 'db/migrations/20241201000001_create_users.cr',
        content: `class CreateUsers::V20241201000001 < Avram::Migrator::Migration::V1
  def migrate
    create table_for(User) do
      primary_key id : Int64
      add_timestamps
      add name : String
      add email : String, unique: true
      add encrypted_password : String
      add role : String, default: "user"
      add is_active : Bool, default: true
    end
  end

  def rollback
    drop table_for(User)
  end
end`
      }
    ];
  }
}