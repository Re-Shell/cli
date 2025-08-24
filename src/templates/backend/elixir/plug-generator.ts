import { ElixirBackendGenerator } from './elixir-base-generator';
import { BackendTemplate } from '../../types';

export class PlugGenerator extends ElixirBackendGenerator {
  getFrameworkDependencies(): any[] {
    return [
      {name: "plug", version: "~> 1.14"},
      {name: "plug_cowboy", version: "~> 2.6"},
      {name: "jason", version: "~> 1.4"},
      {name: "cors_plug", version: "~> 3.0"},
      {name: "dotenv", version: "~> 3.0", only: ["dev", "test"]},
      {name: "httpoison", version: "~> 2.0"},
      {name: "timex", version: "~> 3.7"},
      {name: "uuid", version: "~> 1.1"},
      {name: "cachex", version: "~> 3.6"},
      {name: "telemetry", version: "~> 1.2"},
      {name: "telemetry_metrics", version: "~> 0.6"},
      {name: "telemetry_poller", version: "~> 1.0"},
      {name: "ex_doc", version: "~> 0.27", only: "dev", runtime: false},
      {name: "dialyxir", version: "~> 1.3", only: ["dev"], runtime: false},
      {name: "credo", version: "~> 1.7", only: ["dev", "test"], runtime: false},
      {name: "excoveralls", version: "~> 0.10", only: "test"}
    ];
  }

  generateMainApplicationFile(): string {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Application do
  @moduledoc false

  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    port = String.to_integer(System.get_env("PORT") || "4000")

    children = [
      # Registry for named processes
      {Registry, keys: :unique, name: ${moduleName}.Registry},
      
      # Cachex for caching
      {Cachex, name: :${appName}_cache},
      
      # Telemetry
      ${moduleName}.Telemetry,
      
      # Main supervisor
      ${moduleName}.Supervisors.MainSupervisor,
      
      # Plug/Cowboy server
      {Plug.Cowboy, scheme: :http, plug: ${moduleName}.Router, options: [port: port]}
    ]

    opts = [strategy: :one_for_one, name: ${moduleName}.Supervisor]
    
    Logger.info("Starting ${moduleName} on port #{port}")
    Supervisor.start_link(children, opts)
  end

  @impl true
  def stop(_state) do
    Logger.info("Stopping ${moduleName} application...")
    :ok
  end
end
`;
  }

  generateSupervisorFile(): string {
    // Use base implementation
    return '';
  }

  generateGenServerFiles(): { path: string; content: string }[] {
    // Use base implementation
    return [];
  }

  generateRouterFile(): string {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}.Router do
  use Plug.Router
  use Plug.ErrorHandler

  plug Plug.Logger
  plug CORSPlug
  plug :match
  plug Plug.Parsers,
    parsers: [:json],
    pass: ["application/json"],
    json_decoder: Jason
  plug :dispatch

  # Health check
  get "/health" do
    send_json(conn, 200, %{
      status: "healthy",
      service: "${appName}",
      timestamp: DateTime.utc_now()
    })
  end

  # API routes
  forward "/api/auth", to: ${moduleName}.Routers.AuthRouter
  forward "/api/users", to: ${moduleName}.Routers.UserRouter
  
  # Catch-all
  match _ do
    send_json(conn, 404, %{error: "Not found"})
  end

  @impl Plug.ErrorHandler
  def handle_errors(conn, %{kind: _kind, reason: _reason, stack: _stack}) do
    send_json(conn, conn.status, %{error: "Something went wrong"})
  end

  defp send_json(conn, status, data) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(data))
  end
end
`;
  }

  generateControllerFiles(): { path: string; content: string }[] {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return [
      {
        path: `lib/${appName}/routers/auth_router.ex`,
        content: `defmodule ${moduleName}.Routers.AuthRouter do
  use Plug.Router
  alias ${moduleName}.Services.AuthService
  alias ${moduleName}.Plugs.JSONResponse

  plug :match
  plug :dispatch

  post "/register" do
    with {:ok, params} <- fetch_json_params(conn),
         {:ok, user, token} <- AuthService.register(params) do
      JSONResponse.send(conn, 201, %{
        user: user,
        token: token
      })
    else
      {:error, errors} ->
        JSONResponse.send_error(conn, 422, errors)
    end
  end

  post "/login" do
    with {:ok, params} <- fetch_json_params(conn),
         {:ok, user, token} <- AuthService.login(params["email"], params["password"]) do
      JSONResponse.send(conn, 200, %{
        user: user,
        token: token
      })
    else
      {:error, :invalid_credentials} ->
        JSONResponse.send_error(conn, 401, "Invalid email or password")
    end
  end

  match _ do
    JSONResponse.send_error(conn, 404, "Not found")
  end

  defp fetch_json_params(conn) do
    case conn.body_params do
      %Plug.Conn.Unfetched{} -> {:error, "No body provided"}
      params -> {:ok, params}
    end
  end
end
`
      },
      {
        path: `lib/${appName}/routers/user_router.ex`,
        content: `defmodule ${moduleName}.Routers.UserRouter do
  use Plug.Router
  alias ${moduleName}.Services.UserService
  alias ${moduleName}.Plugs.{JSONResponse, Authenticate}

  plug Authenticate
  plug :match
  plug :dispatch

  get "/" do
    users = UserService.list_users()
    JSONResponse.send(conn, 200, %{users: users})
  end

  get "/:id" do
    case UserService.get_user(id) do
      {:ok, user} ->
        JSONResponse.send(conn, 200, %{user: user})
      {:error, :not_found} ->
        JSONResponse.send_error(conn, 404, "User not found")
    end
  end

  post "/" do
    current_user = conn.assigns[:current_user]
    
    if current_user.role == "admin" do
      with {:ok, params} <- fetch_json_params(conn),
           {:ok, user} <- UserService.create_user(params) do
        JSONResponse.send(conn, 201, %{user: user})
      else
        {:error, errors} ->
          JSONResponse.send_error(conn, 422, errors)
      end
    else
      JSONResponse.send_error(conn, 403, "Forbidden")
    end
  end

  put "/:id" do
    current_user = conn.assigns[:current_user]
    
    if current_user.id == id || current_user.role == "admin" do
      with {:ok, params} <- fetch_json_params(conn),
           {:ok, user} <- UserService.update_user(id, params) do
        JSONResponse.send(conn, 200, %{user: user})
      else
        {:error, :not_found} ->
          JSONResponse.send_error(conn, 404, "User not found")
        {:error, errors} ->
          JSONResponse.send_error(conn, 422, errors)
      end
    else
      JSONResponse.send_error(conn, 403, "Forbidden")
    end
  end

  delete "/:id" do
    current_user = conn.assigns[:current_user]
    
    if current_user.role == "admin" do
      case UserService.delete_user(id) do
        :ok ->
          send_resp(conn, 204, "")
        {:error, :not_found} ->
          JSONResponse.send_error(conn, 404, "User not found")
      end
    else
      JSONResponse.send_error(conn, 403, "Forbidden")
    end
  end

  match _ do
    JSONResponse.send_error(conn, 404, "Not found")
  end

  defp fetch_json_params(conn) do
    case conn.body_params do
      %Plug.Conn.Unfetched{} -> {:error, "No body provided"}
      params -> {:ok, params}
    end
  end
end
`
      },
      {
        path: `lib/${appName}/plugs/json_response.ex`,
        content: `defmodule ${moduleName}.Plugs.JSONResponse do
  @moduledoc """
  Helper module for sending JSON responses.
  """
  import Plug.Conn

  def send(conn, status, data) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(data))
    |> halt()
  end

  def send_error(conn, status, message) when is_binary(message) do
    send(conn, status, %{error: message})
  end

  def send_error(conn, status, errors) when is_map(errors) do
    send(conn, status, %{errors: errors})
  end
end
`
      },
      {
        path: `lib/${appName}/plugs/authenticate.ex`,
        content: `defmodule ${moduleName}.Plugs.Authenticate do
  @moduledoc """
  Plug for JWT authentication.
  """
  import Plug.Conn
  alias ${moduleName}.Services.{AuthService, UserService}
  alias ${moduleName}.Plugs.JSONResponse

  def init(opts), do: opts

  def call(conn, _opts) do
    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         {:ok, user_id} <- AuthService.verify_token(token),
         {:ok, user} <- UserService.get_user(user_id) do
      assign(conn, :current_user, user)
    else
      _ ->
        conn
        |> JSONResponse.send_error(401, "Unauthorized")
        |> halt()
    end
  end
end
`
      }
    ];
  }

  generateServiceFiles(): { path: string; content: string }[] {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return [
      {
        path: `lib/${appName}/services/auth_service.ex`,
        content: `defmodule ${moduleName}.Services.AuthService do
  @moduledoc """
  Authentication service handling user registration, login, and JWT tokens.
  """
  alias ${moduleName}.Services.UserService
  alias ${moduleName}.Utils.JWT

  @token_expiry 86400 # 24 hours

  def register(params) do
    with {:ok, user} <- UserService.create_user(params),
         {:ok, token} <- generate_token(user.id) do
      {:ok, sanitize_user(user), token}
    end
  end

  def login(email, password) do
    with {:ok, user} <- UserService.authenticate(email, password),
         {:ok, token} <- generate_token(user.id) do
      {:ok, sanitize_user(user), token}
    else
      {:error, :invalid_credentials} -> {:error, :invalid_credentials}
      error -> error
    end
  end

  def verify_token(token) do
    JWT.verify_and_validate(token)
  end

  defp generate_token(user_id) do
    claims = %{
      "sub" => user_id,
      "exp" => System.system_time(:second) + @token_expiry
    }
    
    JWT.generate_and_sign(claims)
  end

  defp sanitize_user(user) do
    Map.take(user, [:id, :email, :name, :role])
  end
end
`
      },
      {
        path: `lib/${appName}/services/user_service.ex`,
        content: `defmodule ${moduleName}.Services.UserService do
  @moduledoc """
  User management service.
  """
  alias ${moduleName}.Workers.StateManager
  require Logger

  def list_users do
    case StateManager.get_state() do
      {:ok, state} ->
        state
        |> Map.to_list()
        |> Enum.filter(fn {{type, _id}, _data} -> type == :user end)
        |> Enum.map(fn {{:user, _id}, data} -> data end)
      
      _ ->
        []
    end
  end

  def get_user(id) do
    case StateManager.get_state() do
      {:ok, state} ->
        case Map.get(state, {:user, id}) do
          nil -> {:error, :not_found}
          user -> {:ok, user}
        end
      
      _ ->
        {:error, :not_found}
    end
  end

  def create_user(params) do
    user_id = UUID.uuid4()
    
    user = %{
      id: user_id,
      email: params["email"],
      name: params["name"],
      password_hash: hash_password(params["password"]),
      role: params["role"] || "user",
      created_at: DateTime.utc_now()
    }
    
    event = %{
      type: :user_created,
      user_id: user_id,
      user_data: user
    }
    
    case StateManager.apply_event(event) do
      :ok -> {:ok, Map.drop(user, [:password_hash])}
      error -> error
    end
  end

  def update_user(id, params) do
    with {:ok, existing_user} <- get_user(id) do
      changes = Map.take(params, ["name", "email", "role"])
      
      event = %{
        type: :user_updated,
        user_id: id,
        changes: changes
      }
      
      case StateManager.apply_event(event) do
        :ok -> {:ok, Map.merge(existing_user, changes)}
        error -> error
      end
    end
  end

  def delete_user(id) do
    with {:ok, _user} <- get_user(id) do
      event = %{
        type: :user_deleted,
        user_id: id
      }
      
      case StateManager.apply_event(event) do
        :ok -> :ok
        error -> error
      end
    end
  end

  def authenticate(email, password) do
    users = list_users()
    
    case Enum.find(users, fn u -> u.email == email end) do
      nil ->
        # Prevent timing attacks
        Bcrypt.no_user_verify()
        {:error, :invalid_credentials}
      
      user ->
        if verify_password(password, user.password_hash) do
          {:ok, user}
        else
          {:error, :invalid_credentials}
        end
    end
  end

  defp hash_password(password) do
    # In a real app, use Argon2 or Bcrypt
    :crypto.hash(:sha256, password) |> Base.encode16()
  end

  defp verify_password(password, hash) do
    :crypto.hash(:sha256, password) |> Base.encode16() == hash
  end
end
`
      },
      {
        path: `lib/${appName}/utils/jwt.ex`,
        content: `defmodule ${moduleName}.Utils.JWT do
  @moduledoc """
  Simple JWT implementation for demonstration.
  In production, use a library like Joken.
  """
  
  @secret System.get_env("JWT_SECRET") || "your-secret-key"

  def generate_and_sign(claims) do
    header = %{"alg" => "HS256", "typ" => "JWT"}
    
    payload = 
      claims
      |> Map.put("iat", System.system_time(:second))
    
    encoded_header = encode_part(header)
    encoded_payload = encode_part(payload)
    
    signature = sign("#{encoded_header}.#{encoded_payload}")
    
    {:ok, "#{encoded_header}.#{encoded_payload}.#{signature}"}
  end

  def verify_and_validate(token) do
    with [header, payload, signature] <- String.split(token, "."),
         true <- verify_signature(header, payload, signature),
         {:ok, claims} <- decode_payload(payload),
         true <- valid_expiry?(claims) do
      {:ok, claims["sub"]}
    else
      _ -> {:error, :invalid_token}
    end
  end

  defp encode_part(data) do
    data
    |> Jason.encode!()
    |> Base.url_encode64(padding: false)
  end

  defp decode_payload(encoded) do
    case Base.url_decode64(encoded, padding: false) do
      {:ok, decoded} -> Jason.decode(decoded)
      _ -> {:error, :invalid_payload}
    end
  end

  defp sign(data) do
    :crypto.mac(:hmac, :sha256, @secret, data)
    |> Base.url_encode64(padding: false)
  end

  defp verify_signature(header, payload, signature) do
    expected = sign("#{header}.#{payload}")
    expected == signature
  end

  defp valid_expiry?(%{"exp" => exp}) do
    exp > System.system_time(:second)
  end

  defp valid_expiry?(_), do: true
end
`
      }
    ];
  }

  generateConfigFiles(): { path: string; content: string }[] {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return [
      {
        path: `config/config.exs`,
        content: `import Config

config :${appName},
  port: 4000,
  jwt_secret: System.get_env("JWT_SECRET") || "your-secret-key"

# Configure logging
config :logger, :console,
  format: "$time $metadata[$level] $message\\n",
  metadata: [:request_id]

# Import environment specific config
import_config "#{config_env()}.exs"
`
      },
      {
        path: `config/dev.exs`,
        content: `import Config

# For development, we disable any cache and enable debugging
config :${appName}, ${moduleName}.Endpoint,
  debug_errors: true,
  code_reloader: true,
  check_origin: false

# Set a higher stacktrace during development
config :phoenix, :stacktrace_depth, 20

# Initialize plugs at runtime for faster development compilation
config :phoenix, :plug_init_mode, :runtime
`
      },
      {
        path: `config/test.exs`,
        content: `import Config

# We don't run a server during test
config :${appName}, ${moduleName}.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "test-secret-key",
  server: false

# Print only warnings and errors during test
config :logger, level: :warn

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime
`
      },
      {
        path: `config/prod.exs`,
        content: `import Config

# For production, don't forget to configure the url host
config :${appName},
  port: {:system, "PORT"}

# Do not print debug messages in production
config :logger, level: :info

# Runtime configuration in config/runtime.exs
`
      },
      {
        path: `config/runtime.exs`,
        content: `import Config

if config_env() == :prod do
  port = String.to_integer(System.get_env("PORT") || "4000")
  
  config :${appName},
    port: port,
    jwt_secret: System.fetch_env!("JWT_SECRET")
end
`
      }
    ];
  }

  generateTestFiles(): { path: string; content: string }[] {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return [
      {
        path: `test/${appName}/router_test.exs`,
        content: `defmodule ${moduleName}.RouterTest do
  use ExUnit.Case, async: true
  use Plug.Test

  @opts ${moduleName}.Router.init([])

  describe "health check" do
    test "returns healthy status" do
      conn = conn(:get, "/health")
      conn = ${moduleName}.Router.call(conn, @opts)

      assert conn.state == :sent
      assert conn.status == 200
      
      body = Jason.decode!(conn.resp_body)
      assert body["status"] == "healthy"
      assert body["service"] == "${appName}"
    end
  end

  describe "not found" do
    test "returns 404 for unknown routes" do
      conn = conn(:get, "/unknown")
      conn = ${moduleName}.Router.call(conn, @opts)

      assert conn.state == :sent
      assert conn.status == 404
      
      body = Jason.decode!(conn.resp_body)
      assert body["error"] == "Not found"
    end
  end
end
`
      },
      {
        path: `test/${appName}/services/auth_service_test.exs`,
        content: `defmodule ${moduleName}.Services.AuthServiceTest do
  use ExUnit.Case
  alias ${moduleName}.Services.{AuthService, UserService}

  @valid_user %{
    "email" => "test@example.com",
    "password" => "password123",
    "name" => "Test User"
  }

  describe "register/1" do
    test "creates user and returns token" do
      {:ok, user, token} = AuthService.register(@valid_user)
      
      assert user.email == @valid_user["email"]
      assert user.name == @valid_user["name"]
      assert is_binary(token)
      refute Map.has_key?(user, :password_hash)
    end

    test "returns error for invalid params" do
      {:error, errors} = AuthService.register(%{})
      assert is_map(errors)
    end
  end

  describe "login/2" do
    setup do
      {:ok, _user, _token} = AuthService.register(@valid_user)
      :ok
    end

    test "returns user and token for valid credentials" do
      {:ok, user, token} = AuthService.login(@valid_user["email"], @valid_user["password"])
      
      assert user.email == @valid_user["email"]
      assert is_binary(token)
    end

    test "returns error for invalid credentials" do
      {:error, :invalid_credentials} = AuthService.login("wrong@example.com", "wrong")
    end
  end

  describe "verify_token/1" do
    test "returns user_id for valid token" do
      {:ok, _user, token} = AuthService.register(@valid_user)
      {:ok, user_id} = AuthService.verify_token(token)
      
      assert is_binary(user_id)
    end

    test "returns error for invalid token" do
      {:error, :invalid_token} = AuthService.verify_token("invalid.token.here")
    end
  end
end
`
      }
    ];
  }

  // Helper methods are inherited from base class
}