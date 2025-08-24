import { ElixirBackendGenerator } from './elixir-base-generator';
import { BackendTemplate } from '../../types';

export class PhoenixGenerator extends ElixirBackendGenerator {
  getFrameworkDependencies(): any[] {
    return [
      {name: "phoenix", version: "~> 1.7.10"},
      {name: "phoenix_html", version: "~> 3.3"},
      {name: "phoenix_live_reload", version: "~> 1.4", only: "dev"},
      {name: "phoenix_live_view", version: "~> 0.20.1"},
      {name: "floki", version: ">= 0.30.0", only: "test"},
      {name: "phoenix_live_dashboard", version: "~> 0.8.2"},
      {name: "telemetry_metrics", version: "~> 0.6"},
      {name: "telemetry_poller", version: "~> 1.0"},
      {name: "jason", version: "~> 1.2"},
      {name: "plug_cowboy", version: "~> 2.5"},
      {name: "ecto_sql", version: "~> 3.10"},
      {name: "postgrex", version: ">= 0.0.0"},
      {name: "swoosh", version: "~> 1.3"},
      {name: "finch", version: "~> 0.13"},
      {name: "cors_plug", version: "~> 3.0"},
      {name: "guardian", version: "~> 2.3"},
      {name: "argon2_elixir", version: "~> 3.0"},
      {name: "ex_doc", version: "~> 0.27", only: "dev", runtime: false},
      {name: "dialyxir", version: "~> 1.3", only: ["dev"], runtime: false},
      {name: "credo", version: "~> 1.7", only: ["dev", "test"], runtime: false},
      {name: "excoveralls", version: "~> 0.10", only: "test"}
    ];
  }

  generateMainApplicationFile(): string {
    return ''; // Phoenix uses its own application structure
  }

  generateSupervisorFile(): string {
    return ''; // Phoenix has its own supervision tree
  }

  generateGenServerFiles(): { path: string; content: string }[] {
    return []; // Use base class implementation
  }

  generateRouterFile(): string {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return `defmodule ${moduleName}Web.Router do
  use ${moduleName}Web, :router

  pipeline :api do
    plug :accepts, ["json"]
    plug CORSPlug
  end

  pipeline :authenticated do
    plug ${moduleName}Web.Auth.Pipeline
  end

  scope "/api", ${moduleName}Web do
    pipe_through :api

    # Public routes
    post "/auth/register", AuthController, :register
    post "/auth/login", AuthController, :login
    post "/auth/refresh", AuthController, :refresh

    # Health check
    get "/health", HealthController, :index
  end

  scope "/api", ${moduleName}Web do
    pipe_through [:api, :authenticated]

    # Protected routes
    get "/auth/me", AuthController, :me
    resources "/users", UserController, except: [:new, :edit]
  end

  # Enable LiveDashboard in development
  if Mix.env() in [:dev, :test] do
    import Phoenix.LiveDashboard.Router

    scope "/" do
      pipe_through [:fetch_session, :protect_from_forgery]
      live_dashboard "/dashboard", metrics: ${moduleName}Web.Telemetry
    end
  end
end
`;
  }

  generateControllerFiles(): { path: string; content: string }[] {
    const appName = this.getAppName(this.options);
    const moduleName = this.toPascalCase(appName);

    return [
      {
        path: `lib/${appName}_web/controllers/health_controller.ex`,
        content: `defmodule ${moduleName}Web.HealthController do
  use ${moduleName}Web, :controller

  def index(conn, _params) do
    json(conn, %{
      status: "healthy",
      service: "${appName}",
      timestamp: DateTime.utc_now()
    })
  end
end
`
      },
      {
        path: `lib/${appName}_web/controllers/auth_controller.ex`,
        content: `defmodule ${moduleName}Web.AuthController do
  use ${moduleName}Web, :controller
  alias ${moduleName}.Accounts
  alias ${moduleName}.Guardian

  def register(conn, %{"user" => user_params}) do
    case Accounts.create_user(user_params) do
      {:ok, user} ->
        {:ok, token, _claims} = Guardian.encode_and_sign(user)
        
        conn
        |> put_status(:created)
        |> json(%{
          user: %{
            id: user.id,
            email: user.email,
            name: user.name
          },
          token: token
        })
      
      {:error, changeset} ->
        conn
        |> put_status(:unprocessable_entity)
        |> json(%{errors: translate_errors(changeset)})
    end
  end

  def login(conn, %{"email" => email, "password" => password}) do
    case Accounts.authenticate_user(email, password) do
      {:ok, user} ->
        {:ok, token, _claims} = Guardian.encode_and_sign(user)
        
        json(conn, %{
          user: %{
            id: user.id,
            email: user.email,
            name: user.name
          },
          token: token
        })
      
      {:error, :invalid_credentials} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid email or password"})
    end
  end

  def me(conn, _params) do
    user = Guardian.Plug.current_resource(conn)
    json(conn, %{
      user: %{
        id: user.id,
        email: user.email,
        name: user.name
      }
    })
  end

  def refresh(conn, %{"token" => token}) do
    case Guardian.refresh(token) do
      {:ok, _old_stuff, {new_token, _new_claims}} ->
        json(conn, %{token: new_token})
      
      {:error, _reason} ->
        conn
        |> put_status(:unauthorized)
        |> json(%{error: "Invalid token"})
    end
  end

  defp translate_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Enum.reduce(opts, msg, fn {key, value}, acc ->
        String.replace(acc, "%{#{key}}", to_string(value))
      end)
    end)
  end
end
`
      },
      {
        path: `lib/${appName}_web/controllers/user_controller.ex`,
        content: `defmodule ${moduleName}Web.UserController do
  use ${moduleName}Web, :controller
  alias ${moduleName}.Accounts
  alias ${moduleName}.Accounts.User

  action_fallback ${moduleName}Web.FallbackController

  def index(conn, params) do
    users = Accounts.list_users(params)
    render(conn, "index.json", users: users)
  end

  def create(conn, %{"user" => user_params}) do
    with {:ok, %User{} = user} <- Accounts.create_user(user_params) do
      conn
      |> put_status(:created)
      |> put_resp_header("location", Routes.user_path(conn, :show, user))
      |> render("show.json", user: user)
    end
  end

  def show(conn, %{"id" => id}) do
    user = Accounts.get_user!(id)
    render(conn, "show.json", user: user)
  end

  def update(conn, %{"id" => id, "user" => user_params}) do
    user = Accounts.get_user!(id)

    with {:ok, %User{} = user} <- Accounts.update_user(user, user_params) do
      render(conn, "show.json", user: user)
    end
  end

  def delete(conn, %{"id" => id}) do
    user = Accounts.get_user!(id)

    with {:ok, %User{}} <- Accounts.delete_user(user) do
      send_resp(conn, :no_content, "")
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
        path: `lib/${appName}/accounts.ex`,
        content: `defmodule ${moduleName}.Accounts do
  @moduledoc """
  The Accounts context.
  """

  import Ecto.Query, warn: false
  alias ${moduleName}.Repo
  alias ${moduleName}.Accounts.User

  def list_users(params \\\\ %{}) do
    User
    |> filter_users(params)
    |> Repo.all()
  end

  def get_user!(id), do: Repo.get!(User, id)

  def get_user_by_email(email) do
    Repo.get_by(User, email: email)
  end

  def create_user(attrs \\\\ %{}) do
    %User{}
    |> User.registration_changeset(attrs)
    |> Repo.insert()
  end

  def update_user(%User{} = user, attrs) do
    user
    |> User.changeset(attrs)
    |> Repo.update()
  end

  def delete_user(%User{} = user) do
    Repo.delete(user)
  end

  def authenticate_user(email, password) do
    user = get_user_by_email(email)

    cond do
      user && Argon2.verify_pass(password, user.password_hash) ->
        {:ok, user}
      
      user ->
        {:error, :invalid_credentials}
      
      true ->
        Argon2.no_user_verify()
        {:error, :invalid_credentials}
    end
  end

  defp filter_users(query, params) do
    Enum.reduce(params, query, fn
      {"email", email}, query ->
        where(query, [u], u.email == ^email)
      
      {"name", name}, query ->
        where(query, [u], ilike(u.name, ^"%#{name}%"))
      
      _, query ->
        query
    end)
  end
end
`
      },
      {
        path: `lib/${appName}/guardian.ex`,
        content: `defmodule ${moduleName}.Guardian do
  use Guardian, otp_app: :${appName}

  alias ${moduleName}.Accounts

  def subject_for_token(user, _claims) do
    {:ok, to_string(user.id)}
  end

  def resource_from_claims(%{"sub" => id}) do
    case Accounts.get_user!(id) do
      nil -> {:error, :resource_not_found}
      user -> {:ok, user}
    end
  end
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
  ecto_repos: [${moduleName}.Repo]

# Configures the endpoint
config :${appName}, ${moduleName}Web.Endpoint,
  url: [host: "localhost"],
  render_errors: [view: ${moduleName}Web.ErrorView, accepts: ~w(json), layout: false],
  pubsub_server: ${moduleName}.PubSub,
  live_view: [signing_salt: "your_signing_salt"]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

# Configure Guardian
config :${appName}, ${moduleName}.Guardian,
  issuer: "${appName}",
  secret_key: System.get_env("GUARDIAN_SECRET_KEY") || "your-secret-key"

# Import environment specific config
import_config "#{config_env()}.exs"
`
      },
      {
        path: `config/dev.exs`,
        content: `import Config

# Configure your database
config :${appName}, ${moduleName}.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "${appName}_dev",
  stacktrace: true,
  show_sensitive_data_on_connection_error: true,
  pool_size: 10

config :${appName}, ${moduleName}Web.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4000],
  check_origin: false,
  code_reloader: true,
  debug_errors: true,
  secret_key_base: "your-dev-secret-key-base",
  watchers: []

config :logger, :console, format: "[$level] $message\\n"
config :phoenix, :stacktrace_depth, 20
config :phoenix, :plug_init_mode, :runtime
`
      },
      {
        path: `config/test.exs`,
        content: `import Config

# Configure your database
config :${appName}, ${moduleName}.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "${appName}_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10

config :${appName}, ${moduleName}Web.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "test-secret-key-base",
  server: false

config :logger, level: :warn
config :phoenix, :plug_init_mode, :runtime
`
      },
      {
        path: `config/prod.exs`,
        content: `import Config

config :${appName}, ${moduleName}Web.Endpoint,
  cache_static_manifest: "priv/static/cache_manifest.json"

config :logger, level: :info
`
      },
      {
        path: `config/runtime.exs`,
        content: `import Config

if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  config :${appName}, ${moduleName}.Repo,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10")

  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"
  port = String.to_integer(System.get_env("PORT") || "4000")

  config :${appName}, ${moduleName}Web.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      ip: {0, 0, 0, 0, 0, 0, 0, 0},
      port: port
    ],
    secret_key_base: secret_key_base
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
        path: `test/${appName}_web/controllers/health_controller_test.exs`,
        content: `defmodule ${moduleName}Web.HealthControllerTest do
  use ${moduleName}Web.ConnCase

  describe "GET /api/health" do
    test "returns healthy status", %{conn: conn} do
      conn = get(conn, "/api/health")
      
      assert json_response(conn, 200) == %{
        "status" => "healthy",
        "service" => "${appName}",
        "timestamp" => json_response(conn, 200)["timestamp"]
      }
    end
  end
end
`
      },
      {
        path: `test/${appName}_web/controllers/auth_controller_test.exs`,
        content: `defmodule ${moduleName}Web.AuthControllerTest do
  use ${moduleName}Web.ConnCase
  alias ${moduleName}.Accounts

  @valid_attrs %{
    email: "test@example.com",
    password: "password123",
    name: "Test User"
  }

  setup %{conn: conn} do
    {:ok, conn: put_req_header(conn, "accept", "application/json")}
  end

  describe "register" do
    test "creates user and returns jwt when data is valid", %{conn: conn} do
      conn = post(conn, "/api/auth/register", user: @valid_attrs)
      
      assert %{"user" => user, "token" => token} = json_response(conn, 201)
      assert user["email"] == @valid_attrs.email
      assert user["name"] == @valid_attrs.name
      assert is_binary(token)
    end

    test "returns errors when data is invalid", %{conn: conn} do
      conn = post(conn, "/api/auth/register", user: %{})
      assert json_response(conn, 422)["errors"] != %{}
    end
  end

  describe "login" do
    setup do
      {:ok, user} = Accounts.create_user(@valid_attrs)
      {:ok, user: user}
    end

    test "returns jwt when credentials are valid", %{conn: conn, user: user} do
      conn = post(conn, "/api/auth/login", %{
        email: user.email,
        password: @valid_attrs.password
      })
      
      assert %{"user" => user_data, "token" => token} = json_response(conn, 200)
      assert user_data["id"] == user.id
      assert is_binary(token)
    end

    test "returns error when credentials are invalid", %{conn: conn} do
      conn = post(conn, "/api/auth/login", %{
        email: "wrong@example.com",
        password: "wrongpassword"
      })
      
      assert json_response(conn, 401)["error"] == "Invalid email or password"
    end
  end
end
`
      },
      {
        path: `test/support/conn_case.ex`,
        content: `defmodule ${moduleName}Web.ConnCase do
  use ExUnit.CaseTemplate

  using do
    quote do
      import Plug.Conn
      import Phoenix.ConnTest
      import ${moduleName}Web.ConnCase

      alias ${moduleName}Web.Router.Helpers, as: Routes

      @endpoint ${moduleName}Web.Endpoint
    end
  end

  setup tags do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(${moduleName}.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end
end
`
      }
    ];
  }

  // Helper methods are inherited from base class
}