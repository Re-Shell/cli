/**
 * OCaml Sihl Framework Generator
 * Generates an OCaml backend service with Sihl web framework
 */

import { OCamlBackendGenerator } from './ocaml-base-generator';
import type { FileTemplate } from '../../types';

export class SihlGenerator extends OCamlBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Sihl';
    this.config.features.push(
      'Sihl web framework',
      'Database migrations',
      'Email service',
      'Queue service',
      'Configuration management',
      'Logging service',
      'Authentication service',
      'File storage',
      'Testing utilities',
      'Admin interface'
    );
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'sihl': '>= 4.0.0',
      'sihl-web': '>= 4.0.0',
      'sihl-persistence': '>= 4.0.0',
      'sihl-email': '>= 4.0.0',
      'sihl-queue': '>= 4.0.0',
      'sihl-storage': '>= 4.0.0',
      'lwt': '>= 5.6.0',
      'yojson': '>= 2.0.0',
      'lwt_ppx': '>= 2.1.0',
      'ppx_yojson_conv': '>= v0.16.0',
      'caqti': '>= 2.1.0',
      'caqti-lwt': '>= 2.1.0',
      'logs': '>= 0.7.0',
      'fmt': '>= 0.9.0'
    };
  }

  protected getFrameworkDevDependencies(): Record<string, string> {
    return {
      'alcotest': '>= 1.7.0',
      'alcotest-lwt': '>= 1.7.0',
      'bisect_ppx': '>= 2.8.0',
      'ocaml-lsp-server': '>= 1.17.0',
      'ocamlformat': '>= 0.26.0',
      'utop': '>= 2.13.0'
    };
  }

  protected getFrameworkSpecificFiles(): FileTemplate[] {
    return [
      {
        path: 'lib/app.ml',
        content: this.generateAppFile()
      },
      {
        path: 'lib/app.mli',
        content: this.generateAppInterface()
      },
      {
        path: 'lib/routes.ml',
        content: this.generateRoutesFile()
      },
      {
        path: 'lib/routes.mli',
        content: this.generateRoutesInterface()
      },
      {
        path: 'lib/handlers/user_handlers.ml',
        content: this.generateUserHandlers()
      },
      {
        path: 'lib/handlers/user_handlers.mli',
        content: this.generateUserHandlersInterface()
      },
      {
        path: 'lib/handlers/health_handlers.ml',
        content: this.generateHealthHandlers()
      },
      {
        path: 'lib/handlers/health_handlers.mli',
        content: this.generateHealthHandlersInterface()
      },
      {
        path: 'lib/repository/user_repository.ml',
        content: this.generateUserRepository()
      },
      {
        path: 'lib/repository/user_repository.mli',
        content: this.generateUserRepositoryInterface()
      },
      {
        path: 'lib/migrations/migration_0001_create_users.ml',
        content: this.generateUserMigration()
      },
      {
        path: 'sihl/configuration/development.env',
        content: this.generateDevelopmentEnv()
      },
      {
        path: 'sihl/configuration/production.env',
        content: this.generateProductionEnv()
      }
    ];
  }

  protected generateMainFile(options: any): string {
    return `(** Main application entry point *)
open Lwt.Syntax
open Sihl
open ${options.name.replace(/-/g, '_')}

let services = [
  Sihl.Web.service;
  Sihl.Database.service;
  Sihl.Queue.service;
  Sihl.Email.service;
  Sihl.Storage.service;
]

let () =
  let config = Config.get_config () in
  Logs.info (fun m -> m "🚀 Starting %s server" config.service_name);
  Logs.info (fun m -> m "Environment: %s" config.env);
  
  Sihl.App.empty
  |> Sihl.App.with_services services
  |> App.setup
  |> Sihl.App.run`;
  }

  protected generateConfigFile(options: any): string {
    return `(** Configuration module *)
open Sihl
open Config

type config = {
  port : int;
  host : string;
  env : string;
  service_name : string;
  log_level : string;
  jwt_secret : string;
  jwt_expires_in : string;
}

let get_env key default =
  match Sys.getenv_opt key with
  | Some value -> value
  | None -> default

let get_port () =
  match Sys.getenv_opt "PORT" with
  | Some port_str -> (
    try int_of_string port_str
    with Failure _ -> 8080
  )
  | None -> 8080

let get_config () = {
  port = get_port ();
  host = get_env "HOST" "0.0.0.0";
  env = get_env "SIHL_ENV" "development";
  service_name = get_env "SERVICE_NAME" "${options.name}";
  log_level = get_env "LOG_LEVEL" "info";
  jwt_secret = get_env "JWT_SECRET" "your-secret-key-change-in-production";
  jwt_expires_in = get_env "JWT_EXPIRES_IN" "7d";
}`;
  }

  private generateAppFile(): string {
    return `(** Sihl application setup *)
open Lwt.Syntax
open Sihl
open App

let middlewares = [
  Sihl.Web.Middleware.flash ();
  Sihl.Web.Middleware.json_decode ();
]

let setup app =
  app
  |> Sihl.App.with_middlewares middlewares
  |> Routes.setup

let run () =
  let config = Config.get_config () in
  Sihl.Configuration.read_env_file 
    ~env:config.env 
    ~file:(Printf.sprintf "sihl/configuration/%s.env" config.env);
  
  let services = [
    Sihl.Web.service;
    Sihl.Database.service;
    Sihl.Queue.service;
    Sihl.Email.service;
    Sihl.Storage.service;
  ] in
  
  Sihl.App.empty
  |> Sihl.App.with_services services
  |> setup
  |> Sihl.App.run`;
  }

  private generateAppInterface(): string {
    return `(** Sihl application interface *)

(** Setup the Sihl application with all routes and middleware *)
val setup : Sihl.App.t -> Sihl.App.t

(** Run the Sihl application *)
val run : unit -> unit`;
  }

  private generateRoutesFile(): string {
    return `(** Routes configuration *)
open Sihl
open Routes

let health_routes = [
  Sihl.Web.get "/health" Health_handlers.health;
  Sihl.Web.get "/ready" Health_handlers.ready;
  Sihl.Web.get "/info" Health_handlers.info;
]

let user_routes = [
  Sihl.Web.post "/api/users/register" User_handlers.register;
  Sihl.Web.post "/api/users/login" User_handlers.login;
  Sihl.Web.get "/api/users" User_handlers.list_users;
  Sihl.Web.get "/api/users/profile" User_handlers.get_profile;
  Sihl.Web.get "/api/users/:id" User_handlers.get_user;
  Sihl.Web.put "/api/users/:id" User_handlers.update_user;
  Sihl.Web.delete "/api/users/:id" User_handlers.delete_user;
]

let setup app =
  let all_routes = health_routes @ user_routes in
  app
  |> Sihl.App.with_routes all_routes`;
  }

  private generateRoutesInterface(): string {
    return `(** Routes configuration interface *)

(** Health check routes *)
val health_routes : Sihl.Web.route list

(** User management routes *)
val user_routes : Sihl.Web.route list

(** Setup all application routes *)
val setup : Sihl.App.t -> Sihl.App.t`;
  }

  private generateUserHandlers(): string {
    return `(** User request handlers *)
open Lwt.Syntax
open Sihl
open User_handlers

let json_response ?(status = 200) data =
  let json_string = Yojson.Safe.to_string data in
  Sihl.Web.Response.of_json ~status json_string

let register req =
  let* body = Sihl.Web.Request.to_json req in
  try
    let open Yojson.Safe.Util in
    let email = body |> member "email" |> to_string in
    let name = body |> member "name" |> to_string in
    
    let* result = User_repository.create ~email ~name () in
    match result with
    | Ok user ->
      let response_data = \`Assoc [
        ("success", \`Bool true);
        ("data", \`Assoc [("user", User.to_json user)]);
      ] in
      json_response ~status:201 response_data
    | Error message ->
      let response_data = \`Assoc [
        ("error", \`Bool true);
        ("message", \`String message);
      ] in
      json_response ~status:400 response_data
  with
  | Yojson.Json_error _ ->
    let response_data = \`Assoc [
      ("error", \`Bool true);
      ("message", \`String "Invalid JSON");
    ] in
    json_response ~status:400 response_data
  | exn ->
    let response_data = \`Assoc [
      ("error", \`Bool true);
      ("message", \`String (Printexc.to_string exn));
    ] in
    json_response ~status:500 response_data

let login req =
  let* body = Sihl.Web.Request.to_json req in
  try
    let open Yojson.Safe.Util in
    let email = body |> member "email" |> to_string in
    
    let* user_opt = User_repository.find_by_email email in
    match user_opt with
    | Some user ->
      let response_data = \`Assoc [
        ("success", \`Bool true);
        ("data", \`Assoc [("user", User.to_json user)]);
      ] in
      json_response response_data
    | None ->
      let response_data = \`Assoc [
        ("error", \`Bool true);
        ("message", \`String "Invalid credentials");
      ] in
      json_response ~status:401 response_data
  with
  | Yojson.Json_error _ ->
    let response_data = \`Assoc [
      ("error", \`Bool true);
      ("message", \`String "Invalid JSON");
    ] in
    json_response ~status:400 response_data

let list_users _req =
  let* users = User_repository.find_all () in
  let users_json = users |> List.map User.to_json in
  let response_data = \`Assoc [
    ("success", \`Bool true);
    ("data", \`Assoc [("users", \`List users_json)]);
  ] in
  json_response response_data

let get_profile _req =
  let* users = User_repository.find_all () in
  match users with
  | user :: _ ->
    let response_data = \`Assoc [
      ("success", \`Bool true);
      ("data", \`Assoc [("user", User.to_json user)]);
    ] in
    json_response response_data
  | [] ->
    let response_data = \`Assoc [
      ("error", \`Bool true);
      ("message", \`String "User not found");
    ] in
    json_response ~status:404 response_data

let get_user req =
  let user_id = Sihl.Web.Request.param "id" req in
  let* user_opt = User_repository.find_by_id user_id in
  match user_opt with
  | Some user ->
    let response_data = \`Assoc [
      ("success", \`Bool true);
      ("data", \`Assoc [("user", User.to_json user)]);
    ] in
    json_response response_data
  | None ->
    let response_data = \`Assoc [
      ("error", \`Bool true);
      ("message", \`String "User not found");
    ] in
    json_response ~status:404 response_data

let update_user _req =
  let response_data = \`Assoc [
    ("error", \`Bool true);
    ("message", \`String "Not implemented");
  ] in
  json_response ~status:501 response_data

let delete_user _req =
  let response_data = \`Assoc [
    ("error", \`Bool true);
    ("message", \`String "Not implemented");
  ] in
  json_response ~status:501 response_data`;
  }

  private generateUserHandlersInterface(): string {
    return `(** User request handlers interface *)

(** Register new user handler *)
val register : Sihl.Web.Request.t -> Sihl.Web.Response.t Lwt.t

(** User login handler *)
val login : Sihl.Web.Request.t -> Sihl.Web.Response.t Lwt.t

(** List users handler *)
val list_users : Sihl.Web.Request.t -> Sihl.Web.Response.t Lwt.t

(** Get user profile handler *)
val get_profile : Sihl.Web.Request.t -> Sihl.Web.Response.t Lwt.t

(** Get user by ID handler *)
val get_user : Sihl.Web.Request.t -> Sihl.Web.Response.t Lwt.t

(** Update user handler *)
val update_user : Sihl.Web.Request.t -> Sihl.Web.Response.t Lwt.t

(** Delete user handler *)
val delete_user : Sihl.Web.Request.t -> Sihl.Web.Response.t Lwt.t`;
  }

  private generateHealthHandlers(): string {
    return `(** Health check handlers *)
open Lwt.Syntax
open Sihl
open Health_handlers

let json_response ?(status = 200) data =
  let json_string = Yojson.Safe.to_string data in
  Sihl.Web.Response.of_json ~status json_string

let health _req =
  let status_data = Health_controller.get_health_status () in
  let response_data = \`Assoc [
    ("status", \`String status_data.status);
    ("timestamp", \`String status_data.timestamp);
    ("service", \`String status_data.service);
    ("uptime", \`Float status_data.uptime);
  ] in
  json_response response_data

let ready _req =
  let is_ready = Health_controller.get_readiness_status () in
  if is_ready then
    let response_data = \`Assoc [("ready", \`Bool true)] in
    json_response response_data
  else
    let response_data = \`Assoc [("ready", \`Bool false)] in
    json_response ~status:503 response_data

let info _req =
  let config = Config.get_config () in
  let response_data = \`Assoc [
    ("name", \`String config.service_name);
    ("version", \`String "1.0.0");
    ("framework", \`String "Sihl");
    ("language", \`String "OCaml");
    ("environment", \`String config.env);
    ("port", \`Int config.port);
  ] in
  json_response response_data`;
  }

  private generateHealthHandlersInterface(): string {
    return `(** Health check handlers interface *)

(** Health check handler *)
val health : Sihl.Web.Request.t -> Sihl.Web.Response.t Lwt.t

(** Readiness probe handler *)
val ready : Sihl.Web.Request.t -> Sihl.Web.Response.t Lwt.t

(** Service info handler *)
val info : Sihl.Web.Request.t -> Sihl.Web.Response.t Lwt.t`;
  }

  private generateUserRepository(): string {
    return `(** User repository *)
open Lwt.Syntax
open Sihl
open User_repository

let find_by_id id =
  let* connection = Sihl.Database.connection () in
  let query = "SELECT id, email, name, role, created_at, updated_at FROM users WHERE id = ?" in
  let* result = Sihl.Database.query ~connection query [id] in
  match result with
  | [ row ] ->
    let user = User.{
      id = List.nth row 0;
      email = List.nth row 1;
      name = List.nth row 2;
      role = User.role_from_string (List.nth row 3) |> Option.value ~default:User.User;
      created_at = Float.of_string (List.nth row 4);
      updated_at = Float.of_string (List.nth row 5);
    } in
    Lwt.return (Some user)
  | _ -> Lwt.return None

let find_by_email email =
  let* connection = Sihl.Database.connection () in
  let query = "SELECT id, email, name, role, created_at, updated_at FROM users WHERE email = ?" in
  let* result = Sihl.Database.query ~connection query [email] in
  match result with
  | [ row ] ->
    let user = User.{
      id = List.nth row 0;
      email = List.nth row 1;
      name = List.nth row 2;
      role = User.role_from_string (List.nth row 3) |> Option.value ~default:User.User;
      created_at = Float.of_string (List.nth row 4);
      updated_at = Float.of_string (List.nth row 5);
    } in
    Lwt.return (Some user)
  | _ -> Lwt.return None

let create ~email ~name ?(role = User.User) () =
  let* existing = find_by_email email in
  match existing with
  | Some _ -> Lwt.return (Error "User with this email already exists")
  | None ->
    let user = User.create ~email ~name ~role () in
    let* connection = Sihl.Database.connection () in
    let query = "INSERT INTO users (id, email, name, role, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)" in
    let params = [
      user.id;
      user.email;
      user.name;
      User.role_to_string user.role;
      Float.to_string user.created_at;
      Float.to_string user.updated_at;
    ] in
    let* _ = Sihl.Database.execute ~connection query params in
    Lwt.return (Ok user)

let find_all () =
  let* connection = Sihl.Database.connection () in
  let query = "SELECT id, email, name, role, created_at, updated_at FROM users ORDER BY created_at DESC" in
  let* result = Sihl.Database.query ~connection query [] in
  let users = result |> List.map (fun row ->
    User.{
      id = List.nth row 0;
      email = List.nth row 1;
      name = List.nth row 2;
      role = User.role_from_string (List.nth row 3) |> Option.value ~default:User.User;
      created_at = Float.of_string (List.nth row 4);
      updated_at = Float.of_string (List.nth row 5);
    }
  ) in
  Lwt.return users`;
  }

  private generateUserRepositoryInterface(): string {
    return `(** User repository interface *)

(** Find user by ID *)
val find_by_id : string -> User.user option Lwt.t

(** Find user by email *)
val find_by_email : string -> User.user option Lwt.t

(** Create new user *)
val create : email:string -> name:string -> ?role:User.user_role -> unit -> (User.user, string) result Lwt.t

(** Find all users *)
val find_all : unit -> User.user list Lwt.t`;
  }

  private generateUserMigration(): string {
    return `(** User table migration *)
open Sihl

let migration = {
  Migration.id = "0001-create-users";
  Migration.up = [
    {|
    CREATE TABLE users (
      id VARCHAR(128) PRIMARY KEY,
      email VARCHAR(256) NOT NULL UNIQUE,
      name VARCHAR(256) NOT NULL,
      role VARCHAR(64) NOT NULL DEFAULT 'user',
      created_at REAL NOT NULL,
      updated_at REAL NOT NULL
    )
    |};
    {|
    CREATE INDEX users_email_idx ON users(email)
    |};
    {|
    CREATE INDEX users_created_at_idx ON users(created_at)
    |};
  ];
  Migration.down = [
    {| DROP INDEX IF EXISTS users_created_at_idx |};
    {| DROP INDEX IF EXISTS users_email_idx |};
    {| DROP TABLE IF EXISTS users |};
  ];
}

let () = Migration.register migration`;
  }

  private generateDevelopmentEnv(): string {
    return `# Development Environment Configuration

# Server Configuration
PORT=8080
HOST=0.0.0.0
SIHL_ENV=development

# Logging
LOG_LEVEL=debug

# Database
DATABASE_URL=sqlite3://dev.db

# JWT Configuration
JWT_SECRET=development-secret-key-change-in-production
JWT_EXPIRES_IN=7d

# Email Service (Development)
EMAIL_SENDER=console
EMAIL_SMTP_HOST=localhost
EMAIL_SMTP_PORT=1025

# Queue Service (Development)
QUEUE_BACKEND=memory

# Storage Service (Development)
STORAGE_BACKEND=file
STORAGE_FILE_PATH=./storage

# Service Name
SERVICE_NAME=ocaml-sihl-service`;
  }

  private generateProductionEnv(): string {
    return `# Production Environment Configuration

# Server Configuration
PORT=8080
HOST=0.0.0.0
SIHL_ENV=production

# Logging
LOG_LEVEL=info

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/database

# JWT Configuration
JWT_SECRET=your-production-secret-key-here
JWT_EXPIRES_IN=7d

# Email Service (Production)
EMAIL_SENDER=smtp
EMAIL_SMTP_HOST=smtp.example.com
EMAIL_SMTP_PORT=587
EMAIL_SMTP_USERNAME=your-email@example.com
EMAIL_SMTP_PASSWORD=your-password

# Queue Service (Production)
QUEUE_BACKEND=postgresql

# Storage Service (Production)
STORAGE_BACKEND=aws_s3
STORAGE_AWS_ACCESS_KEY=your-access-key
STORAGE_AWS_SECRET_KEY=your-secret-key
STORAGE_AWS_REGION=us-east-1
STORAGE_AWS_BUCKET=your-bucket

# Service Name
SERVICE_NAME=ocaml-sihl-service`;
  }
}