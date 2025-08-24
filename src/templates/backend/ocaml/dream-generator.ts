/**
 * OCaml Dream Framework Generator
 * Generates an OCaml backend service with Dream web framework
 */

import { OCamlBackendGenerator } from './ocaml-base-generator';
import type { FileTemplate } from '../../types';

export class DreamGenerator extends OCamlBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Dream';
    this.config.features.push(
      'Dream web framework',
      'WebSocket support',
      'Built-in templating',
      'Session management',
      'HTTP/2 support',
      'TLS support',
      'GraphQL integration',
      'Database integration',
      'Static file serving',
      'Hot reloading'
    );
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'dream': '>= 1.0.0',
      'lwt': '>= 5.6.0',
      'yojson': '>= 2.0.0',
      'lwt_ppx': '>= 2.1.0',
      'ppx_yojson_conv': '>= v0.16.0',
      'caqti': '>= 2.1.0',
      'caqti-lwt': '>= 2.1.0',
      'bcrypt': '>= 1.0.0',
      'jose': '>= 0.9.0',
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
        path: 'lib/middleware/auth_middleware.ml',
        content: this.generateAuthMiddleware()
      },
      {
        path: 'lib/middleware/auth_middleware.mli',
        content: this.generateAuthMiddlewareInterface()
      },
      {
        path: 'lib/middleware/cors_middleware.ml',
        content: this.generateCorsMiddleware()
      },
      {
        path: 'lib/middleware/cors_middleware.mli',
        content: this.generateCorsMiddlewareInterface()
      }
    ];
  }

  protected generateMainFile(options: any): string {
    return `(** Main application entry point *)
open Lwt.Syntax
open ${options.name.replace(/-/g, '_')}

let setup_logging () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Logs.Info)

let () =
  setup_logging ();
  let config = Config.get_config () in
  Logs.info (fun m -> m "🚀 Starting %s server on %s:%d" 
    config.service_name config.host config.port);
  Logs.info (fun m -> m "Environment: %s" config.env);
  
  Dream.run ~port:config.port ~interface:config.host
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ Dream.router (Routes.setup ())`;
  }

  protected generateConfigFile(options: any): string {
    return `(** Configuration module *)
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
  env = get_env "OCAML_ENV" "development";
  service_name = get_env "SERVICE_NAME" "${options.name}";
  log_level = get_env "LOG_LEVEL" "info";
  jwt_secret = get_env "JWT_SECRET" "your-secret-key-change-in-production";
  jwt_expires_in = get_env "JWT_EXPIRES_IN" "7d";
}`;
  }

  private generateAppFile(): string {
    return `(** Dream application setup *)
open Lwt.Syntax
open App

let create_app () =
  Dream.router [
    Dream.get "/health" Health_handlers.health;
    Dream.get "/ready" Health_handlers.ready;
    Dream.get "/info" Health_handlers.info;
    
    Dream.scope "/api" [
      Cors_middleware.cors;
    ] [
      Dream.post "/users/register" User_handlers.register;
      Dream.post "/users/login" User_handlers.login;
      
      Dream.scope "/users" [
        Auth_middleware.authenticate;
      ] [
        Dream.get "/" User_handlers.list_users;
        Dream.get "/profile" User_handlers.get_profile;
        Dream.get "/:id" User_handlers.get_user;
        Dream.put "/:id" User_handlers.update_user;
        Dream.delete "/:id" User_handlers.delete_user;
      ];
    ];
  ]

let run_app ?(port = 8080) ?(interface = "0.0.0.0") () =
  let config = Config.get_config () in
  Dream.run ~port:config.port ~interface:config.host
  @@ Dream.logger
  @@ Dream.memory_sessions
  @@ create_app ()`;
  }

  private generateAppInterface(): string {
    return `(** Dream application interface *)

(** Create the Dream application with all routes and middleware *)
val create_app : unit -> Dream.handler

(** Run the Dream application *)
val run_app : ?port:int -> ?interface:string -> unit -> unit`;
  }

  private generateRoutesFile(): string {
    return `(** Routes configuration *)
open Dream
open Routes

let health_routes = [
  get "/health" Health_handlers.health;
  get "/ready" Health_handlers.ready;
  get "/info" Health_handlers.info;
]

let user_routes = [
  post "/register" User_handlers.register;
  post "/login" User_handlers.login;
  
  scope "/" [
    Auth_middleware.authenticate;
  ] [
    get "/" User_handlers.list_users;
    get "/profile" User_handlers.get_profile;
    get "/:id" User_handlers.get_user;
    put "/:id" User_handlers.update_user;
    delete "/:id" User_handlers.delete_user;
  ];
]

let api_routes = 
  scope "/api" [
    Cors_middleware.cors;
  ] [
    scope "/users" [] user_routes;
  ]

let setup () = 
  health_routes @ [api_routes]`;
  }

  private generateRoutesInterface(): string {
    return `(** Routes configuration interface *)

(** Health check routes *)
val health_routes : Dream.route list

(** User management routes *)
val user_routes : Dream.route list

(** API routes with middleware *)
val api_routes : Dream.route

(** Setup all application routes *)
val setup : unit -> Dream.route list`;
  }

  private generateUserHandlers(): string {
    return `(** User request handlers *)
open Lwt.Syntax
open Dream
open User_handlers

let json_response ?(status = \`OK) data =
  let json_string = Yojson.Safe.to_string data in
  Dream.respond json_string
    ~headers:["Content-Type", "application/json"]
    ~status

let register request =
  let* body = Dream.body request in
  try
    let json = Yojson.Safe.from_string body in
    let open Yojson.Safe.Util in
    let email = json |> member "email" |> to_string in
    let name = json |> member "name" |> to_string in
    
    match User_service.create ~email ~name () with
    | Ok user ->
      let response_data = \`Assoc [
        ("success", \`Bool true);
        ("data", \`Assoc [("user", User.to_json user)]);
      ] in
      json_response ~status:\`Created response_data
    | Error message ->
      let response_data = \`Assoc [
        ("error", \`Bool true);
        ("message", \`String message);
      ] in
      json_response ~status:\`Bad_Request response_data
  with
  | Yojson.Json_error _ ->
    let response_data = \`Assoc [
      ("error", \`Bool true);
      ("message", \`String "Invalid JSON");
    ] in
    json_response ~status:\`Bad_Request response_data
  | exn ->
    let response_data = \`Assoc [
      ("error", \`Bool true);
      ("message", \`String (Printexc.to_string exn));
    ] in
    json_response ~status:\`Internal_Server_Error response_data

let login request =
  let* body = Dream.body request in
  try
    let json = Yojson.Safe.from_string body in
    let open Yojson.Safe.Util in
    let email = json |> member "email" |> to_string in
    
    match User_service.find_by_email email with
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
      json_response ~status:\`Unauthorized response_data
  with
  | Yojson.Json_error _ ->
    let response_data = \`Assoc [
      ("error", \`Bool true);
      ("message", \`String "Invalid JSON");
    ] in
    json_response ~status:\`Bad_Request response_data

let list_users _request =
  let users = User_service.list_all () in
  let users_json = users |> List.map User.to_json in
  let response_data = \`Assoc [
    ("success", \`Bool true);
    ("data", \`Assoc [("users", \`List users_json)]);
  ] in
  json_response response_data

let get_profile _request =
  (* For demo, return first user *)
  let users = User_service.list_all () in
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
    json_response ~status:\`Not_Found response_data

let get_user request =
  let user_id = Dream.param request "id" in
  match User_service.find_by_id user_id with
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
    json_response ~status:\`Not_Found response_data

let update_user request =
  let response_data = \`Assoc [
    ("error", \`Bool true);
    ("message", \`String "Not implemented");
  ] in
  json_response ~status:\`Not_Implemented response_data

let delete_user request =
  let response_data = \`Assoc [
    ("error", \`Bool true);
    ("message", \`String "Not implemented");
  ] in
  json_response ~status:\`Not_Implemented response_data`;
  }

  private generateUserHandlersInterface(): string {
    return `(** User request handlers interface *)

(** Register new user handler *)
val register : Dream.handler

(** User login handler *)
val login : Dream.handler

(** List users handler *)
val list_users : Dream.handler

(** Get user profile handler *)
val get_profile : Dream.handler

(** Get user by ID handler *)
val get_user : Dream.handler

(** Update user handler *)
val update_user : Dream.handler

(** Delete user handler *)
val delete_user : Dream.handler`;
  }

  private generateHealthHandlers(): string {
    return `(** Health check handlers *)
open Lwt.Syntax
open Dream
open Health_handlers

let json_response ?(status = \`OK) data =
  let json_string = Yojson.Safe.to_string data in
  Dream.respond json_string
    ~headers:["Content-Type", "application/json"]
    ~status

let health _request =
  let status_data = Health_controller.get_health_status () in
  let response_data = \`Assoc [
    ("status", \`String status_data.status);
    ("timestamp", \`String status_data.timestamp);
    ("service", \`String status_data.service);
    ("uptime", \`Float status_data.uptime);
  ] in
  json_response response_data

let ready _request =
  let is_ready = Health_controller.get_readiness_status () in
  if is_ready then
    let response_data = \`Assoc [("ready", \`Bool true)] in
    json_response response_data
  else
    let response_data = \`Assoc [("ready", \`Bool false)] in
    json_response ~status:\`Service_Unavailable response_data

let info _request =
  let config = Config.get_config () in
  let response_data = \`Assoc [
    ("name", \`String config.service_name);
    ("version", \`String "1.0.0");
    ("framework", \`String "Dream");
    ("language", \`String "OCaml");
    ("environment", \`String config.env);
    ("port", \`Int config.port);
  ] in
  json_response response_data`;
  }

  private generateHealthHandlersInterface(): string {
    return `(** Health check handlers interface *)

(** Health check handler *)
val health : Dream.handler

(** Readiness probe handler *)
val ready : Dream.handler

(** Service info handler *)
val info : Dream.handler`;
  }

  private generateAuthMiddleware(): string {
    return `(** Authentication middleware *)
open Lwt.Syntax
open Dream
open Auth_middleware

let json_error_response ?(status = \`Unauthorized) message =
  let response_data = \`Assoc [
    ("error", \`Bool true);
    ("message", \`String message);
  ] in
  let json_string = Yojson.Safe.to_string response_data in
  Dream.respond json_string
    ~headers:["Content-Type", "application/json"]
    ~status

let authenticate handler request =
  match Dream.header request "Authorization" with
  | Some auth_header when String.starts_with ~prefix:"Bearer " auth_header ->
    (* Extract token and validate - JWT implementation needed *)
    let _token = String.sub auth_header 7 (String.length auth_header - 7) in
    (* TODO: Implement JWT validation with jose library *)
    handler request
  | Some _ ->
    json_error_response "Invalid authorization header format"
  | None ->
    json_error_response "Authorization header required"`;
  }

  private generateAuthMiddlewareInterface(): string {
    return `(** Authentication middleware interface *)

(** JWT authentication middleware *)
val authenticate : Dream.middleware`;
  }

  private generateCorsMiddleware(): string {
    return `(** CORS middleware *)
open Lwt.Syntax
open Dream
open Cors_middleware

let cors handler request =
  let* response = handler request in
  Dream.add_header response "Access-Control-Allow-Origin" "*";
  Dream.add_header response "Access-Control-Allow-Methods" "GET, POST, PUT, DELETE, OPTIONS";
  Dream.add_header response "Access-Control-Allow-Headers" "Content-Type, Authorization";
  Dream.add_header response "Access-Control-Max-Age" "86400";
  Lwt.return response`;
  }

  private generateCorsMiddlewareInterface(): string {
    return `(** CORS middleware interface *)

(** CORS headers middleware *)
val cors : Dream.middleware`;
  }
}