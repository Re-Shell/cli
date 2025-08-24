/**
 * OCaml Opium Framework Generator
 * Generates an OCaml backend service with Opium web framework
 */

import { OCamlBackendGenerator } from './ocaml-base-generator';
import type { FileTemplate } from '../../types';

export class OpiumGenerator extends OCamlBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Opium';
    this.config.features.push(
      'Opium web framework',
      'Sinatra-like DSL',
      'Middleware support',
      'Rock protocol',
      'JSON handling',
      'Route parameters',
      'Static file serving',
      'Cookie support',
      'Session management',
      'WebSocket support'
    );
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'opium': '>= 0.20.0',
      'lwt': '>= 5.6.0',
      'yojson': '>= 2.0.0',
      'lwt_ppx': '>= 2.1.0',
      'ppx_yojson_conv': '>= v0.16.0',
      'cohttp-lwt-unix': '>= 5.0.0',
      'rock': '>= 0.20.0',
      'tyxml': '>= 4.5.0',
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
open Opium
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
  
  App.create_app ()
  |> App.port config.port
  |> App.run_command`;
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
    return `(** Opium application setup *)
open Lwt.Syntax
open Opium
open App

let json_response ?(status = \`OK) data =
  let json_string = Yojson.Safe.to_string data in
  Response.of_json ~status data

let create_app () =
  App.empty
  |> App.middleware (Middleware.logger)
  |> App.middleware (Cors_middleware.cors)
  |> Routes.setup
  |> App.cmd_name "Opium Server"

let run_app ?(port = 8080) () =
  create_app ()
  |> App.port port
  |> App.run_command`;
  }

  private generateAppInterface(): string {
    return `(** Opium application interface *)

(** Create JSON response with optional status *)
val json_response : ?status:Cohttp.Code.status_code -> Yojson.Safe.t -> Response.t Lwt.t

(** Create the Opium application with all routes and middleware *)
val create_app : unit -> App.t

(** Run the Opium application *)
val run_app : ?port:int -> unit -> unit`;
  }

  private generateRoutesFile(): string {
    return `(** Routes configuration *)
open Opium
open Routes

let setup app =
  app
  (* Health check routes *)
  |> App.get "/health" Health_handlers.health
  |> App.get "/ready" Health_handlers.ready
  |> App.get "/info" Health_handlers.info
  
  (* API routes *)
  |> App.post "/api/users/register" User_handlers.register
  |> App.post "/api/users/login" User_handlers.login
  
  (* Protected routes *)
  |> App.get "/api/users" (Auth_middleware.authenticate User_handlers.list_users)
  |> App.get "/api/users/profile" (Auth_middleware.authenticate User_handlers.get_profile)
  |> App.get "/api/users/:id" (Auth_middleware.authenticate User_handlers.get_user)
  |> App.put "/api/users/:id" (Auth_middleware.authenticate User_handlers.update_user)
  |> App.delete "/api/users/:id" (Auth_middleware.authenticate User_handlers.delete_user)`;
  }

  private generateRoutesInterface(): string {
    return `(** Routes configuration interface *)

(** Setup all application routes *)
val setup : App.t -> App.t`;
  }

  private generateUserHandlers(): string {
    return `(** User request handlers *)
open Lwt.Syntax
open Opium
open User_handlers

let json_response ?(status = \`OK) data =
  Response.of_json ~status data

let register req =
  let* body = Request.to_json_exn req in
  try
    let open Yojson.Safe.Util in
    let email = body |> member "email" |> to_string in
    let name = body |> member "name" |> to_string in
    
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

let login req =
  let* body = Request.to_json_exn req in
  try
    let open Yojson.Safe.Util in
    let email = body |> member "email" |> to_string in
    
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

let list_users _req =
  let users = User_service.list_all () in
  let users_json = users |> List.map User.to_json in
  let response_data = \`Assoc [
    ("success", \`Bool true);
    ("data", \`Assoc [("users", \`List users_json)]);
  ] in
  json_response response_data

let get_profile _req =
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

let get_user req =
  let user_id = Router.param req "id" in
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

let update_user _req =
  let response_data = \`Assoc [
    ("error", \`Bool true);
    ("message", \`String "Not implemented");
  ] in
  json_response ~status:\`Not_Implemented response_data

let delete_user _req =
  let response_data = \`Assoc [
    ("error", \`Bool true);
    ("message", \`String "Not implemented");
  ] in
  json_response ~status:\`Not_Implemented response_data`;
  }

  private generateUserHandlersInterface(): string {
    return `(** User request handlers interface *)

(** Register new user handler *)
val register : Request.t -> Response.t Lwt.t

(** User login handler *)
val login : Request.t -> Response.t Lwt.t

(** List users handler *)
val list_users : Request.t -> Response.t Lwt.t

(** Get user profile handler *)
val get_profile : Request.t -> Response.t Lwt.t

(** Get user by ID handler *)
val get_user : Request.t -> Response.t Lwt.t

(** Update user handler *)
val update_user : Request.t -> Response.t Lwt.t

(** Delete user handler *)
val delete_user : Request.t -> Response.t Lwt.t`;
  }

  private generateHealthHandlers(): string {
    return `(** Health check handlers *)
open Lwt.Syntax
open Opium
open Health_handlers

let json_response ?(status = \`OK) data =
  Response.of_json ~status data

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
    json_response ~status:\`Service_Unavailable response_data

let info _req =
  let config = Config.get_config () in
  let response_data = \`Assoc [
    ("name", \`String config.service_name);
    ("version", \`String "1.0.0");
    ("framework", \`String "Opium");
    ("language", \`String "OCaml");
    ("environment", \`String config.env);
    ("port", \`Int config.port);
  ] in
  json_response response_data`;
  }

  private generateHealthHandlersInterface(): string {
    return `(** Health check handlers interface *)

(** Health check handler *)
val health : Request.t -> Response.t Lwt.t

(** Readiness probe handler *)
val ready : Request.t -> Response.t Lwt.t

(** Service info handler *)
val info : Request.t -> Response.t Lwt.t`;
  }

  private generateAuthMiddleware(): string {
    return `(** Authentication middleware *)
open Lwt.Syntax
open Opium
open Auth_middleware

let json_error_response ?(status = \`Unauthorized) message =
  let response_data = \`Assoc [
    ("error", \`Bool true);
    ("message", \`String message);
  ] in
  Response.of_json ~status response_data

let authenticate handler req =
  match Request.header "authorization" req with
  | Some auth_header when String.starts_with ~prefix:"Bearer " auth_header ->
    (* Extract token and validate - JWT implementation needed *)
    let _token = String.sub auth_header 7 (String.length auth_header - 7) in
    (* TODO: Implement JWT validation *)
    handler req
  | Some _ ->
    json_error_response "Invalid authorization header format"
  | None ->
    json_error_response "Authorization header required"`;
  }

  private generateAuthMiddlewareInterface(): string {
    return `(** Authentication middleware interface *)

(** JWT authentication middleware *)
val authenticate : (Request.t -> Response.t Lwt.t) -> Request.t -> Response.t Lwt.t`;
  }

  private generateCorsMiddleware(): string {
    return `(** CORS middleware *)
open Lwt.Syntax
open Opium
open Rock
open Cors_middleware

let cors =
  let filter handler req =
    let* response = handler req in
    let headers = [
      ("Access-Control-Allow-Origin", "*");
      ("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      ("Access-Control-Allow-Headers", "Content-Type, Authorization");
      ("Access-Control-Max-Age", "86400");
    ] in
    let updated_response = List.fold_left (fun acc (name, value) ->
      Response.add_header acc (name, value)
    ) response headers in
    Lwt.return updated_response
  in
  Rock.Middleware.create ~name:"CORS" ~filter`;
  }

  private generateCorsMiddlewareInterface(): string {
    return `(** CORS middleware interface *)

(** CORS headers middleware *)
val cors : Rock.Middleware.t`;
  }
}