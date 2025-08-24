/**
 * OCaml Base Backend Generator
 * Base class for all OCaml backend framework generators
 */

import { BackendTemplateGenerator } from '../shared/backend-template-generator';
import type { FileTemplate } from '../../types';
import { promises as fs } from 'fs';
import * as path from 'path';

export abstract class OCamlBackendGenerator extends BackendTemplateGenerator {
  constructor() {
    super({
      language: 'OCaml',
      framework: 'OCaml Framework',
      packageManager: 'opam',
      buildTool: 'dune',
      testFramework: 'alcotest',
      dependencies: {},
      devDependencies: {},
      scripts: {},
      features: [
        'Type-safe functional programming',
        'Pattern matching',
        'Module system',
        'GADT support',
        'First-class modules',
        'Polymorphic variants',
        'Concurrent programming',
        'Native code compilation',
        'Interactive REPL',
        'Docker support'
      ]
    });
  }

  // Abstract methods that concrete implementations must provide
  protected abstract getFrameworkDependencies(): Record<string, string>;
  protected abstract getFrameworkDevDependencies(): Record<string, string>;
  protected abstract getFrameworkSpecificFiles(): FileTemplate[];

  protected async generateLanguageFiles(projectPath: string, options: any): Promise<void> {
    const files = [
      {
        path: 'dune-project',
        content: this.generateDuneProject(options)
      },
      {
        path: 'lib/dune',
        content: this.generateLibDune(options)
      },
      {
        path: 'bin/dune',
        content: this.generateBinDune(options)
      },
      {
        path: 'bin/main.ml',
        content: this.generateMainFile(options)
      },
      {
        path: 'lib/config.ml',
        content: this.generateConfigFile(options)
      },
      {
        path: 'lib/config.mli',
        content: this.generateConfigInterface()
      },
      {
        path: 'lib/middleware.ml',
        content: this.generateMiddlewareModule()
      },
      {
        path: 'lib/middleware.mli',
        content: this.generateMiddlewareInterface()
      },
      {
        path: 'lib/controllers/health_controller.ml',
        content: this.generateHealthController()
      },
      {
        path: 'lib/controllers/health_controller.mli',
        content: this.generateHealthControllerInterface()
      },
      {
        path: 'lib/controllers/user_controller.ml',
        content: this.generateUserController()
      },
      {
        path: 'lib/controllers/user_controller.mli',
        content: this.generateUserControllerInterface()
      },
      {
        path: 'lib/models/user.ml',
        content: this.generateUserModel()
      },
      {
        path: 'lib/models/user.mli',
        content: this.generateUserModelInterface()
      },
      {
        path: 'lib/services/user_service.ml',
        content: this.generateUserService()
      },
      {
        path: 'lib/services/user_service.mli',
        content: this.generateUserServiceInterface()
      },
      {
        path: 'lib/utils/response.ml',
        content: this.generateResponseUtils()
      },
      {
        path: 'lib/utils/response.mli',
        content: this.generateResponseUtilsInterface()
      },
      {
        path: 'lib/utils/validation.ml',
        content: this.generateValidationUtils()
      },
      {
        path: 'lib/utils/validation.mli',
        content: this.generateValidationUtilsInterface()
      }
    ];

    for (const file of files) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }
  }

  protected async generateFrameworkFiles(projectPath: string, options: any): Promise<void> {
    const files = this.getFrameworkSpecificFiles();
    
    for (const file of files) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }
  }

  protected async generateTestStructure(projectPath: string, options: any): Promise<void> {
    const testFiles = [
      {
        path: 'test/dune',
        content: this.generateTestDune()
      },
      {
        path: 'test/test_health_controller.ml',
        content: this.generateHealthControllerTest()
      },
      {
        path: 'test/test_user_service.ml',
        content: this.generateUserServiceTest()
      },
      {
        path: 'test/test_user_model.ml',
        content: this.generateUserModelTest()
      }
    ];

    for (const file of testFiles) {
      const filePath = path.join(projectPath, file.path);
      await fs.mkdir(path.dirname(filePath), { recursive: true });
      await fs.writeFile(filePath, file.content);
    }
  }

  protected async generateHealthCheck(projectPath: string): Promise<void> {
    // Health check is already generated in generateLanguageFiles
  }

  protected async generateAPIDocs(projectPath: string): Promise<void> {
    const content = `# ${this.config.framework} API Documentation

This service provides RESTful API endpoints for backend operations.

## Authentication

Most endpoints require JWT authentication. Include the token in the Authorization header:

\`\`\`
Authorization: Bearer <your-jwt-token>
\`\`\`

## Endpoints

### Health Check
- \`GET /health\` - Service health status
- \`GET /ready\` - Readiness probe
- \`GET /info\` - Service information

### User Management
- \`POST /api/users/register\` - Register new user
- \`POST /api/users/login\` - User login  
- \`GET /api/users\` - List users (authenticated)
- \`GET /api/users/profile\` - Get user profile (authenticated)
- \`GET /api/users/:id\` - Get user by ID (authenticated)
- \`PUT /api/users/:id\` - Update user (authenticated)
- \`DELETE /api/users/:id\` - Delete user (admin only)

## Response Format

All API responses follow this format:

\`\`\`json
{
  "success": true|false,
  "data": <response-data>,
  "error": <error-message>,
  "timestamp": "<ISO-string>"
}
\`\`\`

## Error Codes

- \`400\` - Bad Request
- \`401\` - Unauthorized
- \`403\` - Forbidden
- \`404\` - Not Found
- \`429\` - Too Many Requests
- \`500\` - Internal Server Error
`;

    await fs.mkdir(path.join(projectPath, 'docs'), { recursive: true });
    await fs.writeFile(path.join(projectPath, 'docs/api.md'), content);
  }

  protected async generateDockerFiles(projectPath: string, options: any): Promise<void> {
    const dockerfile = `# Build stage
FROM ocaml/opam:alpine-ocaml-5.1 AS builder

# Install system dependencies
USER root
RUN apk add --no-cache git bash curl

# Switch back to opam user
USER opam
WORKDIR /home/opam

# Copy opam files
COPY --chown=opam:opam *.opam ./
COPY --chown=opam:opam dune-project ./

# Install OCaml dependencies
RUN opam install -y --deps-only .

# Copy source code
COPY --chown=opam:opam . ./

# Build the application
RUN eval $(opam env) && dune build --profile release

# Production stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache gmp libffi

# Create app user
RUN addgroup -g 1001 -S appuser && adduser -S appuser -u 1001

# Copy binary from builder
COPY --from=builder /home/opam/_build/default/bin/main.exe /usr/local/bin/app

# Set ownership
RUN chown appuser:appuser /usr/local/bin/app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE ${options.port || 8080}

# Start the application
CMD ["/usr/local/bin/app"]`;

    const dockerCompose = `version: '3.8'

services:
  ${options.name}:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "\${PORT:-${options.port || 8080}}:${options.port || 8080}"
    environment:
      - OCAML_ENV=production
      - PORT=${options.port || 8080}
      - SERVICE_NAME=${options.name}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:${options.port || 8080}/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - app-network

networks:
  app-network:
    driver: bridge`;

    await fs.writeFile(path.join(projectPath, 'Dockerfile'), dockerfile);
    await fs.writeFile(path.join(projectPath, 'docker-compose.yml'), dockerCompose);
  }

  protected async generateDocumentation(projectPath: string, options: any): Promise<void> {
    // API docs are generated in generateAPIDocs
    // README is generated by the base class
  }

  protected getBuildCommand(): string {
    return 'dune build';
  }

  protected getDevCommand(): string {
    return 'dune exec bin/main.exe';
  }

  protected getProdCommand(): string {
    return 'dune exec --profile release bin/main.exe';
  }

  protected getTestCommand(): string {
    return 'dune runtest';
  }

  protected getCoverageCommand(): string {
    return 'dune runtest --instrument-with bisect_ppx';
  }

  protected getLintCommand(): string {
    return 'dune fmt';
  }

  protected getInstallCommand(): string {
    return 'opam install --deps-only .';
  }

  protected getSetupAction(): string {
    return 'Install dependencies and build project';
  }

  protected getLanguagePrerequisites(): string {
    return 'OCaml >= 5.1.0, opam >= 2.1.0, dune >= 3.0';
  }

  protected getLanguageSpecificIgnorePatterns(): string[] {
    return [
      '# OCaml',
      '_build/',
      '*.install',
      '.merlin',
      '.utop-history',
      '*.annot',
      '*.cmi',
      '*.cmo',
      '*.cmx',
      '*.cmt',
      '*.cmti',
      '*.o',
      '*.a',
      '*.cmxa',
      '*.cma',
      '',
      '# Dependencies',
      '_opam/',
      '',
      '# Environment',
      '.env',
      '.env.local',
      '',
      '# Build',
      'dist/',
      'build/',
      '',
      '# Testing',
      'coverage/',
      '_coverage/',
      'bisect*.coverage'
    ];
  }

  // Helper methods for generating OCaml-specific content
  protected generateDuneProject(options: any): string {
    return `(lang dune 3.0)

(name ${options.name.replace(/-/g, '_')})

(package
 (name ${options.name.replace(/-/g, '_')})
 (version 1.0.0)
 (synopsis "${options.description}")
 (description "${options.description}")
 (authors "Re-Shell CLI")
 (maintainers "Re-Shell CLI")
 (license MIT)
 (depends
  ocaml
  dune
  ${Object.keys(this.getFrameworkDependencies()).join('\n  ')}
  ${Object.keys(this.getFrameworkDevDependencies()).join('\n  ')}))

(using menhir 2.1)`;
  }

  protected generateLibDune(options: any): string {
    return `(library
 (public_name ${options.name.replace(/-/g, '_')})
 (name ${options.name.replace(/-/g, '_')})
 (libraries ${Object.keys(this.getFrameworkDependencies()).join(' ')}))`;
  }

  protected generateBinDune(options: any): string {
    return `(executable
 (public_name ${options.name.replace(/-/g, '_')})
 (name main)
 (libraries ${options.name.replace(/-/g, '_')} ${Object.keys(this.getFrameworkDependencies()).join(' ')}))`;
  }

  protected generateTestDune(): string {
    return `(tests
 (names test_health_controller test_user_service test_user_model)
 (libraries alcotest))`;
  }

  // Abstract methods for concrete implementations to override
  protected abstract generateMainFile(options: any): string;
  protected abstract generateConfigFile(options: any): string;

  // Common OCaml utility methods
  protected generateConfigInterface(): string {
    return `(** Configuration module interface *)

type config = {
  port : int;
  host : string;
  env : string;
  service_name : string;
  log_level : string;
  jwt_secret : string;
  jwt_expires_in : string;
}

(** Get application configuration *)
val get_config : unit -> config

(** Get environment variable with default *)
val get_env : string -> string -> string

(** Get port from environment *)
val get_port : unit -> int`;
  }

  protected generateMiddlewareInterface(): string {
    return `(** Middleware module interface *)

(** Logger middleware *)
val logger : 'a -> 'a

(** CORS middleware *)
val cors : 'a -> 'a

(** JSON parsing middleware *)
val json_parser : 'a -> 'a

(** Authentication middleware *)
val auth : 'a -> 'a`;
  }

  protected generateHealthControllerInterface(): string {
    return `(** Health controller interface *)

type health_status = {
  status : string;
  timestamp : string;
  service : string;
  uptime : float;
}

(** Get health status *)
val get_health_status : unit -> health_status

(** Get readiness status *)
val get_readiness_status : unit -> bool`;
  }

  protected generateUserControllerInterface(): string {
    return `(** User controller interface *)

(** Register new user *)
val register : 'request -> 'response

(** User login *)
val login : 'request -> 'response

(** List all users *)
val list_users : 'request -> 'response

(** Get user profile *)
val get_profile : 'request -> 'response

(** Get user by ID *)
val get_user : 'request -> 'response`;
  }

  protected generateUserModelInterface(): string {
    return `(** User model interface *)

type user_role = Admin | User | Guest

type user = {
  id : string;
  email : string;
  name : string;
  role : user_role;
  created_at : float;
  updated_at : float;
}

(** Create new user *)
val create : email:string -> name:string -> ?role:user_role -> unit -> user

(** Convert user to JSON *)
val to_json : user -> Yojson.Safe.t

(** Convert user role to string *)
val role_to_string : user_role -> string

(** Convert string to user role *)
val role_from_string : string -> user_role option`;
  }

  protected generateUserServiceInterface(): string {
    return `(** User service interface *)

(** Find user by ID *)
val find_by_id : string -> User.user option

(** Find user by email *)
val find_by_email : string -> User.user option

(** Create new user *)
val create : email:string -> name:string -> ?role:User.user_role -> unit -> (User.user, string) result

(** List all users *)
val list_all : unit -> User.user list`;
  }

  protected generateResponseUtilsInterface(): string {
    return `(** Response utilities interface *)

type 'a api_response = {
  success : bool;
  data : 'a option;
  error : string option;
  timestamp : string;
}

(** Create success response *)
val success : 'a -> 'a api_response

(** Create error response *)
val error : string -> 'a api_response`;
  }

  protected generateValidationUtilsInterface(): string {
    return `(** Validation utilities interface *)

(** Validate email format *)
val is_email : string -> bool

(** Validate strong password *)
val is_strong_password : string -> bool`;
  }

  protected generateMiddlewareModule(): string {
    return `(** Middleware module *)

let logger handler req =
  Printf.printf "[%s] %s %s\\n" 
    (Unix.time () |> Unix.gmtime |> fun tm -> 
      Printf.sprintf "%04d-%02d-%02d %02d:%02d:%02d" 
        (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday 
        tm.tm_hour tm.tm_min tm.tm_sec)
    "METHOD" "PATH"; (* Framework-specific implementation needed *)
  handler req

let cors handler req =
  (* Add CORS headers - framework-specific implementation needed *)
  handler req

let json_parser handler req =
  (* Parse JSON body - framework-specific implementation needed *)
  handler req

let auth handler req =
  (* JWT authentication - framework-specific implementation needed *)
  handler req`;
  }

  protected generateHealthController(): string {
    return `(** Health controller *)
open Health_controller

type health_status = {
  status : string;
  timestamp : string;
  service : string;
  uptime : float;
}

let get_health_status () =
  let config = Config.get_config () in
  {
    status = "healthy";
    timestamp = Unix.time () |> Unix.gmtime |> fun tm ->
      Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ"
        (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
        tm.tm_hour tm.tm_min tm.tm_sec;
    service = config.service_name;
    uptime = Unix.time ();
  }

let get_readiness_status () =
  (* Add actual readiness checks here *)
  true`;
  }

  protected generateUserController(): string {
    return "(** User controller *)\n" +
      "open User_controller\n\n" +
      "let register req =\n" +
      "  (* Framework-specific request parsing needed *)\n" +
      "  let email = \"example@domain.com\" in (* Extract from request *)\n" +
      "  let name = \"Example User\" in (* Extract from request *)\n" +
      "  \n" +
      "  match User_service.create ~email ~name () with\n" +
      "  | Ok user -> \n" +
      "    let response = Response.success (User.to_json user) in\n" +
      "    (* Framework-specific response creation *)\n" +
      "    response\n" +
      "  | Error msg ->\n" +
      "    let response = Response.error msg in\n" +
      "    (* Framework-specific error response *)\n" +
      "    response\n\n" +
      "let login req =\n" +
      "  (* Framework-specific request parsing needed *)\n" +
      "  let email = \"example@domain.com\" in (* Extract from request *)\n" +
      "  \n" +
      "  match User_service.find_by_email email with\n" +
      "  | Some user ->\n" +
      "    let response = Response.success (User.to_json user) in\n" +
      "    (* Framework-specific response creation *)\n" +
      "    response\n" +
      "  | None ->\n" +
      "    let response = Response.error \"Invalid credentials\" in\n" +
      "    (* Framework-specific error response *)\n" +
      "    response\n\n" +
      "let list_users req =\n" +
      "  let users = User_service.list_all () in\n" +
      "  let users_json = users |> List.map User.to_json in\n" +
      "  let response = Response.success (`List users_json) in\n" +
      "  (* Framework-specific response creation *)\n" +
      "  response\n\n" +
      "let get_profile req =\n" +
      "  (* For demo, return first user *)\n" +
      "  let users = User_service.list_all () in\n" +
      "  match users with\n" +
      "  | user :: _ ->\n" +
      "    let response = Response.success (User.to_json user) in\n" +
      "    (* Framework-specific response creation *)\n" +
      "    response\n" +
      "  | [] ->\n" +
      "    let response = Response.error \"User not found\" in\n" +
      "    (* Framework-specific error response *)\n" +
      "    response\n\n" +
      "let get_user req =\n" +
      "  (* Framework-specific parameter extraction needed *)\n" +
      "  let user_id = \"user_id\" in (* Extract from request params *)\n" +
      "  \n" +
      "  match User_service.find_by_id user_id with\n" +
      "  | Some user ->\n" +
      "    let response = Response.success (User.to_json user) in\n" +
      "    (* Framework-specific response creation *)\n" +
      "    response\n" +
      "  | None ->\n" +
      "    let response = Response.error \"User not found\" in\n" +
      "    (* Framework-specific error response *)\n" +
      "    response";
  }

  protected generateUserModel(): string {
    return "(** User model *)\n" +
      "open User\n\n" +
      "type user_role = Admin | User | Guest\n\n" +
      "type user = {\n" +
      "  id : string;\n" +
      "  email : string;\n" +
      "  name : string;\n" +
      "  role : user_role;\n" +
      "  created_at : float;\n" +
      "  updated_at : float;\n" +
      "}\n\n" +
      "let role_to_string = function\n" +
      "  | Admin -> \"admin\"\n" +
      "  | User -> \"user\"\n" +
      "  | Guest -> \"guest\"\n\n" +
      "let role_from_string = function\n" +
      "  | \"admin\" -> Some Admin\n" +
      "  | \"user\" -> Some User\n" +
      "  | \"guest\" -> Some Guest\n" +
      "  | _ -> None\n\n" +
      "let create ~email ~name ?(role = User) () =\n" +
      "  let now = Unix.time () in\n" +
      "  {\n" +
      "    id = Printf.sprintf \"user_%f\" now;\n" +
      "    email;\n" +
      "    name;\n" +
      "    role;\n" +
      "    created_at = now;\n" +
      "    updated_at = now;\n" +
      "  }\n\n" +
      "let to_json user =\n" +
      "  `Assoc [\n" +
      "    (\"id\", `String user.id);\n" +
      "    (\"email\", `String user.email);\n" +
      "    (\"name\", `String user.name);\n" +
      "    (\"role\", `String (role_to_string user.role));\n" +
      "    (\"created_at\", `Float user.created_at);\n" +
      "    (\"updated_at\", `Float user.updated_at);\n" +
      "  ]";
  }

  protected generateUserService(): string {
    return "(** User service *)\n" +
      "open User_service\n\n" +
      "(* In-memory storage for demo *)\n" +
      "let users = ref []\n\n" +
      "let find_by_id id =\n" +
      "  List.find_opt (fun user -> User.(user.id = id)) !users\n\n" +
      "let find_by_email email =\n" +
      "  List.find_opt (fun user -> User.(user.email = email)) !users\n\n" +
      "let create ~email ~name ?role () =\n" +
      "  match find_by_email email with\n" +
      "  | Some _ -> Error \"User with this email already exists\"\n" +
      "  | None ->\n" +
      "    let user = User.create ~email ~name ?role () in\n" +
      "    users := user :: !users;\n" +
      "    Ok user\n\n" +
      "let list_all () =\n" +
      "  !users";
  }

  protected generateResponseUtils(): string {
    return "(** Response utilities *)\n" +
      "open Response\n\n" +
      "type 'a api_response = {\n" +
      "  success : bool;\n" +
      "  data : 'a option;\n" +
      "  error : string option;\n" +
      "  timestamp : string;\n" +
      "}\n\n" +
      "let success data =\n" +
      "  {\n" +
      "    success = true;\n" +
      "    data = Some data;\n" +
      "    error = None;\n" +
      "    timestamp = Unix.time () |> Unix.gmtime |> fun tm ->\n" +
      "      Printf.sprintf \"%04d-%02d-%02dT%02d:%02d:%02dZ\"\n" +
      "        (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday\n" +
      "        tm.tm_hour tm.tm_min tm.tm_sec;\n" +
      "  }\n\n" +
      "let error message =\n" +
      "  {\n" +
      "    success = false;\n" +
      "    data = None;\n" +
      "    error = Some message;\n" +
      "    timestamp = Unix.time () |> Unix.gmtime |> fun tm ->\n" +
      "      Printf.sprintf \"%04d-%02d-%02dT%02d:%02d:%02dZ\"\n" +
      "        (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday\n" +
      "        tm.tm_hour tm.tm_min tm.tm_sec;\n" +
      "  }";
  }

  protected generateValidationUtils(): string {
    return "(** Validation utilities *)\n" +
      "open Validation\n\n" +
      "let is_email email =\n" +
      "  let email_regex = Str.regexp \"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\\\.[a-zA-Z]{2,}$\" in\n" +
      "  Str.string_match email_regex email 0\n\n" +
      "let is_strong_password password =\n" +
      "  let length_check = String.length password >= 8 in\n" +
      "  let has_uppercase = Str.string_match (Str.regexp \".*[A-Z].*\") password 0 in\n" +
      "  let has_lowercase = Str.string_match (Str.regexp \".*[a-z].*\") password 0 in\n" +
      "  let has_digit = Str.string_match (Str.regexp \".*[0-9].*\") password 0 in\n" +
      "  length_check && has_uppercase && has_lowercase && has_digit";
  }

  protected generateHealthControllerTest(): string {
    return "(** Health controller tests *)\n" +
      "open Alcotest\n\n" +
      "let test_health_status () =\n" +
      "  let status = Health_controller.get_health_status () in\n" +
      "  check string \"status should be healthy\" \"healthy\" status.status\n\n" +
      "let test_readiness_status () =\n" +
      "  let ready = Health_controller.get_readiness_status () in\n" +
      "  check bool \"should be ready\" true ready\n\n" +
      "let () =\n" +
      "  run \"Health Controller\" [\n" +
      "    \"health status\", [ test_case \"get health status\" `Quick test_health_status ];\n" +
      "    \"readiness\", [ test_case \"get readiness status\" `Quick test_readiness_status ];\n" +
      "  ]";
  }

  protected generateUserServiceTest(): string {
    return "(** User service tests *)\n" +
      "open Alcotest\n\n" +
      "let test_create_user () =\n" +
      "  match User_service.create ~email:\"test@example.com\" ~name:\"Test User\" () with\n" +
      "  | Ok user ->\n" +
      "    check string \"email should match\" \"test@example.com\" User.(user.email);\n" +
      "    check string \"name should match\" \"Test User\" User.(user.name)\n" +
      "  | Error _ ->\n" +
      "    fail \"Should create user successfully\"\n\n" +
      "let test_find_user_by_email () =\n" +
      "  let _ = User_service.create ~email:\"findme@example.com\" ~name:\"Find Me\" () in\n" +
      "  match User_service.find_by_email \"findme@example.com\" with\n" +
      "  | Some user ->\n" +
      "    check string \"should find user\" \"findme@example.com\" User.(user.email)\n" +
      "  | None ->\n" +
      "    fail \"Should find user by email\"\n\n" +
      "let () =\n" +
      "  run \"User Service\" [\n" +
      "    \"create user\", [ test_case \"create new user\" `Quick test_create_user ];\n" +
      "    \"find user\", [ test_case \"find user by email\" `Quick test_find_user_by_email ];\n" +
      "  ]";
  }

  protected generateUserModelTest(): string {
    return "(** User model tests *)\n" +
      "open Alcotest\n\n" +
      "let test_create_user () =\n" +
      "  let user = User.create ~email:\"model@example.com\" ~name:\"Model User\" () in\n" +
      "  check string \"email should match\" \"model@example.com\" User.(user.email);\n" +
      "  check string \"name should match\" \"Model User\" User.(user.name);\n" +
      "  check string \"default role should be user\" \"user\" (User.role_to_string User.(user.role))\n\n" +
      "let test_role_conversion () =\n" +
      "  check string \"admin role to string\" \"admin\" (User.role_to_string User.Admin);\n" +
      "  check (option (of_pp (fun fmt -> function Admin -> Fmt.string fmt \"Admin\" | User -> Fmt.string fmt \"User\" | Guest -> Fmt.string fmt \"Guest\"))) \n" +
      "    \"string to admin role\" (Some User.Admin) (User.role_from_string \"admin\")\n\n" +
      "let () =\n" +
      "  run \"User Model\" [\n" +
      "    \"create user\", [ test_case \"create user model\" `Quick test_create_user ];\n" +
      "    \"role conversion\", [ test_case \"role string conversion\" `Quick test_role_conversion ];\n" +
      "  ]";
  }
}