/**
 * ReScript Fastify Framework Generator
 * Generates a ReScript backend service with Fastify bindings
 */

import { ReScriptBackendGenerator } from './rescript-base-generator';
import type { FileTemplate } from '../../types';

export class FastifyGenerator extends ReScriptBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Fastify';
    this.config.features.push(
      'Fastify bindings',
      'Schema-based validation',
      'High performance',
      'Plugin architecture',
      'Async/await support',
      'Built-in logging',
      'Request validation',
      'Swagger generation',
      'WebSocket support',
      'Rate limiting'
    );
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'fastify': '^4.24.3',
      '@fastify/cors': '^8.5.0',
      '@fastify/helmet': '^11.1.1',
      '@fastify/compress': '^6.5.0',
      '@fastify/rate-limit': '^9.0.1',
      '@fastify/jwt': '^8.0.0',
      '@fastify/cookie': '^9.2.0',
      '@fastify/swagger': '^8.12.0',
      '@fastify/swagger-ui': '^2.0.1',
      'bcryptjs': '^2.4.3',
      'dotenv': '^16.3.1'
    };
  }

  protected getFrameworkDevDependencies(): Record<string, string> {
    return {
      '@types/node': '^20.0.0',
      '@types/bcryptjs': '^2.4.6',
      'jest': '^29.7.0',
      '@types/jest': '^29.5.11'
    };
  }

  protected getFrameworkSpecificFiles(): FileTemplate[] {
    return [
      {
        path: 'src/app.res',
        content: this.generateAppFile()
      },
      {
        path: 'src/routes/Router.res',
        content: this.generateRouterFile()
      },
      {
        path: 'src/routes/UserRoutes.res',
        content: this.generateUserRoutesFile()
      },
      {
        path: 'src/hooks/Auth.res',
        content: this.generateAuthHooks()
      },
      {
        path: 'src/controllers/UserController.res',
        content: this.generateUserController()
      },
      {
        path: 'src/bindings/Fastify.res',
        content: this.generateFastifyBindings()
      },
      {
        path: 'src/bindings/FastifyPlugins.res',
        content: this.generatePluginBindings()
      }
    ];
  }

  protected generateMainFile(options: any): string {
    return `// Main application entry point
open NodeJs

// Load environment variables
@module("dotenv") external config: unit => unit = "config"
config()

let start = async () => {
  let app = await App.create()
  let port = Config.getPort()
  let host = "0.0.0.0"
  
  try {
    await Fastify.listen(app, {port, host})
    Console.log(\`🚀 Fastify server running on http://\${host}:\${port->Int.toString}\`)
    Console.log(\`Environment: \${Config.config.env}\`)
  } catch {
  | exn => {
    Console.error(\`Failed to start server: \${exn->Obj.magic}\`)
    Process.exit(1)
  }
  }
}

// Handle uncaught errors
Process.on(#unhandledRejection, (err) => {
  Console.error(\`Unhandled rejection: \${err->Obj.magic}\`)
  Process.exit(1)
})

// Graceful shutdown
let gracefulShutdown = async (signal: string) => {
  Console.log(\`\${signal} signal received: closing server\`)
  Process.exit(0)
}

Process.on(#SIGTERM, () => gracefulShutdown("SIGTERM")->ignore)
Process.on(#SIGINT, () => gracefulShutdown("SIGINT")->ignore)

// Start the server
start()->ignore`;
  }

  protected generateConfigFile(options: any): string {
    return `// Configuration module
open NodeJs

type config = {
  port: int,
  env: string,
  serviceName: string,
  logLevel: string,
  jwtSecret: string,
  jwtExpiresIn: string,
  database: option<databaseConfig>,
}

and databaseConfig = {
  host: string,
  port: int,
  user: string,
  password: string,
  database: string,
}

let getEnv = (key: string, default: string): string => {
  switch Process.env->Dict.get(key) {
  | Some(value) => value
  | None => default
  }
}

let getPort = (): int => {
  switch Process.env->Dict.get("PORT") {
  | Some(port) => 
    switch Int.fromString(port) {
    | Some(p) => p
    | None => 3000
    }
  | None => 3000
  }
}

let config: config = {
  port: getPort(),
  env: getEnv("NODE_ENV", "development"),
  serviceName: getEnv("SERVICE_NAME", "${options.name}"),
  logLevel: getEnv("LOG_LEVEL", "info"),
  jwtSecret: getEnv("JWT_SECRET", "your-secret-key-change-in-production"),
  jwtExpiresIn: getEnv("JWT_EXPIRES_IN", "7d"),
  database: switch getEnv("DATABASE_URL", "") {
  | "" => None
  | _ => Some({
      host: getEnv("DB_HOST", "localhost"),
      port: switch getEnv("DB_PORT", "5432")->Int.fromString {
        | Some(p) => p
        | None => 5432
      },
      user: getEnv("DB_USER", "user"),
      password: getEnv("DB_PASSWORD", "password"),
      database: getEnv("DB_NAME", "database"),
    })
  },
}`;
  }

  private generateAppFile(): string {
    return `// Fastify application setup
open Fastify

let create = async (): promise<Fastify.app> => {
  let app = Fastify.create({
    logger: {
      level: Config.config.logLevel,
    },
    trustProxy: true,
    bodyLimit: 10485760, // 10MB
  })
  
  // Register plugins
  await app->Fastify.register(FastifyPlugins.helmet)
  await app->Fastify.register(FastifyPlugins.cors)
  await app->Fastify.register(FastifyPlugins.compress)
  await app->Fastify.register(FastifyPlugins.cookie)
  
  // JWT plugin
  await app->Fastify.register(FastifyPlugins.jwt, {
    secret: Config.config.jwtSecret,
  })
  
  // Global error handler
  app->Fastify.setErrorHandler((error, request, reply) => {
    let statusCode = switch error.statusCode {
    | Some(code) => code
    | None => 500
    }
    
    reply
    ->Fastify.Reply.status(statusCode)
    ->Fastify.Reply.send({
      "error": true,
      "message": error.message,
      "statusCode": statusCode,
    })
  })
  
  // Not found handler
  app->Fastify.setNotFoundHandler((request, reply) => {
    reply
    ->Fastify.Reply.status(404)
    ->Fastify.Reply.send({
      "error": true,
      "message": "Route not found",
      "statusCode": 404,
    })
  })
  
  // Register routes
  await app->Fastify.register(Router.plugin, {prefix: "/api"})
  
  // Health check routes
  app->Fastify.get("/health", async (request, reply) => {
    let status = HealthController.getHealthStatus()
    reply->Fastify.Reply.send(status)
  })
  
  app->Fastify.get("/ready", async (request, reply) => {
    let ready = HealthController.getReadinessStatus()
    if ready {
      reply->Fastify.Reply.send({"ready": true})
    } else {
      reply->Fastify.Reply.status(503)->Fastify.Reply.send({"ready": false})
    }
  })
  
  app->Fastify.get("/info", async (request, reply) => {
    let info = InfoController.getServiceInfo()
    reply->Fastify.Reply.send(info)
  })
  
  app
}`;
  }

  private generateRouterFile(): string {
    return `// Main API router
open Fastify

let plugin = async (app: Fastify.app, opts: 'a): promise<unit> => {
  // API info
  app->Fastify.get("/", async (request, reply) => {
    reply->Fastify.Reply.send({
      "message": "Welcome to API",
      "version": "1.0.0",
      "documentation": "/documentation",
    })
  })
  
  // Register route modules
  await app->Fastify.register(UserRoutes.plugin, {prefix: "/users"})
}`;
  }

  private generateUserRoutesFile(): string {
    return `// User routes
open Fastify

let plugin = async (app: Fastify.app, opts: 'a): promise<unit> => {
  // Public routes
  app->Fastify.post("/register", UserController.register)
  app->Fastify.post("/login", UserController.login)
  
  // Protected routes
  app->Fastify.route({
    method: #GET,
    url: "/",
    preHandler: [Auth.authenticate],
    handler: UserController.listUsers,
  })
  
  app->Fastify.route({
    method: #GET,
    url: "/profile",
    preHandler: [Auth.authenticate],
    handler: UserController.getProfile,
  })
  
  app->Fastify.route({
    method: #GET,
    url: "/:id",
    preHandler: [Auth.authenticate],
    handler: UserController.getUser,
  })
}`;
  }

  private generateUserController(): string {
    return `// User controller
open Fastify
open User

let register: Fastify.handler<'a, 'b, 'c> = async (request, reply) => {
  let body = request.body
  
  // Simple registration logic
  let email = body["email"]
  let name = body["name"]
  
  switch (email, name) {
  | (Some(email), Some(name)) => {
    switch UserService.create(~email, ~name, ()) {
    | Ok(user) => {
      reply
      ->Fastify.Reply.status(201)
      ->Fastify.Reply.send({
        "success": true,
        "data": {"user": User.toJson(user)},
      })
    }
    | Error(message) => {
      reply
      ->Fastify.Reply.status(400)
      ->Fastify.Reply.send({
        "error": true,
        "message": message,
      })
    }
    }
  }
  | _ => {
    reply
    ->Fastify.Reply.status(400)
    ->Fastify.Reply.send({
      "error": true,
      "message": "Email and name are required",
    })
  }
  }
}

let login: Fastify.handler<'a, 'b, 'c> = async (request, reply) => {
  let body = request.body
  
  switch body["email"] {
  | Some(email) => {
    switch UserService.findByEmail(email) {
    | Some(user) => {
      reply->Fastify.Reply.send({
        "success": true,
        "data": {"user": User.toJson(user)},
      })
    }
    | None => {
      reply
      ->Fastify.Reply.status(401)
      ->Fastify.Reply.send({
        "error": true,
        "message": "Invalid credentials",
      })
    }
    }
  }
  | None => {
    reply
    ->Fastify.Reply.status(400)
    ->Fastify.Reply.send({
      "error": true,
      "message": "Email is required",
    })
  }
  }
}

let listUsers: Fastify.handler<'a, 'b, 'c> = async (request, reply) => {
  let users = UserService.listAll()
  reply->Fastify.Reply.send({
    "success": true,
    "data": {"users": users->Array.map(User.toJson)},
  })
}

let getProfile: Fastify.handler<'a, 'b, 'c> = async (request, reply) => {
  // For demo, return first user
  let users = UserService.listAll()
  switch users[0] {
  | Some(user) => {
    reply->Fastify.Reply.send({
      "success": true,
      "data": {"user": User.toJson(user)},
    })
  }
  | None => {
    reply
    ->Fastify.Reply.status(404)
    ->Fastify.Reply.send({
      "error": true,
      "message": "User not found",
    })
  }
  }
}

let getUser: Fastify.handler<'a, 'b, 'c> = async (request, reply) => {
  let userId = request.params["id"]
  
  switch userId {
  | Some(id) => {
    switch UserService.findById(id) {
    | Some(user) => {
      reply->Fastify.Reply.send({
        "success": true,
        "data": {"user": User.toJson(user)},
      })
    }
    | None => {
      reply
      ->Fastify.Reply.status(404)
      ->Fastify.Reply.send({
        "error": true,
        "message": "User not found",
      })
    }
    }
  }
  | None => {
    reply
    ->Fastify.Reply.status(400)
    ->Fastify.Reply.send({
      "error": true,
      "message": "User ID is required",
    })
  }
  }
}`;
  }

  private generateAuthHooks(): string {
    return `// Authentication hooks
open Fastify

let authenticate: Fastify.preHandler = async (request, reply) => {
  // Simple auth - just check for any authorization header
  let authHeader = request.headers["authorization"]
  
  switch authHeader {
  | Some(_) => () // Continue
  | None => {
    reply
    ->Fastify.Reply.status(401)
    ->Fastify.Reply.send({
      "error": true,
      "message": "Authorization header required",
    })
  }
  }
}`;
  }

  private generateFastifyBindings(): string {
    return `// Fastify bindings
type app
type request<'body, 'querystring, 'params>
type reply
type handler<'body, 'querystring, 'params> = (request<'body, 'querystring, 'params>, reply) => promise<unit>
type preHandler = handler<'a, 'b, 'c>
type plugin<'opts> = (app, 'opts) => promise<unit>

type listenOptions = {
  port: int,
  host: string,
}

type fastifyOptions = {
  logger: 'logger,
  trustProxy?: bool,
  bodyLimit?: int,
}

type routeOptions<'body, 'querystring, 'params> = {
  method: [#GET | #POST | #PUT | #DELETE | #PATCH],
  url: string,
  preHandler?: array<preHandler>,
  handler: handler<'body, 'querystring, 'params>,
}

type fastifyError = {
  message: string,
  statusCode?: int,
}

// Create app
@module("fastify") external create: fastifyOptions => app = "default"

// App methods
@send external register: (app, plugin<'opts>, 'opts) => promise<unit> = "register"
@send external registerWithoutOpts: (app, plugin<unit>) => promise<unit> = "register"
@send external listen: (app, listenOptions) => promise<unit> = "listen"
@send external close: app => promise<unit> = "close"

// Route registration
@send external get: (app, string, handler<'body, 'query, 'params>) => app = "get"
@send external post: (app, string, handler<'body, 'query, 'params>) => app = "post"
@send external route: (app, routeOptions<'body, 'query, 'params>) => app = "route"

// Error handling
@send external setErrorHandler: (app, (fastifyError, request<'a, 'b, 'c>, reply) => unit) => app = "setErrorHandler"
@send external setNotFoundHandler: (app, (request<'a, 'b, 'c>, reply) => unit) => app = "setNotFoundHandler"

// Request properties
@get external body: request<'body, 'q, 'p> => 'body = "body"
@get external query: request<'b, 'query, 'p> => 'query = "query"
@get external params: request<'b, 'q, 'params> => 'params = "params"
@get external headers: request<'b, 'q, 'p> => Js.Dict.t<string> = "headers"

// Reply methods
module Reply = {
  @send external status: (reply, int) => reply = "status"
  @send external send: (reply, 'data) => unit = "send"
}`;
  }

  private generatePluginBindings(): string {
    return `// Fastify plugin bindings
open Fastify

// Helmet
@module("@fastify/helmet")
external helmet: plugin<'opts> = "default"

// CORS
@module("@fastify/cors")
external cors: plugin<'opts> = "default"

// Compression
@module("@fastify/compress")
external compress: plugin<'opts> = "default"

// Cookie
@module("@fastify/cookie")
external cookie: plugin<'opts> = "default"

// JWT
@module("@fastify/jwt")
external jwt: 'options => plugin<unit> = "default"`;
  }
}