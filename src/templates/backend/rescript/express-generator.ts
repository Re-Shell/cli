/**
 * ReScript Express Framework Generator
 * Generates a ReScript backend service with Express.js bindings
 */

import { ReScriptBackendGenerator } from './rescript-base-generator';
import type { FileTemplate } from '../../types';

export class ExpressGenerator extends ReScriptBackendGenerator {
  constructor() {
    super();
    this.config.framework = 'Express';
    this.config.features.push(
      'Express.js bindings',
      'Type-safe routing',
      'Middleware pipeline',
      'Request/Response helpers',
      'Body parsing',
      'Cookie parsing',
      'CORS support',
      'Helmet security',
      'Compression',
      'Morgan logging'
    );
  }

  protected getFrameworkDependencies(): Record<string, string> {
    return {
      'express': '^4.18.2',
      'cors': '^2.8.5',
      'helmet': '^7.1.0',
      'compression': '^1.7.4',
      'morgan': '^1.10.0',
      'body-parser': '^1.20.2',
      'cookie-parser': '^1.4.6',
      'express-rate-limit': '^7.1.5',
      'jsonwebtoken': '^9.0.2',
      'bcryptjs': '^2.4.3',
      'dotenv': '^16.3.1'
    };
  }

  protected getFrameworkDevDependencies(): Record<string, string> {
    return {
      '@types/express': '^4.17.21',
      '@types/cors': '^2.8.17',
      '@types/compression': '^1.7.5',
      '@types/morgan': '^1.9.9',
      '@types/jsonwebtoken': '^9.0.5',
      '@types/bcryptjs': '^2.4.6',
      'jest': '^29.7.0',
      '@types/jest': '^29.5.11',
      'supertest': '^6.3.3',
      '@types/supertest': '^6.0.2'
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
        path: 'src/middleware/Auth.res',
        content: this.generateAuthMiddleware()
      },
      {
        path: 'src/middleware/RateLimit.res',
        content: this.generateRateLimitMiddleware()
      },
      {
        path: 'src/controllers/UserController.res',
        content: this.generateUserController()
      },
      {
        path: 'src/bindings/Express.res',
        content: this.generateExpressBindings()
      },
      {
        path: 'src/bindings/Middleware.res',
        content: this.generateMiddlewareBindings()
      },
      {
        path: 'src/bindings/Jwt.res',
        content: this.generateJwtBindings()
      },
      {
        path: 'src/bindings/Bcrypt.res',
        content: this.generateBcryptBindings()
      }
    ];
  }

  protected generateMainFile(options: any): string {
    return `// Main application entry point
open NodeJs

// Load environment variables
@module("dotenv") external config: unit => unit = "config"
config()

let port = Config.getPort()
let app = App.create()

// Start the server
let server = Express.listen(app, port, () => {
  Console.log(\`🚀 Express server running on port \${port->Int.toString}\`)
  Console.log(\`Environment: \${Config.config.env}\`)
})

// Graceful shutdown
Process.on(#SIGTERM, () => {
  Console.log("SIGTERM signal received: closing HTTP server")
  Express.Server.close(server, () => {
    Console.log("HTTP server closed")
    Process.exit(0)
  })
})

Process.on(#SIGINT, () => {
  Console.log("SIGINT signal received: closing HTTP server")
  Express.Server.close(server, () => {
    Console.log("HTTP server closed")
    Process.exit(0)
  })
})`;
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
    return `// Express application setup
open Express

let create = (): Express.app => {
  let app = Express.create()
  
  // Security middleware
  app->Express.use(Middleware.helmet())
  app->Express.use(Middleware.cors({
    origin: Config.config.env === "production" ? "https://yourdomain.com" : true,
    credentials: true,
  }))
  
  // Body parsing middleware
  app->Express.use(Middleware.json({limit: "10mb"}))
  app->Express.use(Middleware.urlencoded({extended: true, limit: "10mb"}))
  app->Express.use(Middleware.cookieParser())
  
  // Compression
  app->Express.use(Middleware.compression())
  
  // Logging
  if Config.config.env !== "test" {
    app->Express.use(Middleware.morgan("combined"))
  }
  
  // Custom middleware
  app->Express.use(Logger.middleware)
  app->Express.use(RateLimit.globalLimit)
  
  // Routes
  app->Express.useWithPath("/api", Router.create())
  
  // Health check routes (no rate limiting)
  app->Express.get("/health", (req, res) => {
    let status = HealthController.getHealthStatus()
    res->Express.json(status)
  })
  app->Express.get("/ready", (req, res) => {
    let ready = HealthController.getReadinessStatus()
    if ready {
      res->Express.status(200)->Express.json({"ready": true})
    } else {
      res->Express.status(503)->Express.json({"ready": false})
    }
  })
  app->Express.get("/info", (req, res) => {
    let info = InfoController.getServiceInfo()
    res->Express.json(info)
  })
  
  // Error handlers
  app->Express.use(ErrorHandler.notFound)
  app->Express.use(ErrorHandler.handleError)
  
  app
}`;
  }

  private generateRouterFile(): string {
    return `// Main API router
open Express

let create = (): Express.router => {
  let router = Express.Router.create()
  
  // API info
  router->Express.Router.get("/", (req, res) => {
    res->Express.json({
      "message": "Welcome to API",
      "version": "1.0.0",
      "documentation": "/api/docs",
    })
  })
  
  // Mount route modules
  router->Express.Router.use("/users", UserRoutes.create())
  
  router
}`;
  }

  private generateUserRoutesFile(): string {
    return `// User routes
open Express

let create = (): Express.router => {
  let router = Express.Router.create()
  
  // Public routes
  router->Express.Router.post("/register", UserController.register)
  router->Express.Router.post("/login", UserController.login)
  
  // Protected routes
  router->Express.Router.get("/", Auth.authenticate, UserController.listUsers)
  router->Express.Router.get("/profile", Auth.authenticate, UserController.getProfile)
  router->Express.Router.get("/:id", Auth.authenticate, UserController.getUser)
  router->Express.Router.put("/:id", Auth.authenticate, UserController.updateUser)
  router->Express.Router.delete("/:id", Auth.authenticate, UserController.deleteUser)
  
  router
}`;
  }

  private generateUserController(): string {
    return `// User controller
open Express
open User

let register = (req: Express.request, res: Express.response): unit => {
  let body = Express.body(req)
  
  // Simple registration logic
  let email = body["email"]
  let name = body["name"]
  
  switch (email, name) {
  | (Some(email), Some(name)) => {
    switch UserService.create(~email, ~name, ()) {
    | Ok(user) => {
      res->Express.status(201)->Express.json({
        "success": true,
        "data": {"user": User.toJson(user)},
      })
    }
    | Error(message) => {
      res->Express.status(400)->Express.json({
        "error": true,
        "message": message,
      })
    }
    }
  }
  | _ => {
    res->Express.status(400)->Express.json({
      "error": true,
      "message": "Email and name are required",
    })
  }
  }
}

let login = (req: Express.request, res: Express.response): unit => {
  let body = Express.body(req)
  
  switch body["email"] {
  | Some(email) => {
    switch UserService.findByEmail(email) {
    | Some(user) => {
      res->Express.json({
        "success": true,
        "data": {"user": User.toJson(user)},
      })
    }
    | None => {
      res->Express.status(401)->Express.json({
        "error": true,
        "message": "Invalid credentials",
      })
    }
    }
  }
  | None => {
    res->Express.status(400)->Express.json({
      "error": true,
      "message": "Email is required",
    })
  }
  }
}

let listUsers = (req: Express.request, res: Express.response): unit => {
  let users = UserService.listAll()
  res->Express.json({
    "success": true,
    "data": {"users": users->Array.map(User.toJson)},
  })
}

let getProfile = (req: Express.request, res: Express.response): unit => {
  // For demo, return first user
  let users = UserService.listAll()
  switch users[0] {
  | Some(user) => {
    res->Express.json({
      "success": true,
      "data": {"user": User.toJson(user)},
    })
  }
  | None => {
    res->Express.status(404)->Express.json({
      "error": true,
      "message": "User not found",
    })
  }
  }
}

let getUser = (req: Express.request, res: Express.response): unit => {
  let userId = Express.params(req)->Js.Dict.get("id")
  
  switch userId {
  | Some(id) => {
    switch UserService.findById(id) {
    | Some(user) => {
      res->Express.json({
        "success": true,
        "data": {"user": User.toJson(user)},
      })
    }
    | None => {
      res->Express.status(404)->Express.json({
        "error": true,
        "message": "User not found",
      })
    }
    }
  }
  | None => {
    res->Express.status(400)->Express.json({
      "error": true,
      "message": "User ID is required",
    })
  }
  }
}

let updateUser = (req: Express.request, res: Express.response): unit => {
  res->Express.status(501)->Express.json({
    "error": true,
    "message": "Not implemented",
  })
}

let deleteUser = (req: Express.request, res: Express.response): unit => {
  res->Express.status(501)->Express.json({
    "error": true,
    "message": "Not implemented",
  })
}`;
  }

  private generateAuthMiddleware(): string {
    return `// Authentication middleware
open Express

let authenticate = (req: Express.request, res: Express.response, next: Express.next): unit => {
  // Simple auth - just check for any authorization header
  let authHeader = Express.headers(req)->Js.Dict.get("authorization")
  
  switch authHeader {
  | Some(_) => next()
  | None => {
    res->Express.status(401)->Express.json({
      "error": true,
      "message": "Authorization header required",
    })
  }
  }
}`;
  }

  private generateRateLimitMiddleware(): string {
    return `// Rate limiting middleware
open Express

// Simple rate limiter
@module("express-rate-limit") 
external rateLimit: 'options => Express.middleware = "default"

let globalLimit = rateLimit({
  "windowMs": 15 * 60 * 1000, // 15 minutes
  "max": 100, // limit each IP to 100 requests per windowMs
  "message": "Too many requests from this IP, please try again later",
})`;
  }

  private generateExpressBindings(): string {
    return `// Express.js bindings
type app
type request
type response
type router
type server
type next = unit => unit
type middleware = (request, response, next) => unit

// Server type
module Server = {
  type t = server
  @send external close: (t, unit => unit) => unit = "close"
}

// Create app and router
@module("express") external create: unit => app = "default"
module Router = {
  @module("express") @scope("Router") external create: unit => router = "default"
  
  // Router methods
  @send external use: (router, middleware) => router = "use"
  @send external get: (router, string, middleware) => router = "get"
  @send external post: (router, string, middleware) => router = "post"
  @send external put: (router, string, middleware) => router = "put"
  @send external delete: (router, string, middleware) => router = "delete"
}

// Request properties
@get external method: request => string = "method"
@get external url: request => string = "url"
@get external params: request => Js.Dict.t<string> = "params"
@get external query: request => Js.Dict.t<string> = "query"
@get external body: request => 'a = "body"
@get external headers: request => Js.Dict.t<string> = "headers"

// Response methods
@send external status: (response, int) => response = "status"
@send external json: (response, 'a) => unit = "json"
@send external send: (response, string) => unit = "send"

// App methods
@send external use: (app, middleware) => app = "use"
@send external useWithPath: (app, string, 'a) => app = "use"
@send external get: (app, string, middleware) => app = "get"
@send external post: (app, string, middleware) => app = "post"
@send external listen: (app, int, unit => unit) => server = "listen"`;
  }

  private generateMiddlewareBindings(): string {
    return `// Middleware bindings
open Express

// Helmet
@module("helmet")
external helmet: unit => middleware = "default"

// CORS
@module("cors")
external cors: 'options => middleware = "default"

// Body parser
@module("body-parser") @scope("json")
external json: 'options => middleware = "default"

@module("body-parser") @scope("urlencoded")
external urlencoded: 'options => middleware = "default"

// Cookie parser
@module("cookie-parser")
external cookieParser: unit => middleware = "default"

// Compression
@module("compression")
external compression: unit => middleware = "default"

// Morgan logging
@module("morgan")
external morgan: string => middleware = "default"`;
  }

  private generateJwtBindings(): string {
    return `// JWT bindings
@module("jsonwebtoken")
external sign: ('payload, string, 'options) => string = "sign"

@module("jsonwebtoken")
external verify: (string, string) => result<'payload, string> = "verify"

// Helper to handle JWT errors
let verifyToken = (token: string, secret: string): result<'payload, string> => {
  try {
    Ok(%raw(\`require('jsonwebtoken').verify(token, secret)\`))
  } catch {
  | _ => Error("Invalid token")
  }
}`;
  }

  private generateBcryptBindings(): string {
    return `// Bcrypt bindings
@module("bcryptjs")
external genSalt: int => string = "genSaltSync"

@module("bcryptjs")
external hash: (string, string) => string = "hashSync"

@module("bcryptjs")
external compare: (string, string) => bool = "compareSync"

// Helper functions
let hashPassword = (password: string): string => {
  let salt = genSalt(10)
  hash(password, salt)
}

let verifyPassword = (password: string, hash: string): bool => {
  compare(password, hash)
}`;
  }
}