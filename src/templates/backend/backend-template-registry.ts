/**
 * Backend Template Registry
 * Central registry for all backend framework templates
 */

import { BackendTemplateGenerator } from './shared/backend-template-generator';

// Swift templates
import VaporGenerator from './swift/vapor-generator';
// import { PerfectGenerator } from './swift/perfect-generator';
// import { KituraGenerator } from './swift/kitura-generator';
// import { HummingbirdGenerator } from './swift/hummingbird-generator';

// Dart templates
import { ShelfGenerator } from './dart/shelf-generator';
import { Angel3Generator } from './dart/angel3-generator';
import { ConduitGenerator } from './dart/conduit-generator';

// Haskell templates
import { ServantGenerator } from './haskell/servant-generator';
import { YesodGenerator } from './haskell/yesod-generator';
import { ScottyGenerator } from './haskell/scotty-generator';
import { SpockGenerator } from './haskell/spock-generator';

// Deno templates
import { OakGenerator } from './deno/oak-generator';
import { FreshGenerator } from './deno/fresh-generator';
import { AlephGenerator } from './deno/aleph-generator';

// Bun templates
import { ElysiaGenerator } from './bun/elysia-generator';
import { HonoGenerator } from './bun/hono-generator';

// Zig templates
import { HttpServerGenerator } from './zig/http-server-generator';
import { ZapGenerator } from './zig/zap-generator';

// Kotlin templates
import { KtorGenerator } from './kotlin/ktor-generator';
import { SpringBootKotlinGenerator } from './kotlin/spring-boot-generator';
import { MicronautGenerator } from './kotlin/micronaut-generator';

// Scala templates
import { AkkaHttpGenerator } from './scala/akka-http-generator';
import { PlayGenerator } from './scala/play-generator';
import { Http4sGenerator } from './scala/http4s-generator';

// Crystal templates
import { KemalGenerator } from './crystal/kemal-generator';
import { LuckyGenerator } from './crystal/lucky-generator';
import { AmberGenerator } from './crystal/amber-generator';

// Nim templates
import { JesterGenerator } from './nim/jester-generator';
import { PrologueGenerator } from './nim/prologue-generator';
import { HappyXGenerator } from './nim/happyx-generator';

// V Language templates
import { VwebGenerator } from './v/vweb-generator';
import { VexGenerator } from './v/vex-generator';

// Gleam templates
import { WispGenerator } from './gleam/wisp-generator';
import { MistGenerator } from './gleam/mist-generator';

// Node.js templates
import { ExpressGenerator } from './node/express-generator';
import { NestJSGenerator } from './node/nestjs-generator';
// import FastifyGenerator from './node/fastify-generator'; // TODO: implement

// PHP templates  
import { LaravelGenerator } from './php/laravel-generator';
import { SymfonyGenerator } from './php/symfony-generator';
import { SlimGenerator } from './php/slim-generator';
import { CodeIgniterGenerator } from './php/codeigniter-generator';

// OCaml templates
import { DreamGenerator } from './ocaml/dream-generator';
import { OpiumGenerator } from './ocaml/opium-generator';
import { SihlGenerator } from './ocaml/sihl-generator';

// Elixir templates
import { PhoenixGenerator } from './elixir/phoenix-generator';
import { PlugGenerator } from './elixir/plug-generator';

// ReScript templates
import { ExpressGenerator as ReScriptExpressGenerator } from './rescript/express-generator';
import { FastifyGenerator as ReScriptFastifyGenerator } from './rescript/fastify-generator';

// Python templates
import { FastAPIGenerator } from './python/fastapi-generator';
import { DjangoGenerator } from './python/django-generator';
import { FlaskGenerator } from './python/flask-generator';

// Go templates
import { GinGenerator } from './go/gin-generator';
import { EchoGenerator } from './go/echo-generator';
import { FiberGenerator } from './go/fiber-generator';

// Rust templates
import { ActixWebGenerator } from './rust/actix-web-generator';
import { WarpGenerator } from './rust/warp-generator';
import { RocketGenerator } from './rust/rocket-generator';
import { AxumGenerator } from './rust/axum-generator';

// Java templates
import { SpringBootGenerator } from './java/spring-boot-generator';
import { QuarkusGenerator } from './java/quarkus-generator';
import { MicronautGenerator as JavaMicronautGenerator } from './java/micronaut-generator';
import { VertxGenerator } from './java/vertx-generator';

// .NET templates
import { AspNetWebApiGenerator } from './dotnet/aspnet-webapi-generator';
import { MinimalApiGenerator } from './dotnet/minimal-api-generator';

export interface BackendTemplate {
  name: string;
  language: string;
  framework: string;
  description: string;
  features: string[];
  defaultPort: number;
  generator: new() => BackendTemplateGenerator;
}

export class BackendTemplateRegistry {
  private static templates = new Map<string, BackendTemplate>();

  static {
    // Register all backend templates
    this.registerTemplates();
  }

  private static registerTemplates(): void {
    // Node.js Templates
    this.register({
      name: 'express',
      language: 'Node.js',
      framework: 'Express',
      description: 'Fast, unopinionated, minimalist web framework for Node.js',
      features: [
        'Minimal and flexible',
        'Robust routing',
        'High performance',
        'Super-high test coverage',
        'HTTP helpers',
        'Content negotiation',
        'Executable for generating applications',
        'View system supporting 14+ template engines'
      ],
      defaultPort: 3000,
      generator: ExpressGenerator
    });

    this.register({
      name: 'nestjs',
      language: 'TypeScript',
      framework: 'NestJS',
      description: 'Progressive Node.js framework for building efficient and scalable server-side applications',
      features: [
        'TypeScript by default',
        'Decorator-based architecture',
        'Dependency injection',
        'Modular structure',
        'Built-in guards and interceptors',
        'GraphQL and REST support',
        'Swagger integration',
        'WebSocket support',
        'Microservices ready',
        'Testing utilities'
      ],
      defaultPort: 3000,
      generator: NestJSGenerator
    });

    // Python Templates
    this.register({
      name: 'python-fastapi',
      language: 'Python',
      framework: 'FastAPI',
      description: 'Modern, fast Python web framework with automatic API documentation',
      features: [
        'Fast performance (Starlette + Pydantic)',
        'Automatic interactive API documentation',
        'Type hints and validation',
        'Async/await support',
        'JWT authentication',
        'WebSocket support',
        'Background tasks',
        'Dependency injection'
      ],
      defaultPort: 8000,
      generator: FastAPIGenerator
    });

    this.register({
      name: 'python-django',
      language: 'Python',
      framework: 'Django',
      description: 'High-level Python web framework that encourages rapid development',
      features: [
        'Batteries included framework',
        'Django ORM with migrations',
        'Django REST Framework',
        'Admin interface',
        'Authentication system',
        'Channels for WebSocket',
        'Celery integration',
        'Built-in security features'
      ],
      defaultPort: 8000,
      generator: DjangoGenerator
    });

    this.register({
      name: 'python-flask',
      language: 'Python',
      framework: 'Flask',
      description: 'Lightweight WSGI web application framework with extensive ecosystem',
      features: [
        'Minimalist core with extensions',
        'Flask-RESTful for APIs',
        'Flask-SQLAlchemy ORM',
        'Flask-JWT-Extended auth',
        'Flask-SocketIO WebSocket',
        'Celery background tasks',
        'Flask-Migrate for DB',
        'Extensive testing support'
      ],
      defaultPort: 5000,
      generator: FlaskGenerator
    });

    // Go Templates
    this.register({
      name: 'go-gin',
      language: 'Go',
      framework: 'Gin',
      description: 'High-performance HTTP web framework written in Go',
      features: [
        'Fast HTTP router',
        'Middleware support',
        'JSON validation',
        'Error management',
        'Rendering built-in',
        'JWT authentication',
        'WebSocket support',
        'Rate limiting',
        'GORM integration',
        'Swagger documentation'
      ],
      defaultPort: 8080,
      generator: GinGenerator
    });

    this.register({
      name: 'go-echo',
      language: 'Go',
      framework: 'Echo',
      description: 'High performance, minimalist Go web framework',
      features: [
        'Optimized HTTP router',
        'RESTful API',
        'Group APIs',
        'Extensible middleware',
        'Data binding for JSON, XML and form',
        'Data rendering',
        'Templates',
        'Centralized HTTP error handling',
        'JWT authentication',
        'WebSocket support'
      ],
      defaultPort: 8080,
      generator: EchoGenerator
    });

    this.register({
      name: 'go-fiber',
      language: 'Go',
      framework: 'Fiber',
      description: 'Express-inspired web framework written in Go',
      features: [
        'Extreme performance',
        'Low memory footprint',
        'Express-like API',
        'Flexible middleware',
        'WebSocket support',
        'Rate limiter',
        'Template engines',
        'Easy JSON/XML rendering',
        'JWT authentication',
        'Built-in caching'
      ],
      defaultPort: 8080,
      generator: FiberGenerator
    });

    // Rust Templates
    this.register({
      name: 'rust-actix-web',
      language: 'Rust',
      framework: 'Actix-Web',
      description: 'Powerful, pragmatic, and extremely fast web framework for Rust',
      features: [
        'Actor model architecture',
        'HTTP/1.x and HTTP/2',
        'Streaming and pipelining',
        'Built-in session management',
        'Middleware support',
        'Static file serving',
        'WebSocket support',
        'Request routing with macros',
        'Type-safe request handling',
        'Async/await support'
      ],
      defaultPort: 8080,
      generator: ActixWebGenerator
    });

    this.register({
      name: 'rust-warp',
      language: 'Rust',
      framework: 'Warp',
      description: 'Composable web framework with focus on type-safety and performance',
      features: [
        'Filter-based routing',
        'Type-safe by design',
        'Composable architecture',
        'Excellent performance',
        'Built on hyper and tokio',
        'Built-in rejection handling',
        'WebSocket support',
        'Streaming responses',
        'Middleware composition',
        'OpenAPI integration'
      ],
      defaultPort: 8080,
      generator: WarpGenerator
    });

    this.register({
      name: 'rust-rocket',
      language: 'Rust',
      framework: 'Rocket',
      description: 'Type-safe, fast web framework with code generation and guards',
      features: [
        'Code generation macros',
        'Type-safe request guards',
        'Built-in form validation',
        'Template engine support',
        'JSON support',
        'Testing framework',
        'Request lifecycle hooks',
        'Async-first design',
        'Structured configuration',
        'Automatic OpenAPI generation'
      ],
      defaultPort: 8080,
      generator: RocketGenerator
    });

    this.register({
      name: 'rust-axum',
      language: 'Rust',
      framework: 'Axum',
      description: 'Ergonomic and modular web framework built with Tokio, Tower, and Hyper',
      features: [
        'Built on hyper and tokio',
        'Type-safe extractors',
        'Tower middleware ecosystem',
        'Async/await first-class support',
        'WebSocket support',
        'JSON/form handling',
        'Route parameters and query parameters',
        'Built-in error handling',
        'State management',
        'OpenAPI integration'
      ],
      defaultPort: 8080,
      generator: AxumGenerator
    });

    // Java Templates
    this.register({
      name: 'java-spring-boot',
      language: 'Java',
      framework: 'Spring Boot',
      description: 'Enterprise-grade Java framework with comprehensive ecosystem',
      features: [
        'Spring ecosystem integration',
        'Auto-configuration and starters',
        'Spring Data JPA with Hibernate',
        'Spring Security with JWT',
        'Actuator monitoring and metrics',
        'OpenAPI/Swagger documentation',
        'WebSocket support with STOMP',
        'Caching with Redis',
        'Email support with templates',
        'Comprehensive testing framework'
      ],
      defaultPort: 8080,
      generator: SpringBootGenerator
    });

    this.register({
      name: 'java-quarkus',
      language: 'Java',
      framework: 'Quarkus',
      description: 'Cloud-native Java framework optimized for containers and serverless',
      features: [
        'Fast startup and low memory usage',
        'Native compilation with GraalVM',
        'JAX-RS and reactive programming',
        'Panache ORM with active record pattern',
        'Built-in JWT and RBAC security',
        'Comprehensive health checks',
        'OpenAPI documentation generation',
        'Redis integration for caching',
        'Flyway database migrations',
        'Quarkus Dev UI and hot reload'
      ],
      defaultPort: 8080,
      generator: QuarkusGenerator
    });

    this.register({
      name: 'java-micronaut',
      language: 'Java',
      framework: 'Micronaut',
      description: 'Modern JVM framework with compile-time DI and GraalVM native support',
      features: [
        'Compile-time dependency injection',
        'GraalVM native image support',
        'Fast startup and low memory footprint',
        'Reactive programming with Netty',
        'Cloud-native microservices features',
        'Built-in service discovery and config',
        'JWT security with compile-time optimization',
        'Micronaut Data compile-time ORM',
        'Distributed tracing and metrics',
        'Serverless and Lambda optimization'
      ],
      defaultPort: 8080,
      generator: JavaMicronautGenerator
    });

    this.register({
      name: 'java-vertx',
      language: 'Java',
      framework: 'Vert.x',
      description: 'Event-driven reactive toolkit for building responsive JVM applications',
      features: [
        'Event-driven and non-blocking',
        'Vert.x event bus for messaging',
        'Verticle deployment model',
        'High-performance async I/O',
        'Reactive Vert.x Web router',
        'JWT authentication with Web',
        'MongoDB reactive client',
        'Circuit breaker patterns',
        'Microservices toolkit',
        'Event loop architecture'
      ],
      defaultPort: 8080,
      generator: VertxGenerator
    });

    // .NET Templates
    this.register({
      name: 'dotnet-webapi',
      language: 'C#',
      framework: 'ASP.NET Core Web API',
      description: 'Enterprise-grade web API with Entity Framework, authentication, and comprehensive features',
      features: [
        'ASP.NET Core 8.0 with controllers',
        'Entity Framework Core with SQL Server',
        'JWT authentication and authorization',
        'Swagger/OpenAPI documentation',
        'AutoMapper for object mapping',
        'FluentValidation for input validation',
        'Serilog structured logging',
        'Health checks and monitoring',
        'Rate limiting and CORS',
        'Comprehensive unit and integration tests'
      ],
      defaultPort: 5000,
      generator: AspNetWebApiGenerator
    });

    this.register({
      name: 'dotnet-minimal-api',
      language: 'C#',
      framework: 'ASP.NET Core Minimal API',
      description: 'Lightweight, high-performance API with minimal ceremony and maximum performance',
      features: [
        'ASP.NET Core 8.0 Minimal APIs',
        'Entity Framework Core with SQLite',
        'JWT authentication',
        'Swagger/OpenAPI documentation',
        'FluentValidation',
        'Serilog structured logging',
        'Rate limiting built-in',
        'Health checks',
        'High-performance endpoint routing',
        'Minimal ceremony, maximum performance'
      ],
      defaultPort: 5000,
      generator: MinimalApiGenerator
    });

    // Swift Templates
    this.register({
      name: 'swift-vapor',
      language: 'Swift',
      framework: 'Vapor',
      description: 'Modern web framework for Swift with async/await, Fluent ORM, and WebSocket support',
      features: [
        'Async/await support',
        'Fluent ORM with migrations',
        'JWT authentication',
        'WebSocket support',
        'Redis integration',
        'Queue system',
        'Middleware pipeline',
        'Type-safe routing',
        'SwiftNIO powered'
      ],
      defaultPort: 8080,
      generator: VaporGenerator
    });

    // Swift Templates - TODO: Fix compilation errors
    /* this.register({
      name: 'swift-perfect',
      language: 'Swift',
      framework: 'Perfect',
      description: 'High-performance server-side Swift with HTTP/2 and WebSocket support',
      features: [
        'HTTP/2 support',
        'WebSocket server',
        'Perfect-ORM',
        'Perfect-Redis',
        'Perfect-Crypto',
        'Mustache templates',
        'MySQL/PostgreSQL/SQLite',
        'Threading and networking'
      ],
      defaultPort: 8181,
      generator: PerfectGenerator
    });

    this.register({
      name: 'swift-kitura',
      language: 'Swift',
      framework: 'Kitura',
      description: 'Enterprise Swift framework by IBM with cloud integration',
      features: [
        'IBM Cloud integration',
        'SwiftKuery ORM',
        'Stencil templating',
        'OpenAPI support',
        'Circuit breaker',
        'Health checks',
        'Metrics collection',
        'Docker optimized'
      ],
      defaultPort: 8090,
      generator: KituraGenerator
    });

    this.register({
      name: 'swift-hummingbird',
      language: 'Swift',
      framework: 'Hummingbird',
      description: 'Lightweight, flexible server framework built on SwiftNIO',
      features: [
        'Minimal footprint',
        'SwiftNIO based',
        'Async/await native',
        'Middleware system',
        'Type-safe routing',
        'WebSocket support',
        'GraphQL ready',
        'Lambda deployment'
      ],
      defaultPort: 8088,
      generator: HummingbirdGenerator
    }); */

    // Dart Templates
    this.register({
      name: 'dart-shelf',
      language: 'Dart',
      framework: 'Shelf',
      description: 'Composable web server middleware framework with hot reload support',
      features: [
        'Middleware pipeline',
        'Hot reload development',
        'JWT authentication',
        'PostgreSQL integration',
        'Redis caching',
        'Rate limiting',
        'CORS support',
        'Request validation',
        'OpenAPI documentation'
      ],
      defaultPort: 8080,
      generator: ShelfGenerator
    });

    this.register({
      name: 'dart-angel3',
      language: 'Dart',
      framework: 'Angel3',
      description: 'Full-stack server-side framework with batteries included',
      features: [
        'Full MVC framework',
        'Angel3 ORM with migrations',
        'WebSocket support',
        'GraphQL integration',
        'Template engines',
        'Service container',
        'Dependency injection',
        'Plugin system',
        'Production mode optimizations'
      ],
      defaultPort: 3000,
      generator: Angel3Generator
    });

    this.register({
      name: 'dart-conduit',
      language: 'Dart',
      framework: 'Conduit',
      description: 'Modern HTTP framework with built-in ORM and OpenAPI support',
      features: [
        'Built-in ORM',
        'Database migrations',
        'OpenAPI generation',
        'OAuth2 server',
        'Multi-threading',
        'CLI tooling',
        'Test harness',
        'Health checks',
        'Type-safe routing'
      ],
      defaultPort: 8080,
      generator: ConduitGenerator
    });

    // Haskell Templates
    this.register({
      name: 'haskell-servant',
      language: 'Haskell',
      framework: 'Servant',
      description: 'Type-safe REST API framework with automatic client generation',
      features: [
        'Type-level API definition',
        'Automatic client generation',
        'OpenAPI/Swagger generation',
        'JWT authentication',
        'PostgreSQL integration',
        'Type-safe SQL queries',
        'Property-based testing',
        'Automatic API documentation',
        'Compile-time guarantees'
      ],
      defaultPort: 8080,
      generator: ServantGenerator
    });

    this.register({
      name: 'haskell-yesod',
      language: 'Haskell',
      framework: 'Yesod',
      description: 'Type-safe, RESTful web framework with compile-time templates',
      features: [
        'Type-safe URLs',
        'Compile-time templates',
        'Persistent ORM',
        'Authentication system',
        'Form handling',
        'Internationalization',
        'Widget system',
        'Type-safe SQL',
        'Development server'
      ],
      defaultPort: 3000,
      generator: YesodGenerator
    });

    this.register({
      name: 'haskell-scotty',
      language: 'Haskell',
      framework: 'Scotty',
      description: 'Haskell web framework inspired by Ruby\'s Sinatra',
      features: [
        'Sinatra-inspired DSL',
        'Lightweight and fast',
        'WAI/Warp based',
        'Simple routing',
        'Middleware support',
        'JSON handling',
        'PostgreSQL integration',
        'JWT authentication',
        'Async request handling'
      ],
      defaultPort: 3000,
      generator: ScottyGenerator
    });

    this.register({
      name: 'haskell-spock',
      language: 'Haskell',
      framework: 'Spock',
      description: 'Lightweight Haskell web framework for rapid development',
      features: [
        'Type-safe routing',
        'Session management',
        'Database pooling',
        'CSRF protection',
        'Type-safe actions',
        'Middleware system',
        'WebSocket support',
        'RESTful design',
        'Hot code reload'
      ],
      defaultPort: 3000,
      generator: SpockGenerator
    });

    // Deno Templates
    this.register({
      name: 'deno-oak',
      language: 'Deno',
      framework: 'Oak',
      description: 'Middleware framework for Deno\'s native HTTP server',
      features: [
        'Express-like middleware',
        'Router with params',
        'TypeScript native',
        'JWT authentication',
        'CORS support',
        'Rate limiting',
        'Request validation',
        'PostgreSQL integration',
        'Redis caching'
      ],
      defaultPort: 8000,
      generator: OakGenerator
    });

    this.register({
      name: 'deno-fresh',
      language: 'Deno',
      framework: 'Fresh',
      description: 'Next-gen web framework with islands architecture',
      features: [
        'Islands architecture',
        'Server-side rendering',
        'File-based routing',
        'TypeScript by default',
        'Zero runtime overhead',
        'Preact components',
        'Tailwind CSS support',
        'Edge deployment ready',
        'No build step'
      ],
      defaultPort: 8000,
      generator: FreshGenerator
    });

    this.register({
      name: 'deno-aleph',
      language: 'Deno',
      framework: 'Aleph.js',
      description: 'React SSR/SSG framework for Deno',
      features: [
        'React SSR/SSG',
        'File-based routing',
        'Hot module replacement',
        'TypeScript support',
        'API routes',
        'CSS-in-JS support',
        'Import maps',
        'Optimized builds',
        'Deploy anywhere'
      ],
      defaultPort: 8000,
      generator: AlephGenerator
    });

    // Bun Templates
    this.register({
      name: 'bun-elysia',
      language: 'Bun',
      framework: 'Elysia',
      description: 'Fast and friendly Bun web framework with end-to-end type safety',
      features: [
        'End-to-end type safety',
        'Auto-generated clients',
        'Swagger documentation',
        'Blazing fast performance',
        'Schema validation',
        'JWT authentication',
        'WebSocket support',
        'File uploads',
        'Plugin system'
      ],
      defaultPort: 3000,
      generator: ElysiaGenerator
    });

    this.register({
      name: 'bun-hono',
      language: 'Bun',
      framework: 'Hono',
      description: 'Small, simple, and ultrafast web framework for the Edge',
      features: [
        'Ultra-lightweight',
        'Edge computing ready',
        'Express-like syntax',
        'TypeScript support',
        'Middleware system',
        'JWT authentication',
        'OpenAPI support',
        'Cross-runtime',
        'RPC mode'
      ],
      defaultPort: 3000,
      generator: HonoGenerator
    });

    // Zig Templates
    this.register({
      name: 'zig-http',
      language: 'Zig',
      framework: 'HTTP Server',
      description: 'Native HTTP server using Zig\'s standard library',
      features: [
        'Zero dependencies',
        'Manual memory management',
        'Minimal footprint',
        'JWT authentication',
        'JSON parsing',
        'SQLite support',
        'Compile-time safety',
        'Cross-compilation',
        'Fast compilation'
      ],
      defaultPort: 8080,
      generator: HttpServerGenerator
    });

    this.register({
      name: 'zig-zap',
      language: 'Zig',
      framework: 'Zap',
      description: 'Blazingly fast web framework for Zig',
      features: [
        'High performance',
        'WebSocket support',
        'Middleware system',
        'Static file serving',
        'JSON handling',
        'Route parameters',
        'Request validation',
        'Built-in auth',
        'Production ready'
      ],
      defaultPort: 8080,
      generator: ZapGenerator
    });

    // Kotlin Templates
    this.register({
      name: 'kotlin-ktor',
      language: 'kotlin',
      framework: 'Ktor',
      description: 'Lightweight async framework with coroutines support',
      features: [
        'Kotlin coroutines',
        'Async request handling',
        'Lightweight and modular',
        'JWT authentication',
        'Exposed ORM integration',
        'WebSocket support',
        'Content negotiation',
        'Rate limiting',
        'Metrics with Micrometer'
      ],
      defaultPort: 8080,
      generator: KtorGenerator
    });

    this.register({
      name: 'kotlin-spring-boot',
      language: 'kotlin',
      framework: 'Spring Boot',
      description: 'Enterprise Java framework with full Kotlin support',
      features: [
        'Spring ecosystem',
        'Spring Data JPA',
        'Spring Security',
        'Actuator metrics',
        'OpenAPI documentation',
        'Flyway migrations',
        'Redis caching',
        'AOP support',
        'Production-ready features'
      ],
      defaultPort: 8080,
      generator: SpringBootKotlinGenerator
    });

    this.register({
      name: 'kotlin-micronaut',
      language: 'kotlin',
      framework: 'Micronaut',
      description: 'Modern JVM framework with GraalVM native support',
      features: [
        'GraalVM native images',
        'Compile-time DI',
        'Reactive programming',
        'Micronaut Data',
        'Cloud-native features',
        'Fast startup time',
        'Low memory footprint',
        'Built-in security',
        'Distributed tracing'
      ],
      defaultPort: 8080,
      generator: MicronautGenerator
    });

    // Scala Templates
    this.register({
      name: 'scala-akka-http',
      language: 'Scala',
      framework: 'Akka HTTP',
      description: 'High-performance toolkit for building REST/HTTP-based services',
      features: [
        'Actor model',
        'Streaming HTTP',
        'Async non-blocking',
        'Type-safe routing',
        'WebSocket support',
        'JWT authentication',
        'Swagger integration',
        'Akka Streams',
        'Clustering support'
      ],
      defaultPort: 8080,
      generator: AkkaHttpGenerator
    });

    this.register({
      name: 'scala-play',
      language: 'Scala',
      framework: 'Play Framework',
      description: 'Reactive web framework for modern web applications',
      features: [
        'MVC architecture',
        'Hot reload',
        'Built-in testing',
        'Async I/O',
        'RESTful by default',
        'WebSocket support',
        'Slick ORM',
        'Action composition',
        'Production ready'
      ],
      defaultPort: 9000,
      generator: PlayGenerator
    });

    this.register({
      name: 'scala-http4s',
      language: 'Scala',
      framework: 'http4s',
      description: 'Typeful, functional, streaming HTTP for Scala',
      features: [
        'Pure functional',
        'Cats Effect',
        'FS2 streaming',
        'Type-safe routing',
        'Doobie integration',
        'JWT authentication',
        'WebSocket support',
        'Prometheus metrics',
        'Tapir integration'
      ],
      defaultPort: 8080,
      generator: Http4sGenerator
    });

    // Crystal Templates
    this.register({
      name: 'crystal-kemal',
      language: 'Crystal',
      framework: 'Kemal',
      description: 'Lightning fast, super simple web framework written in Crystal',
      features: [
        'Sinatra-inspired DSL',
        'High performance',
        'Compile-time safety',
        'WebSocket support',
        'Middleware system',
        'JWT authentication',
        'PostgreSQL integration',
        'Redis support',
        'Docker ready'
      ],
      defaultPort: 3000,
      generator: KemalGenerator
    });

    this.register({
      name: 'crystal-lucky',
      language: 'Crystal',
      framework: 'Lucky',
      description: 'Full-featured Crystal web framework that catches bugs for you',
      features: [
        'Type-safe queries',
        'Compile-time checks',
        'Built-in authentication',
        'Asset pipeline',
        'Background jobs',
        'Email system',
        'Database migrations',
        'Form helpers',
        'Testing framework'
      ],
      defaultPort: 5000,
      generator: LuckyGenerator
    });

    this.register({
      name: 'crystal-amber',
      language: 'Crystal',
      framework: 'Amber',
      description: 'Productive web framework written in Crystal',
      features: [
        'MVC architecture',
        'ORM integration',
        'CLI generators',
        'WebSocket support',
        'Middleware pipeline',
        'Authentication system',
        'Background jobs',
        'Asset compilation',
        'Testing suite'
      ],
      defaultPort: 3000,
      generator: AmberGenerator
    });

    // Nim Templates
    this.register({
      name: 'nim-jester',
      language: 'Nim',
      framework: 'Jester',
      description: 'Simple and flexible micro web framework for Nim',
      features: [
        'Sinatra-inspired DSL',
        'High performance',
        'Async/await support',
        'Compile-time safety',
        'Pattern matching routes',
        'Middleware system',
        'Template engine',
        'WebSocket support',
        'Static file serving'
      ],
      defaultPort: 5000,
      generator: JesterGenerator
    });

    this.register({
      name: 'nim-prologue',
      language: 'Nim',
      framework: 'Prologue',
      description: 'Powerful and flexible web framework written in Nim',
      features: [
        'Full-featured framework',
        'Middleware pipeline',
        'Plugin system',
        'Template engine',
        'ORM integration',
        'Authentication system',
        'WebSocket support',
        'Static file handling',
        'Request validation'
      ],
      defaultPort: 8080,
      generator: PrologueGenerator
    });

    this.register({
      name: 'nim-happyx',
      language: 'Nim',
      framework: 'HappyX',
      description: 'Macro-oriented web framework for Nim',
      features: [
        'Macro-based DSL',
        'Component system',
        'SSR and SPA support',
        'Live views',
        'Built-in ORM',
        'WebSocket support',
        'Hot reload',
        'TypeScript generation',
        'Modern UI components'
      ],
      defaultPort: 5000,
      generator: HappyXGenerator
    });

    // V Language Templates
    this.register({
      name: 'v-vweb',
      language: 'V',
      framework: 'Vweb',
      description: 'Built-in web framework for V with high performance and simplicity',
      features: [
        'Built-in V framework',
        'Template engine',
        'ORM integration',
        'Session management',
        'CSRF protection',
        'Static file serving',
        'WebSocket support',
        'Middleware system',
        'Form validation',
        'Ultra-fast compilation'
      ],
      defaultPort: 8080,
      generator: VwebGenerator
    });

    this.register({
      name: 'v-vex',
      language: 'V',
      framework: 'Vex',
      description: 'Modular web framework for V inspired by Express.js',
      features: [
        'Express-like API',
        'Middleware pipeline',
        'Router system',
        'Request/Response helpers',
        'Template engine',
        'Static file serving',
        'JSON API support',
        'Session management',
        'Performance optimized',
        'Hot reload support'
      ],
      defaultPort: 3000,
      generator: VexGenerator
    });

    // Gleam Templates
    this.register({
      name: 'gleam-wisp',
      language: 'Gleam',
      framework: 'Wisp',
      description: 'Modern web framework for Gleam with type-safe routing and middleware',
      features: [
        'Type-safe functional programming',
        'Runs on BEAM (Erlang VM)',
        'Actor model concurrency',
        'Pattern matching routing',
        'Middleware pipeline',
        'JWT authentication',
        'CORS support',
        'Session management',
        'WebSocket support',
        'Hot code reloading'
      ],
      defaultPort: 8080,
      generator: WispGenerator
    });

    this.register({
      name: 'gleam-mist',
      language: 'Gleam',
      framework: 'Mist',
      description: 'Low-level HTTP server for Gleam with WebSocket and high performance',
      features: [
        'Low-level HTTP handling',
        'WebSocket support',
        'HTTP/2 support',
        'TLS/SSL support',
        'Streaming responses',
        'Binary protocol support',
        'High performance',
        'Connection pooling',
        'Graceful shutdown',
        'Custom request handling'
      ],
      defaultPort: 8080,
      generator: MistGenerator
    });

    // PHP Templates
    this.register({
      name: 'php-laravel',
      language: 'PHP',
      framework: 'Laravel',
      description: 'Modern PHP framework with elegant syntax and powerful features',
      features: [
        'Laravel 11 framework',
        'Eloquent ORM',
        'Artisan CLI',
        'Blade templating',
        'Laravel Sanctum auth',
        'Queue system',
        'Event-driven architecture',
        'Comprehensive testing'
      ],
      defaultPort: 8000,
      generator: LaravelGenerator
    });

    this.register({
      name: 'php-symfony',
      language: 'PHP',
      framework: 'Symfony',
      description: 'Enterprise PHP framework with reusable components',
      features: [
        'Symfony 7.0 framework',
        'Doctrine ORM',
        'Symfony Console',
        'Twig templating',
        'Security component',
        'HTTP kernel',
        'Dependency injection',
        'API Platform ready'
      ],
      defaultPort: 8000,
      generator: SymfonyGenerator
    });

    this.register({
      name: 'php-slim',
      language: 'PHP',
      framework: 'Slim',
      description: 'Fast and lightweight PHP micro framework',
      features: [
        'Slim 4 framework',
        'PSR-7 compliant',
        'Middleware support',
        'Container integration',
        'Error handling',
        'Route caching',
        'JSON responses',
        'Minimal overhead'
      ],
      defaultPort: 8080,
      generator: SlimGenerator
    });

    this.register({
      name: 'php-codeigniter',
      language: 'PHP',
      framework: 'CodeIgniter',
      description: 'Simple and elegant PHP framework with small footprint',
      features: [
        'CodeIgniter 4 framework',
        'MVC architecture',
        'Built-in ORM',
        'Simple configuration',
        'Small footprint',
        'Excellent documentation',
        'Database migrations',
        'Form validation'
      ],
      defaultPort: 8080,
      generator: CodeIgniterGenerator
    });

    // OCaml Templates
    this.register({
      name: 'ocaml-dream',
      language: 'OCaml',
      framework: 'Dream',
      description: 'Tidy, feature-complete web framework for OCaml',
      features: [
        'Type-safe routing',
        'Built-in templating',
        'Session management',
        'WebSocket support',
        'GraphQL integration',
        'HTTP/2 support',
        'TLS support',
        'Excellent performance'
      ],
      defaultPort: 8080,
      generator: DreamGenerator
    });

    this.register({
      name: 'ocaml-opium',
      language: 'OCaml',
      framework: 'Opium',
      description: 'Sinatra-like web framework for OCaml',
      features: [
        'Sinatra-inspired DSL',
        'Middleware support',
        'JSON handling',
        'Route parameters',
        'Cookie support',
        'Static file serving',
        'Error handling',
        'Lightweight core'
      ],
      defaultPort: 3000,
      generator: OpiumGenerator
    });

    this.register({
      name: 'ocaml-sihl',
      language: 'OCaml',
      framework: 'Sihl',
      description: 'Batteries-included web framework for OCaml',
      features: [
        'Full-stack framework',
        'Database migrations',
        'Job queue system',
        'Email support',
        'Configuration management',
        'Logging system',
        'Testing utilities',
        'Production ready'
      ],
      defaultPort: 8080,
      generator: SihlGenerator
    });

    // Elixir Templates
    this.register({
      name: 'elixir-phoenix',
      language: 'Elixir',
      framework: 'Phoenix',
      description: 'Productive web framework for Elixir with real-time features',
      features: [
        'Phoenix framework',
        'Ecto database toolkit',
        'LiveView for SPAs',
        'Channels for real-time',
        'PubSub system',
        'OTP supervision',
        'Hot code reloading',
        'Distributed systems'
      ],
      defaultPort: 4000,
      generator: PhoenixGenerator
    });

    this.register({
      name: 'elixir-plug',
      language: 'Elixir',
      framework: 'Plug',
      description: 'Composable web middleware for Elixir',
      features: [
        'Plug specification',
        'Middleware composition',
        'Router system',
        'Request/Response handling',
        'Connection adapter',
        'Testing support',
        'Minimal overhead',
        'Highly performant'
      ],
      defaultPort: 4000,
      generator: PlugGenerator
    });

    // ReScript Templates
    this.register({
      name: 'rescript-express',
      language: 'ReScript',
      framework: 'Express',
      description: 'Type-safe Express.js bindings for ReScript',
      features: [
        'Type-safe Express bindings',
        'ReScript compilation',
        'JavaScript interop',
        'Middleware support',
        'Route handling',
        'JSON responses',
        'Static typing',
        'Fast compilation'
      ],
      defaultPort: 3000,
      generator: ReScriptExpressGenerator
    });

    this.register({
      name: 'rescript-fastify',
      language: 'ReScript',
      framework: 'Fastify',
      description: 'High-performance ReScript web server with Fastify',
      features: [
        'Type-safe Fastify bindings',
        'High performance',
        'Plugin system',
        'Schema validation',
        'Async/await support',
        'JSON serialization',
        'Hook system',
        'Low overhead'
      ],
      defaultPort: 3000,
      generator: ReScriptFastifyGenerator
    });

    // Add more templates as they are implemented...
  }

  static register(template: BackendTemplate): void {
    this.templates.set(template.name, template);
  }

  static get(name: string): BackendTemplate | undefined {
    return this.templates.get(name);
  }

  static getAll(): BackendTemplate[] {
    return Array.from(this.templates.values());
  }

  static getByLanguage(language: string): BackendTemplate[] {
    return this.getAll().filter(t => t.language.toLowerCase() === language.toLowerCase());
  }

  static getByFramework(framework: string): BackendTemplate[] {
    return this.getAll().filter(t => t.framework.toLowerCase() === framework.toLowerCase());
  }

  static getLanguages(): string[] {
    return [...new Set(this.getAll().map(t => t.language))].sort();
  }

  static getFrameworks(language?: string): string[] {
    const templates = language ? this.getByLanguage(language) : this.getAll();
    return [...new Set(templates.map(t => t.framework))].sort();
  }

  static generateTemplate(name: string, projectPath: string, options: any): Promise<void> {
    const template = this.get(name);
    if (!template) {
      throw new Error(`Backend template '${name}' not found`);
    }

    const generator = new template.generator();
    return generator.generate(projectPath, {
      ...options,
      port: options.port || template.defaultPort,
      name: options.name || 'backend-service'
    });
  }

  static getTemplateChoices(): Array<{ name: string; value: string }> {
    const choices: Array<{ name: string; value: string }> = [];
    const languages = this.getLanguages();

    for (const language of languages) {
      const templates = this.getByLanguage(language);
      
      // Add language header
      choices.push({
        name: `\\n${language.toUpperCase()} FRAMEWORKS`,
        value: ''
      });

      // Add templates for this language
      for (const template of templates) {
        const status = template.generator ? '✅' : '🚧';
        choices.push({
          name: `  ${status} ${template.framework} - ${template.description}`,
          value: template.name
        });
      }
    }

    return choices.filter(c => c.value !== ''); // Remove headers from actual choices
  }

  static async validateTemplate(name: string): Promise<boolean> {
    const template = this.get(name);
    if (!template) {
      return false;
    }

    // Check if generator class exists and can be instantiated
    try {
      new template.generator();
      return true;
    } catch {
      return false;
    }
  }

  static getTemplateInfo(name: string): string {
    const template = this.get(name);
    if (!template) {
      return `Template '${name}' not found`;
    }

    return `
${template.framework} (${template.language})
${'-'.repeat(50)}
${template.description}

Features:
${template.features.map(f => `  • ${f}`).join('\\n')}

Default Port: ${template.defaultPort}
Template ID: ${template.name}
`;
  }

  static searchTemplates(query: string): BackendTemplate[] {
    const lowerQuery = query.toLowerCase();
    return this.getAll().filter(t => 
      t.name.toLowerCase().includes(lowerQuery) ||
      t.language.toLowerCase().includes(lowerQuery) ||
      t.framework.toLowerCase().includes(lowerQuery) ||
      t.description.toLowerCase().includes(lowerQuery) ||
      t.features.some(f => f.toLowerCase().includes(lowerQuery))
    );
  }
}

// Export for CLI integration
export function listBackendTemplates(): void {
  console.log('\\n🚀 Available Backend Templates:\\n');

  const languages = BackendTemplateRegistry.getLanguages();
  
  for (const language of languages) {
    console.log(`\\n${language} Frameworks:`);
    console.log('─'.repeat(40));
    
    const templates = BackendTemplateRegistry.getByLanguage(language);
    for (const template of templates) {
      const status = template.generator ? '✅' : '🚧';
      console.log(`${status} ${template.name.padEnd(20)} - ${template.description}`);
    }
  }

  console.log('\\n✅ = Available, 🚧 = Coming Soon\\n');
}

// Template statistics
export function getTemplateStats(): {
  total: number;
  implemented: number;
  languages: number;
  byLanguage: Record<string, { total: number; implemented: number }>;
} {
  const templates = BackendTemplateRegistry.getAll();
  const languages = BackendTemplateRegistry.getLanguages();
  
  const stats = {
    total: templates.length,
    implemented: templates.filter(t => !!t.generator).length,
    languages: languages.length,
    byLanguage: {} as Record<string, { total: number; implemented: number }>
  };

  for (const language of languages) {
    const langTemplates = BackendTemplateRegistry.getByLanguage(language);
    stats.byLanguage[language] = {
      total: langTemplates.length,
      implemented: langTemplates.filter(t => !!t.generator).length
    };
  }

  return stats;
}

export default BackendTemplateRegistry;