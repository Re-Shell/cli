# Re-Shell CLI v0.19.0

**Full-Stack Development Platform - Microservices & Microfrontends United**

The most comprehensive and powerful command-line interface for building complete full-stack applications with distributed microservices and microfrontend architectures. Re-Shell unites backend and frontend development under a single CLI, providing enterprise-grade reliability, seamless integration, and exceptional developer experience.

[![Version](https://img.shields.io/npm/v/@re-shell/cli.svg)](https://www.npmjs.com/package/@re-shell/cli)
[![License](https://img.shields.io/npm/l/@re-shell/cli.svg)](https://github.com/re-shell/cli/blob/main/LICENSE)
[![Build Status](https://img.shields.io/github/workflow/status/re-shell/cli/CI)](https://github.com/re-shell/cli/actions)
[![Coverage](https://img.shields.io/codecov/c/github/re-shell/cli)](https://codecov.io/gh/re-shell/cli)
[![Downloads](https://img.shields.io/npm/dm/@re-shell/cli.svg)](https://www.npmjs.com/package/@re-shell/cli)

## 🚀 Platform Overview

Re-Shell CLI is a comprehensive full-stack development platform that revolutionizes how teams build modern distributed applications. By uniting microservices and microfrontends under a single powerful CLI, it enables developers to create, integrate, and deploy complete applications with unprecedented ease.

### Key Capabilities

- **🎯 Full-Stack Unity**: Seamless integration between frontend microfrontends and backend microservices
- **🏗️ Microservices Excellence**: Production-ready templates for .NET (ASP.NET Core Web API, Minimal API), Java (Spring Boot, Quarkus, Micronaut, Vert.x), Rust (Actix-Web, Warp, Rocket, Axum), Python (FastAPI, Django, Flask) and Node.js (Express, NestJS)
- **🎨 Microfrontend Architecture**: Module Federation with React, Vue, Svelte, and Angular support
- **🔄 Smart Code Generation**: API-first development with automatic type generation and SDK creation
- **📊 Complete Observability**: Built-in monitoring, tracing, and logging across the entire stack
- **🛡️ Enterprise Security**: JWT authentication, OAuth2, API gateways, and compliance features
- **☁️ Production Ready**: Docker orchestration, Kubernetes manifests, and cloud provider configs

### 🆕 What's New in v0.19.0

- **🔷 .NET Ecosystem Foundation**: Two enterprise-grade .NET Core templates for modern microservices
- **🏗️ ASP.NET Core Web API**: Full MVC architecture with controllers, services, comprehensive middleware
- **⚡ Minimal API**: High-performance functional endpoints with AOT compilation support
- **🔐 Enterprise Authentication**: JWT authentication with Identity framework and custom auth services
- **📊 Performance Optimization**: Output caching, rate limiting, and Redis distributed caching
- **🧪 Entity Framework Core**: Complete ORM integration with migrations and code-first approach
- **📝 Comprehensive Logging**: Serilog structured logging with console and file outputs
- **🔧 Development Excellence**: Hot reload, Docker support, and Swagger/OpenAPI documentation

## 📋 Table of Contents

- [Quick Start](#-quick-start)
- [Architecture](#-architecture)
- [Microservices Templates](#-microservices-templates)
- [Microfrontend Templates](#-microfrontend-templates)
- [Core Features](#-core-features)
- [Advanced Features](#-advanced-features)
- [DevOps & Deployment](#-devops--deployment)
- [Enterprise Features](#-enterprise-features)
- [CLI Commands Reference](#-cli-commands-reference)
- [Configuration](#-configuration)
- [Examples](#-examples)
- [Best Practices](#-best-practices)
- [Contributing](#-contributing)
- [Support](#-support)

## 🚀 Quick Start

### Installation

```bash
# Install globally using npm
npm install -g @re-shell/cli

# Using yarn
yarn global add @re-shell/cli

# Using pnpm
pnpm add -g @re-shell/cli

# Verify installation
re-shell --version
```

### Create Your First Full-Stack Application

```bash
# Initialize a new full-stack project
re-shell create my-app --type full-stack
cd my-app

# Frontend: Add microfrontends
re-shell add dashboard --framework react-ts --port 5173
re-shell add admin-panel --framework vue-ts --port 5174

# Backend: Add microservices
re-shell generate backend api-service --language python --framework fastapi --port 8001
re-shell generate backend auth-service --framework express --port 8002

# Start everything with Docker orchestration
docker-compose up

# Or start individually for development
re-shell dev --all
```

### How Re-Shell Works

#### 1. **Project Structure**
Re-Shell creates a monorepo structure optimized for full-stack development:

```
my-app/
├── apps/                  # Microfrontend applications
│   ├── dashboard/         # React dashboard
│   └── admin-panel/       # Vue.js admin panel
├── services/              # Backend microservices
│   ├── api-service/       # Python FastAPI service
│   └── auth-service/      # Node.js Express service
├── packages/              # Shared libraries
│   ├── ui/                # Shared UI components
│   ├── types/             # Shared TypeScript types
│   └── sdk/               # Auto-generated API SDKs
├── docker-compose.yml     # Local development orchestration
└── re-shell.config.yaml   # Project configuration
```

#### 2. **Microfrontend Generation**
When you run `re-shell add dashboard --framework react-ts`, the CLI:

- Creates a complete React application with TypeScript
- Configures Module Federation for runtime integration
- Sets up a development server with hot reload
- Implements microfrontend patterns (mount/unmount, event bus)
- Generates production-ready build configurations
- Includes Docker support for containerization

#### 3. **Microservice Generation**
When you run `re-shell generate backend api-service --language python --framework fastapi`, the CLI:

- Creates a complete FastAPI project structure
- Includes database models and migrations
- Sets up API documentation (OpenAPI/Swagger)
- Configures testing with pytest
- Implements authentication and middleware
- Generates Docker configuration
- Includes hot-reload for development

### Launch Development Environment

```bash
# Start all services in development mode
re-shell dev --all

# Start specific services
re-shell dev user-service payment-service

# View service health dashboard
re-shell doctor --interactive
```

## 🏗️ Architecture

Re-Shell CLI implements a modern distributed architecture pattern that combines microservices backends with microfrontend presentation layers, providing maximum flexibility and scalability.

```
┌─────────────────────────────────────────────────────────────────┐
│                     Re-Shell Platform                           │
├─────────────────────────────────────────────────────────────────┤
│  🎯 Microfrontend Layer                                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                │
│  │   React     │ │    Vue.js   │ │   Svelte    │                │
│  │ Dashboard   │ │  Catalog    │ │  Analytics  │                │
│  └─────────────┘ └─────────────┘ └─────────────┘                │
│         │               │               │                       │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Shell Application                          │    │
│  │           (Module Federation)                           │    │
│  └─────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│  🔗 API Gateway & Service Mesh                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Load Balancer │ Auth │ Rate Limit │ Circuit Breaker    │    │
│  └─────────────────────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────────────────┤
│  🏗️ Microservices Layer                                         │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                │
│  │  Node.js    │ │   Python    │ │    Rust     │                │
│  │ User Service│ │Payment API  │ │Notification │                │
│  │ (Express)   │ │ (FastAPI)   │ │  (Actix)    │                │
│  └─────────────┘ └─────────────┘ └─────────────┘                │
├─────────────────────────────────────────────────────────────────┤
│  💾 Data Layer                                                  │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐                │
│  │ PostgreSQL  │ │   MongoDB   │ │    Redis    │                │
│  │   Users     │ │  Analytics  │ │   Cache     │                │
│  └─────────────┘ └─────────────┘ └─────────────┘                │
└─────────────────────────────────────────────────────────────────┘
```

### Architecture Principles

- **🔌 Polyglot Persistence**: Choose the right database for each service
- **🌐 Language Agnostic**: Use the best language for each domain
- **📦 Container First**: Docker and Kubernetes native
- **🔄 Event Driven**: Asynchronous communication patterns
- **🛡️ Security by Design**: Zero-trust architecture implementation
- **📊 Observability**: Comprehensive monitoring and tracing

## 🔧 Microservices Templates

### Node.js Ecosystem

#### Express.js Template
```bash
re-shell create api-service --template express-ts
```
**Features**: Middleware composition, JWT auth, health checks, Docker ready
**Use Cases**: REST APIs, traditional web services, rapid prototyping

#### Fastify Template
```bash
re-shell create high-perf-api --template fastify-ts
```
**Features**: Schema validation, plugin architecture, high performance
**Use Cases**: High-throughput APIs, real-time services, performance-critical applications

#### NestJS Template
```bash
re-shell create enterprise-api --template nestjs-ts
```
**Features**: Dependency injection, decorators, enterprise architecture
**Use Cases**: Large-scale applications, complex business logic, team collaboration

#### Koa.js Template
```bash
re-shell create modern-api --template koa-ts
```
**Features**: Modern async/await, middleware composition, lightweight
**Use Cases**: Modern APIs, middleware-heavy applications, clean architecture

### Python Ecosystem ✅ **Complete**

#### FastAPI Template
```bash
re-shell create python-api --template fastapi
```
**Features**: Automatic OpenAPI, type hints, async support, dependency injection, WebSocket support, comprehensive testing
**Use Cases**: ML APIs, data processing, high-performance APIs, real-time services
**Testing**: pytest-asyncio, TestClient, AsyncClient, dependency overrides, WebSocket testing

#### Django Template
```bash
re-shell create web-service --template django
```
**Features**: Django REST Framework, admin interface, ORM, custom management commands, comprehensive testing
**Use Cases**: Enterprise web applications, content management, admin dashboards
**Testing**: Django test framework, DRF testing, model testing, management command testing

#### Flask Template
```bash
re-shell create lightweight-api --template flask
```
**Features**: Blueprint architecture, SQLAlchemy integration, CLI commands, comprehensive testing
**Use Cases**: Lightweight APIs, microservices, rapid prototyping
**Testing**: Flask testing client, app contexts, blueprint testing, CLI testing

#### Tornado Template
```bash
re-shell create async-service --template tornado
```
**Features**: High-performance async, WebSocket support, non-blocking I/O, comprehensive testing
**Use Cases**: Real-time applications, WebSocket services, high-concurrency systems
**Testing**: AsyncHTTPTestCase, WebSocket testing, performance testing

#### Sanic Template
```bash
re-shell create ultra-fast-api --template sanic
```
**Features**: Ultra-fast async framework, blueprint architecture, middleware system, comprehensive testing
**Use Cases**: High-performance APIs, async microservices, speed-critical applications
**Testing**: Sanic TestClient, async testing, middleware testing, rate limiting tests

### 🧪 Python Testing Excellence

All Python templates include enterprise-grade testing infrastructure:

#### Comprehensive pytest Configuration
- **pytest-asyncio**: Full async testing support with event loop management
- **pytest-cov**: 85% coverage threshold with HTML, XML, JSON reports
- **pytest-xdist**: Parallel test execution with worksteal distribution
- **pytest-benchmark**: Performance regression testing and monitoring

#### Framework-Specific Testing
- **FastAPI**: TestClient, AsyncClient, dependency injection testing, WebSocket testing
- **Django**: Model testing, DRF testing, admin testing, management command testing
- **Flask**: Blueprint testing, app context testing, CLI testing, template testing
- **Tornado**: AsyncHTTPTestCase, WebSocket testing, IOLoop testing, performance testing
- **Sanic**: Async testing, middleware testing, rate limiting testing, security testing

#### Test Utilities & Fixtures
- **Authentication**: JWT token generation, user fixtures, permission testing
- **Database**: Transaction rollback, data seeding, cleanup utilities
- **HTTP**: Status assertion, JSON validation, header checking, content validation
- **Files**: Upload testing, download testing, temporary file management
- **Performance**: Memory monitoring, execution time tracking, benchmark utilities

#### Advanced Testing Features
- **Test Markers**: unit, integration, e2e, performance, security categorization
- **Mock Services**: Redis, database, external API mocking with realistic behavior
- **Data Generation**: Factory patterns, fake data generation, random test data
- **Error Scenarios**: Exception testing, validation error testing, edge case coverage
- **Async Testing**: Wait conditions, eventual assertions, retry mechanisms

### 🎯 Modern Python Type System

All templates include comprehensive type hints with Python 3.11+ features:

#### Advanced Typing Features
- **Self**: Self-referential type annotations for method chaining
- **Literal**: Exact value type specifications for enhanced safety
- **Protocol**: Duck typing with structural subtyping
- **TypeGuard**: Runtime type checking with static analysis support
- **Generic**: Type variable support for reusable components

#### Framework-Specific Types
- **FastAPI**: Pydantic models, dependency injection types, route handler types
- **Django**: Model types, QuerySet types, admin types, form types
- **Flask**: Blueprint types, request/response types, view function types
- **Tornado**: Handler types, WebSocket types, async types
- **Sanic**: Request/response types, middleware types, blueprint types

#### Tool Configuration
- **MyPy**: Strict type checking with framework-specific overrides
- **Pyright**: Advanced type analysis with error reporting
- **Ruff**: Fast linting with type-aware rules and automatic fixes

### 🔷 .NET Ecosystem ✅ **Complete**

#### ASP.NET Core Web API Template
```bash
re-shell create enterprise-api --template aspnet-core-webapi
```
**Features**: Full MVC architecture, Identity framework, JWT authentication, Entity Framework Core, comprehensive middleware
**Use Cases**: Enterprise applications, complex business logic, team collaboration, comprehensive API development

#### ASP.NET Core Minimal API Template
```bash
re-shell create lightweight-api --template aspnet-core-minimal
```
**Features**: Functional endpoints, AOT compilation, output caching, rate limiting, high performance
**Use Cases**: High-throughput APIs, cloud-native services, performance-critical applications

### 🔷 .NET Universal Features

All .NET templates include enterprise-grade capabilities:
- **Authentication**: JWT authentication with secure password hashing
- **Database**: Entity Framework Core with code-first migrations
- **Caching**: Redis distributed caching with configurable policies
- **Logging**: Serilog structured logging with multiple sinks
- **API Documentation**: Swagger/OpenAPI with comprehensive schemas
- **Performance**: Output caching, rate limiting, and AOT compilation support
- **Development**: Hot reload with dotnet watch, comprehensive error handling
- **Containerization**: Docker support with optimized multi-stage builds

### Additional Languages *(Roadmap)*

- **🐹 Go**: Gin, Echo, Fiber
- **💎 Ruby**: Rails API, Sinatra
- **🐘 PHP**: Laravel, Symfony

## 🎯 Microfrontend Templates

Re-Shell CLI provides enterprise-grade microfrontend architecture using **Webpack Module Federation**, enabling true microfrontend patterns with dynamic loading, independent deployment, and runtime integration.

### 🏗️ **Module Federation Architecture**

```bash
# Create complete microfrontend platform
re-shell create my-platform --type microfrontend --architecture module-federation

# Generate shell application (host)
re-shell create shell-app --template federation-shell --port 3100

# Generate microfrontend applications (remotes)
re-shell create react-dashboard --template react-mf --port 3000
re-shell create vue-catalog --template vue-mf --port 3001
re-shell create svelte-analytics --template svelte-mf --port 3002
```

### ⚛️ **React Microfrontend**

```bash
re-shell create user-dashboard --template react-mf --port 3000
```
**Features**:
- React 18 with Hooks and Suspense
- Module Federation with dynamic imports
- Error boundaries for isolated failures
- Hot module replacement
- TypeScript support
- Real-time backend integration

**Architecture**:
- Exposes: `./App` component for shell consumption
- Shared: React runtime with singleton pattern
- Independent: Can run standalone or federated

### 🟢 **Vue.js Microfrontend**

```bash
re-shell create product-catalog --template vue-mf --port 3001
```
**Features**:
- Vue 3 Composition API
- Reactive state management
- Module Federation integration
- Component-based architecture
- TypeScript support
- Live data binding

**Architecture**:
- Exposes: `./App` Vue component
- Shared: Vue runtime optimization
- Independent: Standalone development capability

### 🔥 **Svelte Microfrontend**

```bash
re-shell create analytics-widget --template svelte-mf --port 3002
```
**Features**:
- Compile-time optimization
- Minimal runtime overhead
- Reactive programming model
- Module Federation support
- Performance-critical rendering

**Architecture**:
- Exposes: Compiled Svelte components
- Shared: Minimal shared dependencies
- Independent: Ultra-fast standalone execution

### 🅰️ **Angular Microfrontend** *(Enterprise Ready)*

```bash
re-shell create enterprise-app --template angular-mf --port 3003
```
**Features**:
- Angular 17+ with standalone components
- Dependency injection at microfrontend level
- Module Federation with Angular Elements
- Enterprise-grade architecture
- Comprehensive testing framework

**Architecture**:
- Exposes: Angular Elements for federation
- Shared: Angular runtime with zone isolation
- Independent: Full Angular CLI compatibility

### 🏠 **Shell Application (Host)**

The shell application orchestrates all microfrontends:

```bash
re-shell create platform-shell --template federation-shell
```

**Features**:
- **Dynamic Loading**: Load microfrontends on-demand
- **Error Boundaries**: Isolated failure handling per microfrontend
- **Unified Routing**: Seamless navigation between microfrontends
- **Service Health**: Real-time monitoring of all services
- **Loading States**: Smooth UX during microfrontend loading
- **Fallback UI**: Graceful degradation when microfrontends fail

### 🔧 **Development Experience**

```bash
# Start complete microfrontend platform
re-shell dev --microfrontends --all

# Development with hot reload
re-shell dev --mf-mode development --watch

# Production build with optimization
re-shell build --microfrontends --federation --optimize
```

**Development Features**:
- **Independent Development**: Teams work on separate microfrontends
- **Hot Module Replacement**: Live updates without page refresh
- **Cross-Framework**: Mix React, Vue, Svelte, Angular seamlessly
- **Shared Dependencies**: Optimized bundle sizes
- **Runtime Integration**: No build-time coupling

### 📊 **Best Practices Implementation**

- **🔒 Isolation**: Each microfrontend is completely independent
- **📦 Shared Dependencies**: Optimized bundle management
- **🔄 Communication**: Event-driven inter-app communication
- **🛡️ Error Handling**: Graceful degradation and fallbacks
- **🎯 Performance**: Lazy loading and code splitting
- **🧪 Testing**: Independent testing strategies per microfrontend

## 🎛️ Core Features

### 🏗️ **Project Generation**

```bash
# Create workspace
re-shell init my-platform --type hybrid

# Generate microservice
re-shell create user-service --template nestjs-ts --database postgresql

# Generate microfrontend
re-shell create user-ui --template react-ts --route /users --port 4001

# Generate full-stack feature
re-shell generate feature user-management --include backend,frontend,database
```

### 📊 **Health Diagnostics & Monitoring**

```bash
# Comprehensive health check
re-shell doctor

# Interactive dashboard
re-shell doctor --interactive

# Service-specific diagnostics
re-shell doctor user-service --detailed

# Performance analysis
re-shell analyze --performance --services all
```

### 🔄 **Development Workflow**

```bash
# Start development environment
re-shell dev --all --watch

# Hot reload with dependency tracking
re-shell dev --hot-reload --cascade-restart

# Debug mode with detailed logging
re-shell dev --debug --log-level verbose

# Test all services
re-shell test --all --coverage
```

### 🚀 **Build & Deployment**

```bash
# Build all services
re-shell build --all --optimize

# Docker containerization
re-shell build --docker --multi-stage

# Kubernetes deployment
re-shell deploy --target k8s --namespace production

# CI/CD pipeline generation
re-shell cicd generate --provider github-actions
```

## 🎨 Advanced Features

### 🔌 **Plugin Ecosystem**

```bash
# Install plugins
re-shell plugin install @re-shell/monitoring
re-shell plugin install @re-shell/security-scanner

# List available plugins
re-shell plugin marketplace

# Create custom plugin
re-shell plugin create my-custom-plugin
```

### 📈 **Bundle Analysis & Optimization**

```bash
# Analyze bundle sizes
re-shell analyze bundle --interactive

# Performance insights
re-shell analyze performance --report

# Dependency analysis
re-shell analyze deps --security-scan
```

### 🔄 **Workspace Management**

```bash
# Workspace health check
re-shell workspace doctor

# Dependency graph visualization
re-shell workspace graph --interactive

# Workspace migration
re-shell workspace migrate --from 0.8.0 --to 0.9.0
```

### 🛠️ **Code Generation**

```bash
# Generate API endpoints
re-shell generate api users --crud --auth

# Generate database migrations
re-shell generate migration add-user-roles

# Generate test suites
re-shell generate tests --coverage 90
```

## ☁️ DevOps & Deployment

### 🐳 **Container Orchestration**

```bash
# Docker Compose generation
re-shell docker compose --services all --networks custom

# Kubernetes manifests
re-shell k8s generate --helm-charts --monitoring

# Service mesh configuration
re-shell service-mesh setup --provider istio
```

### 🔄 **CI/CD Pipeline Generation**

```bash
# GitHub Actions
re-shell cicd generate --provider github-actions --deploy-to k8s

# GitLab CI
re-shell cicd generate --provider gitlab-ci --include-security-scan

# Jenkins Pipeline
re-shell cicd generate --provider jenkins --multi-stage
```

### 📊 **Monitoring & Observability**

```bash
# Prometheus & Grafana setup
re-shell monitoring setup --provider prometheus --dashboards included

# Distributed tracing
re-shell tracing setup --provider jaeger

# Log aggregation
re-shell logging setup --provider elk-stack
```

## 🏢 Enterprise Features

### 🛡️ **Security & Compliance**

- **Authentication**: OAuth2, SAML, JWT, multi-factor authentication
- **Authorization**: RBAC, ABAC, fine-grained permissions
- **Security Scanning**: Dependency vulnerabilities, code analysis
- **Compliance**: SOC2, GDPR, HIPAA ready templates

### 📊 **Analytics & Reporting**

- **Performance Metrics**: Real-time service performance monitoring
- **Business Intelligence**: Custom dashboards and reporting
- **Usage Analytics**: User behavior and system usage tracking
- **Cost Analysis**: Resource utilization and cost optimization

### 🔧 **Enterprise Integration**

- **Service Discovery**: Consul, Eureka, Kubernetes native
- **API Gateway**: Kong, Ambassador, Istio integration
- **Message Queues**: RabbitMQ, Apache Kafka, Redis Streams
- **Databases**: PostgreSQL, MongoDB, Cassandra, Redis clusters

## 📋 CLI Commands Reference

### Core Commands

| Command | Description | Example |
|---------|-------------|---------|
| `init` | Initialize workspace | `re-shell init my-platform` |
| `create` | Create service/frontend | `re-shell create api --template express-ts` |
| `dev` | Start development | `re-shell dev --all` |
| `build` | Build services | `re-shell build --optimize` |
| `test` | Run tests | `re-shell test --coverage` |
| `deploy` | Deploy to environment | `re-shell deploy --target production` |

### Advanced Commands

| Command | Description | Example |
|---------|-------------|---------|
| `doctor` | Health diagnostics | `re-shell doctor --interactive` |
| `analyze` | Bundle/performance analysis | `re-shell analyze --performance` |
| `generate` | Code generation | `re-shell generate api users` |
| `migrate` | Migration tools | `re-shell migrate --from 0.8.0` |
| `plugin` | Plugin management | `re-shell plugin install monitoring` |
| `workspace` | Workspace operations | `re-shell workspace graph` |

### DevOps Commands

| Command | Description | Example |
|---------|-------------|---------|
| `cicd` | CI/CD generation | `re-shell cicd generate --provider github` |
| `docker` | Container operations | `re-shell docker compose` |
| `k8s` | Kubernetes operations | `re-shell k8s generate --helm` |
| `monitoring` | Setup monitoring | `re-shell monitoring setup` |
| `backup` | Backup operations | `re-shell backup create --full` |

## ⚙️ Configuration

### Global Configuration

```yaml
# ~/.re-shell/config.yaml
version: "1.0"
defaults:
  packageManager: "pnpm"
  framework: "typescript"
  containerRuntime: "docker"
  kubernetesProvider: "local"
templates:
  backend:
    default: "express-ts"
    security: "strict"
  frontend:
    default: "react-ts"
    bundler: "vite"
plugins:
  autoUpdate: true
  marketplace: "https://marketplace.re-shell.dev"
```

### Project Configuration

```yaml
# .re-shell/config.yaml
name: "my-platform"
version: "0.9.0"
type: "hybrid" # microservices | microfrontend | hybrid
architecture:
  gateway: "nginx"
  serviceMesh: "istio"
  monitoring: "prometheus"
services:
  - name: "user-service"
    type: "backend"
    template: "express-ts"
    port: 3001
  - name: "user-dashboard"
    type: "frontend"
    template: "react-ts"
    port: 4001
    route: "/dashboard"
```

## 🎯 Examples

### E-Commerce Platform

```bash
# Initialize e-commerce platform
re-shell init ecommerce-platform --template ecommerce

# Backend services
re-shell create user-service --template nestjs-ts --database postgresql
re-shell create product-service --template fastapi --database mongodb
re-shell create order-service --template express-ts --database postgresql
re-shell create payment-service --template spring-boot --database postgresql

# Frontend applications
re-shell create admin-dashboard --template react-ts --route /admin
re-shell create customer-portal --template vue-ts --route /shop
re-shell create mobile-app --template react-native

# Infrastructure
re-shell cicd generate --provider github-actions
re-shell k8s generate --include monitoring,logging
```

### Financial Services Platform

```bash
# Initialize fintech platform
re-shell init fintech-platform --template financial-services

# Core services
re-shell create account-service --template spring-boot --security high
re-shell create transaction-service --template rust-actix --performance optimized
re-shell create reporting-service --template django --analytics enabled
re-shell create notification-service --template go-gin --realtime

# Compliance and security
re-shell security scan --all-services
re-shell compliance check --standard pci-dss
re-shell audit generate --quarterly-report
```

## 📊 Best Practices

### 🏗️ **Architecture Guidelines**

1. **Service Boundaries**: Define clear service boundaries based on business domains
2. **Data Consistency**: Use event sourcing for distributed data consistency
3. **API Design**: Follow REST and GraphQL best practices
4. **Security**: Implement zero-trust security model
5. **Monitoring**: Set up comprehensive observability from day one

### 🔄 **Development Workflow**

1. **Feature Development**: Use feature branches with automated testing
2. **Code Review**: Implement mandatory code reviews with automated checks
3. **Testing Strategy**: Follow testing pyramid (unit → integration → e2e)
4. **Deployment**: Use blue-green or canary deployment strategies
5. **Rollback**: Always have automated rollback capabilities

### 📊 **Performance Optimization**

1. **Caching Strategy**: Implement multi-level caching (CDN → Redis → Application)
2. **Database Design**: Use appropriate database patterns for each service
3. **Load Balancing**: Implement intelligent load balancing with health checks
4. **Resource Management**: Monitor and optimize resource utilization
5. **Scaling**: Design for horizontal scaling from the beginning

## 🤝 Contributing

We welcome contributions from the community! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/re-shell/cli.git
cd cli

# Install dependencies
pnpm install

# Build the project
pnpm build

# Run tests
pnpm test

# Start development
pnpm dev
```

### Contribution Areas

- 🔧 **Template Development**: Create new microservice/microfrontend templates
- 🐛 **Bug Fixes**: Help identify and fix issues
- 📚 **Documentation**: Improve documentation and examples
- 🎨 **Features**: Implement new CLI features and capabilities
- 🧪 **Testing**: Improve test coverage and quality
- 🌐 **Internationalization**: Add support for multiple languages

## 💬 Support

### Community Support

- **GitHub Discussions**: [https://github.com/re-shell/cli/discussions](https://github.com/re-shell/cli/discussions)
- **Discord Community**: [https://discord.gg/re-shell](https://discord.gg/re-shell)
- **Stack Overflow**: Tag questions with `re-shell-cli`

### Documentation

- **Official Documentation**: [https://docs.re-shell.dev](https://docs.re-shell.dev)
- **API Reference**: [https://api.re-shell.dev](https://api.re-shell.dev)
- **Video Tutorials**: [https://learn.re-shell.dev](https://learn.re-shell.dev)

### Enterprise Support

For enterprise support, consulting, and custom development:
- **Email**: enterprise@re-shell.dev
- **Website**: [https://enterprise.re-shell.dev](https://enterprise.re-shell.dev)

## 📄 License

MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Open Source Community**: For the amazing tools and libraries that make this possible
- **Contributors**: All the developers who have contributed to this project
- **Users**: The community of developers using Re-Shell CLI in production

## 📄 License

Re-Shell CLI is open source software released under the **MIT License**. This means you can:

- ✅ Use it commercially
- ✅ Modify it for your needs
- ✅ Distribute it freely
- ✅ Use it in private projects
- ✅ Sublicense it

See the [LICENSE](./LICENSE) file for the full license text.

---

<div align="center">

**[Website](https://re-shell.dev)** •
**[Documentation](https://docs.re-shell.dev)** •
**[Examples](https://examples.re-shell.dev)** •
**[Community](https://community.re-shell.dev)**

Made with ❤️ by the Re-Shell Team | Open Source MIT License

</div>