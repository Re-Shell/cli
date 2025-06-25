# Re-Shell CLI v0.15.0

**Enterprise-Grade Microservices & Microfrontend Platform**

The most comprehensive and powerful command-line interface for building, managing, and deploying distributed microservices and microfrontend architectures. Built with enterprise-grade reliability, zero-downtime deployments, comprehensive DevOps automation, and world-class developer experience.

[![Version](https://img.shields.io/npm/v/@re-shell/cli.svg)](https://www.npmjs.com/package/@re-shell/cli)
[![License](https://img.shields.io/npm/l/@re-shell/cli.svg)](https://github.com/re-shell/cli/blob/main/LICENSE)
[![Build Status](https://img.shields.io/github/workflow/status/re-shell/cli/CI)](https://github.com/re-shell/cli/actions)
[![Coverage](https://img.shields.io/codecov/c/github/re-shell/cli)](https://codecov.io/gh/re-shell/cli)
[![Downloads](https://img.shields.io/npm/dm/@re-shell/cli.svg)](https://www.npmjs.com/package/@re-shell/cli)

## 🚀 Platform Overview

Re-Shell CLI is an enterprise-grade platform that transforms how organizations build, deploy, and manage distributed systems. It provides a unified development experience across microservices backends and microfrontend architectures, enabling teams to focus on business logic while the platform handles infrastructure complexity.

### Key Capabilities

- **🏗️ Microservices Architecture**: Enterprise-grade backend templates with multiple language support
- **🎯 Microfrontend Framework**: Advanced frontend architecture with framework-agnostic approach
- **🔄 DevOps Automation**: Complete CI/CD pipeline generation and deployment automation
- **📊 Observability**: Comprehensive monitoring, logging, and health diagnostics
- **🛡️ Security First**: Built-in security patterns, authentication, and compliance features
- **🌐 Multi-Language**: Support for Node.js, Python, Rust, Java, .NET, Go, and more
- **☁️ Cloud Native**: Kubernetes-ready with Docker, service mesh, and cloud provider integrations

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Microservices Templates](#microservices-templates)
- [Microfrontend Templates](#microfrontend-templates)
- [Core Features](#core-features)
- [Advanced Features](#advanced-features)
- [DevOps & Deployment](#devops--deployment)
- [Enterprise Features](#enterprise-features)
- [CLI Commands](#cli-commands)
- [Configuration](#configuration)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Contributing](#contributing)
- [Support](#support)

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

### Create Your First Microservice

```bash
# Initialize a new microservices workspace
re-shell init my-platform --type microservices

# Navigate to workspace
cd my-platform

# Create a Node.js microservice with Express.js
re-shell create user-service --template express-ts --port 3001

# Create a Python microservice with FastAPI
re-shell create payment-service --template fastapi --port 3002

# Create a Rust microservice with Actix
re-shell create notification-service --template actix --port 3003
```

### Create Your First Microfrontend

```bash
# Create a React microfrontend
re-shell create user-dashboard --template react-ts --port 4001 --route /dashboard

# Create a Vue.js microfrontend
re-shell create product-catalog --template vue-ts --port 4002 --route /products

# Generate the shell application
re-shell generate shell --name main-app
```

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
│                     Re-Shell Platform                          │
├─────────────────────────────────────────────────────────────────┤
│  🎯 Microfrontend Layer                                        │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │   React     │ │    Vue.js   │ │   Svelte    │              │
│  │ Dashboard   │ │  Catalog    │ │  Analytics  │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
│         │               │               │                      │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Shell Application                          │   │
│  │           (Module Federation)                           │   │
│  └─────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  🔗 API Gateway & Service Mesh                                │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  Load Balancer │ Auth │ Rate Limit │ Circuit Breaker  │   │
│  └─────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────┤
│  🏗️ Microservices Layer                                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │  Node.js    │ │   Python    │ │    Rust     │              │
│  │ User Service│ │Payment API  │ │Notification │              │
│  │ (Express)   │ │ (FastAPI)   │ │  (Actix)    │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
├─────────────────────────────────────────────────────────────────┤
│  💾 Data Layer                                                │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│  │ PostgreSQL  │ │   MongoDB   │ │    Redis    │              │
│  │   Users     │ │  Analytics  │ │   Cache     │              │
│  └─────────────┘ └─────────────┘ └─────────────┘              │
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

### Python Ecosystem ✅ **Complete in v0.15.0**

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

### Additional Languages *(Roadmap)*

- **🦀 Rust**: Actix-web, Rocket, Warp
- **☕ Java**: Spring Boot, Quarkus, Micronaut  
- **🔷 .NET**: ASP.NET Core, Minimal APIs
- **🐹 Go**: Gin, Echo, Fiber
- **💎 Ruby**: Rails API, Sinatra
- **🐘 PHP**: Laravel, Symfony

## 🎯 Microfrontend Templates

### React Ecosystem

#### React TypeScript Template
```bash
re-shell create user-dashboard --template react-ts --route /dashboard
```
**Features**: Hooks, TypeScript, Vite, Module Federation
**Use Cases**: Interactive dashboards, admin panels, user interfaces

### Vue.js Ecosystem

#### Vue TypeScript Template
```bash
re-shell create product-catalog --template vue-ts --route /products
```
**Features**: Composition API, TypeScript, Vite build
**Use Cases**: Product catalogs, content management, e-commerce

### Svelte Ecosystem

#### Svelte TypeScript Template
```bash
re-shell create analytics-widget --template svelte-ts --route /analytics
```
**Features**: Compile-time optimization, reactive programming
**Use Cases**: Performance-critical UIs, widgets, embedded components

### Angular Ecosystem *(Coming Soon)*

#### Angular Template
```bash
re-shell create enterprise-app --template angular-ts --route /enterprise
```
**Features**: Dependency injection, enterprise architecture
**Use Cases**: Large applications, complex forms, enterprise software

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

## 📚 Best Practices

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

## 📞 Support

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

---

<div align="center">

**[Website](https://re-shell.dev)** • 
**[Documentation](https://docs.re-shell.dev)** • 
**[Examples](https://examples.re-shell.dev)** • 
**[Community](https://community.re-shell.dev)**

Made with ❤️ by the Re-Shell Team

</div>