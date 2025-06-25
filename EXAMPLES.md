# Re-Shell CLI Examples

This document provides comprehensive real-world scenarios and examples for using the Re-Shell CLI to build microfrontend applications.

## Table of Contents

1. [Latest Features](#latest-features)
   - [Phase 0 Complete (v0.8.0)](#phase-0-complete-v080)
   - [Performance & Resource Management (v0.7.2)](#performance--resource-management-v072)
   - [Plugin Ecosystem (v0.7.1)](#plugin-ecosystem-v071)
   - [Real-Time Development (v0.4.0)](#real-time-development-v040)
   - [Enterprise Features (v0.3.1)](#enterprise-features-v031)
2. [Getting Started](#getting-started)
3. [Real-World Applications](#real-world-applications)
   - [E-commerce Platform](#e-commerce-platform)
   - [Banking Dashboard](#banking-dashboard)
   - [SaaS Admin Panel](#saas-admin-panel)
   - [Healthcare Portal](#healthcare-portal)
   - [Educational Platform](#educational-platform)
4. [Advanced Scenarios](#advanced-scenarios)

## Latest Features

### Python Ecosystem Complete (v0.15.0)

Complete Python backend ecosystem with comprehensive testing, type hints, and enterprise-grade templates for all major Python frameworks.

#### Python Framework Examples

```bash
# Create FastAPI microservice with async support
re-shell create user-api --template fastapi --port 8001
cd user-api

# Features included:
# - Automatic OpenAPI documentation
# - Type hints with Python 3.11+ features
# - Dependency injection system
# - WebSocket support
# - Comprehensive pytest configuration
# - Coverage reporting with 85% threshold
# - Authentication with JWT tokens

# Start development server with hot-reload
re-shell dev --hot-reload

# Run comprehensive test suite
re-shell test --coverage --async --benchmark

# Create Django REST service
re-shell create content-api --template django --port 8002
cd content-api

# Features included:
# - Django REST Framework
# - Admin interface
# - ORM with custom migrations
# - Management commands
# - Model testing with fixtures
# - DRF testing utilities

# Create Flask microservice
re-shell create auth-api --template flask --port 8003
cd auth-api

# Features included:
# - Blueprint architecture
# - SQLAlchemy integration
# - CLI commands
# - App context testing
# - Blueprint testing

# Create Tornado async service
re-shell create websocket-api --template tornado --port 8004
cd websocket-api

# Features included:
# - High-performance async
# - WebSocket support
# - Non-blocking I/O
# - AsyncHTTPTestCase testing

# Create Sanic ultra-fast API
re-shell create fast-api --template sanic --port 8005
cd fast-api

# Features included:
# - Ultra-fast async framework
# - Blueprint architecture
# - Middleware system
# - Rate limiting
# - Security testing
```

#### Python Testing Excellence

```bash
# All Python templates include comprehensive testing

# Run pytest with async support
pytest --asyncio-mode=auto

# Run with coverage reporting
pytest --cov=app --cov-report=html --cov-report=xml

# Run parallel tests for performance
pytest -n auto --dist worksteal

# Run performance benchmarks
pytest --benchmark-only --benchmark-sort=mean

# Run specific test categories
pytest -m "unit and not slow"          # Fast unit tests
pytest -m "integration or e2e"         # Integration tests
pytest -m "performance"                # Performance tests
pytest -m "security"                   # Security tests

# Framework-specific testing examples

# FastAPI testing
pytest tests/test_fastapi.py::test_async_endpoint
pytest tests/test_fastapi.py::test_websocket_connection
pytest tests/test_fastapi.py::test_dependency_injection

# Django testing
pytest tests/test_django.py::test_model_creation
pytest tests/test_django.py::test_drf_serializer
pytest tests/test_django.py::test_management_command

# Flask testing
pytest tests/test_flask.py::test_blueprint_route
pytest tests/test_flask.py::test_app_context
pytest tests/test_flask.py::test_cli_command

# Tornado testing
pytest tests/test_tornado.py::test_async_handler
pytest tests/test_tornado.py::test_websocket_handler

# Sanic testing
pytest tests/test_sanic.py::test_middleware
pytest tests/test_sanic.py::test_rate_limiting
```

#### Advanced Python Features

```bash
# Type checking with MyPy
mypy app/ --strict --show-error-codes

# Fast linting with Ruff
ruff check app/ --fix
ruff format app/

# Advanced type analysis with Pyright
pyright app/

# Hot-reload development for all frameworks
re-shell dev --hot-reload --framework fastapi
re-shell dev --hot-reload --framework django
re-shell dev --hot-reload --framework flask
re-shell dev --hot-reload --framework tornado
re-shell dev --hot-reload --framework sanic

# Generate comprehensive documentation
re-shell docs generate --python --include-types --include-tests
```

### Phase 0 Complete (v0.8.0)

Complete core infrastructure with documentation system, testing framework, and interactive learning platform.

#### Documentation System

```bash
# Generate interactive API documentation
re-shell docs generate --format interactive

# Create troubleshooting guides with auto-diagnostics
re-shell troubleshoot generate --auto-diagnose

# Generate video tutorials
re-shell tutorials create getting-started --duration 10m

# Create interactive guide
re-shell guide create --interactive --achievements
```

#### Testing Infrastructure

```bash
# Run comprehensive test suite with >95% coverage
re-shell test --coverage --threshold 95

# Cross-platform testing
re-shell test cross-platform --os windows,macos,linux

# Performance benchmarking
re-shell test benchmark --baseline previous

# Load testing for large workspaces
re-shell test load --apps 1000 --concurrent

# Error scenario testing
re-shell test errors --auto-recovery
```

#### Quality Assurance

```bash
# Code quality analysis
re-shell analyze quality --sonarqube

# Security scanning
re-shell analyze security --fix

# Performance profiling
re-shell analyze performance --optimize

# UX metrics collection
re-shell metrics collect --anonymous
```

### Performance & Resource Management (v0.7.2)

Breakthrough performance optimization achieving 85% startup improvement with enterprise-grade resource management.

#### Performance Optimization

```bash
# Fast startup - now under 35ms
re-shell --version

# Profile startup performance with detailed timing
DEBUG=true re-shell --version

# Enable performance profiling for all operations
re-shell --profile init my-project

# Benchmark CLI performance
re-shell benchmark startup --iterations 10

# Test concurrent operations performance
re-shell benchmark concurrency --workers 10

# Run memory stress test
re-shell benchmark memory --allocations 1000

# CPU stress test
re-shell benchmark cpu --duration 5000
```

#### Resource Monitoring

```bash
# Start resource monitoring
re-shell monitor start --interval 5000

# Get current resource usage
re-shell monitor status

# View resource analytics
re-shell monitor analytics --period 24h

# Generate performance report
re-shell monitor report --format json --output report.json

# Export resource data
re-shell monitor export --format csv --output resources.csv

# Clear old monitoring data
re-shell monitor cleanup --retention 168h
```

#### Memory Management

```bash
# Get memory usage statistics
re-shell memory stats

# Monitor memory trends
re-shell memory trends --samples 20

# Get optimization suggestions
re-shell memory optimize

# Force garbage collection (if available)
re-shell memory gc

# Set memory alerts
re-shell memory alerts --warning 100 --critical 200

# View memory leak detection
re-shell memory leaks --check
```

#### Load Testing

```bash
# Run CLI load test
re-shell load-test --concurrent 5 --duration 30 --ramp-up 10

# Custom operation load test
re-shell load-test custom \
  --operation "init test-project --yes" \
  --concurrent 3 \
  --duration 60

# Benchmark against baseline
re-shell benchmark compare --baseline 0.7.1 --current 0.7.2

# Generate benchmark report
re-shell benchmark report --format html --output benchmark.html
```

### Plugin Ecosystem (v0.7.1)

The most powerful addition to Re-Shell CLI - a complete plugin ecosystem with 35+ new commands for extensibility.

#### Plugin Management

```bash
# Discover available plugins
re-shell plugin discover

# Search for specific plugins
re-shell plugin search react-tools

# Install a plugin
re-shell plugin install @re-shell/react-plugin

# List installed plugins with details
re-shell plugin list --verbose

# Show plugin information
re-shell plugin info @re-shell/react-plugin

# Enable/disable plugins
re-shell plugin enable @re-shell/react-plugin
re-shell plugin disable @re-shell/react-plugin

# Update all plugins
re-shell plugin update

# Check plugin lifecycle statistics
re-shell plugin stats
```

#### Plugin Marketplace

```bash
# Search marketplace for plugins
re-shell plugin search testing --category development

# Show plugin details from marketplace
re-shell plugin show @re-shell/testing-tools

# Install from marketplace with specific version
re-shell plugin install-marketplace @re-shell/testing-tools@1.2.0

# Show plugin reviews
re-shell plugin reviews @re-shell/testing-tools

# Browse featured plugins
re-shell plugin featured

# Browse popular plugins by category
re-shell plugin popular development

# Show marketplace statistics
re-shell plugin marketplace-stats
```

#### Command Extension System

```bash
# List all registered plugin commands
re-shell plugin commands

# Show command conflicts
re-shell plugin command-conflicts

# Resolve command conflicts with priority strategy
re-shell plugin resolve-conflict my-command priority

# Show command registry statistics
re-shell plugin command-stats

# Register a test command (for plugin development)
re-shell plugin register-command my-plugin '{"name":"test","description":"Test command"}'

# Show middleware chain for command
re-shell plugin middleware-chain my-command

# Test middleware execution
re-shell plugin test-middleware validation '{"field":"value"}'
```

#### Documentation & Help

```bash
# Generate documentation for all plugin commands
re-shell plugin generate-docs --format markdown --output ./docs

# Generate HTML documentation with examples
re-shell plugin generate-docs --format html --include-examples

# Show detailed help for a command
re-shell plugin help my-command --verbose

# List all documented commands
re-shell plugin list-docs --plugin my-plugin

# Search documentation
re-shell plugin search-docs "validation rules"

# Configure help system
re-shell plugin configure-help displayMode detailed
re-shell plugin configure-help maxWidth 120
```

#### Validation & Transformation

```bash
# List available validation rules
re-shell plugin validation-rules --verbose

# List parameter transformations
re-shell plugin transformations --verbose

# Test command validation
re-shell plugin test-validation my-command '{"args":{"name":"test"},"options":{"verbose":true}}'

# Create validation schema
re-shell plugin create-schema my-command '{
  "strict": true,
  "arguments": {
    "name": {
      "rules": [
        {"type": "required", "message": "Name is required"},
        {"type": "minLength", "options": {"min": 3}}
      ]
    }
  }
}'

# Generate validation template
re-shell plugin generate-template my-command --verbose
```

#### Caching & Performance

```bash
# Show cache statistics
re-shell plugin cache-stats --verbose

# Configure cache settings
re-shell plugin configure-cache enabled true
re-shell plugin configure-cache defaultTTL 600000
re-shell plugin configure-cache strategy hybrid

# Test cache performance
re-shell plugin test-cache 100 --verbose

# Optimize cache configuration
re-shell plugin optimize-cache --force

# Clear cache selectively
re-shell plugin clear-cache --command build --force
re-shell plugin clear-cache --tags development,testing --force

# List cached commands
re-shell plugin list-cached --verbose
```

#### Plugin Security

```bash
# Scan all plugins for security issues
re-shell plugin security-scan --all

# Scan specific plugin
re-shell plugin security-scan @re-shell/my-plugin --detailed

# Check security policy compliance
re-shell plugin security-policy

# Generate comprehensive security report
re-shell plugin security-report --format json --output security-report.json

# Fix security issues automatically
re-shell plugin security-fix @re-shell/my-plugin --auto-fix
```

#### Plugin Development

```bash
# Validate plugin structure
re-shell plugin validate ./my-plugin

# Show available plugin hooks
re-shell plugin hooks @re-shell/my-plugin

# List all hook types
re-shell plugin hook-types

# Execute hook manually for testing
re-shell plugin execute-hook init '{"projectName":"test"}'

# Show example middleware code
re-shell plugin middleware-example validation
re-shell plugin middleware-example authorization

# Test middleware with sample data
re-shell plugin test-middleware cache '{"key":"test","value":"data"}'
```

#### Conflict Resolution

```bash
# Show all conflict resolution strategies
re-shell plugin conflict-strategies --verbose

# Automatically resolve conflicts
re-shell plugin auto-resolve

# Manually resolve specific conflict
re-shell plugin resolve-conflict cmd-123 namespace

# Set command priority override
re-shell plugin set-priority my-command 100

# View resolution history
re-shell plugin resolution-history --json
```

### Real-Time Development (v0.4.0)

Advanced file watching and change detection for optimal development experience.

#### Real-Time File Watching

```bash
# Start real-time file watching for development
re-shell file-watcher start --workspace frontend-app

# Watch multiple workspaces
re-shell file-watcher start --workspace frontend-app,backend-api

# Monitor with custom patterns
re-shell file-watcher start --pattern "**/*.{ts,tsx}" --ignore "**/*.test.ts"

# View file watching statistics
re-shell file-watcher stats --verbose

# Test platform-specific watching
re-shell platform-test --verbose
```

#### Intelligent Change Detection

```bash
# Scan for changes with content hashing
re-shell change-detector scan src/

# Monitor specific files
re-shell change-detector check src/components/Button.tsx

# Analyze change impact
re-shell change-impact analyze --workspace frontend-app

# View dependency impact graph
re-shell change-impact graph --format svg --output impact.svg

# Incremental build based on changes
re-shell incremental-build --workspace frontend-app --cache
```

#### Workspace State Management

```bash
# Save current workspace state
re-shell workspace-state save --name "stable-release"

# Load previous state
re-shell workspace-state load --name "stable-release"

# Compare states
re-shell workspace-state compare "stable-release" "current"

# List all saved states
re-shell workspace-state list --verbose
```

### Enterprise Features (v0.3.1)

Production-ready features for enterprise applications.

#### Advanced Configuration Management

```bash
# Global configuration with user preferences
cat ~/.re-shell/config.yaml

# Project-specific configuration inheritance
cat .re-shell/config.yaml

# Workspace definitions with dependency graphs
cat re-shell.workspaces.yaml

# Configuration migration
re-shell config-migrate upgrade --from 0.2.0 --to 0.3.0

# Configuration diffing
re-shell config-diff compare prod.yaml staging.yaml
```

#### Health Diagnostics & Analysis

```bash
# Comprehensive project health check
re-shell doctor --verbose

# Bundle size analysis
re-shell analyze bundle --workspace frontend-app

# Dependency security audit
re-shell analyze dependencies --security

# Performance profiling
re-shell analyze performance --workspace frontend-app --profile
```

#### CI/CD Integration

```bash
# Generate GitHub Actions workflow
re-shell cicd github --monorepo --docker

# Generate GitLab CI pipeline
re-shell cicd gitlab --stages "test,build,deploy"

# Generate Jenkins pipeline
re-shell cicd jenkins --parallel-builds

# Generate deployment scripts
re-shell cicd deploy --platform aws --environment production
```

## Getting Started

### Installation

```bash
# Install Re-Shell CLI globally
npm install -g @re-shell/cli

# Verify installation
re-shell --version

# Check for updates
re-shell update
```

### Quick Start

```bash
# Create a new monorepo workspace
re-shell init my-platform --monorepo

# Add microfrontends
re-shell add header --framework react --typescript
re-shell add dashboard --framework vue --typescript
re-shell add footer --framework svelte --typescript

# Install plugins for enhanced development
re-shell plugin install @re-shell/dev-tools
re-shell plugin install @re-shell/testing-suite

# Start development with hot-reload
re-shell serve --all --hot-reload
```

### Template-Based Initialization

```bash
# E-commerce platform with pre-configured structure
re-shell init my-store --template ecommerce

# Analytics dashboard with chart components
re-shell init analytics-app --template dashboard

# SaaS platform with auth, billing, and admin
re-shell init my-saas --template saas

# Clean slate for custom setups
re-shell init custom-project --template blank
```

#### Configuration Presets

```bash
# Save your configuration for reuse
re-shell init first-project --template saas --package-manager pnpm
# During setup, save as "company-standard" preset

# Reuse saved configuration
re-shell init second-project --preset company-standard
```

#### Enhanced Features

```bash
# Auto-detect package manager (pnpm, yarn, npm, bun)
re-shell init auto-project

# CI/CD friendly non-interactive mode
re-shell init ci-project --template saas --yes --skip-install

# Debug mode for troubleshooting
re-shell init debug-project --debug

# Skip dependency installation
re-shell init fast-project --skip-install

# Real-time development with file watching
re-shell file-watcher start --interactive

# Advanced change detection with caching
re-shell change-detector scan --verbose

# Configuration management with presets
re-shell init my-project --preset company-standard
```

#### Generated Tooling Suite

Every project now includes:

- **Code Quality**: ESLint, Prettier, CommitLint
- **Git Hooks**: Husky pre-commit hooks
- **Testing**: Jest with coverage thresholds
- **CI/CD**: GitHub Actions workflows
- **Docker**: Multi-stage builds with optimization
- **Documentation**: Contributing guidelines, security policies
- **Monorepo**: Turborepo configuration
- **Dependencies**: Renovate auto-updates

## Real-World Applications

### E-commerce Platform

Complete e-commerce platform with microfrontends and plugins.

```bash
# Initialize e-commerce platform
re-shell init ecommerce-platform --monorepo --yes

# Core microfrontends
re-shell add product-catalog --framework react --typescript
re-shell add shopping-cart --framework vue --typescript  
re-shell add checkout --framework react --typescript
re-shell add user-account --framework vue --typescript

# Install e-commerce plugins
re-shell plugin install @re-shell/payment-gateway
re-shell plugin install @re-shell/inventory-sync
re-shell plugin install @re-shell/analytics-tracker

# Configure plugin settings
re-shell plugin configure-cache enabled true
re-shell plugin configure-cache strategy hybrid

# Setup validation for checkout
re-shell plugin create-schema checkout-form '{
  "arguments": {
    "email": {
      "rules": [
        {"type": "required"},
        {"type": "email"}
      ]
    },
    "cardNumber": {
      "rules": [
        {"type": "required"},
        {"type": "pattern", "options": {"pattern": "^[0-9]{16}$"}}
      ]
    }
  }
}'

# Generate documentation
re-shell plugin generate-docs --format markdown --output ./docs/api
```

### Banking Dashboard

Secure banking application with advanced security features.

```bash
# Initialize with security template
re-shell init secure-banking --template @re-shell/banking-template

# Core modules
re-shell add account-overview --framework react --auth required
re-shell add transaction-history --framework react --auth required
re-shell add payment-transfer --framework vue --auth required

# Security plugins
re-shell plugin install @re-shell/auth-provider
re-shell plugin install @re-shell/encryption-suite
re-shell plugin install @re-shell/audit-logger

# Configure security
re-shell plugin security-policy --strict
re-shell plugin configure-cache encryptionEnabled true

# Setup middleware
re-shell plugin test-middleware authorization '{
  "user": {"role": "admin"},
  "resource": "transactions"
}'

# Regular security scans
re-shell plugin security-scan --all --schedule daily
```

### SaaS Admin Panel

Multi-tenant SaaS administration panel.

```bash
# Initialize SaaS platform
re-shell init saas-admin --monorepo --multi-tenant

# Admin modules
re-shell add tenant-manager --framework react --typescript
re-shell add billing-dashboard --framework vue --typescript
re-shell add analytics-viewer --framework react --typescript
re-shell add user-management --framework svelte --typescript

# SaaS plugins
re-shell plugin install @re-shell/multi-tenant
re-shell plugin install @re-shell/billing-integration
re-shell plugin install @re-shell/usage-metrics

# Configure caching for performance
re-shell plugin cache-stats
re-shell plugin optimize-cache --force

# Setup real-time monitoring
re-shell file-watcher start --workspace all
re-shell change-impact analyze --real-time
```

### Healthcare Portal

HIPAA-compliant healthcare application.

```bash
# Initialize with compliance template
re-shell init healthcare-portal --template @re-shell/hipaa-compliant

# Healthcare modules
re-shell add patient-records --framework react --encrypted
re-shell add appointment-scheduler --framework vue --encrypted
re-shell add lab-results --framework react --encrypted
re-shell add telemedicine --framework vue --webrtc

# Healthcare plugins
re-shell plugin install @re-shell/hipaa-compliance
re-shell plugin install @re-shell/medical-records
re-shell plugin install @re-shell/hl7-integration

# Compliance validation
re-shell plugin validation-rules --category healthcare
re-shell plugin security-report --compliance hipaa
```

### Educational Platform

Interactive learning management system.

```bash
# Initialize educational platform
re-shell init edu-platform --monorepo

# Learning modules
re-shell add course-catalog --framework react --typescript
re-shell add video-player --framework vue --streaming
re-shell add quiz-engine --framework svelte --interactive
re-shell add discussion-forum --framework react --realtime

# Educational plugins
re-shell plugin install @re-shell/video-streaming
re-shell plugin install @re-shell/quiz-builder
re-shell plugin install @re-shell/progress-tracker

# Configure for scalability
re-shell plugin configure-cache maxSize 5000
re-shell plugin configure-cache strategy hybrid
```

## Advanced Scenarios

### Plugin Development Workflow

```bash
# Create new plugin project
mkdir my-re-shell-plugin
cd my-re-shell-plugin

# Initialize plugin structure
re-shell plugin validate . --init

# Development cycle
re-shell plugin hooks --available
re-shell plugin middleware-example custom

# Test plugin locally
re-shell plugin validate .
re-shell plugin test-middleware my-middleware '{"test":"data"}'

# Register commands
re-shell plugin register-command my-plugin '{
  "name": "my-command",
  "description": "Custom command",
  "arguments": [
    {"name": "input", "required": true}
  ]
}'

# Generate documentation
re-shell plugin generate-template my-command
re-shell plugin generate-docs my-command --format markdown
```

### Performance Optimization

```bash
# Analyze current performance
re-shell plugin cache-stats --verbose
re-shell analyze performance --all

# Optimize caching
re-shell plugin optimize-cache --force
re-shell plugin test-cache 1000 --verbose

# Configure incremental builds
re-shell incremental-build --enable
re-shell change-impact analyze --optimize

# Monitor improvements
re-shell plugin cache-stats --compare-before
```

### Enterprise Deployment

```bash
# Prepare for production
re-shell doctor --production
re-shell analyze bundle --all --optimize

# Generate CI/CD pipelines
re-shell cicd github --monorepo --docker --k8s
re-shell cicd generate-secrets --environment production

# Security hardening
re-shell plugin security-scan --all --fix
re-shell plugin security-policy --enforce strict

# Generate deployment documentation
re-shell plugin generate-docs --all --format html --output ./deploy-docs
```

### Troubleshooting

```bash
# Debug plugin issues
re-shell plugin list --debug
re-shell plugin info @re-shell/my-plugin --verbose

# Check for conflicts
re-shell plugin command-conflicts --verbose
re-shell plugin resolution-history

# Clear caches if needed
re-shell plugin clear-cache --all --force
re-shell plugin clear-middleware-cache

# Validate configurations
re-shell validate --all --verbose
re-shell doctor --fix
```

## Best Practices

### Plugin Selection

1. **Check compatibility**: `re-shell plugin info <plugin> --compatibility`
2. **Review security**: `re-shell plugin security-scan <plugin>`
3. **Test in isolation**: `re-shell plugin validate <plugin> --sandbox`
4. **Monitor performance**: `re-shell plugin test-cache 100 --with <plugin>`

### Performance Tips

1. **Enable caching**: `re-shell plugin configure-cache enabled true`
2. **Use hybrid strategy**: `re-shell plugin configure-cache strategy hybrid`
3. **Optimize TTL**: `re-shell plugin optimize-cache --analyze`
4. **Monitor metrics**: `re-shell plugin cache-stats --watch`

### Security Guidelines

1. **Regular scans**: `re-shell plugin security-scan --all --schedule weekly`
2. **Policy enforcement**: `re-shell plugin security-policy --strict`
3. **Audit logging**: `re-shell plugin install @re-shell/audit-logger`
4. **Update regularly**: `re-shell plugin update --security-only`

## Conclusion

Re-Shell CLI with its plugin ecosystem provides unlimited extensibility for building modern microfrontend applications. The combination of core features and plugin capabilities enables teams to create sophisticated, scalable, and maintainable applications with ease.

For more information:
- Documentation: https://re-shell.dev/docs
- Plugin Registry: https://re-shell.dev/plugins
- GitHub: https://github.com/re-shell/cli
- Support: support@re-shell.dev

