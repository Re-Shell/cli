# Re-Shell CLI Examples

This document provides comprehensive examples of using Re-Shell CLI for various scenarios.

## 🚀 Getting Started Examples

### Example 1: E-commerce Platform

Create a multi-framework e-commerce platform with different teams using different technologies.

```bash
# Initialize the monorepo
re-shell init ecommerce-platform
cd ecommerce-platform

# Install dependencies
pnpm install

# Create the main storefront (React team)
re-shell create storefront --framework react-ts --type app --port 3000 --route /

# Create admin panel (Vue team)  
re-shell create admin --framework vue-ts --type app --port 3001 --route /admin

# Create mobile app shell (Svelte team)
re-shell create mobile --framework svelte-ts --type app --port 3002 --route /mobile

# Create shared UI components library
re-shell create ui-components --framework react-ts --type lib

# Create shared utilities
re-shell create utils --type package

# Create API client library
re-shell create api-client --framework react-ts --type lib
```

### Example 2: Enterprise Dashboard

Build an enterprise dashboard with multiple microfrontends.

```bash
# Initialize monorepo
re-shell init enterprise-dashboard
cd enterprise-dashboard

# Main shell application
re-shell create shell --framework react-ts --type app --port 3000 --route /

# Analytics dashboard
re-shell create analytics --framework vue-ts --type app --port 3001 --route /analytics

# User management
re-shell create user-management --framework react-ts --type app --port 3002 --route /users

# Reporting module
re-shell create reporting --framework svelte-ts --type app --port 3003 --route /reports

# Shared design system
re-shell create design-system --framework react-ts --type lib

# Shared state management
re-shell create state --type package
```

## 🔧 Workspace Management Examples

### Managing Dependencies

```bash
# List all workspaces
re-shell workspace list

# List only applications
re-shell workspace list --type app

# List React workspaces
re-shell workspace list --framework react-ts

# Update all workspaces
re-shell workspace update

# Update specific workspace
re-shell workspace update --workspace storefront

# Update specific dependency across all workspaces
re-shell workspace update --dependency react --version ^18.3.0

# Update dev dependency
re-shell workspace update --dependency @types/node --version ^20.0.0 --dev
```

### Dependency Visualization

```bash
# Show text-based dependency graph
re-shell workspace graph

# Generate Mermaid diagram
re-shell workspace graph --format mermaid --output dependency-graph.mmd

# Export as JSON
re-shell workspace graph --format json --output dependencies.json
```

## 🔗 Git Submodule Examples

### Adding External Dependencies

```bash
# Add a shared component library as submodule
re-shell submodule add https://github.com/company/shared-components.git libs/shared-components

# Add with specific branch
re-shell submodule add https://github.com/company/design-tokens.git libs/design-tokens --branch main

# Add to specific path
re-shell submodule add https://github.com/company/utils.git packages/external-utils --path packages/external-utils
```

### Managing Submodules

```bash
# Check submodule status
re-shell submodule status

# Update all submodules
re-shell submodule update

# Update specific submodule
re-shell submodule update --path libs/shared-components

# Remove submodule
re-shell submodule remove libs/old-components

# Interactive management
re-shell submodule manage
```

### Submodule Workflow Example

```bash
# Initial setup for new team member
git clone --recursive https://github.com/company/ecommerce-platform.git
cd ecommerce-platform

# Or if already cloned
git submodule update --init --recursive

# Working with submodules
cd libs/shared-components
git checkout feature/new-button
git pull origin feature/new-button
cd ../..

# Update parent repository to track new submodule commit
git add libs/shared-components
git commit -m "Update shared-components to latest"
```

## 🏗️ Framework-Specific Examples

### React with TypeScript

```bash
re-shell create react-app --framework react-ts --type app

# Generated structure:
# react-app/
# ├── src/
# │   ├── index.tsx          # Entry point with microfrontend setup
# │   ├── App.tsx            # Main component
# │   ├── App.css            # Styles
# │   └── eventBus.ts        # Event communication
# ├── public/
# │   └── index.html         # Development HTML
# ├── package.json           # Dependencies and scripts
# ├── vite.config.ts         # Vite configuration
# ├── tsconfig.json          # TypeScript configuration
# └── .eslintrc.js           # ESLint configuration
```

### Vue 3 with TypeScript

```bash
re-shell create vue-app --framework vue-ts --type app

# Generated structure:
# vue-app/
# ├── src/
# │   ├── main.ts            # Entry point
# │   ├── App.vue            # Main component
# │   └── eventBus.ts        # Event bus
# ├── public/
# │   └── index.html
# ├── package.json
# ├── vite.config.ts
# └── tsconfig.json
```

### Svelte with TypeScript

```bash
re-shell create svelte-app --framework svelte-ts --type app

# Generated structure:
# svelte-app/
# ├── src/
# │   ├── main.ts            # Entry point
# │   ├── App.svelte         # Main component
# │   └── eventBus.ts        # Event bus
# ├── public/
# │   └── index.html
# ├── package.json
# ├── vite.config.ts
# ├── svelte.config.js
# └── tsconfig.json
```

## 🚀 Development Workflow Examples

### Local Development

```bash
# Start all applications
pnpm run dev

# Start specific application
cd apps/storefront
pnpm run dev

# Build all applications
pnpm run build

# Run tests across all workspaces
pnpm run test

# Lint all code
pnpm run lint
```

### Production Build

```bash
# Build all workspaces
pnpm run build

# Build specific workspace
pnpm --filter storefront build

# Build with dependencies
pnpm --filter storefront... build
```

## 🐳 Docker Examples

### Development with Docker

```bash
# Build development image
docker build -t ecommerce-platform:dev .

# Run with volume mounting for development
docker run -p 3000:3000 -v $(pwd):/app ecommerce-platform:dev

# Docker Compose for multiple services
cat > docker-compose.yml << EOF
version: '3.8'
services:
  storefront:
    build: ./apps/storefront
    ports:
      - "3000:3000"
    volumes:
      - ./apps/storefront:/app
  admin:
    build: ./apps/admin
    ports:
      - "3001:3001"
    volumes:
      - ./apps/admin:/app
EOF

docker-compose up
```

## 📊 Monitoring and Analytics

### Workspace Analytics

```bash
# Get workspace statistics
re-shell workspace list --json | jq '.[] | {name: .name, type: .type, framework: .framework, deps: (.dependencies | length)}'

# Find workspaces with specific dependencies
re-shell workspace list --json | jq '.[] | select(.dependencies[] | contains("react"))'

# Generate dependency report
re-shell workspace graph --format json | jq '.edges | group_by(.from) | map({workspace: .[0].from, dependencies: length})'
```

## 🔄 Migration Examples

### Migrating Existing Projects

```bash
# Create new monorepo structure
re-shell init migrated-project
cd migrated-project

# Add existing projects as submodules
re-shell submodule add https://github.com/company/legacy-frontend.git apps/legacy-frontend
re-shell submodule add https://github.com/company/admin-panel.git apps/admin-panel

# Create new applications using modern stack
re-shell create new-frontend --framework react-ts --type app
re-shell create shared-components --framework react-ts --type lib

# Gradually migrate functionality from legacy to new applications
```

### Framework Migration

```bash
# Current Vue 2 app, migrating to Vue 3
re-shell create new-vue-app --framework vue-ts --type app --port 3001

# Keep old app running during migration
# apps/old-vue-app (Vue 2)
# apps/new-vue-app (Vue 3)

# Gradually move routes and components
# Update shell routing to point to new app
```

## 🧪 Testing Examples

### Cross-Workspace Testing

```bash
# Run tests in all workspaces
pnpm run test

# Run tests with coverage
pnpm run test -- --coverage

# Test specific workspace
pnpm --filter storefront test

# Integration testing across workspaces
pnpm --filter "storefront..." test
```

### E2E Testing Setup

```bash
# Create E2E testing workspace
re-shell create e2e-tests --type tool

# Add Playwright or Cypress
cd tools/e2e-tests
pnpm add -D @playwright/test
```

## 📈 Scaling Examples

### Large Team Organization

```bash
# Team-based workspace organization
re-shell init large-enterprise
cd large-enterprise

# Frontend team
re-shell create customer-portal --framework react-ts --type app --team frontend
re-shell create mobile-app --framework react-ts --type app --team frontend

# Backend team
re-shell create api-gateway --type package --team backend
re-shell create auth-service --type package --team backend

# Design team
re-shell create design-system --framework react-ts --type lib --team design
re-shell create icons --type package --team design

# DevOps team
re-shell create build-tools --type tool --team devops
re-shell create deployment-scripts --type tool --team devops
```

### Multi-Repository Setup

```bash
# Main monorepo
re-shell init main-platform

# Add team repositories as submodules
re-shell submodule add https://github.com/company/frontend-team.git teams/frontend
re-shell submodule add https://github.com/company/backend-team.git teams/backend
re-shell submodule add https://github.com/company/design-team.git teams/design

# Each team maintains their own Re-Shell monorepo
# Main repository orchestrates integration
```

## 🎯 Legacy Command Examples

### Using the `add` Command (Legacy)

```bash
# Navigate to existing Re-Shell project
cd my-existing-project

# Add a new microfrontend using legacy command
re-shell add user-profile --template react-ts --route /profile --port 5174

# Add with team and organization
re-shell add shopping-cart --template vue-ts --route /cart --team ecommerce --org mycompany

# Add with custom description
re-shell add notifications --template svelte-ts --route /notifications --description "Real-time notification system"
```

### Legacy Project Structure

```bash
# Traditional Re-Shell project structure (pre-monorepo)
my-project/
├── apps/
│   ├── shell/             # Main shell application
│   ├── user-profile/      # User profile microfrontend
│   ├── shopping-cart/     # Shopping cart microfrontend
│   └── notifications/     # Notifications microfrontend
├── packages/
│   └── shared/            # Shared utilities
└── package.json
```

## 🔨 Build and Serve Examples

### Building Applications

```bash
# Build all applications
re-shell build

# Build specific application
re-shell build storefront

# Production build with optimization
re-shell build storefront --production

# Build with bundle analysis
re-shell build storefront --analyze
```

### Development Server

```bash
# Serve all applications
re-shell serve

# Serve specific application
re-shell serve storefront

# Serve with custom port and host
re-shell serve storefront --port 8080 --host 0.0.0.0

# Serve and open in browser
re-shell serve storefront --open
```

### Build Pipeline Integration

```bash
# CI/CD Pipeline example
#!/bin/bash
set -e

# Install dependencies
pnpm install

# Lint all code
pnpm run lint

# Run tests
pnpm run test

# Build all applications
re-shell build --production

# Deploy to staging
./deploy.sh staging

# Run E2E tests
pnpm --filter e2e-tests test

# Deploy to production (if tests pass)
./deploy.sh production
```

## 🏃‍♂️ Quick Setup Examples

### Simple Standalone Application

```bash
# Create a simple standalone React app
re-shell create my-simple-app --framework react-ts

# Directory structure:
# my-simple-app/
# ├── src/
# ├── public/
# ├── package.json
# ├── vite.config.ts
# └── tsconfig.json

cd my-simple-app
pnpm install
pnpm run dev
```

### Microfrontend with Event Communication

```bash
# Create microfrontend with event bus setup
re-shell create communication-demo --framework react-ts --type app

# Example event bus usage in generated code:
# src/eventBus.ts - Event communication setup
# src/index.tsx - Mount/unmount lifecycle with events
```

## 📱 Mobile-First Examples

### Progressive Web App Setup

```bash
# Create PWA-ready application
re-shell create mobile-pwa --framework react-ts --type app --port 3000

# Add PWA configuration (manual step after creation)
cd apps/mobile-pwa
pnpm add -D vite-plugin-pwa
```

### Responsive Design System

```bash
# Create design system with mobile-first approach
re-shell create mobile-design-system --framework react-ts --type lib

# Structure includes:
# - Responsive components
# - Mobile breakpoints
# - Touch-friendly interactions
# - Accessibility features
```

## 🌐 Multi-Language Examples

### Internationalization Setup

```bash
# Create multi-language application
re-shell create i18n-app --framework react-ts --type app

# Add i18n libraries (manual step)
cd apps/i18n-app
pnpm add react-i18next i18next i18next-browser-languagedetector

# Create language packages
re-shell create locales --type package
```

### Multi-Region Deployment

```bash
# Create region-specific applications
re-shell create app-us --framework react-ts --type app --port 3000
re-shell create app-eu --framework react-ts --type app --port 3001
re-shell create app-asia --framework react-ts --type app --port 3002

# Shared localization package
re-shell create shared-locales --type package
```

## 🔐 Security Examples

### Authentication Microfrontend

```bash
# Create dedicated auth service
re-shell create auth-service --framework react-ts --type app --route /auth

# Create protected applications
re-shell create secure-dashboard --framework vue-ts --type app --route /dashboard
re-shell create admin-panel --framework react-ts --type app --route /admin

# Shared auth utilities
re-shell create auth-utils --type package
```

### Security Headers and Configuration

```bash
# Create security configuration package
re-shell create security-config --type package

# Example security setup in vite.config.ts:
# - Content Security Policy
# - CORS configuration
# - Authentication middleware
# - Rate limiting setup
```

## 🧩 Component Library Examples

### Design System Creation

```bash
# Create comprehensive design system
re-shell create design-system --framework react-ts --type lib

# Component categories:
re-shell create atoms --framework react-ts --type lib        # Basic components
re-shell create molecules --framework react-ts --type lib    # Composite components
re-shell create organisms --framework react-ts --type lib    # Complex components
re-shell create templates --framework react-ts --type lib    # Page templates

# Shared design tokens
re-shell create design-tokens --type package
```

### Storybook Integration

```bash
# Create documentation workspace
re-shell create storybook --type tool

# Setup Storybook (manual steps after creation)
cd tools/storybook
pnpm add -D @storybook/react @storybook/builder-vite
```

## 🚀 Performance Examples

### Micro-optimization Setup

```bash
# Create performance monitoring
re-shell create performance-monitor --type package

# Create lazy-loaded modules
re-shell create lazy-dashboard --framework react-ts --type app
re-shell create lazy-reports --framework vue-ts --type app

# Bundle analysis tools
re-shell create bundle-analyzer --type tool
```

### CDN and Caching Strategy

```bash
# Create CDN-optimized applications
re-shell create cdn-optimized-app --framework react-ts --type app

# Asset optimization workspace
re-shell create asset-optimizer --type tool

# Edge function workspace
re-shell create edge-functions --type package
```

## 🔍 Debugging Examples

### Development Tools Setup

```bash
# Create debugging utilities
re-shell create dev-tools --type tool

# Error tracking and logging
re-shell create error-tracking --type package

# Development dashboard
re-shell create dev-dashboard --framework react-ts --type app --port 9000
```

### Troubleshooting Common Issues

```bash
# Check workspace health
re-shell workspace list --json | jq '.[] | select(.hasErrors == true)'

# Verify submodule integrity
re-shell submodule status

# Dependency conflict resolution
re-shell workspace graph --format json | jq '.conflicts'

# Build diagnostics
re-shell build --analyze > build-report.txt
```

## 📦 Package Management Examples

### Publishing Workflow

```bash
# Create publishable packages
re-shell create ui-kit --framework react-ts --type package
re-shell create utilities --type package
re-shell create hooks --framework react-ts --type package

# Setup publishing workflow
# packages/ui-kit/package.json:
# {
#   "name": "@myorg/ui-kit",
#   "version": "1.0.0",
#   "main": "dist/index.js",
#   "types": "dist/index.d.ts",
#   "files": ["dist"],
#   "publishConfig": {
#     "access": "public"
#   }
# }
```

### Version Management

```bash
# Workspace version synchronization
pnpm changeset init
pnpm changeset
pnpm changeset version
pnpm changeset publish

# Automated versioning with CLI
re-shell workspace update --version patch
```

## 🌟 Advanced Integration Examples

### Third-Party Service Integration

```bash
# Analytics integration
re-shell create analytics-service --type package

# Payment processing
re-shell create payment-gateway --type package

# Real-time features
re-shell create websocket-service --type package

# External API clients
re-shell create api-clients --type package
```

### Micro-service Architecture

```bash
# API Gateway
re-shell create api-gateway --type app --framework react-ts

# Service discovery
re-shell create service-registry --type package

# Load balancer configuration
re-shell create load-balancer-config --type tool

# Health check monitoring
re-shell create health-monitor --type package
```

## 🎓 Learning and Development Examples

### Tutorial Projects

```bash
# Beginner tutorial
re-shell init tutorial-basics
cd tutorial-basics
re-shell create hello-world --framework react --type app

# Intermediate tutorial
re-shell init tutorial-intermediate
cd tutorial-intermediate
re-shell create todo-app --framework vue-ts --type app
re-shell create shared-api --type package

# Advanced tutorial
re-shell init tutorial-advanced
cd tutorial-advanced
re-shell create complex-dashboard --framework react-ts --type app
re-shell create data-processing --type package
re-shell create worker-service --type tool
```

### Prototype Development

```bash
# Rapid prototyping setup
re-shell init prototype-2024
cd prototype-2024

# Quick feature exploration
re-shell create feature-a --framework react-ts --type app --port 3000
re-shell create feature-b --framework vue-ts --type app --port 3001
re-shell create shared-proto-utils --type package
```

This comprehensive example guide demonstrates the flexibility and power of Re-Shell CLI for various development scenarios, from simple applications to complex enterprise systems, covering modern development practices, performance optimization, security considerations, and advanced architectural patterns.
