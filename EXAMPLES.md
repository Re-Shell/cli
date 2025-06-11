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

This comprehensive example guide demonstrates the flexibility and power of Re-Shell CLI for various development scenarios, from simple applications to complex enterprise systems.
