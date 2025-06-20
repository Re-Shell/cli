# Re-Shell CLI Examples

This document provides comprehensive real-world scenarios and examples for using the Re-Shell CLI to build microfrontend applications.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Plugin Ecosystem (v0.7.1)](#plugin-ecosystem-v071)
3. [Enterprise Features (v0.3.1)](#enterprise-features-v031)
4. [E-commerce Platform](#e-commerce-platform)
5. [Banking Dashboard](#banking-dashboard)
6. [SaaS Admin Panel](#saas-admin-panel)
7. [Healthcare Portal](#healthcare-portal)
8. [Educational Platform](#educational-platform)
9. [Advanced Scenarios](#advanced-scenarios)

## Getting Started

### Basic Setup

```bash
# Install Re-Shell CLI globally
npm install -g @re-shell/cli

# Verify installation
re-shell --version
```

### 🚀 Latest in v0.4.0: Real-Time Development Infrastructure

Re-Shell CLI v0.4.0 introduces real-time development infrastructure with intelligent file watching, content-based change detection, and advanced workspace state management, building on the enterprise-grade reliability from previous versions:

#### Real-Time File Watching & Change Detection

```bash
# Start real-time file watching for development
re-shell file-watcher start --workspace frontend-app

# Intelligent change detection with content hashing
re-shell change-detector scan src/

# Monitor specific files for changes
re-shell change-detector check src/components/Button.tsx

# View file watching statistics
re-shell file-watcher stats
```

#### Advanced Configuration Management

```bash
# Global configuration with user preferences
cat ~/.re-shell/config.yaml

# Project-specific configuration inheritance
cat .re-shell/config.yaml

# Workspace definitions with dependency graphs
cat re-shell.workspaces.yaml
```

#### Zero Terminal Hanging

```bash
# All commands now complete cleanly with timeout protection
re-shell workspace list    # No more hanging issues
re-shell submodule status  # Graceful error handling
re-shell build             # Reliable completion
```

#### Enhanced Error Handling & Recovery

```bash
# Comprehensive error recovery with helpful messages
re-shell init my-project --debug    # Enhanced debugging
re-shell workspace list --json      # Structured error output
re-shell build --analyze           # Build failure recovery
```

#### Template-Based Initialization

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

## Plugin Ecosystem (v0.7.1)

### Plugin Management

```bash
# Discover available plugins
re-shell plugin discover

# Search for specific plugins
re-shell plugin search react-tools

# Install a plugin
re-shell plugin install @re-shell/react-plugin

# List installed plugins
re-shell plugin list --verbose

# Show plugin information
re-shell plugin info @re-shell/react-plugin

# Enable/disable plugins
re-shell plugin enable @re-shell/react-plugin
re-shell plugin disable @re-shell/react-plugin

# Update all plugins
re-shell plugin update
```

### Plugin Marketplace

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
```

### Command Extension System

```bash
# List all registered plugin commands
re-shell plugin commands

# Show command conflicts
re-shell plugin command-conflicts

# Resolve command conflicts
re-shell plugin resolve-conflicts my-command priority

# Show command registry statistics
re-shell plugin command-stats

# Register a test command (for plugin development)
re-shell plugin register-command my-plugin '{"name":"test","description":"Test command"}'
```

### Documentation & Help

```bash
# Generate documentation for plugin commands
re-shell plugin generate-docs --format markdown --output ./docs

# Show detailed help for a command
re-shell plugin help my-command --verbose

# List all documented commands
re-shell plugin list-docs --plugin my-plugin

# Search documentation
re-shell plugin search-docs "validation rules"

# Show documentation templates
re-shell plugin docs-templates
```

### Validation & Transformation

```bash
# List available validation rules
re-shell plugin validation-rules --verbose

# List parameter transformations
re-shell plugin transformations --verbose

# Test command validation
re-shell plugin test-validation my-command '{"args":{"name":"test"},"options":{"verbose":true}}'

# Create validation schema
re-shell plugin create-schema my-command '{"strict":true,"arguments":{"name":{"rules":[{"type":"required"}]}}}'

# Generate validation template
re-shell plugin generate-template my-command --verbose
```

### Caching & Performance

```bash
# Show cache statistics
re-shell plugin cache-stats --verbose

# Configure cache settings
re-shell plugin configure-cache enabled true
re-shell plugin configure-cache defaultTTL 600000

# Test cache performance
re-shell plugin test-cache 100 --verbose

# Optimize cache configuration
re-shell plugin optimize-cache --force

# Clear cache
re-shell plugin clear-cache --force

# List cached commands
re-shell plugin list-cached --verbose
```

### Plugin Security

```bash
# Scan plugins for security issues
re-shell plugin security-scan --all

# Check security policy compliance
re-shell plugin security-policy

# Generate security report
re-shell plugin security-report --format json

# Fix security issues
re-shell plugin security-fix @re-shell/my-plugin
```

### Plugin Development

```bash
# Validate plugin structure
re-shell plugin validate ./my-plugin

# Show plugin hooks
re-shell plugin hooks @re-shell/my-plugin

# Execute hook manually
re-shell plugin execute-hook init '{"projectName":"test"}'

# Show middleware chain for command
re-shell plugin middleware-chain my-command

# Test middleware execution
re-shell plugin test-middleware validation '{"field":"value"}'
```

## Enterprise Features (v0.4.0)

Re-Shell CLI v0.4.0 introduces real-time development infrastructure with advanced file watching, intelligent change detection, and workspace state management, building on the comprehensive enterprise features from v0.3.1.

### 🏥 Health Diagnostics & Analysis

#### Complete Project Health Check

```bash
# Run comprehensive health check
re-shell doctor

# Example output:
# 🏥 Re-Shell Health Check Results
#
# Summary:
#   ✓ 12 checks passed
#   ⚠ 2 warnings
#   ✗ 1 errors
#
# ✓ package-json           Package.json structure is valid
# ✓ dependency-duplicates  No dependency version conflicts found
# ⚠ outdated-dependencies Found 5 outdated dependencies
# ✗ security-audit        Found 3 security vulnerabilities
```

#### Auto-Fix Common Issues

```bash
# Automatically fix issues where possible
re-shell doctor --fix --verbose

# This will:
# - Fix security vulnerabilities with npm audit fix
# - Create missing .gitignore files
# - Update outdated configurations
# - Resolve dependency conflicts
```

#### Export Health Reports for CI/CD

```bash
# Generate JSON report for automation
re-shell doctor --json > health-report.json

# Use in CI/CD pipelines
if ! re-shell doctor --json | jq -e '.checks[] | select(.status == "error")' > /dev/null; then
  echo "Health check passed!"
else
  echo "Health check failed!"
  exit 1
fi
```

### 📊 Advanced Project Analysis

#### Bundle Analysis

```bash
# Analyze all workspaces
re-shell analyze --type bundle

# Focus on specific workspace
re-shell analyze --type bundle --workspace frontend-app

# Export detailed analysis
re-shell analyze --type bundle --output bundle-report.json
```

#### Dependency Analysis

```bash
# Check for outdated dependencies and security issues
re-shell analyze --type dependencies

# Example output:
# 📦 frontend-app
#   Dependencies:
#     Total: 45
#     Outdated: 8
#     Vulnerabilities: 2 high, 1 medium
```

#### Performance Analysis

```bash
# Analyze build times and performance
re-shell analyze --type performance

# Get suggestions for optimization
re-shell analyze --type performance --verbose
```

#### Complete Analysis with Export

```bash
# Comprehensive analysis of everything
re-shell analyze --type all --output analysis.json --verbose

# This analyzes:
# - Bundle sizes and optimization opportunities
# - Dependency health and security
# - Build performance and bottlenecks
# - Security vulnerabilities and best practices
```

### 🔄 Migration & Project Management

#### Import Existing Projects

```bash
# Import a React project into your monorepo
re-shell migrate import ../my-react-app

# Import with backup (recommended)
re-shell migrate import ../legacy-project --backup

# Dry run to see what would happen
re-shell migrate import ../complex-project --dry-run --verbose
```

#### Export Projects

```bash
# Export current monorepo for deployment
re-shell migrate export ../deployment-package

# Export with specific configuration
re-shell migrate export ../backup --force
```

#### Backup and Restore

```bash
# Create timestamped backup
re-shell migrate backup

# Restore from backup
re-shell migrate restore ../backup-2024-06-13T16-30-00 ../restored-project
```

### 🤖 Code Generation

#### Generate React Components

```bash
# Generate a React component with TypeScript
re-shell generate component UserProfile --framework react --workspace ui-components

# Generate Vue component
re-shell generate component ProductCard --framework vue --workspace product-catalog

# Generate with automatic exports
re-shell generate component Button --framework react --export --verbose
```

#### Generate React Hooks

```bash
# Generate custom hook
re-shell generate hook useUserData --workspace shared-hooks

# Generated files:
# - src/hooks/useUserData.ts
# - src/hooks/useUserData.test.ts
```

#### Generate Services

```bash
# Generate API service
re-shell generate service UserService --workspace api-client

# Generated files:
# - src/services/UserService.ts
# - src/services/UserService.test.ts
```

#### Generate Test Suites

```bash
# Generate complete test suite for workspace
re-shell generate test frontend-app

# Generated files:
# - jest.config.js
# - src/setupTests.ts
# - src/test-utils/index.ts
```

#### Generate Documentation

```bash
# Generate project documentation
re-shell generate docs

# Generated files:
# - README.md (updated)
# - docs/ directory
# - API documentation
# - typedoc.json configuration
```

### 🚀 CI/CD Integration

#### GitHub Actions (Recommended)

```bash
# Generate basic GitHub Actions workflow
re-shell cicd generate --provider github

# Generate advanced workflow with matrix builds
re-shell cicd generate --provider github --template advanced

# Files generated:
# - .github/workflows/ci.yml
# - .github/workflows/security.yml
# - .github/workflows/advanced-ci.yml (if advanced)
```

#### GitLab CI

```bash
# Generate GitLab CI configuration
re-shell cicd generate --provider gitlab --template advanced

# Generated files:
# - .gitlab-ci.yml
```

#### Multiple Providers

```bash
# Generate configurations for multiple providers
re-shell cicd generate --provider github
re-shell cicd generate --provider azure
re-shell cicd generate --provider jenkins
```

#### Deployment Configuration

```bash
# Generate deployment config for staging
re-shell cicd deploy staging

# Generate production deployment
re-shell cicd deploy production

# Generated files:
# - scripts/deploy/deploy.sh
# - scripts/deploy/rollback.sh
# - Dockerfile
# - docker-compose.yml
# - docker-compose.prod.yml
```

### 🔍 Real-Time File Watching & Change Detection (🆕 v0.4.0)

#### Real-Time File Watching

```bash
# Start watching files with default configuration
re-shell file-watcher start

# Start with custom configuration
re-shell file-watcher start --workspace frontend-app --patterns "src/**/*.{ts,tsx,js,jsx}"

# Check current watching status
re-shell file-watcher status

# View detailed statistics
re-shell file-watcher stats

# Stop file watching
re-shell file-watcher stop
```

#### Change Propagation Rules

```bash
# Watch with change propagation (interactive setup)
re-shell file-watcher start --interactive

# Example propagation rule configuration:
# Source: packages/ui-components/src/**/*.tsx
# Target: apps/*/src/components
# Action: copy-and-transform
# Debounce: 500ms
```

#### Intelligent Change Detection

```bash
# Scan for file changes with content hashing
re-shell change-detector scan

# Scan specific directory
re-shell change-detector scan src/components

# Check if specific file changed
re-shell change-detector check src/components/Button.tsx

# View change detection status and cache info
re-shell change-detector status

# Get performance statistics
re-shell change-detector stats

# Real-time change monitoring
re-shell change-detector watch

# Compare file states between scans
re-shell change-detector compare

# Clear change detection cache
re-shell change-detector clear
```

#### Example Output - Change Detection

```bash
$ re-shell change-detector scan

🔍 Change Detection Results

📊 Summary:
  • Total files scanned: 1,247
  • Files changed: 8
  • Files added: 2
  • Files deleted: 1
  • Scan time: 234ms
  • Cache hit rate: 87%

📝 Changes detected:
  + src/components/NewButton.tsx
  + src/hooks/useNewFeature.ts
  ~ src/components/Header.tsx
  ~ src/utils/api.ts
  ~ package.json
  - src/components/OldComponent.tsx

💾 Cache Statistics:
  • Cached files: 1,085
  • Memory usage: 2.3 MB
  • Cache efficiency: High
```

#### Advanced Configuration Management

```bash
# View global configuration
cat ~/.re-shell/config.yaml

# Example global config:
# defaultPackageManager: pnpm
# templatePreferences:
#   react: react-ts
#   vue: vue-ts
# environments:
#   development:
#     watchMode: true
#     hotReload: true
#   production:
#     optimize: true

# Project-specific configuration with inheritance
cat .re-shell/config.yaml

# Example project config:
# extends: ~/.re-shell/config.yaml
# workspaces:
#   apps/*:
#     type: application
#     framework: auto-detect
#   packages/*:
#     type: library
#     publishable: true
```

#### Workspace State Management

```bash
# View workspace schema and validation
cat re-shell.workspaces.yaml

# Example workspace definition:
# version: "1.0"
# workspaces:
#   apps/frontend:
#     type: react-app
#     dependencies: ["packages/ui", "packages/utils"]
#     port: 3000
#   packages/ui:
#     type: react-library
#     exports: ["./src/index.ts"]
```

### 🔗 Complete Workflow Example

Here's a complete workflow using all the new features:

```bash
# 1. Initialize with health-first approach
re-shell init my-enterprise-app --template saas --yes

# 2. Health check immediately
cd my-enterprise-app
re-shell doctor --fix

# 3. Generate core components
re-shell generate component Layout --framework react --workspace ui-components --export
re-shell generate hook useAuth --workspace shared-hooks
re-shell generate service AuthService --workspace api-client

# 4. Set up CI/CD
re-shell cicd generate --provider github --template advanced

# 5. Create comprehensive analysis baseline
re-shell analyze --type all --output baseline-analysis.json

# 6. Set up deployment
re-shell cicd deploy production

# 7. Generate documentation
re-shell generate docs

# 8. Final health check and backup
re-shell doctor --json > pre-deployment-health.json
re-shell migrate backup

# 9. Your enterprise-grade monorepo is ready!
```

## E-commerce Platform

Build a complete e-commerce platform with separate microfrontends for different features.

### 1. Initialize the Project

#### Option A: Using E-commerce Template (Recommended)

```bash
# Create with built-in e-commerce template
re-shell init ecommerce-platform --template ecommerce

# Navigate to the project (dependencies already installed)
cd ecommerce-platform
```

#### Option B: Manual Setup

```bash
# Create the monorepo with auto-detected package manager
re-shell init ecommerce-platform

# Navigate to the project
cd ecommerce-platform

# Install dependencies (if --skip-install was used)
pnpm install
```

#### Option C: Using Saved Preset

```bash
# If you have a company preset saved
re-shell init ecommerce-platform --preset company-ecommerce
```

### 2. Create Product Catalog Microfrontend

```bash
# Add product catalog
re-shell add product-catalog \
  --team ProductTeam \
  --template react \
  --route /products \
  --port 5001

# Navigate and customize
cd apps/product-catalog

# Install Re-Shell packages
pnpm add @re-shell/core @re-shell/ui
```

Update `apps/product-catalog/src/App.jsx`:

```jsx
import React, { useState, useEffect } from 'react';
import { Card, Button, Badge, Grid, Input } from '@re-shell/ui';
import { eventBus } from '@re-shell/core';

function App() {
  const [products, setProducts] = useState([]);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    // Listen for cart events
    const unsubscribe = eventBus.on('cart:updated', data => {
      console.log('Cart updated:', data);
    });

    // Load products
    setProducts([
      { id: 1, name: 'Laptop', price: 999, stock: 5 },
      { id: 2, name: 'Mouse', price: 29, stock: 50 },
      { id: 3, name: 'Keyboard', price: 79, stock: 25 },
    ]);

    return () => eventBus.off(unsubscribe);
  }, []);

  const addToCart = product => {
    eventBus.emit('cart:add', {
      payload: product,
      source: 'product-catalog',
    });
  };

  const filteredProducts = products.filter(p =>
    p.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div style={{ padding: '20px' }}>
      <h1>Product Catalog</h1>

      <Input
        placeholder="Search products..."
        value={searchTerm}
        onChange={e => setSearchTerm(e.target.value)}
        style={{ marginBottom: '20px' }}
      />

      <Grid cols={3} gap={20}>
        {filteredProducts.map(product => (
          <Card key={product.id}>
            <h3>{product.name}</h3>
            <p>${product.price}</p>
            <Badge variant={product.stock > 10 ? 'success' : 'warning'}>
              Stock: {product.stock}
            </Badge>
            <Button
              onClick={() => addToCart(product)}
              variant="primary"
              fullWidth
              style={{ marginTop: '10px' }}
            >
              Add to Cart
            </Button>
          </Card>
        ))}
      </Grid>
    </div>
  );
}

export default App;
```

### 3. Create Shopping Cart Microfrontend

```bash
# Add shopping cart
re-shell add shopping-cart \
  --team CheckoutTeam \
  --template react \
  --route /cart \
  --port 5002

# Navigate and setup
cd ../shopping-cart
pnpm add @re-shell/core @re-shell/ui
```

Update `apps/shopping-cart/src/App.jsx`:

```jsx
import React, { useState, useEffect } from 'react';
import { Card, Button, Badge, Alert, List } from '@re-shell/ui';
import { eventBus } from '@re-shell/core';

function App() {
  const [cartItems, setCartItems] = useState([]);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    // Listen for add to cart events
    const unsubscribe = eventBus.on('cart:add', data => {
      const product = data.payload;
      setCartItems(prev => {
        const existing = prev.find(item => item.id === product.id);
        if (existing) {
          return prev.map(item =>
            item.id === product.id ? { ...item, quantity: item.quantity + 1 } : item
          );
        }
        return [...prev, { ...product, quantity: 1 }];
      });
    });

    return () => eventBus.off(unsubscribe);
  }, []);

  useEffect(() => {
    const newTotal = cartItems.reduce((sum, item) => sum + item.price * item.quantity, 0);
    setTotal(newTotal);

    // Emit cart updated event
    eventBus.emit('cart:updated', {
      payload: { items: cartItems, total: newTotal },
      source: 'shopping-cart',
    });
  }, [cartItems]);

  const removeItem = id => {
    setCartItems(prev => prev.filter(item => item.id !== id));
  };

  const checkout = () => {
    eventBus.emit('checkout:initiate', {
      payload: { items: cartItems, total },
      source: 'shopping-cart',
    });
  };

  return (
    <div style={{ padding: '20px' }}>
      <Card>
        <h2>Shopping Cart</h2>

        {cartItems.length === 0 ? (
          <Alert variant="info">Your cart is empty</Alert>
        ) : (
          <>
            <List>
              {cartItems.map(item => (
                <List.Item key={item.id}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <div>
                      <strong>{item.name}</strong>
                      <Badge variant="secondary" style={{ marginLeft: '10px' }}>
                        Qty: {item.quantity}
                      </Badge>
                    </div>
                    <div>
                      ${(item.price * item.quantity).toFixed(2)}
                      <Button
                        size="small"
                        variant="danger"
                        onClick={() => removeItem(item.id)}
                        style={{ marginLeft: '10px' }}
                      >
                        Remove
                      </Button>
                    </div>
                  </div>
                </List.Item>
              ))}
            </List>

            <div style={{ marginTop: '20px', textAlign: 'right' }}>
              <h3>Total: ${total.toFixed(2)}</h3>
              <Button variant="success" size="large" onClick={checkout}>
                Proceed to Checkout
              </Button>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}

export default App;
```

### 4. Create User Account Microfrontend

```bash
# Add user account
re-shell add user-account \
  --team UserTeam \
  --template react \
  --route /account \
  --port 5003
```

### 5. Build and Run

```bash
# Go back to root
cd ../..

# Build all microfrontends
re-shell build

# Run all microfrontends
re-shell serve
```

## Banking Dashboard

Create a secure banking dashboard with multiple specialized microfrontends.

### 1. Initialize Banking Project

#### Option A: Using Dashboard Template (Recommended)

```bash
# Create with built-in dashboard template optimized for analytics
re-shell init banking-dashboard --template dashboard

cd banking-dashboard
```

#### Option B: Manual Setup with Auto-Detection

```bash
# Create banking dashboard with auto-detected package manager
re-shell init banking-dashboard

cd banking-dashboard
```

#### Option C: Save Configuration as Preset

```bash
# Create with custom configuration and save as preset
re-shell init banking-dashboard --template dashboard --package-manager pnpm
# During setup, choose "Yes" when asked "Save this configuration as a preset?"
# Name it "banking-setup" for future projects
```

### 2. Create Account Overview

```bash
re-shell add account-overview \
  --team AccountTeam \
  --template react \
  --route /accounts \
  --port 6001
```

### 3. Create Transaction History

```bash
re-shell add transactions \
  --team TransactionTeam \
  --template react \
  --route /transactions \
  --port 6002
```

### 4. Create Payment Module

```bash
re-shell add payments \
  --team PaymentTeam \
  --template react \
  --route /payments \
  --port 6003
```

### 5. Implement Secure Communication

Update `apps/account-overview/src/App.jsx`:

```jsx
import React, { useState, useEffect } from 'react';
import { Card, Table, Badge, Alert, Progress } from '@re-shell/ui';
import { eventBus, performance } from '@re-shell/core';

function App() {
  const [accounts, setAccounts] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Track performance
    const perfId = performance.startMeasure('account-load');

    // Simulate secure API call
    setTimeout(() => {
      setAccounts([
        { id: 1, type: 'Checking', balance: 5420.5, status: 'active' },
        { id: 2, type: 'Savings', balance: 12500.0, status: 'active' },
        { id: 3, type: 'Credit', balance: -1250.0, limit: 5000, status: 'active' },
      ]);
      setLoading(false);

      performance.endMeasure(perfId);

      // Notify other microfrontends
      eventBus.emit('accounts:loaded', {
        payload: { count: 3 },
        namespace: 'banking',
        source: 'account-overview',
      });
    }, 1000);
  }, []);

  const initiateTransfer = accountId => {
    eventBus.emit('transfer:initiate', {
      payload: { fromAccount: accountId },
      namespace: 'banking',
      source: 'account-overview',
    });
  };

  return (
    <div style={{ padding: '20px' }}>
      <h1>Account Overview</h1>

      {loading ? (
        <Card>
          <Progress indeterminate />
          <p>Loading accounts securely...</p>
        </Card>
      ) : (
        <Table>
          <Table.Head>
            <Table.Row>
              <Table.Cell>Account Type</Table.Cell>
              <Table.Cell>Balance</Table.Cell>
              <Table.Cell>Status</Table.Cell>
              <Table.Cell>Actions</Table.Cell>
            </Table.Row>
          </Table.Head>
          <Table.Body>
            {accounts.map(account => (
              <Table.Row key={account.id}>
                <Table.Cell>{account.type}</Table.Cell>
                <Table.Cell>
                  <strong>${account.balance.toFixed(2)}</strong>
                </Table.Cell>
                <Table.Cell>
                  <Badge variant="success">{account.status}</Badge>
                </Table.Cell>
                <Table.Cell>
                  <Button size="small" onClick={() => initiateTransfer(account.id)}>
                    Transfer
                  </Button>
                </Table.Cell>
              </Table.Row>
            ))}
          </Table.Body>
        </Table>
      )}

      <Alert variant="info" style={{ marginTop: '20px' }}>
        All transactions are encrypted and secure
      </Alert>
    </div>
  );
}

export default App;
```

## SaaS Admin Panel

Build a comprehensive admin panel for a SaaS application.

### 1. Initialize Admin Panel

#### Option A: Using SaaS Template (Recommended)

```bash
# Create with built-in SaaS template including auth, billing, and admin features
re-shell init saas-admin --template saas

cd saas-admin
```

#### Option B: Manual Setup with Yarn

```bash
# Create SaaS admin with specific package manager
re-shell init saas-admin --package-manager yarn

cd saas-admin
```

#### Option C: CI/CD Optimized Setup

```bash
# Non-interactive setup for automated deployment
re-shell init saas-admin --template saas --package-manager yarn --yes --debug
```

### 2. Create Dashboard

```bash
re-shell add admin-dashboard \
  --team AdminTeam \
  --template react \
  --route /dashboard \
  --port 7001
```

### 3. Create User Management

```bash
re-shell add user-management \
  --team AdminTeam \
  --template react \
  --route /users \
  --port 7002
```

### 4. Create Analytics Module

```bash
re-shell add analytics \
  --team DataTeam \
  --template react \
  --route /analytics \
  --port 7003
```

## Healthcare Portal

Create a healthcare portal with patient and provider microfrontends.

### 1. Initialize Healthcare Project

```bash
re-shell init healthcare-portal --package-manager pnpm
cd healthcare-portal
pnpm install
```

### 2. Create Patient Portal

```bash
re-shell add patient-portal \
  --team PatientTeam \
  --template react \
  --route /patient \
  --port 8001
```

### 3. Create Provider Dashboard

```bash
re-shell add provider-dashboard \
  --team ProviderTeam \
  --template react \
  --route /provider \
  --port 8002
```

### 4. Create Appointment Scheduler

```bash
re-shell add appointments \
  --team SchedulingTeam \
  --template react \
  --route /appointments \
  --port 8003
```

## Educational Platform

Build an educational platform with courses, assessments, and progress tracking.

### 1. Initialize Education Project

```bash
re-shell init edu-platform --package-manager npm
cd edu-platform
npm install
```

### 2. Create Course Catalog

```bash
re-shell add course-catalog \
  --team ContentTeam \
  --template react \
  --route /courses \
  --port 9001
```

### 3. Create Student Dashboard

```bash
re-shell add student-dashboard \
  --team StudentTeam \
  --template react \
  --route /student \
  --port 9002
```

## Advanced Scenarios

### Cross-Framework Integration

Create microfrontends with different frameworks:

```bash
# React microfrontend
re-shell add react-mf --template react --team ReactTeam

# Vue microfrontend
re-shell add vue-mf --template vue --team VueTeam

# Svelte microfrontend
re-shell add svelte-mf --template svelte --team SvelteTeam
```

### Workspace Management

```bash
# List all workspaces
re-shell workspace list

# Show dependency graph
re-shell workspace graph

# Update dependencies in specific workspace
re-shell workspace update --workspace react-mf --dependency react --version 18.2.0

# Generate Mermaid diagram
re-shell workspace graph --format mermaid --output deps.mmd
```

### CLI Command Testing

```bash
# Test all CLI commands
re-shell --version
re-shell list
re-shell list --json
re-shell build dashboard
re-shell build
re-shell remove test-app
re-shell submodule status
```

### Performance Monitoring

```javascript
// In shell application
import { performance } from '@re-shell/core';

// Configure performance monitoring
performance.configure({
  thresholds: {
    loadTime: 3000,
    renderTime: 1000,
    mountTime: 500,
  },
  enableLogging: true,
});

// Monitor microfrontend loading
performance.on('measure:complete', data => {
  if (data.duration > data.threshold) {
    console.warn(`Performance issue: ${data.name} took ${data.duration}ms`);
  }
});
```

### Event Communication Examples

```javascript
// Product catalog communicates with shopping cart
import { eventBus } from '@re-shell/core';

// Emit events
eventBus.emit('cart:add', {
  payload: { id: 1, name: 'Product', price: 99 },
  source: 'product-catalog',
});

// Listen for events
const unsubscribe = eventBus.on('cart:updated', data => {
  console.log('Cart updated:', data.payload);
});

// Clean up
return () => eventBus.off(unsubscribe);
```

### Testing Integration

```bash
# Run tests for specific microfrontend
cd apps/product-catalog
npm test

# Integration testing across microfrontends
# Create test file: tests/integration/cross-mf.test.js
```

```javascript
import { eventBus } from '@re-shell/core';
import { render, waitFor } from '@testing-library/react';

describe('Cross-Microfrontend Communication', () => {
  it('should handle cart events between product catalog and shopping cart', async () => {
    // Emit event from product catalog
    eventBus.emit('cart:add', {
      payload: { id: 1, name: 'Test Product', price: 99 },
      source: 'product-catalog',
    });

    // Verify event received in shopping cart
    await waitFor(() => {
      const cartEvents = eventBus.getEventHistory().filter(e => e.source === 'shopping-cart');
      expect(cartEvents).toHaveLength(1);
    });
  });
});
```

## Best Practices

### 1. Consistent Naming Convention

```bash
# Use kebab-case for microfrontend names
re-shell add user-profile     # ✓ Good
re-shell add UserProfile      # ✗ Avoid
re-shell add user_profile     # ✗ Avoid
```

### 2. Team Organization

```bash
# Organize by feature teams
re-shell add checkout --team CheckoutTeam
re-shell add inventory --team InventoryTeam
re-shell add customer-support --team SupportTeam
```

### 3. Port Management

```bash
# Use consistent port ranges
# 5000-5099: Product-related microfrontends
# 5100-5199: User-related microfrontends
# 5200-5299: Admin-related microfrontends

re-shell add products --port 5001
re-shell add inventory --port 5002
re-shell add user-profile --port 5101
re-shell add user-settings --port 5102
```

### 4. Version Management

```json
// In package.json of each microfrontend
{
  "peerDependencies": {
    "@re-shell/core": "^0.3.0",
    "@re-shell/ui": "^0.2.0"
  }
}
```

### 5. Error Handling

```javascript
// Global error boundary in shell
import { ErrorBoundary } from '@re-shell/core';

function Shell() {
  return (
    <ErrorBoundary
      fallback={<ErrorFallback />}
      onError={(error, errorInfo) => {
        // Log to monitoring service
        logError({ error, errorInfo, source: 'shell' });
      }}
    >
      <MicrofrontendContainer />
    </ErrorBoundary>
  );
}
```

## Troubleshooting

### Common Issues

1. **Port conflicts**

   ```bash
   # Check if port is in use
   lsof -i :5001

   # Use different port
   re-shell add my-app --port 5555
   ```

2. **Build failures**

   ```bash
   # Clean and rebuild
   re-shell clean
   re-shell build
   ```

3. **Module resolution**

   ```bash
   # Clear node_modules and reinstall
   rm -rf node_modules
   pnpm install
   ```

4. **Event bus issues**
   ```javascript
   // Enable debug mode
   import { eventBus } from '@re-shell/core';
   eventBus.setDebugMode(true);
   ```

## Contributing

To contribute examples:

1. Fork the repository
2. Add your example to this file
3. Test all commands
4. Submit a pull request

For more information, visit [Re-Shell Documentation](https://github.com/Re-Shell/re-shell).

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
