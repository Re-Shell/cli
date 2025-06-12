# Re-Shell CLI v0.2.8

A powerful command-line interface for creating and managing multi-framework monorepo and microfrontend applications using the Re-Shell architecture.

## 🚀 Features

- **🎯 Multi-Framework Support**: React, Vue, Svelte with TypeScript-first approach
- **📦 Advanced Monorepo**: Workspace management with pnpm/yarn/npm/bun support and dependency graphs
- **🔧 Git Submodule Integration**: Full lifecycle management with documentation auto-generation
- **🛠️ Microfrontend Architecture**: UMD builds, standardized mount/unmount APIs, event communication
- **📱 Modern Tooling**: Vite-powered builds, ESLint strict mode, comprehensive templates
- **📊 Workspace Intelligence**: Dependency tracking, updates, visualization (text/JSON/Mermaid)
- **💬 Smart CLI**: Interactive prompts with non-interactive CI/CD mode (`--yes` flag)
- **🐳 Production Ready**: Docker multi-stage builds, GitHub Actions workflows
- **📋 Auto Documentation**: Generated READMEs, API docs, and workspace insights
- **🔄 Auto Updates**: Built-in update detection and package manager integration
- **🔐 Security First**: Automatic vulnerability scanning and security best practices
- **🎨 Template System**: Built-in templates (e-commerce, dashboard, SaaS) with smart scaffolding
- **⚙️ Configuration Management**: Preset system for saving and reusing project configurations
- **🧰 Professional Tooling**: ESLint, Prettier, Husky, CommitLint, and more out-of-the-box

## 📦 Installation

Install the CLI globally using your preferred package manager:

```bash
# Using npm
npm install -g @re-shell/cli

# Using yarn  
yarn global add @re-shell/cli

# Using pnpm
pnpm add -g @re-shell/cli
```

## 🚀 Quick Start

### 1. Initialize a New Monorepo

```bash
re-shell init my-monorepo
cd my-monorepo
```

This creates a complete monorepo with:
- **5 workspace types**: `apps/`, `packages/`, `libs/`, `tools/`, `docs/`
- **Git repository** with submodule support
- **Package manager** configuration (pnpm/yarn/npm)
- **Development tooling**: ESLint, TypeScript, Vite
- **Docker & CI/CD**: Multi-stage builds, GitHub Actions
- **VSCode workspace**: Settings, extensions, tasks

### 2. Create Your First Application

```bash
# Interactive mode (recommended)
re-shell create my-app

# Or specify options directly
re-shell create my-app --framework react-ts --type app --port 3000
```

### 3. Add More Workspaces

```bash
# Create a shared library
re-shell create ui-components --framework react-ts --type lib

# Create a Vue application  
re-shell create admin-panel --framework vue-ts --type app --port 3001

# Create a Svelte microfrontend
re-shell create dashboard --framework svelte-ts --type app --port 3002

# Create a utility package
re-shell create utils --type package
```

## 📚 Examples

For comprehensive examples including real-world scenarios, framework-specific setups, enterprise patterns, and advanced workflows, see our **[Examples Guide](EXAMPLES.md)**.

The examples cover:
- 🏪 **E-commerce Platform** - Multi-team, multi-framework setup
- 🏢 **Enterprise Dashboard** - Complex microfrontend architecture  
- 🔧 **Workspace Management** - Dependency management and visualization
- 🔗 **Git Submodules** - External dependency integration
- 🏗️ **Framework-Specific** - React, Vue, Svelte examples
- 🚀 **Development Workflows** - Local development and production builds
- 🐳 **Docker Integration** - Containerization examples
- 📊 **Monitoring** - Analytics and reporting
- 🔄 **Migration Strategies** - Legacy system modernization
- 📈 **Scaling Patterns** - Large team and enterprise setups

## 📋 Commands Reference

### Core Commands

#### `re-shell init <name>`
Initialize a new monorepo workspace.

**Arguments:**
- `name` - Name of the monorepo (required)

**Options:**
- `--package-manager <pm>` - Package manager to use (npm|yarn|pnpm|bun) [default: auto-detected]
- `--template <template>` - Template to use (blank|ecommerce|dashboard|saas) [default: blank]
- `--preset <name>` - Use saved configuration preset
- `--skip-install` - Skip dependency installation
- `--no-git` - Skip Git repository initialization
- `--no-submodules` - Skip submodule support setup
- `--force` - Overwrite existing directory
- `--debug` - Enable debug output
- `-y, --yes` - Skip interactive prompts and use defaults (ideal for CI/CD)

**Enhanced Features:**
- **🎨 Template System**: Choose from pre-built templates (e-commerce, dashboard, SaaS)
- **🔍 Auto-Detection**: Automatically detects package manager and system requirements
- **⚙️ Preset Management**: Save and reuse project configurations
- **🔐 Security Scanning**: Automatic vulnerability assessment with remediation guidance
- **🧰 Professional Tooling**: Complete setup with ESLint, Prettier, Husky, CommitLint
- **📋 Quality Gates**: Git hooks for code quality enforcement
- **🐳 Container Ready**: Docker and docker-compose configuration
- **⚡ Modern Build Tools**: Turborepo configuration for monorepo optimization
- **📚 Documentation**: Auto-generated contributing guidelines and security policies
- **🔄 Dependency Management**: Renovate configuration for automated updates
- **🧪 Testing Setup**: Jest configuration with coverage thresholds
- **💻 IDE Integration**: VS Code workspace with recommended extensions

**Examples:**
```bash
# Interactive mode with template selection
re-shell init my-project

# E-commerce template with auto-detected package manager
re-shell init ecommerce-site --template ecommerce

# Dashboard template with pnpm
re-shell init analytics-app --template dashboard --package-manager pnpm

# Use saved preset
re-shell init new-project --preset my-company-setup

# Non-interactive mode for CI/CD
re-shell init my-project --template saas --package-manager pnpm --yes

# Development mode with debug output
re-shell init test-project --debug --skip-install

# Force overwrite with specific configuration
re-shell init my-project --template ecommerce --force --yes
```

#### `re-shell update`
Check for and perform Re-Shell CLI updates.

**Features:**
- **Auto-detection**: Checks npm registry for latest version
- **Package Manager Detection**: Automatically detects npm, yarn, or pnpm
- **Interactive Updates**: Prompts for confirmation before updating
- **Actual Updates**: Performs real package updates (not just notifications)
- **Background Checks**: Non-intrusive checks on all commands (cached for 24 hours)
- **Version Comparison**: Smart semantic version comparison
- **Update Instructions**: Provides manual update commands if auto-update fails

**Auto-Update Behavior:**
- All CLI commands automatically check for updates (except `update` and `--version`)
- Updates are cached for 24 hours to avoid performance impact
- Non-interactive environments skip update prompts

**Example:**
```bash
# Check and update CLI
re-shell update

# Manual update if auto-update fails
npm install -g @re-shell/cli@latest
# or
pnpm add -g @re-shell/cli@latest
# or  
yarn global add @re-shell/cli@latest
```

#### `re-shell create <name>`
Create a new workspace (app, package, lib, or tool).

**Arguments:**
- `name` - Name of the project/workspace (required)

**Options:**
- `--framework <framework>` - Framework (react|react-ts|vue|vue-ts|svelte|svelte-ts)
- `--type <type>` - Workspace type (app|package|lib|tool) - monorepo only
- `--port <port>` - Development server port [default: 5173]
- `--route <route>` - Route path (for apps)
- `--team <team>` - Team name
- `--org <org>` - Organization name [default: re-shell]
- `--description <description>` - Project description
- `--template <template>` - Template to use (react|react-ts) [default: react-ts]
- `--package-manager <pm>` - Package manager (npm|yarn|pnpm) [default: pnpm]

**Features:**
- Auto-detects monorepo vs standalone project
- Supports 6 framework templates (React, Vue, Svelte with JS/TS variants)
- Interactive framework selection
- Generates framework-specific configurations
- Creates complete project structure
- Sets up module federation with Vite
- Configures development environment
- Includes sample components and tests

**Examples:**
```bash
# Interactive creation
re-shell create my-app

# React TypeScript app
re-shell create frontend --framework react-ts --type app --port 3000

# Vue library
re-shell create components --framework vue-ts --type lib

# Utility package
re-shell create helpers --type package
```

#### `re-shell add <name>`
Add a new microfrontend to existing project.

**Arguments:**
- `name` - Name of the microfrontend (required)

**Options:**
- `--team <team>` - Team name
- `--org <organization>` - Organization name [default: re-shell]
- `--description <description>` - Microfrontend description
- `--template <template>` - Template to use (react|react-ts) [default: react-ts]
- `--route <route>` - Route path for the microfrontend
- `--port <port>` - Dev server port [default: 5173]

**Features:**
- Creates microfrontend in apps/ directory
- Generates Vite configuration for module federation
- Sets up entry point with mount/unmount lifecycle
- Creates eventBus for inter-microfrontend communication
- Includes development HTML file for standalone testing
- Auto-generates integration documentation
- Configures build output for UMD format
- Sets up TypeScript configuration (if applicable)
- Creates ESLint configuration
- Includes sample App component

#### `re-shell remove <name>`
Remove a microfrontend from project.

**Arguments:**
- `name` - Name of the microfrontend to remove (required)

**Options:**
- `--force` - Force removal without confirmation

**Features:**
- Interactive confirmation prompt (bypassed with --force)
- Validates microfrontend existence
- Checks for references in shell application
- Warns about manual cleanup requirements
- Completely removes microfrontend directory
- Suggests files to check for references

#### `re-shell list`
List all microfrontends in current project.

**Options:**
- `--json` - Output as JSON format

**Features:**
- Displays comprehensive microfrontend information (name, version, team, route, path)
- Automatically excludes shell application
- Formatted table output (default)
- JSON output for programmatic use
- Shows count of microfrontends found
- Handles missing package.json gracefully
- Color-coded output for better readability

#### `re-shell build [name]`
Build microfrontends for deployment.

**Arguments:**
- `name` - Specific microfrontend to build (optional - builds all if omitted)

**Options:**
- `--production` - Build for production environment
- `--analyze` - Analyze bundle size

**Features:**
- Sets NODE_ENV based on production flag
- Auto-detects package manager (pnpm > yarn > npm)
- Supports bundle size analysis
- Can build individual or all microfrontends
- Executes build scripts from package.json
- Streams build output in real-time
- Handles build errors gracefully
- Shows success/failure status

#### `re-shell serve [name]`
Start development server(s).

**Arguments:**
- `name` - Specific microfrontend to serve (optional - serves all if omitted)

**Options:**
- `--port <port>` - Port to serve on [default: 3000]
- `--host <host>` - Host to serve on [default: localhost]
- `--open` - Open in browser automatically

**Features:**
- Serves individual or all applications
- Auto-detects package manager
- Keeps process running (Ctrl+C to stop)
- Streams server output in real-time
- Passes options to underlying dev server
- Shows server URL on startup
- Handles multiple concurrent servers
- Maintains interactive terminal session

### Workspace Management

#### `re-shell workspace list`
List all workspaces in the monorepo.

**Options:**
- `--json` - Output as JSON
- `--type <type>` - Filter by type (app|package|lib|tool)
- `--framework <framework>` - Filter by framework

**Features:**
- Groups workspaces by type
- Shows framework badges with colors (React: Blue, Vue: Green, Svelte: Orange, Node: Green)
- Displays version information
- Shows dependency count
- Supports filtering by multiple criteria
- Formatted table or JSON output

#### `re-shell workspace update`
Update workspace dependencies.

**Options:**
- `--workspace <name>` - Update specific workspace
- `--dependency <name>` - Update specific dependency
- `--version <version>` - Target version for dependency
- `--dev` - Update dev dependency

**Features:**
- Updates dependencies across workspaces
- Can target specific workspace
- Supports specific dependency updates
- Handles dev dependencies separately
- Auto-detects package manager
- Shows progress with spinner
- Validates workspace existence
- Updates lock files appropriately

#### `re-shell workspace graph`
Generate workspace dependency graph.

**Options:**
- `--output <file>` - Output file path
- `--format <format>` - Output format (text|json|mermaid) [default: text]

**Features:**
- Analyzes workspace interdependencies
- Multiple output formats (Text: Human-readable tree, JSON: Machine-readable data, Mermaid: Diagram syntax)
- Different node shapes by type (Apps: Rectangles, Packages: Rounded rectangles, Libraries: Hexagons, Tools: Trapezoids)
- Shows bidirectional dependencies
- Can save to file or display

### Submodule Management

#### `re-shell submodule add <url>`
Add a new Git submodule.

**Arguments:**
- `url` - Repository URL (required)

**Options:**
- `--path <path>` - Submodule path
- `--branch <branch>` - Branch to track [default: main]

**Features:**
- Interactive prompts for missing options
- Auto-generates path from repository URL
- Validates Git repository existence
- Updates submodule documentation
- Configures branch tracking
- Shows success confirmation

#### `re-shell submodule remove <path>`
Remove a Git submodule.

**Arguments:**
- `path` - Submodule path (required)

**Options:**
- `--force` - Force removal without confirmation

**Features:**
- Validates submodule existence
- Interactive confirmation prompt
- Properly deinitializes submodule
- Updates Git configuration
- Updates documentation
- Cleans up directories

#### `re-shell submodule update`
Update Git submodules.

**Options:**
- `--path <path>` - Update specific submodule

**Features:**
- Updates all or specific submodule
- Recursive update support
- Remote tracking updates
- Updates documentation after changes
- Shows update progress
- Handles update errors

#### `re-shell submodule status`
Show Git submodule status.

**Features:**
- Detailed status for each submodule (path, URL, branch, current commit, working directory status)
- Color-coded status indicators (✓ Clean (green), ⚡ Modified (yellow), ✗ Untracked (red), ↑ Ahead (blue), ↓ Behind (magenta))
- Summary statistics
- No submodules message

#### `re-shell submodule init`
Initialize Git submodules.

**Features:**
- Initializes submodules for new clones
- Runs update after initialization
- Recursive initialization
- Shows progress with spinner
- Error handling

#### `re-shell submodule manage`
Interactive submodule management.

**Features:**
- Interactive menu system
- All submodule operations in one place
- Dynamic submodule selection
- Operation confirmation
- Combines all submodule commands
- User-friendly interface

## 🏗️ Supported Frameworks

| Framework | Template Name | TypeScript | Build Tool |
|-----------|---------------|------------|------------|
| React | `react` | ❌ | Vite |
| React + TS | `react-ts` | ✅ | Vite |
| Vue 3 | `vue` | ❌ | Vite |
| Vue 3 + TS | `vue-ts` | ✅ | Vite |
| Svelte | `svelte` | ❌ | Vite |
| Svelte + TS | `svelte-ts` | ✅ | Vite |

### Framework-Specific Features

**React (JavaScript & TypeScript)**
- Vite configuration with module federation setup
- Hot module replacement
- JSX/TSX support
- Full TypeScript configuration (TS variant)
- Type definitions and strict mode support

**Vue 3 (JavaScript & TypeScript)**
- Composition API support
- Single File Components
- Vue Router ready
- Vite optimized
- TypeScript support with type-safe components (TS variant)

**Svelte (JavaScript & TypeScript)**
- SvelteKit ready
- Component compilation
- Reactive statements
- Scoped styling
- TypeScript preprocessing with type checking (TS variant)

## 📁 Project Structure

```
my-monorepo/
├── apps/                    # Applications
│   ├── frontend/           # React app
│   ├── admin/              # Vue app
│   └── dashboard/          # Svelte app
├── packages/               # Shared packages
│   ├── ui-components/      # Component library
│   └── utils/              # Utility functions
├── libs/                   # Shared libraries
│   └── core/               # Core functionality
├── tools/                  # Build tools and scripts
│   └── build-scripts/      # Custom build tools
├── docs/                   # Documentation
│   ├── README.md
│   └── SUBMODULES.md       # Submodule documentation
├── scripts/                # Helper scripts
│   └── submodule-helper.sh # Submodule management
├── .github/                # GitHub workflows
├── package.json            # Root package.json
├── pnpm-workspace.yaml     # Workspace configuration
└── .gitignore
```

## 🔧 Workspace Types

### Apps (`--type app`)
Full applications with routing, development servers, and build configurations.
- Includes development server setup
- Route configuration for microfrontends
- Production build optimization
- Hot module replacement

### Packages (`--type package`)
Shared packages that can be published to npm.
- Library build configuration
- TypeScript declarations
- Export configurations
- Version management

### Libraries (`--type lib`)
Internal shared libraries for the monorepo.
- Internal dependency management
- Shared utilities and components
- Type definitions
- Documentation

### Tools (`--type tool`)
Build tools, scripts, and development utilities.
- Custom build scripts
- Development tools
- CI/CD utilities
- Code generators

## 🔗 Git Submodule Integration

Re-Shell CLI provides comprehensive Git submodule support:

### Features
- **Easy Management**: Simple commands for adding, removing, and updating submodules
- **Status Tracking**: Visual status indicators for submodule states
- **Documentation**: Auto-generated submodule documentation
- **Helper Scripts**: Bash scripts for advanced submodule operations
- **Interactive Mode**: User-friendly submodule management interface

### Workflow
```bash
# Add a submodule
re-shell submodule add https://github.com/user/repo.git apps/external-app

# Check status
re-shell submodule status

# Update all submodules
re-shell submodule update

# Interactive management
re-shell submodule manage
```

## 📦 Package Manager Support

- **pnpm (recommended default)**
  - Workspace support
  - Efficient disk usage
  - Strict dependencies
  - Auto-detected when available

- **bun (experimental)**
  - Ultra-fast package installation
  - Built-in bundler
  - JavaScript runtime
  - Emerging ecosystem

- **yarn**
  - Workspace protocol
  - Plug'n'Play support
  - Berry compatibility
  - Mature ecosystem

- **npm**
  - Native workspaces
  - Standard registry
  - Wide compatibility
  - Always available fallback

## 🛠️ Build Tool Integration

- **Vite** as primary build tool
- Module federation configuration
- Hot module replacement
- Optimized production builds
- Code splitting support
- Asset optimization
- Environment variable handling

## 🐳 Docker Support

Generated projects include Docker configurations:

```dockerfile
# Multi-stage build for production
FROM node:18-alpine AS base
# ... (see generated Dockerfile for full configuration)
```

## 📊 Workspace Management

### Dependency Visualization
```bash
# Text-based dependency graph
re-shell workspace graph

# Mermaid diagram
re-shell workspace graph --format mermaid --output deps.mmd

# JSON export
re-shell workspace graph --format json --output deps.json
```

### Bulk Operations
```bash
# Update all workspaces
re-shell workspace update

# Update specific dependency across workspaces
re-shell workspace update --dependency react --version ^18.3.0
```

## 🎨 Template System

### Available Templates

#### Blank Template (`blank`)
- **Description**: Clean monorepo structure without pre-configured applications
- **Best for**: Custom setups, learning, and experimentation
- **Includes**: Basic workspace structure, development tooling

#### E-commerce Template (`ecommerce`)
- **Description**: Multi-team e-commerce platform setup
- **Applications**: Shell app, product catalog, checkout flow
- **Packages**: Shared UI components, cart state management
- **Best for**: Online stores, marketplace platforms
- **Technologies**: React/Vue/Svelte, state management, payment integration

#### Dashboard Template (`dashboard`)
- **Description**: Analytics and reporting platform
- **Applications**: Shell app, analytics module, user management
- **Packages**: Chart components, data processing utilities
- **Best for**: Admin panels, business intelligence, monitoring
- **Technologies**: Data visualization, user management, reporting

#### SaaS Template (`saas`)
- **Description**: Software-as-a-Service platform
- **Applications**: Shell app, authentication, billing, admin panel
- **Packages**: Auth utilities, payment integration
- **Best for**: B2B platforms, subscription services, multi-tenant apps
- **Technologies**: Authentication, billing systems, admin tools

### Template Features

- **Smart Scaffolding**: Template-specific directory structures
- **Dependency Management**: Automatic installation of template dependencies
- **Documentation**: Generated README with template-specific instructions
- **Getting Started**: Step-by-step setup guides for each template

## 🎨 Developer Experience

- **Interactive prompts** for configuration
- **Color-coded output** with chalk
- **Progress indicators** with real-time updates
- **Comprehensive error messages**
- **ASCII art banner** for branding
- **Detailed help** for each command
- **Validation and error prevention**
- **Smart defaults** for all options
- **Auto-detection** of environment and tools
- **Preset management** for team consistency

## 📄 Generated Configurations

### Project Files
- `package.json` with scripts and dependencies
- `tsconfig.json` for TypeScript projects
- `vite.config.ts/js` with module federation
- `.eslintrc.json` with comprehensive rules
- `README.md` with template-specific documentation
- `turbo.json` for monorepo optimization

### Code Quality & Standards
- `.prettierrc` and `.prettierignore` for formatting
- `.eslintrc.json` with React/TypeScript rules
- `commitlint.config.js` for conventional commits
- `.lintstagedrc.json` for pre-commit hooks
- `.husky/` directory with Git hooks

### Development Environment
- `.editorconfig` for consistent coding
- `.nvmrc` for Node version management
- `.vscode/settings.json` for IDE optimization
- `.vscode/extensions.json` with recommendations
- `.env` and `.env.example` for environment variables

### Testing & Quality
- `jest.config.js` with coverage thresholds
- Test directory structure
- Coverage configuration
- CI/CD integration

### Documentation & Governance
- `CONTRIBUTING.md` with development guidelines
- `SECURITY.md` for security policies
- `README.md` with getting started guide
- Template-specific documentation

### Build & Deploy
- `Dockerfile` with multi-stage builds
- `docker-compose.yml` for local development
- `.dockerignore` for optimized builds
- `.github/workflows/ci.yml` for CI/CD
- `renovate.json` for dependency management

## 🔄 Migration from v0.1.x

If you're upgrading from Re-Shell CLI v0.1.x:

1. **New Command Structure**: `create` command now supports multiple frameworks
2. **Monorepo Support**: Use `init` for new monorepos
3. **Workspace Types**: Specify `--type` for different workspace types
4. **Framework Selection**: Use `--framework` instead of `--template`

### Migration Example
```bash
# Old (v0.1.x)
re-shell create my-project
re-shell add my-feature --template react-ts

# New (v0.2.5)
re-shell init my-project
cd my-project
re-shell create my-feature --framework react-ts --type app
```

## What's New in v0.2.8

### 🚀 World-Class Init Command Enhancement

The init command has been completely transformed into a world-class development experience, rivaling and exceeding industry-leading CLI tools.

#### 🎨 New Template System
- **Built-in Templates**: Choose from professional templates (e-commerce, dashboard, SaaS)
- **Smart Scaffolding**: Template-specific directory structures and dependencies
- **Getting Started Guides**: Auto-generated documentation for each template

#### ⚙️ Configuration Presets
- **Save Configurations**: Save your preferred settings as named presets
- **Reuse Presets**: Use `--preset` flag to apply saved configurations
- **Team Consistency**: Share presets across team members

#### 🔍 Enhanced Auto-Detection
- **Package Manager Detection**: Automatically detects npm, yarn, pnpm, or bun
- **System Requirements**: Validates Node.js version and available tools
- **Smart Defaults**: Context-aware defaults based on your environment

#### 🔐 Security & Quality First
- **Vulnerability Scanning**: Automatic dependency vulnerability assessment
- **Security Policies**: Generated SECURITY.md and security best practices
- **Git Hooks**: Pre-commit hooks for code quality enforcement
- **Conventional Commits**: CommitLint setup for standardized commit messages

#### 🧰 Professional Tooling Suite
- **Code Quality**: ESLint, Prettier, and comprehensive rules out-of-the-box
- **Testing**: Jest configuration with coverage thresholds
- **Build Optimization**: Turborepo configuration for monorepo performance
- **CI/CD**: Enhanced GitHub Actions workflows
- **Documentation**: Auto-generated CONTRIBUTING.md and project guidelines

#### 🐳 Production-Ready Infrastructure
- **Docker**: Multi-stage builds with package manager optimization
- **Docker Compose**: Local development environment setup
- **Dependency Management**: Renovate configuration for automated updates
- **VS Code Integration**: Workspace settings and extension recommendations

#### 📊 Enhanced Package Manager Support
- **Bun Support**: Added experimental support for Bun package manager
- **Auto-Detection**: Intelligently selects the best available package manager
- **Lockfile Support**: Proper handling for all package manager lockfiles

#### 🎯 Developer Experience Improvements
- **Interactive Flows**: Enhanced prompts with better validation
- **Progress Tracking**: Real-time progress indicators for all operations
- **Debug Mode**: `--debug` flag for troubleshooting
- **Error Handling**: Comprehensive error messages with remediation steps

#### 🏗️ Infrastructure as Code
- **Renovate**: Automated dependency updates with sensible defaults
- **Quality Gates**: 80% code coverage thresholds
- **Monorepo Optimization**: Advanced Turborepo pipeline configuration
- **Multi-Stage Builds**: Optimized Docker builds for all package managers

### 📈 Comparison with Industry Leaders

The enhanced init command now matches or exceeds features found in:
- **create-next-app**: Template selection, package manager detection
- **Vue CLI**: Preset system, interactive configuration
- **Nx**: Monorepo optimization, workspace management
- **create-t3-app**: Type safety, modern tooling stack

### 🔧 Breaking Changes
- Package manager detection may select different defaults
- New configuration files are generated (can be customized)
- Template system replaces some hardcoded behaviors

### 📦 Migration Guide
Existing projects are not affected. New projects created with v0.2.8 will include all new features automatically.

## What's New in v0.2.5

### 🐛 Critical Bug Fixes
- **✅ FIXED: Terminal Output Buffering**: Completely resolved the issue where CLI commands would hang with "Creating..." text
- **✅ FIXED: Non-TTY Environment Hanging**: Resolved hanging issues in environments where `process.stdout.isTTY` is undefined
- **✅ IMPROVED: Interactive Prompts**: Fixed prompts appearing even when using `--yes/-y` flag
- **✅ ENHANCED: Progress Indication**: Spinner now properly advances through each step with real-time updates
- **✅ ADDED: Non-Interactive Mode**: New `--yes/-y` flag to skip all interactive prompts for CI/CD environments
- **✅ IMPROVED: Environment Detection**: Better detection of CI environments and non-interactive terminals

### 🚀 New Features
- **📋 Step-by-Step Progress**: Detailed progress updates for each initialization step
- **⚡ Enhanced Terminal Compatibility**: Better support for various terminal emulators and environments
- **🔧 Improved Error Handling**: More robust error handling during initialization process

### 🔧 Technical Improvements
- Enhanced output flushing mechanisms for immediate terminal feedback
- Better spinner state management and cleanup
- Improved prompts conditional logic for non-interactive mode
- More robust terminal compatibility detection
- **Auto-detection of non-TTY environments**: CLI automatically switches to non-interactive mode in environments like CI/CD, Docker containers, or terminals without TTY support
- **Force non-interactive mode**: CLI will skip all prompts when `process.stdout.isTTY` is false, preventing hanging issues

## What's New in v0.2.4

### Bug Fixes
- **✅ Fixed Terminal Output Buffering**: Resolved issue where CLI commands would hang with "Creating..." text until Enter was pressed
- **✅ Improved Spinner Behavior**: Enhanced spinner and progress indicators for better terminal compatibility
- **✅ Better Terminal Detection**: Added fallback behavior for non-interactive terminals (CI environments, etc.)
- **✅ Immediate Output Flushing**: All CLI output now appears immediately without requiring user input
- **✅ Enhanced Progress Updates**: Spinner now properly updates during each step of the initialization process

### Improvements
- Enhanced terminal experience across different environments
- Better support for various terminal emulators and shell environments
- Improved progress indication with step-by-step updates
- More robust output flushing for immediate terminal feedback

## What's New in v0.2.3

### New Features
- **Automatic Update Notifications**: CLI now checks for updates and notifies you when a new version is available
- **Update Command**: New `re-shell update` command to check for and install updates
- **Framework Option**: Added `--framework` option to `create` command for better clarity (backward compatible with `--template`)
- **Version Caching**: Update checks are cached for 24 hours to avoid excessive network requests

### Improvements
- Better command option handling and backward compatibility
- Enhanced user experience with non-intrusive update notifications

## What's New in v0.2.2

- Fixed all unused variables and imports for cleaner code
- Enhanced TypeScript strict mode compliance
- Improved error handling and code organization
- Updated dependencies and optimized performance

## What's New in v0.2.1

### Bug Fixes and Improvements
- Fixed version mismatch in package.json
- Updated documentation to match actual CLI functionality
- Removed deprecated options that were not implemented
- Improved error handling and messages
- Enhanced test coverage and reliability
- Fixed workspace detection and path resolution issues

## What's New in v0.2.0

### New Features
- **Enhanced Command Structure**: Improved command organization and help messages
- **Build Command**: New command for building microfrontends with production mode and bundle analysis
- **Serve Command**: New command for starting development servers with customizable ports and hosts
- **List Command**: New command for listing all microfrontends with JSON output support
- **Remove Command**: New command for removing microfrontends with force option
- **ASCII Banner**: Added visual branding when running CLI commands
- **Performance Optimizations**: Faster builds and more efficient resource usage

### Breaking Changes
- The `create-mf` command has been renamed to `add` for consistency
- Configuration format has been updated for better extensibility

## 📚 Integration with Shell Application

After creating a microfrontend, you can integrate it with your shell application by adding it to your shell configuration:

```javascript
// In your shell application
import { ShellProvider, MicrofrontendContainer } from '@re-shell/core';

const microfrontends = [
  {
    id: 'my-microfrontend',
    name: 'My Microfrontend',
    url: '/apps/my-microfrontend/dist/mf.umd.js',
    containerId: 'my-microfrontend-container',
    route: '/my-feature',
    team: 'My Team'
  }
  // ... other microfrontends
];
```

## 🔗 Related Packages

- **[@re-shell/core](https://github.com/Re-Shell/re-shell/tree/main/packages/core)** - Core microfrontend framework and utilities
- **[@re-shell/ui](https://github.com/Re-Shell/re-shell/tree/main/packages/ui)** - Comprehensive React component library for microfrontend applications

## 📖 Documentation

For comprehensive documentation, examples, and guides, visit:

- **[CLI Documentation](https://github.com/Re-Shell/re-shell/tree/main/packages/cli/docs)**
- **[Examples Guide](https://github.com/Re-Shell/re-shell/blob/main/packages/cli/EXAMPLES.md)**
- **[Getting Started](https://github.com/Re-Shell/re-shell/blob/main/docs/getting-started.md)**
- **[Best Practices](https://github.com/Re-Shell/re-shell/blob/main/docs/best-practices.md)**

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](https://github.com/Re-Shell/re-shell/blob/main/CONTRIBUTING.md) for details on:

- Code of Conduct
- Development setup
- Submitting pull requests
- Reporting issues

## 📄 License

MIT License - see [LICENSE](https://github.com/Re-Shell/re-shell/blob/main/LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://github.com/Re-Shell/re-shell/tree/main/packages/cli/docs)
- 🐛 [Issue Tracker](https://github.com/Re-Shell/re-shell/issues)
- 💬 [Discussions](https://github.com/Re-Shell/re-shell/discussions)
- 📧 [Email Support](mailto:support@re-shell.org)

---

**Re-Shell CLI v0.2.8** - Built with ❤️ for modern microfrontend development