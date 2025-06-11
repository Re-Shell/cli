# Re-Shell CLI v0.2.0

A powerful command-line interface for creating and managing multi-framework monorepo and microfrontend applications using the Re-Shell architecture.

## 🚀 Features

- **🎯 Multi-Framework Support**: React, Vue, Angular, Svelte with TypeScript support
- **📦 Monorepo Architecture**: Built-in workspace management with pnpm/yarn/npm support  
- **🔧 Git Submodule Integration**: Advanced submodule management and documentation
- **🛠️ Microfrontend Ready**: Designed specifically for microfrontend patterns
- **📱 Modern Tooling**: Vite-powered builds, ESLint, and comprehensive templates
- **📊 Workspace Management**: Dependency tracking, updates, and visualization
- **💬 Interactive CLI**: User-friendly prompts and comprehensive help
- **🐳 Docker Support**: Ready-to-use Docker configurations
- **📋 Documentation**: Auto-generated documentation and examples

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
- Multi-framework workspace support
- Git repository initialization  
- Submodule management setup
- Development tooling configuration
- Docker support
- CI/CD workflows

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

## 📋 Commands Reference

### Core Commands

#### `re-shell init <name>`
Initialize a new monorepo workspace.

**Options:**
- `--package-manager <pm>` - Package manager (npm, yarn, pnpm)
- `--no-git` - Skip Git repository initialization
- `--no-submodules` - Skip submodule support setup
- `--force` - Overwrite existing directory

**Example:**
```bash
re-shell init my-project --package-manager pnpm
```

#### `re-shell create <name>`
Create a new workspace (app, package, lib, or tool).

**Options:**
- `--framework <framework>` - Framework (react, react-ts, vue, vue-ts, svelte, svelte-ts)
- `--type <type>` - Workspace type (app, package, lib, tool)
- `--port <port>` - Development server port (for apps)
- `--route <route>` - Route path (for apps)
- `--team <team>` - Team name
- `--org <org>` - Organization name

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

### Workspace Management

#### `re-shell workspace list`
List all workspaces in the monorepo.

**Options:**
- `--json` - Output as JSON
- `--type <type>` - Filter by workspace type
- `--framework <framework>` - Filter by framework

#### `re-shell workspace update`
Update workspace dependencies.

**Options:**
- `--workspace <name>` - Update specific workspace
- `--dependency <name>` - Update specific dependency
- `--version <version>` - Target version
- `--dev` - Update dev dependency

#### `re-shell workspace graph`
Generate workspace dependency graph.

**Options:**
- `--output <file>` - Output file path
- `--format <format>` - Output format (text, json, mermaid)

### Submodule Management

#### `re-shell submodule add <url>`
Add a new Git submodule.

**Options:**
- `--path <path>` - Submodule path
- `--branch <branch>` - Branch to track

#### `re-shell submodule remove <path>`
Remove a Git submodule.

**Options:**
- `--force` - Force removal without confirmation

#### `re-shell submodule update`
Update Git submodules.

**Options:**
- `--path <path>` - Update specific submodule

#### `re-shell submodule status`
Show Git submodule status.

#### `re-shell submodule manage`
Interactive submodule management.

### Legacy Commands

#### `re-shell add <name>`
Add a microfrontend (legacy, use `create` instead).

#### `re-shell remove <name>`
Remove a microfrontend.

#### `re-shell list`
List microfrontends.

#### `re-shell build [name]`
Build microfrontends.

#### `re-shell serve [name]`
Start development server.

## 🏗️ Supported Frameworks

| Framework | Template Name | TypeScript | Build Tool |
|-----------|---------------|------------|------------|
| React | `react` | ❌ | Vite |
| React + TS | `react-ts` | ✅ | Vite |
| Vue 3 | `vue` | ❌ | Vite |
| Vue 3 + TS | `vue-ts` | ✅ | Vite |
| Svelte | `svelte` | ❌ | Vite |
| Svelte + TS | `svelte-ts` | ✅ | Vite |
| Angular | `angular` | ✅ | Webpack |

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

# New (v0.2.0)
re-shell init my-project
cd my-project
re-shell create my-feature --framework react-ts --type app
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 [Documentation](https://github.com/Re-Shell/cli/docs)
- 🐛 [Issue Tracker](https://github.com/Re-Shell/cli/issues)
- 💬 [Discussions](https://github.com/Re-Shell/cli/discussions)
- 📧 [Email Support](mailto:support@re-shell.org)

---

**Re-Shell CLI v0.2.0** - Built with ❤️ for modern microfrontend development
