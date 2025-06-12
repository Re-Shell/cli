# Re-Shell CLI v0.2.2

A powerful command-line interface for creating and managing multi-framework monorepo and microfrontend applications using the Re-Shell architecture.

## 🚀 Features

- **🎯 Multi-Framework Support**: React, Vue, Svelte with TypeScript support
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
- `--package-manager <pm>` - Package manager to use (npm|yarn|pnpm) [default: pnpm]
- `--no-git` - Skip Git repository initialization
- `--no-submodules` - Skip submodule support setup
- `--force` - Overwrite existing directory

**Features:**
- Creates complete monorepo directory structure (apps/, packages/, libs/, tools/, docs/)
- Interactive prompts for missing configuration
- Customizable directory structure during setup
- Generates root package.json with workspace configuration
- Creates development environment files (.nvmrc, .editorconfig, .vscode/)
- Sets up GitHub Actions workflow (if Git enabled)
- Creates Docker configuration (Dockerfile, .dockerignore)
- Generates submodule helper scripts (if enabled)
- Initializes Git repository with proper .gitignore

**Example:**
```bash
re-shell init my-project --package-manager pnpm
```

#### `re-shell update`
Check for Re-Shell CLI updates.

**Features:**
- Checks npm registry for latest version
- Compares with current installed version
- Provides update instructions for npm, yarn, and pnpm
- Non-intrusive background checks (cached for 24 hours)
- Shows changelog link for version updates

**Example:**
```bash
re-shell update
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

- **yarn**
  - Workspace protocol
  - Plug'n'Play support
  - Berry compatibility

- **npm**
  - Native workspaces
  - Standard registry
  - Wide compatibility

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

## 🎨 Developer Experience

- **Interactive prompts** for configuration
- **Color-coded output** with chalk
- **Progress indicators** with ora spinners
- **Comprehensive error messages**
- **ASCII art banner** for branding
- **Detailed help** for each command
- **Validation and error prevention**
- **Smart defaults** for all options

## 📄 Generated Configurations

### Project Files
- `package.json` with scripts and dependencies
- `tsconfig.json` for TypeScript projects
- `vite.config.ts/js` with module federation
- `.eslintrc.js` with framework rules
- `README.md` with documentation

### Development Environment
- `.editorconfig` for consistent coding
- `.nvmrc` for Node version management
- `.vscode/settings.json` for IDE
- `.vscode/extensions.json` recommendations

### Build & Deploy
- `Dockerfile` for containerization
- `.dockerignore` for Docker builds
- `.github/workflows/ci.yml` for CI/CD
- Build scripts in package.json

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

# New (v0.2.2)
re-shell init my-project
cd my-project
re-shell create my-feature --framework react-ts --type app
```

## What's New in v0.2.4

### Bug Fixes
- **Fixed Terminal Output Buffering**: Resolved issue where CLI commands would hang with "Creating..." text until Enter was pressed
- **Improved Spinner Behavior**: Enhanced spinner and progress indicators for better terminal compatibility
- **Better Terminal Detection**: Added fallback behavior for non-interactive terminals (CI environments, etc.)
- **Immediate Output Flushing**: All CLI output now appears immediately without requiring user input

### Improvements
- Enhanced terminal experience across different environments
- Better support for various terminal emulators and shell environments

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

**Re-Shell CLI v0.2.2** - Built with ❤️ for modern microfrontend development