# Re-Shell CLI (v0.2.0)

A comprehensive command-line interface for creating and managing microfrontend applications with Re-Shell.

## Installation

### Global Installation

```bash
npm install -g @re-shell/cli
```

Or using yarn:

```bash
yarn global add @re-shell/cli
```

With pnpm:

```bash
pnpm add -g @re-shell/cli
```

### Local Installation

```bash
npm install @re-shell/cli --save-dev
```

Then add a script to your package.json:

```json
{
  "scripts": {
    "re-shell": "re-shell"
  }
}
```

## Commands

### Create a New Project

```bash
re-shell create my-project
```

This creates a new Re-Shell project with a shell application and the necessary structure for microfrontends.

#### Options

| Option | Description |
|--------|-------------|
| `--team <team>` | Team name |
| `--org <organization>` | Organization name (default: "re-shell") |
| `--description <description>` | Project description |
| `--template <template>` | Template to use (react, react-ts) |
| `--package-manager <pm>` | Package manager to use (npm, yarn, pnpm) |

### Add a Microfrontend

```bash
re-shell add my-microfrontend
```

Adds a new microfrontend to an existing Re-Shell project.

#### Options

| Option | Description |
|--------|-------------|
| `--team <team>` | Team name |
| `--org <organization>` | Organization name (default: "re-shell") |
| `--description <description>` | Microfrontend description |
| `--template <template>` | Template to use (react, react-ts) |
| `--route <route>` | Route path for the microfrontend (default: "/my-microfrontend") |
| `--port <port>` | Dev server port (default: 5173) |

### Remove a Microfrontend

```bash
re-shell remove my-microfrontend
```

Removes a microfrontend from an existing Re-Shell project.

#### Options

| Option | Description |
|--------|-------------|
| `--force` | Force removal without confirmation |
| `--keep-code` | Keep the source code but unregister from shell |

### List Microfrontends

```bash
re-shell list
```

Lists all microfrontends in the current project.

#### Options

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |
| `--format <format>` | Output format (table, json, yaml) |
| `--include-details` | Include additional details about each microfrontend |

### Build Microfrontends

```bash
re-shell build
# Or build a specific microfrontend
re-shell build my-microfrontend
```

Builds all or a specific microfrontend.

#### Options

| Option | Description |
|--------|-------------|
| `--production` | Build for production environment |
| `--analyze` | Analyze bundle size |
| `--watch` | Watch for changes and rebuild |
| `--verbose` | Show detailed build output |

### Start Development Server

```bash
re-shell serve
# Or serve a specific microfrontend
re-shell serve my-microfrontend
```

Starts the development server for all or a specific microfrontend.

#### Options

| Option | Description |
|--------|-------------|
| `--port <port>` | Port to serve on (default: 3000) |
| `--host <host>` | Host to serve on (default: localhost) |
| `--open` | Open in browser |
| `--https` | Use HTTPS |
| `--proxy <config>` | Proxy configuration file |

## What's New in v0.2.0

### New Features

- **Enhanced Command Structure**: Improved command organization and help messages
- **Build Command Improvements**: Added watch mode and bundle analysis
- **Serve Command Updates**: HTTPS support and improved proxy configuration
- **List Command Enhancements**: Multiple output formats and detailed information
- **Project Templates**: Additional project templates with better customization
- **Performance Optimizations**: Faster builds and more efficient resource usage

### Breaking Changes

- The `create-mf` command has been renamed to `add` for consistency
- Configuration format has been updated for better extensibility

## Project Structure

Re-Shell creates the following project structure:

```
my-project/
├── apps/                 # Microfrontend applications
│   ├── shell/            # Main shell application
│   └── test-app/         # Test application for development
├── packages/             # Shared libraries
└── docs/                 # Documentation
```

## Integration with Shell Application

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

## Testing with Test Application

The CLI automatically configures the test application to include your new microfrontends.

To run the test application:

```bash
# From the root of your Re-Shell project
pnpm --filter test-app dev
```

## License

MIT