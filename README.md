# Re-Shell CLI (v0.2.1)

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

### List Microfrontends

```bash
re-shell list
```

Lists all microfrontends in the current project.

#### Options

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |

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

## What's New in v0.2.1

### Bug Fixes and Improvements

- Fixed version mismatch in package.json
- Updated documentation to match actual CLI functionality
- Removed deprecated options that were not implemented
- Improved error handling and messages

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

## Project Structure

Re-Shell creates the following project structure:

```
my-project/
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


## License

MIT