# ReShell CLI

A comprehensive command-line interface for creating and managing microfrontend applications with ReShell.

## Installation

### Global Installation

```bash
npm install -g reshell-cli
```

Or using yarn:

```bash
yarn global add reshell-cli
```

### Local Installation

```bash
npm install reshell-cli --save-dev
```

Then add a script to your package.json:

```json
{
  "scripts": {
    "reshell": "reshell"
  }
}
```

## Commands

### Create a New Project

```bash
reshell create my-project
```

This creates a new ReShell project with a shell application and the necessary structure for microfrontends.

#### Options

| Option | Description |
|--------|-------------|
| `--team <team>` | Team name |
| `--org <organization>` | Organization name (default: "reshell") |
| `--description <description>` | Project description |
| `--template <template>` | Template to use (react, react-ts) |
| `--package-manager <pm>` | Package manager to use (npm, yarn, pnpm) |

### Add a Microfrontend

```bash
reshell add user-dashboard
```

Adds a new microfrontend to an existing ReShell project.

#### Options

| Option | Description |
|--------|-------------|
| `--team <team>` | Team name |
| `--org <organization>` | Organization name (default: "reshell") |
| `--description <description>` | Microfrontend description |
| `--template <template>` | Template to use (react, react-ts) |
| `--route <route>` | Route path for the microfrontend |
| `--port <port>` | Dev server port |

### Remove a Microfrontend

```bash
reshell remove user-dashboard
```

Removes a microfrontend from an existing ReShell project.

#### Options

| Option | Description |
|--------|-------------|
| `--force` | Force removal without confirmation |

### List Microfrontends

```bash
reshell list
```

Lists all microfrontends in the current project.

#### Options

| Option | Description |
|--------|-------------|
| `--json` | Output as JSON |

### Build Microfrontends

```bash
reshell build
# Or build a specific microfrontend
reshell build user-dashboard
```

Builds all or a specific microfrontend.

#### Options

| Option | Description |
|--------|-------------|
| `--production` | Build for production environment |
| `--analyze` | Analyze bundle size |

### Start Development Server

```bash
reshell serve
# Or serve a specific microfrontend
reshell serve user-dashboard
```

Starts the development server for all or a specific microfrontend.

#### Options

| Option | Description |
|--------|-------------|
| `--port <port>` | Port to serve on (default: 3000) |
| `--host <host>` | Host to serve on (default: localhost) |
| `--open` | Open in browser |

## Project Structure

ReShell creates the following project structure:

```
my-project/
├── apps/                 # Microfrontend applications
│   └── shell/            # Main shell application
├── packages/             # Shared libraries
└── docs/                 # Documentation
```

## Integration with Shell Application

After creating a microfrontend, you can integrate it with your shell application by adding it to your shell configuration:

```javascript
// In your shell application
import { ShellProvider, MicrofrontendContainer } from '@reshell/core';

const microfrontends = [
  {
    id: 'user-dashboard',
    name: 'User Dashboard',
    url: '/apps/user-dashboard/dist/mf.umd.js',
    containerId: 'user-dashboard-container',
    route: '/users',
    team: 'User Team'
  }
  // ... other microfrontends
];
```

## License

MIT