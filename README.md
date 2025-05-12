# Re-Shell CLI

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
re-shell add user-dashboard
```

Adds a new microfrontend to an existing Re-Shell project.

#### Options

| Option | Description |
|--------|-------------|
| `--team <team>` | Team name |
| `--org <organization>` | Organization name (default: "re-shell") |
| `--description <description>` | Microfrontend description |
| `--template <template>` | Template to use (react, react-ts) |
| `--route <route>` | Route path for the microfrontend |
| `--port <port>` | Dev server port |

### Remove a Microfrontend

```bash
re-shell remove user-dashboard
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
re-shell build user-dashboard
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
re-shell serve user-dashboard
```

Starts the development server for all or a specific microfrontend.

#### Options

| Option | Description |
|--------|-------------|
| `--port <port>` | Port to serve on (default: 3000) |
| `--host <host>` | Host to serve on (default: localhost) |
| `--open` | Open in browser |

## Project Structure

Re-Shell creates the following project structure:

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
import { ShellProvider, MicrofrontendContainer } from '@re-shell/core';

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