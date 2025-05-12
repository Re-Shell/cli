import * as fs from 'fs-extra';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as prompts from 'prompts';

const execAsync = promisify(exec);

interface CreateMicrofrontendOptions {
  team?: string;
  org?: string;
  description?: string;
  template?: string;
  route?: string;
  standalone?: boolean;
}

/**
 * Creates a new microfrontend repository
 *
 * @param name - Name of the microfrontend
 * @param options - Additional options for creation
 */
export async function createMicrofrontend(
  name: string,
  options: CreateMicrofrontendOptions
): Promise<void> {
  const {
    team,
    org = 'reshell',
    description = `${name} microfrontend for ReShell`,
    template = 'react',
    route = `/${name.toLowerCase()}`,
    standalone = false
  } = options;

  // Normalize name to kebab-case for consistency
  const normalizedName = name.toLowerCase().replace(/\s+/g, '-');

  console.log(`Creating microfrontend "${normalizedName}"...`);

  // Ask for additional information if not provided
  const responses = await prompts([
    {
      type: options.template ? null : 'select',
      name: 'template',
      message: 'Select a template:',
      choices: [
        { title: 'React', value: 'react' },
        { title: 'React with TypeScript', value: 'react-ts' }
      ],
      initial: 0
    },
    {
      type: options.route ? null : 'text',
      name: 'route',
      message: 'Route path for the microfrontend:',
      initial: `/${normalizedName}`
    },
    {
      type: options.standalone !== undefined ? null : 'confirm',
      name: 'standalone',
      message: 'Create as standalone project? (not in a monorepo)',
      initial: false
    }
  ]);

  // Merge responses with options
  const finalOptions = {
    ...options,
    template: options.template || responses.template,
    route: options.route || responses.route,
    standalone: options.standalone !== undefined ? options.standalone : responses.standalone
  };

  // Create local directory structure
  const repoPath = path.resolve(process.cwd(), normalizedName);

  // Check if directory already exists
  if (fs.existsSync(repoPath)) {
    throw new Error(`Directory already exists: ${repoPath}`);
  }

  // Create directory structure
  fs.mkdirSync(repoPath);
  fs.mkdirSync(path.join(repoPath, 'src'));
  fs.mkdirSync(path.join(repoPath, 'public'));

  // Create package.json
  const packageJson = {
    name: finalOptions.standalone ? normalizedName : `@${org.toLowerCase()}/${normalizedName}`,
    version: '0.1.0',
    description,
    main: 'dist/index.js',
    scripts: {
      dev: 'vite',
      build: 'vite build',
      preview: 'vite preview',
      lint: 'eslint src --ext ts,tsx',
      test: 'vitest'
    },
    dependencies: {
      react: '^18.2.0',
      'react-dom': '^18.2.0'
    },
    peerDependencies: {
      '@reshell/core': '^0.1.0'
    },
    devDependencies: {
      'vite': '^4.4.0',
      '@vitejs/plugin-react': '^4.0.0',
      'eslint': '^8.44.0',
      'vitest': '^0.34.3',
      ...(finalOptions.template === 'react-ts' ? {
        'typescript': '^5.0.0',
        '@types/react': '^18.2.0',
        '@types/react-dom': '^18.2.0',
      } : {})
    },
    keywords: [
      'microfrontend',
      'react',
      'reshell'
    ],
    author: team || org,
    license: 'MIT',
    reshell: {
      type: 'microfrontend',
      route: finalOptions.route
    }
  };

  fs.writeFileSync(
    path.join(repoPath, 'package.json'),
    JSON.stringify(packageJson, null, 2)
  );

  // Create vite.config.ts or vite.config.js
  const fileExtension = finalOptions.template === 'react-ts' ? 'ts' : 'js';
  const viteConfig = `
import { defineConfig } from 'vite';
import { resolve } from 'path';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.${finalOptions.template === 'react-ts' ? 'tsx' : 'jsx'}'),
      name: '${normalizedName.charAt(0).toUpperCase() + normalizedName.slice(1).replace(/-./g, x => x[1].toUpperCase())}',
      formats: ['umd'],
      fileName: 'mf'
    },
    rollupOptions: {
      external: ['react', 'react-dom', '@reshell/core'],
      output: {
        globals: {
          react: 'React',
          'react-dom': 'ReactDOM',
          '@reshell/core': 'ReShell'
        }
      }
    }
  },
  server: {
    port: 5173,
    cors: true,
    headers: {
      'Access-Control-Allow-Origin': '*'
    }
  }
});
`;

  fs.writeFileSync(path.join(repoPath, `vite.config.${fileExtension}`), viteConfig);

  // Create TypeScript configuration if using a TypeScript template
  if (finalOptions.template === 'react-ts') {
    const tsConfig = {
      compilerOptions: {
        target: 'ES2020',
        useDefineForClassFields: true,
        lib: ['ES2020', 'DOM', 'DOM.Iterable'],
        module: 'ESNext',
        skipLibCheck: true,
        moduleResolution: 'bundler',
        allowImportingTsExtensions: true,
        resolveJsonModule: true,
        isolatedModules: true,
        noEmit: true,
        jsx: 'react-jsx',
        strict: true,
        noImplicitAny: true,
        strictNullChecks: true
      },
      include: ['src'],
      references: [{ path: './tsconfig.node.json' }]
    };

    fs.writeFileSync(
      path.join(repoPath, 'tsconfig.json'),
      JSON.stringify(tsConfig, null, 2)
    );

    const tsNodeConfig = {
      compilerOptions: {
        composite: true,
        skipLibCheck: true,
        module: 'ESNext',
        moduleResolution: 'bundler',
        allowSyntheticDefaultImports: true
      },
      include: [`vite.config.${fileExtension}`]
    };

    fs.writeFileSync(
      path.join(repoPath, 'tsconfig.node.json'),
      JSON.stringify(tsNodeConfig, null, 2)
    );
  }

  // Create main index file
  const indexFileExtension = finalOptions.template === 'react-ts' ? 'tsx' : 'jsx';
  const indexContent = `${finalOptions.template === 'react-ts' ? 'import React from \'react\';\nimport { createRoot } from \'react-dom/client\';\n' : 'import { createRoot } from \'react-dom/client\';\n'}import App from './App';
import { eventBus } from ${finalOptions.standalone ? './eventBus' : '\'@reshell/core\''};

// Entry point for the microfrontend
// This gets exposed when the script is loaded
window.${normalizedName.replace(/-./g, x => x[1].toUpperCase())} = {
  mount: (containerId) => {
    const container = document.getElementById(containerId);
    if (!container) {
      console.error(\`Container element with ID "\${containerId}" not found\`);
      return;
    }

    // Using React 18's createRoot API
    const root = createRoot(container);
    root.render(<App />);

    // Notify shell that microfrontend is loaded
    eventBus.emit('microfrontend:loaded', { id: '${normalizedName}' });

    // Store root for unmounting
    window.${normalizedName.replace(/-./g, x => x[1].toUpperCase())}.root = root;
  },
  unmount: () => {
    if (window.${normalizedName.replace(/-./g, x => x[1].toUpperCase())}.root) {
      window.${normalizedName.replace(/-./g, x => x[1].toUpperCase())}.root.unmount();
    }
  }
};

// For development mode - mount the app immediately
if (process.env.NODE_ENV === 'development') {
  const devRoot = document.getElementById('root');
  if (devRoot) {
    const root = createRoot(devRoot);
    root.render(<App />);
  }
}

export default App;
`;

  fs.writeFileSync(path.join(repoPath, 'src', `index.${indexFileExtension}`), indexContent);

  // Create app component
  const appFileExtension = finalOptions.template === 'react-ts' ? 'tsx' : 'jsx';
  const appContent = `${finalOptions.template === 'react-ts' ? 'import React from \'react\';\n\ninterface AppProps {}\n\n' : ''}
function App(${finalOptions.template === 'react-ts' ? 'props: AppProps' : ''}) {
  return (
    <div className="${normalizedName}-app">
      <h2>${normalizedName} Microfrontend</h2>
      <p>This is a microfrontend created with ReShell CLI</p>
    </div>
  );
}

export default App;
`;

  fs.writeFileSync(path.join(repoPath, 'src', `App.${appFileExtension}`), appContent);

  // If standalone, create eventBus file
  if (finalOptions.standalone) {
    const eventBusFileExtension = finalOptions.template === 'react-ts' ? 'ts' : 'js';
    const eventBusContent = `${finalOptions.template === 'react-ts' ? 'type EventHandler = (data: any) => void;\n\ninterface EventBus {\n  events: Record<string, EventHandler[]>;\n  on(event: string, callback: EventHandler): void;\n  off(event: string, callback: EventHandler): void;\n  emit(event: string, data: any): void;\n}\n\n' : ''}
/**
 * Simple event bus for communication between microfrontends
 * In a real implementation, you would use the eventBus from @reshell/core
 */
export const eventBus${finalOptions.template === 'react-ts' ? ': EventBus' : ''} = {
  events: {},
  on(event, callback) {
    if (!this.events[event]) {
      this.events[event] = [];
    }
    this.events[event].push(callback);
  },
  off(event, callback) {
    if (this.events[event]) {
      this.events[event] = this.events[event].filter(cb => cb !== callback);
    }
  },
  emit(event, data) {
    if (this.events[event]) {
      this.events[event].forEach(callback => callback(data));
    }
  }
};
`;

    fs.writeFileSync(path.join(repoPath, 'src', `eventBus.${eventBusFileExtension}`), eventBusContent);
  }

  // Create HTML file for development mode
  const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${normalizedName} - ReShell Microfrontend</title>
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/index.${finalOptions.template === 'react-ts' ? 'tsx' : 'jsx'}"></script>
</body>
</html>
`;

  fs.writeFileSync(path.join(repoPath, 'public', 'index.html'), htmlContent);

  // Create README.md
  const readmeContent = `# ${normalizedName}

## Overview
This is a microfrontend for the ReShell architecture.

## Development
To start the development server:
\`\`\`bash
npm install
npm run dev
\`\`\`

## Building
To build the microfrontend:
\`\`\`bash
npm run build
\`\`\`

## Integration
This microfrontend can be integrated into a ReShell application by adding the following configuration to your shell application:

\`\`\`javascript
const microfrontendConfig = {
  id: '${normalizedName}',
  name: '${normalizedName.charAt(0).toUpperCase() + normalizedName.slice(1).replace(/-./g, x => x[1].toUpperCase())}',
  url: '/apps/${normalizedName}/dist/mf.umd.js', // Path to built bundle
  containerId: '${normalizedName}-container',
  route: '${finalOptions.route}',
  team: '${team || 'Your Team'}'
};
\`\`\`

Then add the container element in your shell application:
\`\`\`jsx
<div id="${normalizedName}-container"></div>
\`\`\`
`;

  fs.writeFileSync(path.join(repoPath, 'README.md'), readmeContent);

  // Create .gitignore
  const gitignoreContent = `# Logs
logs
*.log
npm-debug.log*
yarn-debug.log*
yarn-error.log*
pnpm-debug.log*
lerna-debug.log*

node_modules
dist
dist-ssr
*.local

# Editor directories and files
.vscode/*
!.vscode/extensions.json
.idea
.DS_Store
*.suo
*.ntvs*
*.njsproj
*.sln
*.sw?
`;

  fs.writeFileSync(path.join(repoPath, '.gitignore'), gitignoreContent);

  // If part of a monorepo, suggest shell integration
  if (!finalOptions.standalone) {
    console.log(`\nLooking for shell application to update...`);
    const shellPath = path.resolve(process.cwd(), '..', 'shell');

    if (fs.existsSync(shellPath) && fs.existsSync(path.join(shellPath, 'src', 'App.tsx'))) {
      console.log(`Found shell application at ${shellPath}`);
      console.log(`You can integrate this microfrontend by updating the shell application's App.tsx file.`);
    } else {
      console.log(`No shell application found at ${shellPath}`);
      console.log(`To integrate this microfrontend, add it to your shell application's configuration.`);
    }
  }

  console.log(`\nMicrofrontend "${normalizedName}" created successfully at ${repoPath}`);
  console.log('\nNext steps:');
  console.log(`  1. cd ${normalizedName}`);
  console.log('  2. npm install or pnpm install');
  console.log('  3. npm run dev (to start development server)');

  if (finalOptions.standalone) {
    console.log('  4. npm run build (to create production build)');
    console.log('  5. git init && git add . && git commit -m "Initial commit"');
  } else {
    console.log('  4. Update your shell application to include this microfrontend');
  }
}