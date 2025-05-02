import * as fs from 'fs-extra';
import * as path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

interface CreateMicrofrontendOptions {
  team?: string;
  org?: string;
  description?: string;
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
  const { team, org = 'Re-Shell', description = `${name} microfrontend for ReShell` } = options;
  
  console.log(`Creating microfrontend "${name}"...`);
  
  // Step 1: Create repository on GitHub
  console.log('Creating GitHub repository...');
  // This would normally use Octokit to interact with GitHub API
  // For now, we'll just create directories locally
  
  // Step 2: Create local directory structure
  const repoPath = path.resolve(process.cwd(), name);
  
  // Check if directory already exists
  if (fs.existsSync(repoPath)) {
    throw new Error(`Directory already exists: ${repoPath}`);
  }
  
  // Create directory
  fs.mkdirSync(repoPath);
  fs.mkdirSync(path.join(repoPath, 'src'));
  fs.mkdirSync(path.join(repoPath, 'public'));
  
  // Step 3: Create package.json
  const packageJson = {
    name: `@${org.toLowerCase()}/${name}`,
    version: '0.1.0',
    description,
    main: 'dist/index.js',
    scripts: {
      dev: 'vite',
      build: 'vite build',
      preview: 'vite preview',
      lint: 'eslint src --ext ts,tsx',
      test: 'jest'
    },
    dependencies: {
      react: '^18.2.0',
      'react-dom': '^18.2.0'
    },
    peerDependencies: {
      '@reshell/core': '^0.1.0'
    },
    keywords: [
      'microfrontend',
      'react',
      'reshell'
    ],
    author: team || org,
    license: 'MIT'
  };
  
  fs.writeFileSync(
    path.join(repoPath, 'package.json'),
    JSON.stringify(packageJson, null, 2)
  );
  
  // Step 4: Create vite.config.ts
  const viteConfig = `
import { defineConfig } from 'vite';
import { resolve } from 'path';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.tsx'),
      name: '${name.charAt(0).toUpperCase() + name.slice(1)}',
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
  }
});
`;
  
  fs.writeFileSync(path.join(repoPath, 'vite.config.ts'), viteConfig);
  
  // Step 5: Create tsconfig.json
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
      noImplicitAny: true
    },
    include: ['src'],
    references: [{ path: './tsconfig.node.json' }]
  };
  
  fs.writeFileSync(
    path.join(repoPath, 'tsconfig.json'),
    JSON.stringify(tsConfig, null, 2)
  );
  
  // Step 6: Create tsconfig.node.json
  const tsNodeConfig = {
    compilerOptions: {
      composite: true,
      skipLibCheck: true,
      module: 'ESNext',
      moduleResolution: 'bundler',
      allowSyntheticDefaultImports: true
    },
    include: ['vite.config.ts']
  };
  
  fs.writeFileSync(
    path.join(repoPath, 'tsconfig.node.json'),
    JSON.stringify(tsNodeConfig, null, 2)
  );
  
  // Step 7: Create sample component files
  const indexContent = `
import App from './App';

// Entry point for the microfrontend
// This gets exposed when the script is loaded
window.${name.charAt(0).toLowerCase() + name.slice(1)}App = {
  mount: (containerId) => {
    const container = document.getElementById(containerId);
    if (!container) {
      console.error(\`Container element with ID "\${containerId}" not found\`);
      return;
    }
    
    const root = document.createElement('div');
    container.appendChild(root);
    
    // In a real implementation, you would use ReactDOM.createRoot
    // and render the App component here
    const appElement = document.createElement('div');
    appElement.textContent = '${name} Microfrontend Loaded!';
    root.appendChild(appElement);
  },
  unmount: (containerId) => {
    const container = document.getElementById(containerId);
    if (container) {
      container.innerHTML = '';
    }
  }
};

export default App;
`;
  
  fs.writeFileSync(path.join(repoPath, 'src', 'index.tsx'), indexContent);
  
  const appContent = `
import React from 'react';

function App() {
  return (
    <div className="${name}-app">
      <h2>${name} Microfrontend</h2>
      <p>This is a microfrontend created with ReShell CLI</p>
    </div>
  );
}

export default App;
`;
  
  fs.writeFileSync(path.join(repoPath, 'src', 'App.tsx'), appContent);
  
  // Step 8: Create README.md
  const readmeContent = `
# ${name}

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
This microfrontend can be integrated into a ReShell application.
`;
  
  fs.writeFileSync(path.join(repoPath, 'README.md'), readmeContent);
  
  // Step 9: Create .gitignore
  const gitignoreContent = `
# Logs
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
  
  console.log(`Microfrontend "${name}" created successfully at ${repoPath}`);
  console.log('Next steps:');
  console.log(`  1. cd ${name}`);
  console.log('  2. npm install or pnpm install');
  console.log('  3. git init && git add . && git commit -m "Initial commit"');
  console.log(`  4. git remote add origin git@github.com:${org}/${name}.git`);
  console.log('  5. git push -u origin main');
}