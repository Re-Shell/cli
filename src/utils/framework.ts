import * as fs from 'fs-extra';
import * as path from 'path';

export interface FrameworkConfig {
  name: string;
  displayName: string;
  buildTool: 'vite' | 'webpack' | 'rollup' | 'esbuild';
  packageManager: string[];
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  scripts: Record<string, string>;
  configFiles: string[];
  entryFile: string;
  extensions: string[];
  hasTypeScript?: boolean;
}

export const SUPPORTED_FRAMEWORKS: Record<string, FrameworkConfig> = {
  'react': {
    name: 'react',
    displayName: 'React',
    buildTool: 'vite',
    packageManager: ['npm', 'yarn', 'pnpm'],
    dependencies: {
      'react': '^18.2.0',
      'react-dom': '^18.2.0'
    },
    devDependencies: {
      'vite': '^4.4.0',
      '@vitejs/plugin-react': '^4.0.0',
      'eslint': '^8.44.0',
      'vitest': '^0.34.3'
    },
    scripts: {
      'dev': 'vite',
      'build': 'vite build',
      'preview': 'vite preview',
      'lint': 'eslint src --ext js,jsx',
      'test': 'vitest'
    },
    configFiles: ['vite.config.js', '.eslintrc.js'],
    entryFile: 'src/index.jsx',
    extensions: ['.js', '.jsx']
  },
  'react-ts': {
    name: 'react-ts',
    displayName: 'React with TypeScript',
    buildTool: 'vite',
    packageManager: ['npm', 'yarn', 'pnpm'],
    dependencies: {
      'react': '^18.2.0',
      'react-dom': '^18.2.0'
    },
    devDependencies: {
      'vite': '^4.4.0',
      '@vitejs/plugin-react': '^4.0.0',
      'typescript': '^5.0.0',
      '@types/react': '^18.2.0',
      '@types/react-dom': '^18.2.0',
      'eslint': '^8.44.0',
      'vitest': '^0.34.3'
    },
    scripts: {
      'dev': 'vite',
      'build': 'vite build',
      'preview': 'vite preview',
      'lint': 'eslint src --ext ts,tsx',
      'test': 'vitest',
      'type-check': 'tsc --noEmit'
    },
    configFiles: ['vite.config.ts', 'tsconfig.json', '.eslintrc.js'],
    entryFile: 'src/index.tsx',
    extensions: ['.ts', '.tsx'],
    hasTypeScript: true
  },
  'vue': {
    name: 'vue',
    displayName: 'Vue 3',
    buildTool: 'vite',
    packageManager: ['npm', 'yarn', 'pnpm'],
    dependencies: {
      'vue': '^3.3.0'
    },
    devDependencies: {
      'vite': '^4.4.0',
      '@vitejs/plugin-vue': '^4.0.0',
      'eslint': '^8.44.0',
      'vitest': '^0.34.3'
    },
    scripts: {
      'dev': 'vite',
      'build': 'vite build',
      'preview': 'vite preview',
      'lint': 'eslint src --ext js,vue',
      'test': 'vitest'
    },
    configFiles: ['vite.config.js', '.eslintrc.js'],
    entryFile: 'src/main.js',
    extensions: ['.js', '.vue']
  },
  'vue-ts': {
    name: 'vue-ts',
    displayName: 'Vue 3 with TypeScript',
    buildTool: 'vite',
    packageManager: ['npm', 'yarn', 'pnpm'],
    dependencies: {
      'vue': '^3.3.0'
    },
    devDependencies: {
      'vite': '^4.4.0',
      '@vitejs/plugin-vue': '^4.0.0',
      'typescript': '^5.0.0',
      'vue-tsc': '^1.8.0',
      'eslint': '^8.44.0',
      'vitest': '^0.34.3'
    },
    scripts: {
      'dev': 'vite',
      'build': 'vue-tsc && vite build',
      'preview': 'vite preview',
      'lint': 'eslint src --ext ts,vue',
      'test': 'vitest',
      'type-check': 'vue-tsc --noEmit'
    },
    configFiles: ['vite.config.ts', 'tsconfig.json', '.eslintrc.js'],
    entryFile: 'src/main.ts',
    extensions: ['.ts', '.vue'],
    hasTypeScript: true
  },
  'svelte': {
    name: 'svelte',
    displayName: 'Svelte',
    buildTool: 'vite',
    packageManager: ['npm', 'yarn', 'pnpm'],
    dependencies: {},
    devDependencies: {
      'svelte': '^4.0.0',
      'vite': '^4.4.0',
      '@sveltejs/vite-plugin-svelte': '^2.4.0',
      'eslint': '^8.44.0',
      'vitest': '^0.34.3'
    },
    scripts: {
      'dev': 'vite',
      'build': 'vite build',
      'preview': 'vite preview',
      'lint': 'eslint src --ext js,svelte',
      'test': 'vitest'
    },
    configFiles: ['vite.config.js', 'svelte.config.js', '.eslintrc.js'],
    entryFile: 'src/main.js',
    extensions: ['.js', '.svelte']
  },
  'svelte-ts': {
    name: 'svelte-ts',
    displayName: 'Svelte with TypeScript',
    buildTool: 'vite',
    packageManager: ['npm', 'yarn', 'pnpm'],
    dependencies: {},
    devDependencies: {
      'svelte': '^4.0.0',
      'vite': '^4.4.0',
      '@sveltejs/vite-plugin-svelte': '^2.4.0',
      'typescript': '^5.0.0',
      'svelte-check': '^3.4.0',
      'eslint': '^8.44.0',
      'vitest': '^0.34.3'
    },
    scripts: {
      'dev': 'vite',
      'build': 'vite build',
      'preview': 'vite preview',
      'lint': 'eslint src --ext ts,svelte',
      'test': 'vitest',
      'check': 'svelte-check --tsconfig ./tsconfig.json'
    },
    configFiles: ['vite.config.ts', 'svelte.config.js', 'tsconfig.json', '.eslintrc.js'],
    entryFile: 'src/main.ts',
    extensions: ['.ts', '.svelte'],
    hasTypeScript: true
  }
};

export function getFrameworkChoices() {
  return Object.values(SUPPORTED_FRAMEWORKS).map(framework => ({
    title: framework.displayName,
    value: framework.name
  }));
}

export function getFrameworkConfig(framework: string): FrameworkConfig {
  const config = SUPPORTED_FRAMEWORKS[framework];
  if (!config) {
    throw new Error(`Unsupported framework: ${framework}`);
  }
  return config;
}

export function detectFramework(projectPath: string): string | null {
  const packageJsonPath = path.join(projectPath, 'package.json');
  
  if (!fs.existsSync(packageJsonPath)) {
    return null;
  }

  try {
    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
    const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };

    // Check for framework-specific dependencies
    if (dependencies['@angular/core']) return 'angular';
    if (dependencies['vue']) return dependencies['typescript'] ? 'vue-ts' : 'vue';
    if (dependencies['svelte']) return dependencies['typescript'] ? 'svelte-ts' : 'svelte';
    if (dependencies['react']) return dependencies['typescript'] ? 'react-ts' : 'react';

    return null;
  } catch (error) {
    return null;
  }
}

export function validateFramework(framework: string): boolean {
  return framework in SUPPORTED_FRAMEWORKS;
}
