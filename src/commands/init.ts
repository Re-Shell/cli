import * as fs from 'fs-extra';
import * as path from 'path';
import prompts from 'prompts';
import chalk from 'chalk';
import { initializeMonorepo, DEFAULT_MONOREPO_STRUCTURE } from '../utils/monorepo';
import { initializeGitRepository, generateSubmoduleScript, createSubmoduleDocumentation } from '../utils/submodule';

interface InitOptions {
  packageManager?: 'npm' | 'yarn' | 'pnpm';
  structure?: Partial<typeof DEFAULT_MONOREPO_STRUCTURE>;
  git?: boolean;
  submodules?: boolean;
  force?: boolean;
}

/**
 * Initialize a new monorepo workspace with Re-Shell CLI
 * 
 * @param name - Name of the monorepo
 * @param options - Initialization options
 */
export async function initMonorepo(
  name: string,
  options: InitOptions = {}
): Promise<void> {
  const normalizedName = name.toLowerCase().replace(/\s+/g, '-');
  const projectPath = path.resolve(process.cwd(), normalizedName);

  // Check if directory already exists
  if (fs.existsSync(projectPath) && !options.force) {
    const { overwrite } = await prompts({
      type: 'confirm',
      name: 'overwrite',
      message: `Directory "${normalizedName}" already exists. Overwrite?`,
      initial: false
    });

    if (!overwrite) {
      console.log(chalk.yellow('Operation cancelled.'));
      return;
    }
  }

  // Interactive prompts for missing options
  const responses = await prompts([
    {
      type: options.packageManager ? null : 'select',
      name: 'packageManager',
      message: 'Select a package manager:',
      choices: [
        { title: 'pnpm (recommended)', value: 'pnpm' },
        { title: 'yarn', value: 'yarn' },
        { title: 'npm', value: 'npm' }
      ],
      initial: 0
    },
    {
      type: options.git !== undefined ? null : 'confirm',
      name: 'git',
      message: 'Initialize Git repository?',
      initial: true
    },
    {
      type: options.submodules !== undefined ? null : 'confirm',
      name: 'submodules',
      message: 'Set up Git submodule support?',
      initial: true
    },
    {
      type: 'confirm',
      name: 'customStructure',
      message: 'Customize directory structure?',
      initial: false
    }
  ]);

  let customStructure = {};
  if (responses.customStructure) {
    const structureResponses = await prompts([
      {
        type: 'text',
        name: 'apps',
        message: 'Applications directory name:',
        initial: 'apps'
      },
      {
        type: 'text',
        name: 'packages',
        message: 'Packages directory name:',
        initial: 'packages'
      },
      {
        type: 'text',
        name: 'libs',
        message: 'Libraries directory name:',
        initial: 'libs'
      },
      {
        type: 'text',
        name: 'tools',
        message: 'Tools directory name:',
        initial: 'tools'
      },
      {
        type: 'text',
        name: 'docs',
        message: 'Documentation directory name:',
        initial: 'docs'
      }
    ]);
    customStructure = structureResponses;
  }

  // Merge options with responses
  const finalOptions = {
    packageManager: options.packageManager || responses.packageManager || 'pnpm',
    git: options.git !== undefined ? options.git : responses.git,
    submodules: options.submodules !== undefined ? options.submodules : responses.submodules,
    structure: { ...options.structure, ...customStructure }
  };

  console.log(chalk.cyan(`\nInitializing monorepo "${normalizedName}"...`));

  try {
    // Remove existing directory if force option is used
    if (fs.existsSync(projectPath) && options.force) {
      await fs.remove(projectPath);
    }

    // Initialize monorepo structure
    await initializeMonorepo(
      normalizedName,
      finalOptions.packageManager as 'npm' | 'yarn' | 'pnpm',
      finalOptions.structure
    );

    console.log(chalk.green('✓ Monorepo structure created'));

    // Initialize Git repository
    if (finalOptions.git) {
      await initializeGitRepository(projectPath);
      console.log(chalk.green('✓ Git repository initialized'));
    }

    // Set up submodule support
    if (finalOptions.submodules) {
      await generateSubmoduleScript(projectPath);
      await createSubmoduleDocumentation(projectPath, []);
      console.log(chalk.green('✓ Submodule support configured'));
    }

    // Create additional configuration files
    await createAdditionalConfigs(projectPath, finalOptions);
    console.log(chalk.green('✓ Configuration files created'));

    // Success message
    console.log(chalk.green(`\n🎉 Monorepo "${normalizedName}" initialized successfully!`));
    console.log('\nNext steps:');
    console.log(`  1. cd ${normalizedName}`);
    console.log(`  2. ${finalOptions.packageManager} install`);
    console.log('  3. re-shell create my-app --framework react-ts');
    console.log('  4. re-shell workspace list');

    if (finalOptions.submodules) {
      console.log('\nSubmodule commands:');
      console.log('  • re-shell submodule add <url> <path>');
      console.log('  • re-shell submodule status');
      console.log('  • ./scripts/submodule-helper.sh --help');
    }

  } catch (error) {
    console.error(chalk.red('Error initializing monorepo:'), error);
    throw error;
  }
}

async function createAdditionalConfigs(
  projectPath: string,
  options: { packageManager: string; git: boolean; submodules: boolean }
): Promise<void> {
  // Create .nvmrc for Node.js version
  await fs.writeFile(
    path.join(projectPath, '.nvmrc'),
    '18.17.0\n'
  );

  // Create .editorconfig
  const editorConfig = `root = true

[*]
charset = utf-8
end_of_line = lf
indent_style = space
indent_size = 2
insert_final_newline = true
trim_trailing_whitespace = true

[*.md]
trim_trailing_whitespace = false

[*.{yml,yaml}]
indent_size = 2

[*.json]
indent_size = 2
`;

  await fs.writeFile(
    path.join(projectPath, '.editorconfig'),
    editorConfig
  );

  // Create VSCode settings
  const vscodeDir = path.join(projectPath, '.vscode');
  await fs.ensureDir(vscodeDir);

  const vscodeSettings = {
    "typescript.preferences.includePackageJsonAutoImports": "on",
    "typescript.suggest.autoImports": true,
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.fixAll.eslint": true
    },
    "files.associations": {
      "*.json": "jsonc"
    },
    "search.exclude": {
      "**/node_modules": true,
      "**/dist": true,
      "**/build": true,
      "**/.next": true,
      "**/.nuxt": true
    }
  };

  await fs.writeFile(
    path.join(vscodeDir, 'settings.json'),
    JSON.stringify(vscodeSettings, null, 2)
  );

  const vscodeExtensions = {
    "recommendations": [
      "esbenp.prettier-vscode",
      "dbaeumer.vscode-eslint",
      "bradlc.vscode-tailwindcss",
      "ms-vscode.vscode-typescript-next",
      "ms-vscode.vscode-json",
      "redhat.vscode-yaml",
      "ms-vscode.vscode-npm-script"
    ]
  };

  await fs.writeFile(
    path.join(vscodeDir, 'extensions.json'),
    JSON.stringify(vscodeExtensions, null, 2)
  );

  // Create GitHub workflows if Git is enabled
  if (options.git) {
    const githubDir = path.join(projectPath, '.github', 'workflows');
    await fs.ensureDir(githubDir);

    const ciWorkflow = `name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        node-version: [16.x, 18.x]
    
    steps:
    - uses: actions/checkout@v3
      with:
        submodules: recursive
    
    - name: Use Node.js \${{ matrix.node-version }}
      uses: actions/setup-node@v3
      with:
        node-version: \${{ matrix.node-version }}
        cache: '${options.packageManager}'
    
    - name: Install dependencies
      run: ${options.packageManager} install
    
    - name: Run linting
      run: ${options.packageManager} run lint
    
    - name: Run tests
      run: ${options.packageManager} run test
    
    - name: Build
      run: ${options.packageManager} run build
`;

    await fs.writeFile(
      path.join(githubDir, 'ci.yml'),
      ciWorkflow
    );
  }

  // Create Docker support files
  const dockerfile = `# Multi-stage build for production
FROM node:18-alpine AS base

# Install dependencies only when needed
FROM base AS deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY ${options.packageManager === 'pnpm' ? 'pnpm-lock.yaml' : options.packageManager === 'yarn' ? 'yarn.lock' : 'package-lock.json'} ./

# Install dependencies
RUN ${options.packageManager === 'pnpm' ? 'npm install -g pnpm && pnpm install --frozen-lockfile' : 
     options.packageManager === 'yarn' ? 'yarn install --frozen-lockfile' : 
     'npm ci'}

# Build stage
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

RUN ${options.packageManager} run build

# Production stage
FROM base AS runner
WORKDIR /app

ENV NODE_ENV production

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json

USER nextjs

EXPOSE 3000

ENV PORT 3000

CMD ["node", "dist/index.js"]
`;

  await fs.writeFile(
    path.join(projectPath, 'Dockerfile'),
    dockerfile
  );

  const dockerignore = `node_modules
npm-debug.log
.next
.git
.gitignore
README.md
Dockerfile
.dockerignore
.env.local
.env.development.local
.env.test.local
.env.production.local
`;

  await fs.writeFile(
    path.join(projectPath, '.dockerignore'),
    dockerignore
  );
}
